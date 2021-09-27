# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
# created: 2018-03-31


import os
import logging
import math
import pprint
import shutil
import time
import traceback
import urllib
import requests

from pathlib import Path

from sign_node.utils.file_utils import download_file, hash_file, safe_mkdir
from sign_node.uploaders.pulp import PulpRpmUploader
from sign_node.package_sign import sign_dsc_package, sign_deb_package, sign_rpm_package

from .errors import ConnectionError
from .utils.hashing import get_hasher

__all__ = ["Signer"]


class Signer(object):
    def __init__(self, config, password_db, gpg):
        self.__config = config
        self.__password_db = password_db
        self.__gpg = gpg
        self.__pulp_uploader = PulpRpmUploader(
            self.__config.pulp_host,
            self.__config.pulp_user,
            self.__config.pulp_password,
            self.__config.pulp_chunk_size,
        )
        self.__download_credentials = {
            "login": config.node_id,
            "password": config.jwt_token,
        }
        if config.development_mode:
            self.__download_credentials["no_ssl_verify"] = True

    def sign_loop(self):
        try:
            while True:
                task = self._request_task()
                if not task:
                    logging.debug("There is no task to sign")
                    time.sleep(30)
                    continue
                logging.info(
                    "Signing the following task:\n{0}".format(pprint.pformat(task))
                )
                try:
                    self._sign_build(task)
                    logging.info("the {0} task is signed".format(task["id"]))
                except Exception as e:
                    msg = f"Signing failed: {e}.\nTraceback: {traceback.format_exc()}"
                    logging.info(msg)
                    self.__call_master(
                        "sign_task_completed", task_id=task["id"], msg=msg
                    )
                    continue
        except Exception as e:
            logging.debug(f"Couldn't receive task from web_server: {e}")

    def _sign_build(self, task):
        """
        Signs packages from the specified task and uploads them to the server.

        Parameters
        ----------
        task : dict
            Sign task.
        """
        pgp_keyid = task["pgp_keyid"]
        pgp_key_password = self.__password_db.get_password(pgp_keyid)
        task_dir = os.path.join(self.__config.working_dir, task["id"])
        rpms_dir = os.path.join(task_dir, "rpms")
        debs_dir = os.path.join(task_dir, "debs")
        downloaded = []
        has_rpms = False
        try:
            for platform, packages in task["packages"].items():
                for package in packages:
                    package_type = package.get("package_type", "rpm")
                    if package_type in ("deb", "dsc"):
                        download_dir = debs_dir
                    else:
                        download_dir = rpms_dir
                        has_rpms = True
                    package_path = self._download_package(
                        download_dir, platform, package
                    )
                    downloaded.append(
                        (platform, package["id"], package["file_name"], package_path)
                    )
                    if package_type == "dsc":
                        sign_dsc_package(
                            self.__gpg, package_path, pgp_keyid, pgp_key_password
                        )
                    elif package_type == "deb":
                        sign_deb_package(
                            self.__gpg, package_path, pgp_keyid, pgp_key_password
                        )
            if has_rpms:
                # NOTE: if a build contains a lot of packages with long names
                #       the expanded path can exceed shell limits and crash
                #       the rpmsign process so we have to sign packages in
                #       smaller portions.
                for platform_dir in os.listdir(rpms_dir):
                    sign_rpm_package(
                        os.path.join(rpms_dir, platform_dir, "*/*.rpm"),
                        pgp_keyid,
                        pgp_key_password,
                    )
            # upload signed packages and report the task completion
            for platform, package_id, file_name, package_path in downloaded:
                self._upload_artifact(
                    task["id"], platform, package_id, file_name, package_path
                )
            self._report_signed_build(task["id"])
        finally:
            if os.path.exists(task_dir):
                shutil.rmtree(task_dir)

    def _report_signed_build(self, task_id):
        """
        Reports a build sign completion to the master.

        Parameters
        ----------
        task_id : str
            Sign task identifier.
        """
        response = self.__call_master("sign_task_completed", task_id=task_id)
        if not response["success"]:
            raise Exception(
                "Server side error: {0}".format(response.get("error", "unknown"))
            )

    def _upload_artifact(self, task_id, platform, package_id, file_name, file_path):
        artifacts_dir = Path(file_path) / Path(file_name)
        logging.info(
            "Uploading {0} signed package".format(os.path.basename(artifacts_dir))
        )
        artifacts = self._pulp_uploader.upload(artifacts_dir)
        return artifacts

    def _download_package(self, download_dir, platform, package, try_count=3):
        """
        Downloads the specified package from the Build System server and checks
        the download file checksum.

        Parameters
        ----------
        download_dir : str
            Download directory base path.
        platform : str
            Build platform name.
        package : dict
            Package information.
        try_count : int, optional
            The number of download tries before aborting.

        Returns
        -------
        str
            Downloaded file path.

        Raises
        ------
        castor.errors.ConnectionError
            If the package download is failed.
        """
        package_dir = os.path.join(download_dir, platform, package["id"])
        safe_mkdir(package_dir)
        package_path = os.path.join(package_dir, package["file_name"])
        download_url = package["download_url"]
        last_exc = None
        for i in range(1, try_count + 1):
            logging.debug("Downloading {0} {1}/{2}".format(download_url, i, try_count))
            try:
                download_file(download_url, package_path, **self.__download_credentials)
                checksum = hash_file(package_path, get_hasher("sha256"))
                if checksum != package["checksum"]:
                    raise ValueError(f"Checksum does not match for {download_url}.")
                return package_path
            except Exception as e:
                last_exc = e
                logging.error(
                    "Cannot download {0}: {1}.\nTraceback:\n"
                    "{2}".format(download_url, str(e), traceback.format_exc())
                )
        raise last_exc

    def _request_task(self):
        """
        Requests a new signing task from the master.

        Returns
        -------
        dict or None
            Task to process or None if master didn't return a task.
        """
        response = self.__call_master(
            "get_sign_task", pgp_keyids=self.__config.pgp_keyids
        )
        if not response["success"]:
            raise Exception(
                "Server side error: {0}.\nTraceback: {1}".format(
                    response.get("error", "unknown"), traceback.format_exc()
                )
            )
        return response.get("sign_task")

    def __call_master(self, endpoint, **parameters):
        full_url = urllib.parse.urljoin(
            self.__config.master_url, f"sign_node/{endpoint}"
        )
        headers = {"authorization": f"Bearer {self.__config.jwt_token}"}
        if endpoint == "sign_done":
            response = requests.post(full_url, json=parameters, headers=headers)
        else:
            response = requests.get(full_url, json=parameters, headers=headers)
        response.raise_for_status()
        return response.json()
