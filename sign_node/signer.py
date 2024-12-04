# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
# created: 2018-03-31


import logging
import os
import pprint
import time
import traceback
import typing
import urllib.parse
from pathlib import Path

import plumbum
import requests
import requests.adapters
from albs_common_lib.constants import COMMUNITY_KEY_SUFFIX
from albs_sign_lib.base_signer import BaseSigner
from urllib3 import Retry

from sign_node.config import (
    GPG_SCENARIO_TEMPLATE,
)
from sign_node.uploaders.pulp import PulpRpmUploader
from sign_node.utils.codenotary import Codenotary


class Signer(BaseSigner):
    def __init__(self, config, password_db, gpg):
        super().__init__(
            config=config,
            key_ids=password_db.key_ids,
            gpg=gpg,
            codenotary_enabled=config.codenotary_enabled,
            files_sign_cert_path=config.files_sign_cert_path
        )
        self.__password_db = password_db
        self.__pulp_uploader = PulpRpmUploader(
            self._config.pulp_host,
            self._config.pulp_user,
            self._config.pulp_password,
            self._config.pulp_chunk_size,
        )
        if self._notar_enabled:
            self.__notary = Codenotary(
                immudb_username=self._config.immudb_username,
                immudb_password=self._config.immudb_password,
                immudb_database=self._config.immudb_database,
                immudb_address=self._config.immudb_address,
                immudb_public_key_file=self._config.immudb_public_key_file,
            )
        self.__session = self.__generate_request_session()

    def __generate_request_session(self):
        retry_strategy = Retry(
            total=10,
            backoff_factor=1,
            raise_on_status=True,
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        session = requests.Session()
        session.headers.update({
            'Authorization': f'Bearer {self._config.jwt_token}',
        })
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    @staticmethod
    def _generate_key_uid(task: typing.Dict):
        return (
            f"{task['user_name']}/{task['product_name']} "
            f"{COMMUNITY_KEY_SUFFIX} <{task['user_email']}>"
        )

    def notarize_artifact(self, package_path, old_meta):
        return self.__notary.notarize_artifact(package_path, old_meta)

    def verify_artifact(self, pkg_path: str):
        return self.__notary.verify_artifact(pkg_path)

    def report_signed_build_error(self, task: typing.Dict, msg: str):
        response_payload = {
            'build_id': task['build_id'],
            'success': False,
            'error_message': msg,
        }
        self._report_signed_build(task['id'], response_payload)

    def report_generate_sign_key_error(self, task: typing.Dict, msg: str):
        sign_key_name = self._generate_key_uid(task)
        response_payload = {
            'key_name': sign_key_name,
            'success': False,
            'error_message': msg,
        }
        self._report_generated_sign_key(task['id'], response_payload)

    def sign_loop(self):
        while True:
            sign_task = None
            gen_sign_key_task = None
            try:
                sign_task = self._request_sign_task()
                gen_sign_key_task = self._request_gen_sign_key_task()
            except Exception as err:
                logging.exception(
                    'Can\'t receive new task from web server because "%s"',
                    err,
                )
            if not sign_task and not gen_sign_key_task:
                logging.debug('There is no task to process')
                time.sleep(30)
                continue
            for task, processing_method, report_error_method in (
                (
                    sign_task,
                    self._sign_build,
                    self.report_signed_build_error,
                ),
                (
                    gen_sign_key_task,
                    self.generate_sign_key,
                    self.report_generate_sign_key_error,
                ),
            ):
                if not task:
                    continue
                logging.info(
                    'Processing the following task:\n%s', pprint.pformat(task)
                )
                task_id = task['id']
                try:
                    processing_method(task)
                    logging.info('The task "%s" is processed', task_id)
                except Exception as err:
                    logging.exception(
                        'Can\'t process task from web server because "%s"',
                        err,
                    )
                    msg = (
                        f'Processing failed: {err}.\n'
                        f'Traceback: {traceback.format_exc()}'
                    )
                    try:
                        report_error_method(task=task, msg=msg)
                    except requests.RequestException as err:
                        logging.exception(
                            'Wrong answer from a web server: "%s"',
                            err,
                        )

    @staticmethod
    def _write_file_content(path: Path, content, mode='w'):
        with path.open(mode=mode) as fd:
            fd.write(content)

    @staticmethod
    def _extract_key_fingerprint(keyid: str) -> str:
        fingerprint_cmd = plumbum.local['gpg'][
            '-k',
            keyid,
        ]
        _, stdout, _ = fingerprint_cmd.run()
        # the sample of GPG output
        # [root@almalinux_8_x86_64 /]# gpg -k packager@almalinux.org
        # pub   rsa4096 2021-01-12 [C] [expires: 2024-01-12]
        #       5E9B8F5617B5066CE92057C3488FCF7C3ABB34F8
        # uid           [ unknown] AlmaLinux <packager@almalinux.org>
        # sub   rsa3072 2021-01-12 [S] [expires: 2024-01-12]
        #
        # [root@almalinux_8_x86_64 /]#
        # the second line is a full key fingerprint
        key_fingerprint = stdout.split('\n')[1].strip()
        return key_fingerprint

    def _export_key(
        self,
        fingerprint: str,
        backup_dir: Path,
        is_public_key: bool,
    ) -> str:
        key_type = 'public' if is_public_key else 'private'
        key_file_name = f'{fingerprint}_{key_type}.key'
        key_path = backup_dir.joinpath(key_file_name)
        export_key_cmd = plumbum.local['gpg'][
            '-a',
            '--batch',
            '--export' if is_public_key else '--export-secret-keys',
            fingerprint,
        ]
        logging.info(
            'Export %s PGP key for fingerprint: %s',
            key_type,
            fingerprint,
        )
        _, stdout, _ = export_key_cmd.run()
        self._write_file_content(
            path=key_path,
            content=stdout,
        )
        return key_file_name

    def _generate_sign_key(
        self,
        sign_key_uid: str,
        task_dir: Path,
    ) -> typing.Tuple[str, str]:
        gpg_scenario = GPG_SCENARIO_TEMPLATE.format(sign_key_uid=sign_key_uid)
        scenario_path = task_dir.joinpath('gpg-scenario')
        self._write_file_content(
            path=scenario_path,
            content=gpg_scenario,
        )
        generate_sign_key_cmd = plumbum.local['gpg'][
            '--batch',
            '--gen-key',
            scenario_path,
        ]
        logging.info('Generate PGP key for UID: %s', sign_key_uid)
        _, _, stderr = generate_sign_key_cmd.run()
        # the needed string looks like
        # 'gpg: key 29237BFE7EBF38BE marked as ultimately trusted'
        keyid = stderr.split('\n')[0].split('gpg: key ')[1].split(' ')[0]
        fingerprint = self._extract_key_fingerprint(keyid=keyid)
        return keyid, fingerprint

    def generate_sign_key(self, task):
        task_id = task['id']
        sign_key_uid = self._generate_key_uid(task)
        task_dir = self._working_dir_path.joinpath(f'gen_key_{task_id}')
        backup_dir = self._working_dir_path.joinpath('community_keys_backups')
        task_dir.mkdir(parents=True, exist_ok=True)
        backup_dir.mkdir(parents=True, exist_ok=True)

        key_id, fingerprint = self._generate_sign_key(
            sign_key_uid=sign_key_uid,
            task_dir=task_dir,
        )
        public_key_file_name = self._export_key(
            fingerprint=fingerprint,
            backup_dir=task_dir,
            is_public_key=True,
        )
        self._export_key(
            fingerprint=fingerprint,
            backup_dir=backup_dir,
            is_public_key=False,
        )
        public_key_file_path = task_dir.joinpath(public_key_file_name)
        logging.info(
            'Upload public PGP key for UID "%s" to Pulp',
            sign_key_uid,
        )
        artifact = self.__pulp_uploader.upload_single_file(
            filename=str(public_key_file_path),
            artifact_type='public_pgp_key',
        )
        response_payload = {
            'success': True,
            'error_message': '',
            'sign_key_href': artifact.href,
            'key_name': sign_key_uid,
            'key_id': key_id,
            'fingerprint': fingerprint,
            'file_name': public_key_file_name,
        }
        logging.info(
            'Response payload "%s"',
            response_payload,
        )
        self._report_generated_sign_key(
            task_id=task_id,
            response_payload=response_payload,
        )

    def _report_signed_build(self, task_id, response_payload):
        """
        Reports a build sign completion to the master.

        Parameters
        ----------
        task_id : str
            Sign task identifier.
        """
        response = self.__call_master(
            f'{task_id}/complete', **response_payload
        )
        if not response['success']:
            raise Exception(
                'Server side error: {0}'.format(
                    response.get('error', 'unknown')
                )
            )

    def _report_generated_sign_key(self, task_id, response_payload):
        """
        Reports generating of a sign key completion to the master.

        Parameters
        ----------
        task_id : str
            Generating sign key task identifier.
        """
        response = self.__call_master(
            f'community/{task_id}/complete', **response_payload
        )
        if (
            not response
            and 'success' not in response
            and not response['success']
        ):
            raise Exception(
                'Server side error: {0}'.format(
                    response.get('error', 'unknown')
                )
            )

    def _upload_artifact(
        self,
        file_path,
        task_id=None,
        platform=None,
        package_id=None,
        file_name=None,
    ):
        artifacts_dir = os.path.dirname(file_path)
        logging.info('Artifacts dir: %s', artifacts_dir)
        logging.info(
            'Uploading %s signed package', os.path.basename(file_path)
        )
        return self.__pulp_uploader.upload_single_file(file_path)

    def _request_sign_task(self) -> typing.Dict:
        """
        Requests a new signing task from the master.

        Returns
        -------
        dict or None
            Task to process or None if master didn't return a task.
        """
        pgp_keyids = list(self.__password_db.key_ids.keys())
        response = self.__call_master('get_sign_task', key_ids=pgp_keyids)
        return response

    def _request_gen_sign_key_task(self) -> typing.Dict:
        """
        Requests a new generating sign key task from the master

        Returns
        -------
        dict or None
            Task to process or None if master didn't return a task.
        """
        response = self.__call_master('community/get_gen_sign_key_task')
        return response

    def __call_master(self, endpoint, **parameters):
        full_url = urllib.parse.urljoin(
            self._config.master_url, f'sign-tasks/{endpoint}/'
        )
        response = self.__session.post(full_url, json=parameters, timeout=30)
        response.raise_for_status()
        return response.json()
