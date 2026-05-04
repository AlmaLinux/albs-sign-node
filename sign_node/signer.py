# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
# created: 2018-03-31


import enum
import os
import logging
import pprint
import queue
import shutil
import threading
import time
import traceback
import typing
import urllib.parse
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)
from datetime import datetime
from pathlib import Path

from urllib3 import Retry

import requests
import requests.adapters
import plumbum
import rpm
import pgpy

from sign_node.config import (
    GPG_SCENARIO_TEMPLATE,
    COMMUNITY_KEY_SUFFIX,
)
from sign_node.errors import SignError
from sign_node.utils.file_utils import (
    download_file,
    hash_file,
    safe_mkdir,
)
from sign_node.utils.codenotary import Codenotary
from sign_node.uploaders.pulp import PulpRpmUploader
from sign_node.package_sign import sign_rpm_package


__all__ = ['Signer']


class SignStatusEnum(enum.IntEnum):
    SUCCESS = 1
    READ_ERROR = 2
    NO_SIGNATURE = 3
    WRONG_SIGNATURE = 4


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
        self.__working_dir_path = Path(self.__config.working_dir)
        self.__download_credentials = {
            'login': config.node_id,
            'password': config.jwt_token,
        }
        if config.development_mode:
            self.__download_credentials['no_ssl_verify'] = True
        self.__notar_enabled = self.__config.codenotary_enabled
        if self.__notar_enabled:
            self.__notary = Codenotary(
                immudb_username=self.__config.immudb_username,
                immudb_password=self.__config.immudb_password,
                immudb_database=self.__config.immudb_database,
                immudb_address=self.__config.immudb_address,
                immudb_public_key_file=self.__config.immudb_public_key_file,
            )
        # grpcio in immudb client is not thread-safe — serialize all notary calls
        self.__notary_lock = threading.Lock()
        self.__session = self.__generate_request_session()

    def __generate_request_session(self):
        retry_strategy = Retry(
            total=10,
            backoff_factor=1,
            raise_on_status=True,
        )
        adapter = requests.adapters.HTTPAdapter(
            max_retries=retry_strategy)
        session = requests.Session()
        session.headers.update({
            'Authorization': f'Bearer {self.__config.jwt_token}',
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
        self._report_generated_sign_key(
            task['id'],
            response_payload
        )

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
                    'Processing the following task:\n%s',
                    pprint.pformat(task)
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
                        report_error_method(
                            task=task,
                            msg=msg
                        )
                    except requests.RequestException as err:
                        logging.exception(
                            'Wrong answer from a web server: "%s"',
                            err,
                        )

    def _check_signature(self, files, key_id):
        errors = []
        key_id_lower = key_id.lower()
        ts = rpm.TransactionSet()
        ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
        subkeys = [i.lower() for i in self.__password_db.get_subkeys(key_id)]

        def check(pkg_path: str) -> typing.Tuple[SignStatusEnum, str]:
            if not os.path.exists(pkg_path):
                return SignStatusEnum.READ_ERROR, ''

            with open(pkg_path, 'rb') as fd:
                header = ts.hdrFromFdno(fd)
                signature = header[rpm.RPMTAG_SIGGPG]
                if not signature:
                    signature = header[rpm.RPMTAG_SIGPGP]
                if not signature:
                    return SignStatusEnum.NO_SIGNATURE, ''

            pgp_msg = pgpy.PGPMessage.from_blob(signature)
            sig = ''
            for signature in pgp_msg.signatures:
                sig = signature.signer.lower()
                if sig == key_id_lower:
                    return SignStatusEnum.SUCCESS, ''
                if subkeys and sig in subkeys:
                    return SignStatusEnum.SUCCESS, ''

            return SignStatusEnum.WRONG_SIGNATURE, sig

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for file_ in files:
                futures[executor.submit(check, file_)] = file_

            for future in as_completed(futures):
                pkg_path = futures[future]
                result, signature = future.result()
                if result == SignStatusEnum.READ_ERROR:
                    errors.append(f'Cannot read file {pkg_path}')
                elif result == SignStatusEnum.NO_SIGNATURE:
                    errors.append(f'Package {pkg_path} is not signed')
                elif result == SignStatusEnum.WRONG_SIGNATURE:
                    errors.append(f'Package {pkg_path} is signed '
                                  f'with the wrong key: {signature}')

        return errors

    def _check_signature_single(self, pkg_path: str, key_id: str) -> typing.List[str]:
        key_id_lower = key_id.lower()
        subkeys = [i.lower() for i in self.__password_db.get_subkeys(key_id)]
        ts = rpm.TransactionSet()
        ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES)

        if not os.path.exists(pkg_path):
            return [f'Cannot read file {pkg_path}']
        with open(pkg_path, 'rb') as fd:
            header = ts.hdrFromFdno(fd)
            signature = header[rpm.RPMTAG_SIGGPG]
            if not signature:
                signature = header[rpm.RPMTAG_SIGPGP]
            if not signature:
                return [f'Package {pkg_path} is not signed']

        pgp_msg = pgpy.PGPMessage.from_blob(signature)
        sig = ''
        for signature in pgp_msg.signatures:
            sig = signature.signer.lower()
            if sig == key_id_lower:
                return []
            if subkeys and sig in subkeys:
                return []
        return [f'Package {pkg_path} is signed with the wrong key: {sig}']

    @staticmethod
    def timedelta_seconds(start_time: datetime, finish_time: datetime) -> int:
        return int((finish_time - start_time).total_seconds())

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
        task_dir = self.__working_dir_path.joinpath(f'gen_key_{task_id}')
        backup_dir = self.__working_dir_path.joinpath('community_keys_backups')
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

    def _sign_build(self, task):
        """
        Signs packages from the specified task and uploads them to the server.

        Pipeline:
            download pool (4) -> [verify under notary lock] -> sign queue
                              -> sign batcher (1) -> sign_rpm_package(batch)
                              -> upload pool (4 parallel + 1 sequential)
                              -> [check signature, upload, notarize under lock]

        Sign batches flush on size (>=500MB), count (>=50), or age (>=10s).
        Non-RPM packages skip the sign stage and go straight to upload.
        """
        SIGN_BATCH_BYTES = 500 * 1024 * 1024
        SIGN_BATCH_COUNT = 50
        SIGN_BATCH_AGE_SECONDS = 10.0

        stats = {'sign_task_start_time': str(datetime.utcnow())}
        pgp_keyid = task['keyid']
        sign_files = task.get('sign_files', False)
        pgp_key_password = self.__password_db.get_password(pgp_keyid)
        fingerprint = self.__password_db.get_fingerprint(pgp_keyid)
        task_dir = self.__working_dir_path.joinpath(str(task['id']))
        rpms_dir = task_dir.joinpath('rpms')
        debs_dir = task_dir.joinpath('debs')
        response_payload = {'build_id': task['build_id'], 'success': True}

        packages = {}                 # pkg_id -> response payload dict
        packages_hrefs = {}           # name -> href (for same-arch fill-in)
        seen_shas = set()             # dedup uploads by content sha
        packages_lock = threading.Lock()
        seen_lock = threading.Lock()

        sign_q: queue.Queue = queue.Queue()
        download_done = threading.Event()
        error_event = threading.Event()
        first_error: typing.List[BaseException] = []
        error_lock = threading.Lock()
        upload_futures: typing.List = []
        upload_futures_lock = threading.Lock()

        # Per-stage wall-clock first-in / last-out timestamps
        stage_times: typing.Dict[str, typing.Optional[float]] = {
            'download_first': None, 'download_last': None,
            'sign_first': None, 'sign_last': None,
            'upload_first': None, 'upload_last': None,
        }
        stage_lock = threading.Lock()

        def mark_first(key: str):
            with stage_lock:
                if stage_times[key] is None:
                    stage_times[key] = time.monotonic()

        def mark_last(key: str):
            now = time.monotonic()
            with stage_lock:
                if stage_times[key] is None or now > stage_times[key]:
                    stage_times[key] = now

        def record_error(exc: BaseException):
            with error_lock:
                if not first_error:
                    first_error.append(exc)
            error_event.set()

        def submit_upload(item, ul_par, ul_seq):
            if item['size'] > self.__config.parallel_upload_file_size:
                pool = ul_seq
            else:
                pool = ul_par
            fut = pool.submit(upload_worker, item)
            with upload_futures_lock:
                upload_futures.append(fut)

        def download_worker(package, ul_par, ul_seq):
            if error_event.is_set():
                return
            mark_first('download_first')
            try:
                package_type = package.get('type', 'rpm')
                is_rpm = package_type == 'rpm'
                download_dir = rpms_dir if is_rpm else debs_dir
                pkg_path = self._download_package(download_dir, package)

                cas_meta = None
                if self.__notar_enabled and package.get('cas_hash'):
                    with self.__notary_lock:
                        cas_meta = self.__notary.verify_artifact(pkg_path)
                    if not cas_meta:
                        raise SignError(
                            f'Package {package} cannot be verified'
                        )

                signed_package = package.copy()
                signed_package['fingerprint'] = fingerprint
                signed_package.pop('download_url', None)
                with packages_lock:
                    packages[package['id']] = signed_package

                item = {
                    'pkg_id': package['id'],
                    'name': package['name'],
                    'path': pkg_path,
                    'size': os.stat(pkg_path).st_size,
                    'cas_meta': cas_meta,
                    'is_rpm': is_rpm,
                }
                mark_last('download_last')
                if is_rpm:
                    sign_q.put(item)
                else:
                    submit_upload(item, ul_par, ul_seq)
            except Exception as e:
                logging.exception('Download stage failed for %s', package)
                record_error(e)

        def flush_batch(batch, ul_par, ul_seq):
            if not batch or error_event.is_set():
                return
            mark_first('sign_first')
            paths = [it['path'] for it in batch]
            sign_rpm_package(
                ' '.join(paths),
                pgp_keyid,
                pgp_key_password,
                sign_files=sign_files,
                sign_files_cert_path=self.__config.files_sign_cert_path,
                locks_dir_path=self.__config.locks_dir_path,
            )
            mark_last('sign_last')
            for it in batch:
                submit_upload(it, ul_par, ul_seq)

        def sign_batcher(ul_par, ul_seq):
            buf: typing.List[dict] = []
            buf_bytes = 0
            first_age: typing.Optional[float] = None
            try:
                while True:
                    if error_event.is_set():
                        return
                    if first_age is None:
                        timeout = 1.0
                    else:
                        timeout = max(
                            0.05,
                            SIGN_BATCH_AGE_SECONDS - (time.monotonic() - first_age),
                        )
                    try:
                        item = sign_q.get(timeout=timeout)
                    except queue.Empty:
                        if download_done.is_set() and sign_q.empty():
                            flush_batch(buf, ul_par, ul_seq)
                            return
                        if buf and (time.monotonic() - first_age) >= SIGN_BATCH_AGE_SECONDS:
                            flush_batch(buf, ul_par, ul_seq)
                            buf, buf_bytes, first_age = [], 0, None
                        continue
                    buf.append(item)
                    buf_bytes += item['size']
                    if first_age is None:
                        first_age = time.monotonic()
                    if (len(buf) >= SIGN_BATCH_COUNT
                            or buf_bytes >= SIGN_BATCH_BYTES):
                        flush_batch(buf, ul_par, ul_seq)
                        buf, buf_bytes, first_age = [], 0, None
            except Exception as e:
                logging.exception('Sign stage failed')
                record_error(e)

        def upload_worker(item):
            if error_event.is_set():
                return
            mark_first('upload_first')
            try:
                path = item['path']
                sha256 = hash_file(path, hash_type='sha256')
                with packages_lock:
                    packages[item['pkg_id']]['sha256'] = sha256

                with seen_lock:
                    is_first = sha256 not in seen_shas
                    if is_first:
                        seen_shas.add(sha256)
                if not is_first:
                    # Duplicate content; href is filled in via name lookup
                    # after the pipeline drains.
                    mark_last('upload_last')
                    return

                if item['is_rpm']:
                    sign_errors = self._check_signature_single(path, pgp_keyid)
                    if sign_errors:
                        msg = 'Errors during checking packages signatures: \n{}'.format(
                            '\n'.join(sign_errors)
                        )
                        logging.error(msg)
                        raise SignError(msg)

                result = self._upload_artifact(path)
                with packages_lock:
                    packages[item['pkg_id']]['href'] = result.href
                    packages_hrefs[item['name']] = result.href

                if self.__notar_enabled and item.get('cas_meta') is not None:
                    with self.__notary_lock:
                        cas_hash = self.__notary.notarize_artifact(
                            path, item['cas_meta']
                        )
                    with packages_lock:
                        packages[item['pkg_id']]['cas_hash'] = cas_hash

                mark_last('upload_last')
            except Exception as e:
                logging.exception('Upload stage failed for %s', item.get('path'))
                record_error(e)

        pipeline_start = time.monotonic()
        try:
            with ThreadPoolExecutor(max_workers=4) as dl_pool, \
                 ThreadPoolExecutor(max_workers=1) as sign_pool, \
                 ThreadPoolExecutor(max_workers=4) as ul_par, \
                 ThreadPoolExecutor(max_workers=1) as ul_seq:

                sign_future = sign_pool.submit(sign_batcher, ul_par, ul_seq)
                dl_futures = [
                    dl_pool.submit(download_worker, p, ul_par, ul_seq)
                    for p in task['packages']
                ]
                for f in as_completed(dl_futures):
                    f.result()
                download_done.set()

                sign_future.result()

                with upload_futures_lock:
                    pending = list(upload_futures)
                for f in as_completed(pending):
                    f.result()

            if error_event.is_set():
                raise first_error[0]

            # Fill href for packages of the same architecture (e.g. duplicates
            # deduped by sha256 above).
            for id_, package in packages.items():
                if not package.get('href'):
                    packages[id_]['href'] = packages_hrefs[package['name']]
            response_payload['packages'] = list(packages.values())

            pipeline_end = time.monotonic()
            if stage_times['download_first'] and stage_times['download_last']:
                stats['download_packages_time'] = int(
                    stage_times['download_last'] - stage_times['download_first']
                )
            if stage_times['sign_first'] and stage_times['sign_last']:
                stats['sign_packages_time'] = int(
                    stage_times['sign_last'] - stage_times['sign_first']
                )
            if stage_times['upload_first'] and stage_times['upload_last']:
                stats['upload_packages_time'] = int(
                    stage_times['upload_last'] - stage_times['upload_first']
                )
            stats['pipeline_total_time'] = int(pipeline_end - pipeline_start)
            response_payload['stats'] = stats
        except Exception:
            error_message = traceback.format_exc()
            response_payload['success'] = False
            response_payload['error_message'] = error_message
        finally:
            logging.info('Response payload:')
            logging.info(response_payload)
            self._report_signed_build(task['id'], response_payload)
            if os.path.exists(task_dir):
                shutil.rmtree(task_dir)

    def _report_signed_build(self, task_id, response_payload):
        """
        Reports a build sign completion to the master.

        Parameters
        ----------
        task_id : str
            Sign task identifier.
        """
        response = self.__call_master(f'{task_id}/complete',
                                      **response_payload)
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
            f'community/{task_id}/complete',
            **response_payload
        )
        if not response and 'success' not in response and not response['success']:
            raise Exception(
                'Server side error: {0}'.format(
                    response.get('error', 'unknown')
                )
            )

    def _upload_artifact(self, file_path):
        artifacts_dir = os.path.dirname(file_path)
        logging.info('Artifacts dir: %s', artifacts_dir)
        logging.info(
            'Uploading %s signed package', os.path.basename(file_path)
        )
        return self.__pulp_uploader.upload_single_file(file_path)

    @staticmethod
    def _download_package(download_dir, package, try_count=3):
        """
        Downloads the specified package from the Build System server and checks
        the download file checksum.

        Parameters
        ----------
        download_dir : str
            Download directory base path.
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
        package_dir = os.path.join(download_dir, str(package['id']))
        safe_mkdir(package_dir)
        package_path = os.path.join(package_dir, package['name'])
        download_url = package['download_url']
        last_exc = None
        for i in range(1, try_count + 1):
            logging.debug('Downloading %s %d/%d', download_url, i, try_count)
            try:
                download_file(download_url, package_path)
                # FIXME: check checksum later
                # checksum = hash_file(package_path, get_hasher('sha256'))
                # if checksum != package['checksum']:
                #     raise ValueError(f'Checksum does not match for {download_url}.')
                return package_path
            except Exception as e:
                last_exc = e
                logging.error(
                    'Cannot download %s: %s.\nTraceback:\n%s',
                    download_url, str(e), traceback.format_exc()
                )
        raise last_exc

    def _request_sign_task(self) -> typing.Dict:
        """
        Requests a new signing task from the master.

        Returns
        -------
        dict or None
            Task to process or None if master didn't return a task.
        """
        pgp_keyids = list(self.__password_db.key_ids.keys())
        response = self.__call_master(
            'get_sign_task', key_ids=pgp_keyids
        )
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
            self.__config.master_url, f'sign-tasks/{endpoint}/'
        )
        response = self.__session.post(full_url, json=parameters, timeout=30)
        response.raise_for_status()
        return response.json()
