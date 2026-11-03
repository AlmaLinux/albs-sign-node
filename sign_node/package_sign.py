"""
RPM packages signing functions.
"""

import contextlib
import logging
import os
import tempfile
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

import gnupg
import pexpect

from sign_node.utils.locking import (
    GPG_AGENT_LOCK_FILENAME,
    exclusive_lock,
    shared_lock,
)
from sign_node.utils.pgp_utils import restart_gpg_agent

__all__ = [
    "sign_rpm_package",
    "sign_rpm_packages",
    "PackageSignError",
]

import plumbum


class PackageSignError(Exception):
    pass


@contextlib.contextmanager
def gpg_sign_locks(
    keyid,
    gpg_locks_dir,
    yubikey_keyids,
):
    """
    Acquire the locks needed for a signing operation with ``keyid``.

    A shared lock on the gpg-agent file is always held during signing
    so that no other process can restart gpg-agent mid-sign. When
    ``keyid`` is a Yubikey-backed key, an additional per-key exclusive
    lock serializes hardware access, and gpg-agent is reloaded (under
    the exclusive gpg-agent lock) after the sign region exits.
    """
    yubikey_keyids = yubikey_keyids or []
    is_yubikey = keyid in yubikey_keyids
    with shared_lock(gpg_locks_dir, GPG_AGENT_LOCK_FILENAME):
        if is_yubikey:
            with exclusive_lock(gpg_locks_dir, keyid):
                yield
        else:
            yield
    if is_yubikey:
        with exclusive_lock(
            gpg_locks_dir, GPG_AGENT_LOCK_FILENAME,
        ):
            restart_gpg_agent()

def sign_rpm_package(
    path,
    keyid,
    password,
    sign_files=False,
    sign_files_cert_path='/etc/pki/ima/ima-sign.key',
    locks_dir_path: str = '/tmp/gpg_locks',
    yubikey_keyids: Optional[List[str]] = None,
    delete_old_signatures: bool = True,
    with_locks: bool = True,
):
    """
    Signs an RPM package.

    Parameters
    ----------
    path : str
        RPM (or source RPM) package path.
    keyid : str
        PGP key keyid.
    password : str
        PGP key password.
    sign_files : bool
        Flag to indicate if file signing is needed
    sign_files_cert_path : str
        Path to the certificate used for files signing
    locks_dir_path : str
        Path to a dir with lock files
    yubikey_keyids: list
        List of YubiKey IDs
    delete_old_signatures : bool
        Run ``rpmsign --delsign`` first (default). ``sign_rpm_packages``
        turns this off because it deletes the signatures itself.
    with_locks : bool
        Take the gpg locks around the signing command (default).
        ``sign_rpm_packages`` holds them for the whole batch instead.

    Raises
    ------
    PackageSignError
        If an error occurred.
    """
    sign_cmd_parts = ['rpmsign', '--rpmv3', '--resign']
    if sign_files:
        sign_cmd_parts.extend(
            ['--signfiles', '--fskpath', sign_files_cert_path]
        )
    sign_cmd_parts.extend(['-D', f"'_gpg_name {keyid}'", path])
    sign_cmd = ' '.join(sign_cmd_parts)
    final_cmd = f'/bin/bash -c "{sign_cmd}"'
    pkg_paths = path.split(' ')
    if delete_old_signatures:
        _delete_signatures(pkg_paths)
    locks = contextlib.nullcontext()
    if with_locks:
        locks = gpg_sign_locks(
            keyid=keyid,
            gpg_locks_dir=locks_dir_path,
            yubikey_keyids=yubikey_keyids,
        )
    with locks:
        out, status = pexpect.run(
            command=final_cmd,
            events={"Enter passphrase:.*": f"{password}\r"},
            env={"LC_ALL": "en_US.UTF-8"},
            timeout=100000,
            withexitstatus=True,
        )
    if status is None:
        message = (
            f"The RPM signing command is failed with timeout."
            f"\nCommand: {final_cmd}\nOutput:\n{out}"
        )
        logging.error(message)
        raise PackageSignError(message)
    if status != 0:
        logging.error(
            "The RPM signing command is failed with %s exit code."
            "\nCommand: %s\nOutput:\n%s.\nTraceback: %s",
            status,
            final_cmd,
            out,
            traceback.format_exc(),
        )
        raise PackageSignError(
            f"RPM sign failed with {status} exit code.\n"
            f"Traceback: {traceback.format_exc()}"
        )


def _delete_signatures(pkg_paths: List[str]):
    logging.info(
        'Deleting previous signatures from %d package(s)', len(pkg_paths)
    )
    code, out, err = plumbum.local['rpmsign'].run(
        args=['--delsign'] + pkg_paths,
        retcode=None,
    )
    logging.debug('Command result: %d, %s\n%s', code, out, err)
    if code != 0:
        full_out = '\n'.join((out, err))
        raise PackageSignError(f'Cannot delete package signature: {full_out}')


def _generate_throwaway_key(gpg_home: str) -> str:
    """
    Generates an unprotected RSA-2048 signing key in ``gpg_home`` and
    returns its fingerprint.

    rpmsign cannot add IMA file signatures without also adding a PGP
    signature, so the preparation phase signs with this key and the real
    key replaces that signature later. RSA-2048 keeps the throwaway
    signatures smaller than the real RSA-4096 ones, which lets rpmsign
    rewrite the signature header in place instead of copying the package.
    """
    gpg = gnupg.GPG(gpgbinary='/usr/bin/gpg2', gnupghome=gpg_home)
    key = gpg.gen_key(
        gpg.gen_key_input(
            key_type='RSA',
            key_length=2048,
            key_usage='sign',
            name_real='albs-sign-node throwaway key',
            expire_date=0,
            no_protection=True,
        )
    )
    if not key.fingerprint:
        raise PackageSignError(
            f'Cannot generate a throwaway PGP key: {key.status}'
        )
    return key.fingerprint


def _sign_with_throwaway_key(
    path: str, fingerprint: str, gpg_home: str, sign_files_cert_path: str
):
    code, out, err = plumbum.local['rpmsign'].run(
        args=[
            '--resign',
            '--signfiles',
            '--fskpath',
            sign_files_cert_path,
            '-D',
            f'_gpg_name {fingerprint}',
            '-D',
            f'_gpg_path {gpg_home}',
            path,
        ],
        retcode=None,
        # rpmsign warns when GPG_TTY is unset and stdin is not a terminal
        env={'GPG_TTY': os.environ.get('GPG_TTY', '/dev/null')},
    )
    logging.debug('Command result: %d, %s\n%s', code, out, err)
    if code != 0:
        full_out = '\n'.join((out, err))
        raise PackageSignError(f'Cannot sign files in {path}: {full_out}')


def sign_rpm_packages(
    paths: List[str],
    keyid: str,
    password: str,
    sign_files: bool = False,
    sign_files_cert_path: str = '/etc/pki/ima/ima-sign.key',
    locks_dir_path: str = '/tmp/gpg_locks',
    yubikey_keyids: Optional[List[str]] = None,
    key_workers: int = 2,
    prepare_workers: Optional[int] = None,
):
    """
    Signs RPM packages in two overlapping phases.

    Phase one runs ``prepare_workers`` threads and never uses the signing
    key: it deletes the old signatures and, when ``sign_files`` is set,
    adds the IMA file signatures together with a PGP signature made by a
    throwaway software key. Phase two re-signs every prepared package
    with the real key as soon as it is ready, ``key_workers`` at a time,
    so a slow hardware key is kept busy while other packages are still
    being hashed. The gpg locks are held once for the whole call.

    Parameters
    ----------
    paths : list
        RPM package paths.
    keyid : str
        PGP key keyid.
    password : str
        PGP key password.
    sign_files : bool
        Flag to indicate if file signing is needed
    sign_files_cert_path : str
        Path to the certificate used for files signing
    locks_dir_path : str
        Path to a dir with lock files
    yubikey_keyids: list
        List of YubiKey IDs
    key_workers : int
        Number of packages signed with the real key concurrently.
    prepare_workers : int, optional
        Number of preparation threads, defaults to the CPU count.

    Raises
    ------
    PackageSignError
        If an error occurred.
    """
    prepare_workers = prepare_workers or min(32, os.cpu_count() or 1)
    logging.info(
        'Signing %d package(s) with %d preparation and %d key worker(s)',
        len(paths),
        prepare_workers,
        key_workers,
    )
    with tempfile.TemporaryDirectory(prefix='sign-node-gpg-') as gpg_home:
        throwaway_key = None
        if sign_files:
            throwaway_key = _generate_throwaway_key(gpg_home)

        def prepare(path: str):
            _delete_signatures([path])
            if throwaway_key:
                _sign_with_throwaway_key(
                    path, throwaway_key, gpg_home, sign_files_cert_path
                )
            return key_pool.submit(
                sign_rpm_package,
                path,
                keyid,
                password,
                delete_old_signatures=False,
                with_locks=False,
            )

        try:
            with gpg_sign_locks(
                keyid=keyid,
                gpg_locks_dir=locks_dir_path,
                yubikey_keyids=yubikey_keyids,
            ), ThreadPoolExecutor(
                prepare_workers
            ) as prepare_pool, ThreadPoolExecutor(
                key_workers
            ) as key_pool:
                try:
                    prepared = [prepare_pool.submit(prepare, p) for p in paths]
                    for future in [f.result() for f in prepared]:
                        future.result()
                except Exception:
                    prepare_pool.shutdown(cancel_futures=True)
                    key_pool.shutdown(cancel_futures=True)
                    raise
        finally:
            if throwaway_key:
                plumbum.local['gpgconf'].run(
                    args=['--homedir', gpg_home, '--kill', 'gpg-agent'],
                    retcode=None,
                )
