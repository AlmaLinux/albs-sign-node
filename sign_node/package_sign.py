"""
RPM packages signing functions.
"""

import contextlib
import logging
import traceback
from typing import List, Optional

import pexpect

from sign_node.utils.locking import (
    GPG_AGENT_LOCK_FILENAME,
    exclusive_lock,
    shared_lock,
)
from sign_node.utils.pgp_utils import restart_gpg_agent

__all__ = [
    "sign_rpm_package",
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
    logging.info('Deleting previous signatures from %d package(s)', len(pkg_paths))
    code, out, err = plumbum.local['rpmsign'].run(
        args=['--delsign'] + pkg_paths,
        retcode=None,
    )
    logging.debug('Command result: %d, %s\n%s', code, out, err)
    if code != 0:
        full_out = '\n'.join((out, err))
        raise PackageSignError(
            f'Cannot delete package signature: {full_out}'
        )
    with gpg_sign_locks(
        keyid=keyid,
        gpg_locks_dir=locks_dir_path,
        yubikey_keyids=yubikey_keyids,
    ):
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
