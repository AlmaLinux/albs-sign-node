"""
RPM packages signing functions.
"""

import logging
import traceback

import pexpect

__all__ = [
    "sign_rpm_package",
    "PackageSignError",
]

import plumbum


class PackageSignError(Exception):
    pass


def sign_rpm_package(path, keyid, password, sign_files=False,
                     sign_files_cert_path='/etc/pki/ima/ima-sign.key'):
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
    logging.info('Deleting previous signatures')
    for pkg_path in path.split(' '):
        logging.debug('Deleting signature from %s', pkg_path)
        code, out, err = plumbum.local['rpmsign'].run(
            args=('--delsign', pkg_path),
            retcode=None
        )
        logging.debug('Command result: %d, %s\n%s', code, out, err)
        if code != 0:
            full_out = '\n'.join((out, err))
            raise PackageSignError(f'Cannot delete package signature: {full_out}')
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
            status, final_cmd, out, traceback.format_exc()
        )
        raise PackageSignError(
            f"RPM sign failed with {status} exit code.\n"
            f"Traceback: {traceback.format_exc()}"
        )
