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


class PackageSignError(Exception):
    pass


def sign_rpm_package(path, keyid, password):
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

    Raises
    ------
    PackageSignError
        If an error occurred.
    """
    cmd = (
        '/bin/bash -c "'
        f"rpmsign --rpmv3 --resign -D '_gpg_name {keyid}' {path}"
        '"'
    )
    out, status = pexpect.run(
        command=cmd,
        events={"Enter passphrase:.*": f"{password}\r"},
        env={"LC_ALL": "en_US.UTF-8"},
        timeout=100000,
        withexitstatus=True,
    )
    if status is None:
        message = (
            f"The RPM signing command is failed with timeout."
            f"\nCommand: {cmd}\nOutput:\n{out}"
        )
        logging.error(message)
        raise PackageSignError(message)
    if status != 0:
        logging.error(
            "The RPM signing command is failed with %s exit code."
            "\nCommand: %s\nOutput:\n%s.\nTraceback: %s",
            status, cmd, out, traceback.format_exc()
        )
        raise PackageSignError(
            f"RPM sign failed with {status} exit code.\n"
            f"Traceback: {traceback.format_exc()}"
        )
