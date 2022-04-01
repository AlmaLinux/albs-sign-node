# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
#         Sergey Fokin <sfokin@cloudlinux.com>
# created: 2018-04-01

"""
RPM and deb packages signing functions.
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile
import traceback

import pexpect

__all__ = [
    "sign_deb_package",
    "sign_dsc_package",
    "sign_rpm_package",
    "PackageSignError",
]


class PackageSignError(Exception):

    pass


def _list_ar_contents(ar_path):
    """
    Lists file names in the specified .ar archive.

    Parameters
    ----------
    ar_path : str
        .ar archive path.

    Returns
    -------
    list of str
        List of file names in the specified .ar archive.

    Raises
    ------
    PackageSignError
        If ar command execution failed.
    """
    env = os.environ.copy()
    env["LANG"] = "en_US.UTF-8"
    list_cmd = ["ar", "t", ar_path]
    proc = subprocess.Popen(
        list_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    file_names, err = proc.communicate()
    if proc.returncode != 0:
        msg = (
            'Cannot list "%s" package contents (return code %d):\n%s.'
            "\nTraceback: %s"
        )
        logging.error(msg, ar_path, proc.returncode, err, traceback.format_exc())
        raise PackageSignError(msg)
    return file_names.split()


def _unpack_ar_file(ar_path, file_name, stdout):
    """
    Unpacks the file from the specified .ar archive to stdout.

    Parameters
    ----------
    ar_path : str
        .ar archive path.
    file_name : str
        File name.
    stdout : file-like
        Any file-like object which will be used as stdout for the ar command.

    Raises
    ------
    PackageSignError
        If the file unpacking failed.
    """
    env = os.environ.copy()
    env["LANG"] = "en_US.UTF-8"
    unpack_cmd = ["ar", "p", ar_path, file_name]
    proc = subprocess.Popen(unpack_cmd, env=env, stdout=stdout, stderr=subprocess.PIPE)
    _, err = proc.communicate()
    # NOTE: ar returns 0 exit code if a file is missing in an archive
    if re.search(r"no entry.*?in archive", str(err)) or proc.returncode != 0:
        msg = (
            'Cannot extract "%s" file from the "%s" package '
            "(return code %d):\n%s.\nTraceback: %s"
        )
        logging.error(msg, file_name, ar_path, proc.returncode, err, traceback.format_exc())
        raise PackageSignError(msg)


def _append_to_ar_archive(ar_path, file_path):
    """
    Appends the specified file to the .ar archive.

    Parameters
    ----------
    ar_path : str
        .ar archive path.
    file_path : str
        File path.

    Raises
    ------
    PackageSignError
        If the operation failed.
    """
    env = os.environ.copy()
    env["LANG"] = "en_US.UTF-8"
    add_cmd = ["ar", "q", ar_path, file_path]
    proc = subprocess.Popen(add_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = proc.communicate()
    if proc.returncode != 0:
        msg = (
            "Сannot add gpgorigin to the %s (%d exit code): %s.\n"
            "Traceback: %s"
        )
        logging.error(msg, ar_path, proc.returncode, out, traceback.format_exc())
        raise PackageSignError(msg)


def sign_deb_package(gpg, path, keyid, password):
    """
    Signs a Debian binary (deb) package.

    Parameters
    ----------
    gpg: gnupg.GPG
        Gpg wrapper.
    path : str
        deb file path.
    keyid : str
        PGP key keyid.
    password : str
        PGP key password.

    Raises
    ------
    PackageSignError
        If an error occurred.
    """
    tmp_dir = tempfile.mkdtemp(prefix="alt_sign_")
    try:
        file_names = _list_ar_contents(path)
        # unpack debian package files into single file for checksum calculation
        contents_file = os.path.join(tmp_dir, "combined-contents")
        with open(contents_file, "wb") as fd:
            for file_name in file_names:
                if file_name == "_gpgorigin":
                    continue
                _unpack_ar_file(path, file_name, stdout=fd)
        # calculate deb package contents GPG signature
        gpgorigin_file = os.path.join(tmp_dir, "_gpgorigin")
        with open(contents_file, "rb") as fd:
            rslt = gpg.sign_file(
                fd,
                keyid=keyid,
                passphrase=password,
                output=gpgorigin_file,
                binary=True,
                detach=True,
                extra_args=["--openpgp"],
            )
            if rslt.status != "signature created":
                raise PackageSignError(
                    "deb _gpgorigin sign failed with the "
                    "following output:\n{0}.\nTraceback: "
                    "{1}".format(rslt.stderr, traceback.format_exc())
                )
        # add GPG signature to deb package
        _append_to_ar_archive(path, gpgorigin_file)
    except PackageSignError as e:
        raise e
    except Exception as e:
        msg = 'Cannot sign "%s" package: %s. Traceback:\n%s'
        logging.error(msg, path, str(e), traceback.format_exc())
        raise PackageSignError(msg)
    finally:
        shutil.rmtree(tmp_dir)


def sign_dsc_package(gpg, path, keyid, password):
    """
    Signs a Debian source (dsc) package.

    Parameters
    ----------
    gpg : gnupg.GPG
        Gpg wrapper.
    path : str
        Dsc file path.
    keyid : str
        PGP key keyid.
    password : str
        PGP key password.

    Raises
    ------
    PackageSignError
        If an error occurred.
    """
    output_path = "{0}.asc".format(path)
    with open(path, "rb") as fd:
        rslt = gpg.sign_file(fd, keyid=keyid, passphrase=password, output=output_path)
        if rslt.status != "signature created":
            raise PackageSignError(
                "dsc sign failed with the following output:"
                "\n{0}.\nTraceback: {1}".format(rslt.stderr, traceback.format_exc())
            )
    shutil.move(output_path, path)


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
    cmd = """/bin/bash -c \"rpmsign --resign -D '_gpg_name {0}' {1}\"""".format(
        keyid, path
    )
    out, status = pexpect.run(
        command=cmd,
        events={"Enter passphrase:.*": "{0}\r".format(password)},
        env={"LC_ALL": "en_US.UTF-8"},
        timeout=100000,
        withexitstatus=1,
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
            "RPM sign failed with {0} exit code.\n"
            "Traceback: {1}".format(status, traceback.format_exc())
        )
