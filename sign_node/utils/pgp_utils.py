# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
#         Sergey Fokin <sfokin@cloudlinux.com>
# created: 2018-03-28

"""CloudLinux Build System PGP related utility functions."""

import typing
import getpass
import datetime

import gnupg
import plumbum

from ..errors import ConfigurationError


__all__ = [
    "init_gpg",
    "scan_pgp_info_from_file",
    "verify_pgp_key_password",
    "restart_gpg_agent",
    "PGPPasswordDB",
]


def init_gpg():
    """
    A gpg binding initialization function.

    Returns
    -------
    gnupg.GPG
        Initialized gpg wrapper.
    """
    gpg = gnupg.GPG(
        gpgbinary="/usr/bin/gpg2",
        keyring="/home/alt/.gnupg/pubring.kbx",
    )
    return gpg


def scan_pgp_info_from_file(gpg, key_file):
    """
    Extracts a PGP key information from the specified key file.

    Parameters
    ----------
    gpg : gnupg.GPG
        Gpg wrapper.
    key_file : str
        Key file path.

    Returns
    -------
    dict
        PGP key information.

    ValueError
    ----------
    If a given file doesn't contain a valid PGP key.
    """
    keys = gpg.scan_keys(key_file)
    if not keys:
        raise ValueError("there is no PGP key found")
    key = keys[0]
    return {
        "fingerprint": key["fingerprint"],
        "keyid": key["keyid"],
        "uid": key["uids"][0],
        "date": datetime.date.fromtimestamp(float(key["date"])),
    }


def restart_gpg_agent():
    """
    Restarts gpg-agent.
    """
    plumbum.local["gpgconf"]["--reload", "gpg-agent"].run(retcode=None)


def verify_pgp_key_password(gpg, keyid, password):
    """
    Checks the provided PGP key password validity.

    Parameters
    ----------
    gpg : gnupg.GPG
        Gpg wrapper.
    keyid : str
        Private key keyid.
    password : str
        Private key password.

    Returns
    -------
    bool
        True if password is correct, False otherwise.
    """
    # Clean all cached passwords.
    restart_gpg_agent()
    return gpg.verify(
        gpg.sign("test", keyid=keyid, passphrase=password).data
    ).valid


class PGPPasswordDB(object):
    def __init__(
            self,
            gpg,
            key_ids_from_config: typing.List[str],
            is_community_sign_node: bool = False,
            development_mode: bool = False,
            development_password: str = None
    ):
        """
        Password DB initialization.

        Parameters
        ----------
        gpg : gnupg.GPG
            Gpg wrapper.
        key_ids_from_config : list of str
            List of PGP keyids from the config.
        """
        self.__key_ids = None
        self.__key_ids_from_config = key_ids_from_config
        self.__gpg = gpg
        self.__is_community_sign_node = is_community_sign_node
        if development_mode and not development_password:
            raise ConfigurationError('You need to provide development PGP '
                                     'password when running in development '
                                     'mode')
        self.__development_mode = development_mode
        self.__development_password = development_password

    @property
    def key_ids(self):
        self.__key_ids = {}
        if self.__is_community_sign_node:
            self.__key_ids.update({
                key['keyid']: {'password': ''}
                for key in self.__gpg.list_keys(True)
            })
        self.__key_ids.update({
            keyid: {'password': ''} for keyid in self.__key_ids_from_config
        })
        return self.__key_ids

    def ask_for_passwords(self):
        """
        Asks a user for PGP private key passwords and stores them in the DB.

        Raises
        ------
        castor.errors.ConfigurationError
            If a private GPG key is not found or an entered password is
            incorrect.
        """
        existent_keys = {key["keyid"]: key
                         for key in self.__gpg.list_keys(True)}
        for keyid in self.key_ids:
            key = existent_keys.get(keyid)
            if not key:
                raise ConfigurationError(
                    "PGP key {0} is not found in the " "gnupg2 "
                    "database".format(keyid)
                )
            if self.__development_mode:
                password = self.__development_password
            else:
                password = getpass.getpass('\nPlease enter the {0} PGP key '
                                           'password: '.format(keyid))
            if not verify_pgp_key_password(self.__gpg, keyid, password):
                raise ConfigurationError(
                    "PGP key {0} password is not valid".format(keyid)
                )
            self.key_ids[keyid]["password"] = password
            self.key_ids[keyid]["fingerprint"] = key["fingerprint"]
            self.key_ids[keyid]["subkeys"] = [
                subkey[0] for subkey in key.get("subkeys", [])
            ]

    def get_password(self, keyid):
        """
        Returns a password for the specified private PGP key.

        Parameters
        ----------
        keyid : str
            Private PGP key keyid.

        Returns
        -------
        str
            Password.
        """
        return self.key_ids[keyid]["password"]

    def get_fingerprint(self, keyid):
        """
        Returns a fingerprint for the specified private PGP key.

        Parameters
        ----------
        keyid : str
            Private PGP key keyid.

        Returns
        -------
        str
            fingerprint.
        """
        return self.key_ids[keyid]["fingerprint"]

    def get_subkeys(self, keyid):
        """
        Returns a list of subkey fingerprints.

        Parameters
        ----------
        keyid : str
            Private PGP key keyid.

        Returns
        -------
        list
            Subkey fingerprints.
        """
        return self.key_ids[keyid]["subkeys"]
