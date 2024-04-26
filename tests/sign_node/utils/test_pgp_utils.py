import datetime
import os
from collections import defaultdict
from unittest.mock import Mock, patch

from sign_node.config import COMMUNITY_KEY_SUFFIX
from sign_node.utils import pgp_utils


def test_init_gpg():
    gpg = pgp_utils.init_gpg()
    assert gpg.keyring == [os.path.expanduser('~/.gnupg/pubring.kbx')]


def test_verify_pgp_key_password():
    gpgconf = Mock()
    plumbum_local = {
        "gpgconf": defaultdict(lambda: gpgconf)
    }
    gpg = Mock()

    with patch('sign_node.utils.pgp_utils.plumbum.local', new=plumbum_local):
        pgp_utils.verify_pgp_key_password(gpg, 'keyid', 'password')

    gpgconf.run.assert_called()
    gpg.sign.assert_called()
    gpg.verify.assert_called()


def test_scan_pgp_info_from_file():
    keys = [
        {
            'keyid': 'keyid-1',
            'fingerprint': 'fingerprint-1',
            'uids': ['uid-1'],
            'date': 0,
        },
    ]
    gpg = Mock()
    gpg.scan_keys.return_value = keys

    key = pgp_utils.scan_pgp_info_from_file(gpg, '/keyfile')
    gpg.scan_keys.assert_called_with('/keyfile')
    assert key == {
        'keyid': 'keyid-1',
        'fingerprint': 'fingerprint-1',
        'uid': 'uid-1',
        'date': datetime.date(1970, 1, 1),
    }


def test_PGPPasswordDB():
    keys = [
        {
            'keyid': 'keyid-1',
            'fingerprint': 'fingerprint-1',
            'subkeys': [['subkey-1']],
            'uids': ['uid-1 ' + COMMUNITY_KEY_SUFFIX]
        },
        {
            'keyid': 'keyid-2',
            'fingerprint': 'fingerprint-2',
            'subkeys': [['subkey-2']],
            'uids': ['uid-2 ' + COMMUNITY_KEY_SUFFIX]
        },
    ]
    gpg = Mock()
    gpg.list_keys.return_value = keys

    password_db = pgp_utils.PGPPasswordDB(
        gpg,
        key_ids_from_config=['keyid-1', 'keyid-2'],
        is_community_sign_node=True,
        development_mode=True,
        development_password='password',
    )

    password_db.ask_for_passwords()
    assert password_db.get_password('keyid-1') == 'password'
    assert password_db.get_fingerprint('keyid-2') == 'fingerprint-2'
    assert password_db.get_subkeys('keyid-1') == ['subkey-1']
