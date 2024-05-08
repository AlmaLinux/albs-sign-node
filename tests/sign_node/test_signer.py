import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from pyfakefs.fake_filesystem_unittest import TestCase

import sign_node
from sign_node.config import SignNodeConfig
from sign_node.signer import Signer


class TestSigner(TestCase):

    def setUp(self):
        self.setUpPyfakefs()
        self.config = SignNodeConfig()
        self.signer = Signer(self.config, 'password', None)

    def test__generate_sign_key(self):
        self.fs.create_dir('/task_dir')
        key = '88888BFEEEB938BE'

        gpg = MagicMock()
        gpg.__getitem__.return_value = gpg
        gpg.run.side_effect = gpg.side_effect = (
            (
                0,
                '',
                f'gpg: key {key} marked as ultimately trusted'
            ),
            (
                0,
                'pub   rsa4096 2024-05-12 [C] [expires: 2024-12-12]\n'
                + f'      {key}\n',
                '',
            ),
        )

        key_uid = self.signer._generate_key_uid({
            'user_name': 'user_name',
            'product_name': 'product_name',
            'user_email': 'user_email',
        })
        with patch('sign_node.signer.plumbum.local', new={'gpg': gpg}):
            result = self.signer._generate_sign_key(key_uid, Path('/task_dir'))

        assert result == (key, key)
        assert os.path.exists('/task_dir/gpg-scenario')

    def test__export_key(self):
        self.fs.create_dir('/backup_dir')
        backup_dir = Path('/backup_dir')
        key_fp = '88888BFEEEB938BE'

        gpg = MagicMock()
        gpg.__getitem__.return_value = gpg
        gpg.run.return_value = gpg.return_value = (0, key_fp, '')

        with patch('sign_node.signer.plumbum.local', new={'gpg': gpg}):
            key_file_name = self.signer._export_key(key_fp, backup_dir, True)

        key_file = backup_dir.joinpath(key_file_name)
        assert key_file.exists()
        assert key_file.open().read() == key_fp

    def test_generate_sign_key(self):
        key = '88888BFEEEB938BE'
        gpg = MagicMock()
        gpg.__getitem__.return_value = gpg
        gpg.run.side_effect = gpg.side_effect = (
            (
                0,
                '',
                f'gpg: key {key} marked as ultimately trusted'
            ),
            (
                0,
                'pub   rsa4096 2024-05-12 [C] [expires: 2024-12-12]\n'
                + f'      {key}\n',
                '',
            ),
            (0, key, ''),
            (0, key, ''),
        )

        with (
            patch(
                'sign_node.signer.plumbum.local',
                new={'gpg': gpg}
            ),
            patch.object(
                sign_node.signer.PulpRpmUploader,
                '_send_file',
                return_value=('file_sha256', 'artifact_href')
            ),
            patch.object(
                sign_node.signer.Signer,
                '_Signer__call_master',
                return_value={'success': True}
            )
        ):
            self.signer.generate_sign_key({
                'id': 'task_1',
                'user_name': 'user_name',
                'product_name': 'product_name',
                'user_email': 'user_email',
            })

        work_dir = Path(self.config.working_dir)
        public_key = work_dir.joinpath('gen_key_task_1', f'{key}_public.key')
        private_key = work_dir.joinpath('community_keys_backups', f'{key}_private.key')

        assert public_key.exists()
        assert private_key.exists()
        assert public_key.open().read() == key
        assert private_key.open().read() == key
