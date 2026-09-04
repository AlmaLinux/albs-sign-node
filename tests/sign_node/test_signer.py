import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import rpm
from pyfakefs.fake_filesystem_unittest import TestCase

import sign_node
from sign_node.config import SignNodeConfig
from sign_node.errors import SignError
from sign_node.signer import Signer

REGULAR_FILE_MODE = stat.S_IFREG | 0o644
DIRECTORY_MODE = stat.S_IFDIR | 0o755
SYMLINK_MODE = stat.S_IFLNK | 0o777


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


def make_header(modes, signatures, flags=None):
    if flags is None:
        flags = [0] * len(modes)
    return {
        rpm.RPMTAG_FILEMODES: modes,
        rpm.RPMTAG_FILEFLAGS: flags,
        rpm.RPMTAG_FILESIGNATURES: signatures,
    }


class TestCheckFileSignatures:

    def test_signed_regular_files(self):
        header = make_header(
            [REGULAR_FILE_MODE, REGULAR_FILE_MODE],
            ['aabb', 'ccdd'],
        )
        assert Signer._check_file_signatures(header) is True

    def test_unsigned_regular_file(self):
        header = make_header(
            [REGULAR_FILE_MODE, REGULAR_FILE_MODE],
            ['aabb', ''],
        )
        assert Signer._check_file_signatures(header) is False

    def test_no_signatures_at_all(self):
        header = make_header([REGULAR_FILE_MODE], [])
        assert Signer._check_file_signatures(header) is False
        header = make_header([REGULAR_FILE_MODE], None)
        assert Signer._check_file_signatures(header) is False

    def test_metapackage_without_regular_files(self):
        header = make_header(
            [DIRECTORY_MODE, SYMLINK_MODE],
            [],
        )
        assert Signer._check_file_signatures(header) is True

    def test_empty_package(self):
        header = make_header([], [])
        assert Signer._check_file_signatures(header) is True

    def test_unsigned_ghost_file_is_skipped(self):
        header = make_header(
            [REGULAR_FILE_MODE, REGULAR_FILE_MODE],
            ['aabb', ''],
            flags=[0, rpm.RPMFILE_GHOST],
        )
        assert Signer._check_file_signatures(header) is True


class TestFilesSignatureRequired:

    def make_signer(self, platforms):
        config = SignNodeConfig(
            require_files_signature_platforms=platforms,
        )
        return Signer(config, 'password', None)

    def test_option_not_set(self):
        signer = self.make_signer([])
        task = {'packages': [{'name': 'pkg-1.rpm', 'type': 'rpm'}]}
        assert signer._files_signature_required(task) is False

    def test_platform_listed(self):
        signer = self.make_signer(['AlmaLinux-10'])
        task = {'packages': [
            {
                'name': 'pkg-1.rpm',
                'type': 'rpm',
                'platform_name': 'AlmaLinux-9',
            },
            {
                'name': 'pkg-2.rpm',
                'type': 'rpm',
                'platform_name': 'AlmaLinux-10',
            },
        ]}
        assert signer._files_signature_required(task) is True

    def test_platform_not_listed(self):
        signer = self.make_signer(['AlmaLinux-10'])
        task = {'packages': [
            {
                'name': 'pkg-1.rpm',
                'type': 'rpm',
                'platform_name': 'AlmaLinux-9',
            },
        ]}
        assert signer._files_signature_required(task) is False

    def test_missing_platform_info(self):
        signer = self.make_signer(['AlmaLinux-10'])
        task = {'packages': [{'name': 'pkg-1.rpm', 'type': 'rpm'}]}
        with pytest.raises(SignError, match='no platform information'):
            signer._files_signature_required(task)

    def test_non_rpm_packages_are_ignored(self):
        signer = self.make_signer(['AlmaLinux-10'])
        task = {'packages': [{'name': 'pkg_1.deb', 'type': 'deb'}]}
        assert signer._files_signature_required(task) is False


class TestCheckSignatureFileSignatures(TestCase):

    def setUp(self):
        self.setUpPyfakefs()
        self.config = SignNodeConfig()
        password_db = MagicMock()
        password_db.get_subkeys.return_value = []
        self.signer = Signer(self.config, password_db, None)

    def run_check(self, header, require_file_signature):
        pkg_path = '/pkg/test-package.rpm'
        self.fs.create_file(pkg_path)
        header = dict(header)
        header.setdefault(rpm.RPMTAG_SIGGPG, b'fake-signature')
        ts = MagicMock()
        ts.hdrFromFdno.return_value = header
        pgp_msg = MagicMock()
        signature = MagicMock()
        signature.signer = 'aabbccdd11223344'
        pgp_msg.signatures = [signature]
        with (
            patch('sign_node.signer.rpm.TransactionSet', return_value=ts),
            patch(
                'sign_node.signer.pgpy.PGPMessage.from_blob',
                return_value=pgp_msg,
            ),
        ):
            return self.signer._check_signature(
                [pkg_path],
                'AABBCCDD11223344',
                files_require_signature=(
                    {pkg_path} if require_file_signature else None
                ),
            )

    def test_missing_file_signatures_reported(self):
        header = make_header([REGULAR_FILE_MODE], [])
        errors = self.run_check(header, require_file_signature=True)
        assert len(errors) == 1
        assert 'does not contain file (IMA) signatures' in errors[0]

    def test_present_file_signatures_pass(self):
        header = make_header([REGULAR_FILE_MODE], ['aabb'])
        errors = self.run_check(header, require_file_signature=True)
        assert errors == []

    def test_file_signatures_not_required(self):
        header = make_header([REGULAR_FILE_MODE], [])
        errors = self.run_check(header, require_file_signature=False)
        assert errors == []


class TestSignBuildFilesSignatureGuard(TestCase):
    """
    The guard must fail the sign task *and report the failure*, so it has
    to run inside the '_sign_build' try block.
    """

    def setUp(self):
        self.setUpPyfakefs()
        self.config = SignNodeConfig(
            require_files_signature_platforms=['AlmaLinux-10'],
        )
        self.signer = Signer(self.config, MagicMock(), None)

    @staticmethod
    def make_task(sign_files, platform_name='AlmaLinux-10'):
        package = {
            'id': 1,
            'name': 'pkg-1.el10.x86_64.rpm',
            'type': 'rpm',
            'arch': 'x86_64',
            'download_url': 'http://pulp/pkg-1.el10.x86_64.rpm',
        }
        if platform_name is not None:
            package['platform_name'] = platform_name
        return {
            'id': 6,
            'build_id': 14,
            'keyid': 'AABBCCDD11223344',
            'sign_files': sign_files,
            'packages': [package],
        }

    def run_sign_build(self, task):
        with (
            patch.object(Signer, '_report_signed_build') as report,
            patch.object(
                Signer,
                '_download_package',
                side_effect=RuntimeError('download reached'),
            ) as download,
        ):
            self.signer._sign_build(task)
        assert report.call_count == 1
        task_id, payload = report.call_args[0]
        return task_id, payload, download

    def test_required_platform_without_sign_files_fails_task(self):
        task_id, payload, download = self.run_sign_build(self.make_task(False))

        assert task_id == 6
        assert payload['success'] is False
        assert 'sign_files=false' in payload['error_message']
        assert 'AlmaLinux-10' in payload['error_message']
        download.assert_not_called()

    def test_missing_platform_info_fails_task(self):
        _, payload, download = self.run_sign_build(
            self.make_task(False, platform_name=None)
        )

        assert payload['success'] is False
        assert 'no platform information' in payload['error_message']
        download.assert_not_called()

    def test_unlisted_platform_is_not_blocked(self):
        _, payload, download = self.run_sign_build(
            self.make_task(False, platform_name='AlmaLinux-9')
        )

        assert 'sign_files=false' not in payload['error_message']
        download.assert_called()

    def test_sign_files_enabled_is_not_blocked(self):
        _, payload, download = self.run_sign_build(self.make_task(True))

        assert 'sign_files=false' not in payload['error_message']
        download.assert_called()
