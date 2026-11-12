from unittest.mock import patch, MagicMock

import pytest

from sign_node import package_sign
from sign_node.package_sign import (
    PackageSignError,
    sign_rpm_package,
    sign_rpm_packages,
)


@patch('sign_node.package_sign.plumbum')
def test_sign_rpm_package(plumbum):
    pexpect_run = 'sign_node.package_sign.pexpect.run'
    rpm_sign = MagicMock()
    rpm_sign.run = MagicMock(return_value=(0, '', ''))
    plumbum.local = {'rpmsign': rpm_sign}

    with patch(pexpect_run, return_value=(None, None)):
        with pytest.raises(PackageSignError):
            sign_rpm_package('path', 'keyid', 'password')

    with patch(pexpect_run, return_value=(None, 1)):
        with pytest.raises(PackageSignError):
            sign_rpm_package('path', 'keyid', 'password', retries=0)

    with patch(pexpect_run, return_value=(None, 0)):
        sign_rpm_package('path', 'keyid', 'password')


@patch('sign_node.package_sign.gnupg')
@patch('sign_node.package_sign.plumbum')
def test_sign_rpm_packages(plumbum, gnupg, tmp_path):
    rpm_sign = MagicMock()
    rpm_sign.run = MagicMock(return_value=(0, '', ''))
    gpgconf = MagicMock()
    gpgconf.run = MagicMock(return_value=(0, '', ''))
    plumbum.local = {'rpmsign': rpm_sign, 'gpgconf': gpgconf}
    gnupg.GPG.return_value.gen_key.return_value.fingerprint = 'THROWAWAY'
    paths = [f'/tmp/pkg{i}.rpm' for i in range(5)]
    signed = []

    def pexpect_run(command, **_):
        signed.append(command.split()[-1].rstrip('"'))
        return None, 0

    with patch('sign_node.package_sign.pexpect.run', side_effect=pexpect_run):
        sign_rpm_packages(
            paths,
            'keyid',
            'password',
            sign_files=True,
            locks_dir_path=str(tmp_path),
            key_workers=2,
            prepare_workers=3,
        )

    rpmsign_calls = [
        call.kwargs['args'] for call in rpm_sign.run.call_args_list
    ]
    for path in paths:
        assert ['--delsign', path] in rpmsign_calls
        prepared = [
            args
            for args in rpmsign_calls
            if args[:2] == ['--resign', '--signfiles'] and args[-1] == path
        ]
        assert len(prepared) == 1
        assert '_gpg_name THROWAWAY' in prepared[0]
    assert sorted(signed) == sorted(paths)
    # the throwaway key's gpg-agent is stopped afterwards
    assert gpgconf.run.call_args.kwargs['args'][-2:] == ['--kill', 'gpg-agent']

    # without file signing there is no throwaway key at all
    gnupg.GPG.reset_mock()
    rpm_sign.run.reset_mock()
    with patch('sign_node.package_sign.pexpect.run', return_value=(None, 0)):
        sign_rpm_packages(
            paths[:1], 'keyid', 'password', locks_dir_path=str(tmp_path)
        )
    gnupg.GPG.assert_not_called()
    assert [c.kwargs['args'] for c in rpm_sign.run.call_args_list] == [
        ['--delsign', paths[0]]
    ]

    # a failing signature is reported
    with patch('sign_node.package_sign.pexpect.run', return_value=(None, 1)):
        with pytest.raises(PackageSignError):
            sign_rpm_packages(
                paths,
                'keyid',
                'password',
                locks_dir_path=str(tmp_path),
                retries=0,
            )


@patch('sign_node.package_sign.time.sleep')
@patch('sign_node.package_sign.plumbum')
def test_sign_rpm_package_retries(plumbum, sleep):
    pexpect_run = 'sign_node.package_sign.pexpect.run'
    gpgconf = MagicMock()
    plumbum.local = {'gpgconf': gpgconf}
    sign = dict(delete_old_signatures=False, with_locks=False, retries=2)

    # the card comes back after scdaemon is restarted
    with patch(pexpect_run, side_effect=[(b'', 1), (b'', 1), (b'', 0)]) as run:
        sign_rpm_package('path', 'keyid', 'password', **sign)
    assert run.call_count == 3
    assert [c.kwargs['args'] for c in gpgconf.run.call_args_list] == [
        ['--kill', 'scdaemon']
    ] * 2
    assert [c.args[0] for c in sleep.call_args_list] == [5, 10]

    # the attempts are limited
    with patch(pexpect_run, return_value=(b'', 1)) as run:
        with pytest.raises(PackageSignError):
            sign_rpm_package('path', 'keyid', 'password', **sign)
    assert run.call_count == 3

    # a failure caused by a restart made by another thread does not
    # restart scdaemon once more
    gpgconf.run.reset_mock()

    def restarted_meanwhile(**_):
        package_sign._restart_scdaemon(package_sign._scdaemon_restarts)
        return (b'', 1) if gpgconf.run.call_count == 1 else (b'', 0)

    with patch(pexpect_run, side_effect=restarted_meanwhile):
        sign_rpm_package('path', 'keyid', 'password', **sign)
    assert gpgconf.run.call_count == 2
