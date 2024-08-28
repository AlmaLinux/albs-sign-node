from unittest.mock import patch, MagicMock

import pytest

from sign_node.package_sign import PackageSignError, sign_rpm_package


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
            sign_rpm_package('path', 'keyid', 'password')

    with patch(pexpect_run, return_value=(None, 0)):
        sign_rpm_package('path', 'keyid', 'password')
