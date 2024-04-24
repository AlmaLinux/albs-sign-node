from unittest.mock import patch

import pytest

from sign_node.package_sign import PackageSignError, sign_rpm_package


def test_sign_rpm_package():
    pexpect_run = 'sign_node.package_sign.pexpect.run'

    with patch(pexpect_run, return_value=(None, None)):
        with pytest.raises(PackageSignError):
            sign_rpm_package('path', 'keyid', 'password')

    with patch(pexpect_run, return_value=(None, 1)):
        with pytest.raises(PackageSignError):
            sign_rpm_package('path', 'keyid', 'password')

    with patch(pexpect_run, return_value=(None, 0)):
        sign_rpm_package('path', 'keyid', 'password')
