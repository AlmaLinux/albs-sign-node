import sys
import types
from unittest.mock import MagicMock

import pytest

from sign_node.errors import ConfigurationError


KEY_A = "AAAA1111BBBB2222"
KEY_B = "CCCC3333DDDD4444"


class FakeContainer:
    def __init__(self, mapping):
        self._mapping = mapping

    def __contains__(self, item):
        return item in self._mapping

    def get_credentials(self, name, password_only=False):
        value = self._mapping[name]
        return value if password_only else (None, value)


@pytest.fixture
def fake_bsbw(monkeypatch):
    """Install a stub `bsbw.wrapper` module so the fetcher can import it.

    Mirrors the real package layout: ``BWCLIWrapper`` lives in
    ``bsbw.wrapper`` and is not re-exported from the package root.
    """
    package = types.ModuleType("bsbw")
    wrapper = types.ModuleType("bsbw.wrapper")
    wrapper.BWCLIWrapper = MagicMock()
    package.wrapper = wrapper
    monkeypatch.setitem(sys.modules, "bsbw", package)
    monkeypatch.setitem(sys.modules, "bsbw.wrapper", wrapper)
    yield wrapper


def _import_fetcher():
    from sign_node.utils.bitwarden import fetch_passphrases
    return fetch_passphrases


def test_fetch_passphrases_returns_keyid_map(fake_bsbw):
    fake_bsbw.BWCLIWrapper.return_value.get_secrets.return_value = (
        FakeContainer({KEY_A: "secret-a", KEY_B: "secret-b"})
    )

    fetch_passphrases = _import_fetcher()
    result = fetch_passphrases(keyids=[KEY_A, KEY_B], password="master")

    assert result == {KEY_A: "secret-a", KEY_B: "secret-b"}
    fake_bsbw.BWCLIWrapper.assert_called_once_with(
        username=None,
        password="master",
        password_file=None,
        collection_id=None,
    )


def test_fetch_passphrases_passes_collection_and_password_file(fake_bsbw):
    fake_bsbw.BWCLIWrapper.return_value.get_secrets.return_value = (
        FakeContainer({KEY_A: "x"})
    )

    fetch_passphrases = _import_fetcher()
    fetch_passphrases(
        keyids=[KEY_A],
        username="signer@example.com",
        password_file="/tmp/bw_master",
        collection_id="col-1",
    )

    fake_bsbw.BWCLIWrapper.assert_called_once_with(
        username="signer@example.com",
        password=None,
        password_file="/tmp/bw_master",
        collection_id="col-1",
    )


def test_fetch_passphrases_requires_master_credential(fake_bsbw):
    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match="master password"):
        fetch_passphrases(keyids=[KEY_A])
    fake_bsbw.BWCLIWrapper.assert_not_called()


def test_fetch_passphrases_missing_item_raises(fake_bsbw):
    fake_bsbw.BWCLIWrapper.return_value.get_secrets.return_value = (
        FakeContainer({KEY_A: "secret-a"})
    )

    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match=KEY_B):
        fetch_passphrases(keyids=[KEY_A, KEY_B], password="m")


def test_fetch_passphrases_empty_passphrase_treated_as_missing(fake_bsbw):
    fake_bsbw.BWCLIWrapper.return_value.get_secrets.return_value = (
        FakeContainer({KEY_A: ""})
    )

    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match=KEY_A):
        fetch_passphrases(keyids=[KEY_A], password="m")


def test_fetch_passphrases_without_bsbw_installed(monkeypatch):
    # Ensure bsbw cannot be imported (block both the package and the
    # submodule the fetcher imports from).
    monkeypatch.setitem(sys.modules, "bsbw", None)
    monkeypatch.setitem(sys.modules, "bsbw.wrapper", None)

    from sign_node.utils.bitwarden import fetch_passphrases
    with pytest.raises(ConfigurationError, match="bitwarden-wrapper"):
        fetch_passphrases(keyids=[KEY_A], password="m")
