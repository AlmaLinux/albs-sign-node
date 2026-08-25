import sys
import types
from unittest.mock import MagicMock

import pytest

from sign_node.errors import ConfigurationError

KEY_A = "AAAA1111BBBB2222"
KEY_B = "CCCC3333DDDD4444"
ADDR = "https://vault.example.com:8200"


class InvalidPath(Exception):
    pass


class VaultError(Exception):
    pass


@pytest.fixture
def fake_hvac(monkeypatch):
    """Install a stub ``hvac`` module with the bits the fetcher touches."""
    package = types.ModuleType("hvac")
    exceptions = types.ModuleType("hvac.exceptions")
    exceptions.InvalidPath = InvalidPath
    exceptions.VaultError = VaultError
    package.exceptions = exceptions
    package.Client = MagicMock()
    monkeypatch.setitem(sys.modules, "hvac", package)
    monkeypatch.setitem(sys.modules, "hvac.exceptions", exceptions)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    yield package


def _import_fetcher():
    from sign_node.utils.vault import fetch_passphrases

    return fetch_passphrases


def _kv(fake_hvac):
    return fake_hvac.Client.return_value.secrets.kv.v2


def _secrets(mapping, field="passphrase"):
    """Build a read_secret_version side effect from a path -> value map."""

    def _read(path, mount_point, raise_on_deleted_version):
        if path not in mapping:
            raise InvalidPath(path)
        return {"data": {"data": {field: mapping[path]}}}

    return _read


def test_fetch_passphrases_returns_keyid_map(fake_hvac):
    _kv(fake_hvac).read_secret_version.side_effect = _secrets({
        f"albs/sign-keys/{KEY_A}": "secret-a",
        f"albs/sign-keys/{KEY_B}": "secret-b",
    })

    fetch_passphrases = _import_fetcher()
    result = fetch_passphrases(
        keyids=[KEY_A, KEY_B],
        addr=ADDR,
        token="t",
        path_prefix="albs/sign-keys",
    )

    assert result == {KEY_A: "secret-a", KEY_B: "secret-b"}
    fake_hvac.Client.assert_called_once_with(
        url=ADDR, namespace=None, verify=True
    )


def test_fetch_passphrases_without_path_prefix(fake_hvac):
    _kv(fake_hvac).read_secret_version.side_effect = _secrets({KEY_A: "x"})

    fetch_passphrases = _import_fetcher()
    assert fetch_passphrases(keyids=[KEY_A], addr=ADDR, token="t") == {
        KEY_A: "x"
    }


def test_fetch_passphrases_custom_mount_and_field(fake_hvac):
    _kv(fake_hvac).read_secret_version.side_effect = _secrets(
        {KEY_A: "x"}, field="password"
    )

    fetch_passphrases = _import_fetcher()
    result = fetch_passphrases(
        keyids=[KEY_A], addr=ADDR, token="t", mount="kv", field="password"
    )

    assert result == {KEY_A: "x"}
    _, kwargs = _kv(fake_hvac).read_secret_version.call_args
    assert kwargs["mount_point"] == "kv"


def test_fetch_passphrases_missing_secret_raises(fake_hvac):
    _kv(fake_hvac).read_secret_version.side_effect = _secrets({KEY_A: "a"})

    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match=KEY_B):
        fetch_passphrases(keyids=[KEY_A, KEY_B], addr=ADDR, token="t")


def test_fetch_passphrases_wrong_field_treated_as_missing(fake_hvac):
    _kv(fake_hvac).read_secret_version.side_effect = _secrets(
        {KEY_A: "a"}, field="other"
    )

    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match=KEY_A):
        fetch_passphrases(keyids=[KEY_A], addr=ADDR, token="t")


def test_fetch_passphrases_sealed_vault_raises(fake_hvac):
    _kv(fake_hvac).read_secret_version.side_effect = VaultError("sealed")

    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match="Cannot read Vault secret"):
        fetch_passphrases(keyids=[KEY_A], addr=ADDR, token="t")


def test_fetch_passphrases_reads_token_file(fake_hvac, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("s.tokenvalue\n")
    _kv(fake_hvac).read_secret_version.side_effect = _secrets({KEY_A: "x"})

    fetch_passphrases = _import_fetcher()
    fetch_passphrases(keyids=[KEY_A], addr=ADDR, token_file=str(token_file))

    assert fake_hvac.Client.return_value.token == "s.tokenvalue"


def test_fetch_passphrases_empty_token_file_raises(fake_hvac, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("\n")

    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match="is empty"):
        fetch_passphrases(keyids=[KEY_A], addr=ADDR, token_file=str(token_file))


def test_fetch_passphrases_unreadable_token_file_raises(fake_hvac, tmp_path):
    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match="Cannot read Vault token"):
        fetch_passphrases(
            keyids=[KEY_A], addr=ADDR, token_file=str(tmp_path / "nope")
        )


def test_fetch_passphrases_approle_login(fake_hvac, tmp_path):
    secret_id_file = tmp_path / "secret_id"
    secret_id_file.write_text("sid-value\n")
    _kv(fake_hvac).read_secret_version.side_effect = _secrets({KEY_A: "x"})

    fetch_passphrases = _import_fetcher()
    fetch_passphrases(
        keyids=[KEY_A],
        addr=ADDR,
        role_id="rid",
        secret_id_file=str(secret_id_file),
    )

    fake_hvac.Client.return_value.auth.approle.login.assert_called_once_with(
        role_id="rid", secret_id="sid-value"
    )


def test_fetch_passphrases_approle_without_secret_id_raises(fake_hvac):
    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match="requires a secret id"):
        fetch_passphrases(keyids=[KEY_A], addr=ADDR, role_id="rid")


def test_fetch_passphrases_approle_login_failure_raises(fake_hvac):
    fake_hvac.Client.return_value.auth.approle.login.side_effect = VaultError(
        "denied"
    )

    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match="AppRole authentication"):
        fetch_passphrases(
            keyids=[KEY_A], addr=ADDR, role_id="rid", secret_id="sid"
        )


def test_fetch_passphrases_falls_back_to_env(fake_hvac, monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", ADDR)
    monkeypatch.setenv("VAULT_TOKEN", "env-token")
    _kv(fake_hvac).read_secret_version.side_effect = _secrets({KEY_A: "x"})

    fetch_passphrases = _import_fetcher()
    assert fetch_passphrases(keyids=[KEY_A]) == {KEY_A: "x"}

    assert fake_hvac.Client.return_value.token == "env-token"
    fake_hvac.Client.assert_called_once_with(
        url=ADDR, namespace=None, verify=True
    )


def test_fetch_passphrases_requires_addr(fake_hvac):
    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match="Vault address"):
        fetch_passphrases(keyids=[KEY_A], token="t")


def test_fetch_passphrases_requires_credentials(fake_hvac):
    fetch_passphrases = _import_fetcher()
    with pytest.raises(ConfigurationError, match="No Vault credentials"):
        fetch_passphrases(keyids=[KEY_A], addr=ADDR)


def test_fetch_passphrases_passes_namespace_and_ca_cert(fake_hvac):
    _kv(fake_hvac).read_secret_version.side_effect = _secrets({KEY_A: "x"})

    fetch_passphrases = _import_fetcher()
    fetch_passphrases(
        keyids=[KEY_A],
        addr=ADDR,
        token="t",
        namespace="admin/albs",
        ca_cert="/etc/pki/vault-ca.pem",
    )

    fake_hvac.Client.assert_called_once_with(
        url=ADDR, namespace="admin/albs", verify="/etc/pki/vault-ca.pem"
    )


def test_fetch_passphrases_without_hvac_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "hvac", None)
    monkeypatch.setitem(sys.modules, "hvac.exceptions", None)

    from sign_node.utils.vault import fetch_passphrases

    with pytest.raises(ConfigurationError, match="hvac is not installed"):
        fetch_passphrases(keyids=[KEY_A], addr=ADDR, token="t")
