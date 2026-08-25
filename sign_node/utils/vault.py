# -*- mode:python; coding:utf-8; -*-

"""Fetch GPG key passphrases from a HashiCorp Vault KV v2 store.

Each GPG keyid must correspond to a secret at
``<mount>/<path_prefix>/<keyid>`` holding the passphrase in a single field
(``passphrase`` by default).
"""

import logging
import os
from typing import Dict, List, Optional

from ..errors import ConfigurationError

__all__ = ["fetch_passphrases", "DEFAULT_FIELD", "DEFAULT_MOUNT"]

logger = logging.getLogger(__name__)

DEFAULT_MOUNT = "secret"
DEFAULT_FIELD = "passphrase"


def _read_secret_file(path: str, what: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fd:
            value = fd.read().strip()
    except OSError as e:
        raise ConfigurationError(
            f"Cannot read Vault {what} from {path}: {e}"
        ) from e
    if not value:
        raise ConfigurationError(f"Vault {what} file {path} is empty")
    return value


def _authenticate(
    client,
    hvac_exceptions,
    *,
    token: Optional[str],
    token_file: Optional[str],
    role_id: Optional[str],
    secret_id: Optional[str],
    secret_id_file: Optional[str],
):
    """Log the client in, preferring a static token over AppRole."""
    if token_file:
        client.token = _read_secret_file(token_file, "token")
    elif token:
        client.token = token
    elif role_id:
        if secret_id_file:
            secret_id = _read_secret_file(secret_id_file, "secret_id")
        if not secret_id:
            raise ConfigurationError(
                "Vault AppRole authentication requires a secret id "
                "(set vault_secret_id or vault_secret_id_file)"
            )
        try:
            client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        except hvac_exceptions.VaultError as e:
            raise ConfigurationError(
                f"Vault AppRole authentication failed: {e}"
            ) from e
    elif os.environ.get("VAULT_TOKEN"):
        # Honour the ambient environment, e.g. a host running a Vault agent.
        client.token = os.environ["VAULT_TOKEN"]
    else:
        raise ConfigurationError(
            "No Vault credentials provided (set vault_token_file, "
            "vault_token, an AppRole via vault_role_id, or VAULT_TOKEN "
            "in the environment)"
        )


def fetch_passphrases(
    keyids: List[str],
    *,
    addr: Optional[str] = None,
    token: Optional[str] = None,
    token_file: Optional[str] = None,
    role_id: Optional[str] = None,
    secret_id: Optional[str] = None,
    secret_id_file: Optional[str] = None,
    namespace: Optional[str] = None,
    mount: str = DEFAULT_MOUNT,
    path_prefix: str = "",
    field: str = DEFAULT_FIELD,
    ca_cert: Optional[str] = None,
) -> Dict[str, str]:
    """Return a keyid -> passphrase mapping read from Vault."""
    try:
        import hvac
        from hvac import exceptions as hvac_exceptions
    except ImportError as e:
        raise ConfigurationError(
            "hvac is not installed. Install it with: pip install hvac"
        ) from e

    addr = addr or os.environ.get("VAULT_ADDR")
    if not addr:
        raise ConfigurationError(
            "Vault address must be provided (set vault_addr or VAULT_ADDR)"
        )

    logger.info(
        "Fetching GPG passphrases from Vault %s for %d keys", addr, len(keyids)
    )
    client = hvac.Client(
        url=addr,
        namespace=namespace,
        verify=ca_cert if ca_cert else True,
    )
    _authenticate(
        client,
        hvac_exceptions,
        token=token,
        token_file=token_file,
        role_id=role_id,
        secret_id=secret_id,
        secret_id_file=secret_id_file,
    )

    prefix = path_prefix.strip("/")
    result: Dict[str, str] = {}
    missing: List[str] = []
    for keyid in keyids:
        path = f"{prefix}/{keyid}" if prefix else keyid
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount,
                raise_on_deleted_version=True,
            )
        except hvac_exceptions.InvalidPath:
            missing.append(keyid)
            continue
        except hvac_exceptions.VaultError as e:
            # Sealed vault, bad token, denied policy: not a missing key, so
            # fail loudly instead of degrading to an interactive prompt.
            raise ConfigurationError(
                f"Cannot read Vault secret {mount}/{path}: {e}"
            ) from e
        passphrase = (response.get("data", {}).get("data") or {}).get(field)
        if not passphrase:
            missing.append(keyid)
            continue
        result[keyid] = passphrase

    if missing:
        raise ConfigurationError(
            f"Vault is missing passphrases (field '{field}') for keys: "
            + ", ".join(missing)
        )

    return result
