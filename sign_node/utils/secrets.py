# -*- mode:python; coding:utf-8; -*-

"""Resolve GPG key passphrases from an external secret provider.

Exactly one provider may be enabled at a time: signing keys should have a
single unambiguous source of truth, so enabling several is a configuration
error rather than a merge of their results.
"""

import logging
from typing import Dict, Optional

from ..errors import ConfigurationError
from . import bitwarden, vault

__all__ = ["resolve_passphrases", "enabled_providers"]

logger = logging.getLogger(__name__)


def enabled_providers(config) -> list:
    """Names of the secret providers switched on in the configuration."""
    flags = (
        ("bitwarden", config.bitwarden_enabled),
        ("vault", config.vault_enabled),
    )
    return [name for name, enabled in flags if enabled]


def _from_vault(config) -> Dict[str, str]:
    return vault.fetch_passphrases(
        keyids=config.pgp_keys,
        addr=config.vault_addr,
        token=config.vault_token,
        token_file=config.vault_token_file,
        role_id=config.vault_role_id,
        secret_id=config.vault_secret_id,
        secret_id_file=config.vault_secret_id_file,
        namespace=config.vault_namespace,
        mount=config.vault_mount,
        path_prefix=config.vault_path_prefix,
        field=config.vault_passphrase_field,
        ca_cert=config.vault_ca_cert,
    )


def _from_bitwarden(config) -> Dict[str, str]:
    return bitwarden.fetch_passphrases(
        keyids=config.pgp_keys,
        username=config.bitwarden_username,
        password=config.bitwarden_password,
        password_file=config.bitwarden_password_file,
        collection_id=config.bitwarden_collection_id,
    )


def resolve_passphrases(config) -> Optional[Dict[str, str]]:
    """Fetch passphrases from the configured provider.

    Returns ``None`` when no provider is enabled, leaving the caller to fall
    back to development mode or interactive prompts.
    """
    providers = enabled_providers(config)
    if len(providers) > 1:
        raise ConfigurationError(
            "Only one secret provider may be enabled at a time, but these "
            "are enabled: " + ", ".join(providers)
        )
    if not providers:
        return None
    provider = providers[0]
    logger.info("Using the %s secret provider for GPG passphrases", provider)
    fetchers = {"bitwarden": _from_bitwarden, "vault": _from_vault}
    return fetchers[provider](config)
