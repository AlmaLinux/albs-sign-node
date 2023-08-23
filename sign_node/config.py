# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
# created: 2018-03-31

"""
CloudLinux Build System builds sign node configuration storage.
"""

from .utils.config import BaseConfig
from .utils.file_utils import normalize_path

__all__ = ["SignNodeConfig"]


DEFAULT_MASTER_URL = 'http://web_server:8000/api/v1/'
DEFAULT_WS_MASTER_URL = 'ws://web_server:8000/api/v1/'
DEFAULT_PULP_HOST = "http://pulp"
DEFAULT_PULP_USER = "pulp"
DEFAULT_PULP_PASSWORD = "test_pwd"
DEFAULT_PULP_CHUNK_SIZE = 8388608  # 8 MiB
# Max file size to allow parallel upload for
DEFAULT_PARALLEL_FILE_UPLOAD_SIZE = 52428800  # 500 MB
DEFAULT_PGP_PASSWORD = "test_pwd"
DEFAULT_SENTRY_DSN = ""
DEFAULT_SENTRY_ENVIRONMENT = "dev"
DEFAULT_SENTRY_TRACES_SAMPLE_RATE = 0.2

COMMUNITY_KEY_SUFFIX = 'ALBS community repo'

GPG_SCENARIO_TEMPLATE = (
    '%no-protection\n'
    'Key-Type: RSA\n'
    'Key-Length: 4096\n'
    'Subkey-Type: default\n'
    'Subkey-Length: 4096\n'
    'Name-Real: {sign_key_uid}\n'
    'Expire-Date: 0\n'
)


class SignNodeConfig(BaseConfig):
    def __init__(self, config_file=None, **cmd_args):
        """
        Builds sign node configuration initialization.

        Parameters
        ----------
        config_file : str, optional
            Configuration file path.
        cmd_args : dict
            Command line arguments.
        """
        default_config = {
            "development_mode": False,
            "is_community_sign_node": False,
            "pgp_keys": {},
            "master_url": DEFAULT_MASTER_URL,
            "ws_master_url": DEFAULT_WS_MASTER_URL,
            "node_id": self.generate_node_id(postfix=".sign"),
            "working_dir": "/srv/alternatives/sign_node",
            "pulp_host": DEFAULT_PULP_HOST,
            "pulp_user": DEFAULT_PULP_USER,
            "pulp_password": DEFAULT_PULP_PASSWORD,
            "pulp_chunk_size": DEFAULT_PULP_CHUNK_SIZE,
            "parallel_upload_file_size": DEFAULT_PARALLEL_FILE_UPLOAD_SIZE,
            "dev_pgp_key_password": DEFAULT_PGP_PASSWORD,
            'sentry_dsn': DEFAULT_SENTRY_DSN,
            'sentry_environment': DEFAULT_SENTRY_ENVIRONMENT,
            'sentry_traces_sample_rate': DEFAULT_SENTRY_TRACES_SAMPLE_RATE,
            'immudb_username': None,
            'immudb_password': None,
            'immudb_database': None,
            'immudb_address': None,
            'immudb_public_key_file': None,
        }
        schema = {
            "development_mode": {"type": "boolean", "default": False},
            "is_community_sign_node": {"type": "boolean", "default": False},
            "pgp_keys": {
                "type": "list",
                "required": True,
                "empty": False,
            },
            "node_id": {"type": "string", "required": True},
            "master_url": {"type": "string", "required": True},
            "ws_master_url": {"type": "string", "required": True},
            "working_dir": {"type": "string", "required": True,
                            "coerce": normalize_path},
            "pulp_host": {"type": "string", "nullable": False},
            "pulp_user": {"type": "string", "nullable": False},
            "pulp_password": {"type": "string", "nullable": False},
            "pulp_chunk_size": {"type": "integer", "nullable": False},
            "parallel_upload_file_size": {"type": "integer", "nullable": False},
            "jwt_token": {"type": "string", "nullable": True},
            "dev_pgp_key_password": {"type": "string", "nullable": False},
            "sentry_dsn": {"type": "string", "nullable": True},
            "sentry_environment": {"type": "string", "nullable": True},
            "sentry_traces_sample_rate": {"type": "float", "nullable": True},
            'immudb_username': {'type': 'string', 'nullable': True},
            'immudb_password': {'type': 'string', 'nullable': True},
            'immudb_database': {'type': 'string', 'nullable': True},
            'immudb_address': {'type': 'string', 'nullable': True},
            'immudb_public_key_file': {'type': 'string', 'nullable': True},
        }
        super(SignNodeConfig, self).__init__(
            default_config, config_file, schema, **cmd_args
        )

    @property
    def codenotary_enabled(self) -> bool:
        return bool(self.immudb_username) and bool(self.immudb_password)
