# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
# created: 2018-03-31

"""
CloudLinux Build System builds sign node configuration storage.
"""

import platform
import re

from .errors import ConfigurationError
from .utils.config import BaseConfig
from .utils.file_utils import normalize_path

__all__ = ["SignNodeConfig"]


DEFAULT_PULP_HOST = "http://pulp"
DEFAULT_PULP_USER = "pulp"
DEFAULT_PULP_PASSWORD = "test_pwd"
DEFAULT_PULP_CHUNK_SIZE = 8388608  # 8 MiB


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
            "pgp_keyids": [],
            "private_key_path": "~/.config/sign_node/"
            "{0}.key_secret".format(platform.node()),
            "public_key_path": "~/.config/sign_node/" "{0}.key".format(platform.node()),
            "node_id": self.generate_node_id(postfix=".sign"),
            "master_key_path": "~/.config/sign_node/build_server.key",
            "master_url": "tcp://127.0.0.1:32167",
            "working_dir": "/srv/alternatives/sign_node",
            "pulp_host": DEFAULT_PULP_HOST,
            "pulp_user": DEFAULT_PULP_USER,
            "pulp_password": DEFAULT_PULP_PASSWORD,
            "pulp_chunk_size": DEFAULT_PULP_CHUNK_SIZE,
        }
        schema = {
            "development_mode": {"type": "boolean", "default": False},
            "pgp_keyids": {
                "type": "list",
                "required": True,
                "empty": False,
                "schema": {"type": "string"},
            },
            "private_key_path": {
                "type": "string",
                "required": True,
                "coerce": normalize_path,
            },
            "public_key_path": {
                "type": "string",
                "required": True,
                "coerce": normalize_path,
            },
            "node_id": {"type": "string", "required": True},
            "master_key_path": {
                "type": "string",
                "required": True,
                "coerce": normalize_path,
            },
            "master_url": {"type": "string", "required": True},
            "working_dir": {
                "type": "string",
                "required": True,
                "coerce": normalize_path,
            },
            "pulp_host": {"type": "string", "nullable": False},
            "pulp_user": {"type": "string", "nullable": False},
            "pulp_password": {"type": "string", "nullable": False},
            "pulp_chunk_size": {"type": "integer", "nullable": False},
            "jwt_token": {"type": "string", "nullable": True},
        }
        super(SignNodeConfig, self).__init__(
            default_config, config_file, schema, **cmd_args
        )
