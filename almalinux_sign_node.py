#!/usr/bin/env python3
# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
# created: 2018-03-31

"""
CloudLinux Build System builds sign node.
"""

import sys

import sentry_sdk

from sign_node.errors import ConfigurationError
from sign_node.config import SignNodeConfig
from sign_node.cli import init_args_parser, init_working_dir
from sign_node.signer import Signer
from sign_node.utils.config import locate_config_file
from sign_node.utils.log import configure_logger
from sign_node.utils.pgp_utils import init_gpg, PGPPasswordDB


def init_sentry(config: SignNodeConfig):
    if not config.sentry_dsn:
        return
    sentry_sdk.init(
        dsn=config.sentry_dsn,
        traces_sample_rate=config.sentry_traces_sample_rate,
        environment=config.sentry_environment,
    )


def main():
    args_parser = init_args_parser()
    args = args_parser.parse_args()
    logger = configure_logger(args.verbose)
    try:
        config_file = locate_config_file('sign_node', args.config)
        logger.debug("Loading %s", config_file if config_file else 'default configuration')
        config = SignNodeConfig(config_file)
    except ValueError as e:
        args_parser.error('Configuration error: {0}'.format(e))

    init_sentry(config)
    gpg = init_gpg()
    password_db = PGPPasswordDB(
        gpg,
        key_ids_from_config=config.pgp_keys.copy(),
        is_community_sign_node=config.is_community_sign_node,
        development_mode=config.development_mode,
        development_password=config.dev_pgp_key_password
    )
    try:
        password_db.ask_for_passwords()
    except ConfigurationError as e:
        args_parser.error(str(e))

    init_working_dir(config.working_dir)

    signer = Signer(config, password_db, gpg)
    signer.sign_loop()


if __name__ == '__main__':
    sys.exit(main())
