#!/usr/bin/env python3
# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
# created: 2018-03-31

"""
AlmaLinux Build System builds sign node.
"""

import argparse
import logging
import sys

import sentry_sdk
from albs_common_lib.errors import ConfigurationError
from albs_common_lib.utils.file_utils import clean_dir, safe_mkdir
from albs_common_lib.utils.pgp_utils import PGPPasswordDB, init_gpg

from sign_node.config import SignNodeConfig
from sign_node.signer import Signer
from sign_node.utils.config import locate_config_file


def init_arg_parser():
    parser = argparse.ArgumentParser(
        prog="sign_node", description="AlmaLinux Build System builds sign node"
    )
    parser.add_argument("-c", "--config", help="configuration file path")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable additional debug output",
    )
    return parser


def init_logger(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    handler.setLevel(level)
    log_format = "%(asctime)s %(levelname)-8s [%(threadName)s]: %(message)s"
    formatter = logging.Formatter(log_format, "%y.%m.%d %H:%M:%S")
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def init_sentry(config: SignNodeConfig):
    if not config.sentry_dsn:
        return
    sentry_sdk.init(
        dsn=config.sentry_dsn,
        traces_sample_rate=config.sentry_traces_sample_rate,
        environment=config.sentry_environment,
    )


def init_working_dir(config):
    working_dir = config.working_dir
    if not safe_mkdir(working_dir):
        logging.debug("cleaning up the %s working directory", working_dir)
        clean_dir(working_dir)
    else:
        logging.debug("working directory %s was created", working_dir)


def main():
    args_parser = init_arg_parser()
    args = args_parser.parse_args()
    logger = init_logger(args.verbose)
    try:
        config_file = locate_config_file('sign_node', args.config)
        logger.debug(
            "Loading %s",
            config_file if config_file else 'default configuration',
        )
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
        development_password=config.dev_pgp_key_password,
    )
    try:
        password_db.ask_for_passwords()
    except ConfigurationError as e:
        args_parser.error(str(e))

    init_working_dir(config)

    signer = Signer(config, password_db, gpg)
    signer.sign_loop()


if __name__ == '__main__':
    sys.exit(main())
