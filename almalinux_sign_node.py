#!/usr/bin/env python3
# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
# created: 2018-03-31

"""
CloudLinux Build System builds sign node.
"""

import errno
import signal
import sys


from sign_node.errors import ConfigurationError
from sign_node.config import SignNodeConfig
from sign_node.cli import init_args_parser, init_working_dir
from sign_node.signer import Signer
from sign_node.utils.config import locate_config_file
from sign_node.utils.log import configure_logger
from sign_node.utils.pgp_utils import init_gpg, PGPPasswordDB


def main(sys_args):
    args_parser = init_args_parser()
    args = args_parser.parse_args(sys_args)
    configure_logger(args.verbose)
    try:
        config_file = locate_config_file('sign_node', args.config)
        config = SignNodeConfig(config_file)
    except ValueError as e:
        args_parser.error('Configuration error: {0}'.format(e))
        return errno.EINVAL

    gpg = init_gpg()
    password_db = PGPPasswordDB(gpg, config.pgp_keyids[:], config.pgp_key_password)
    try:
        password_db.ask_for_passwords()
    except ConfigurationError as e:
        args_parser.error(str(e))
        return errno.EACCES

    init_working_dir(config.working_dir)
    
    # signal.signal(signal.SIGINT, signal_handler)
    # signal.signal(signal.SIGTERM, signal_handler)

    signer = Signer(config, password_db, gpg)
    signer.sign_loop()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
