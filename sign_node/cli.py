# -*- mode:python; coding:utf-8; -*-
# author: Eugene Zamriy <ezamriy@cloudlinux.com>
# created: 2018-03-31

"""
CloudLinux Build System builds sign node command line tool functions.
"""

import argparse
import logging

from .utils.file_utils import safe_mkdir, clean_dir

__all__ = ["init_args_parser", "init_working_dir"]


def init_working_dir(working_dir):
    """
    The working directory initialization function. It removes files from
    previous executions and creates the necessary directories.

    Parameters
    ----------
    working_dir : str
        Working directory path.
    """
    # TODO: move this function to a common module like utils since its
    #       used by the sign node and we have something very similar in the
    #       build node's code.
    if not safe_mkdir(working_dir):
        logging.debug("cleaning up the {0} working directory".format(working_dir))
        clean_dir(working_dir)
    else:
        logging.debug("working directory {0} was created".format(working_dir))


def init_args_parser():
    """
    Sign daemon command line arguments parser initialization.

    Returns
    -------
    argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog="sign_node", description="CloudLinux Build System builds sign node"
    )
    parser.add_argument("-c", "--config", help="configuration file path")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable additional debug output"
    )
    return parser
