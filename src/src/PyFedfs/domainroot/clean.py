"""
Set up FedFS domain root infrastructure on an NFS server
"""

__copyright__ = """
Copyright 2013 Oracle.  All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2.0
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License version 2.0 for more details.

A copy of the GNU General Public License version 2.0 is
available here:

    http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
"""


try:
    import sys
    import os
    import logging as log

    from PyFedfs.domainroot.paths import DOMAINROOT_PATH
    from PyFedfs.domainroot.paths import DOMAINROOTS_DIR_PATH

    from PyFedfs.run import EXIT_SUCCESS, EXIT_FAILURE
    from PyFedfs.userinput import confirm
    from PyFedfs.utilities import list_directory, remove_directory
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)


def do_clean(domainroots_dir_path, force):
    """
    Remove FedFS domainroot infrastructure

    Returns a shell exit status value
    """
    ret = remove_directory(DOMAINROOT_PATH, force)
    if ret != EXIT_SUCCESS:
        return ret

    ret = remove_directory(domainroots_dir_path, force)
    if ret != EXIT_SUCCESS:
        return ret

    return EXIT_SUCCESS


def subcmd_clean(args):
    """
    The 'clean infrastructure' subcommand

    Returns a shell exit status value
    """

    if not args.force:
        items = list_directory(DOMAINROOT_PATH)
        if len(items):
            log.error('There still exist some domain root directories')
            return EXIT_FAILURE
        print('This tool will remove all FedFS domain root infrastructure')
        if not confirm('Do you want to continue? [y/N] '):
            print('Command aborted')
            return EXIT_FAILURE

    domainroots_dir_path = os.path.join(args.statedir, DOMAINROOTS_DIR_PATH)

    ret = do_clean(domainroots_dir_path, args.force)
    if ret != EXIT_SUCCESS:
        return ret

    if not args.force:
        print('Successfully cleaned FedFS domain root infrastructure')
    return EXIT_SUCCESS


__all__ = ['subcmd_clean']
