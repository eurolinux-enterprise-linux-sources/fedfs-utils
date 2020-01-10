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

    from PyFedfs.domainroot.paths import DOMAINROOT_PATH
    from PyFedfs.domainroot.exports import display_export

    from PyFedfs.run import EXIT_SUCCESS
    from PyFedfs.run import check_for_daemon
    from PyFedfs.utilities import list_directory
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)


# pylint: disable-msg=W0613
def subcmd_status(args):
    """
    The 'display status' subcommand

    Returns a shell exit status value
    """
    if not check_for_daemon('nfsd'):
        print('NFSD is not running')
        return EXIT_SUCCESS

    output = list_directory(DOMAINROOT_PATH)
    if len(output):
        print('FedFS domain roots:')
        for item in output:
            display_export(os.path.join(DOMAINROOT_PATH, item))
    else:
        print('FedFS domain roots:  None')

    return EXIT_SUCCESS


__all__ = ['subcmd_status']
