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
    from PyFedfs.domainroot.mounts import add_mount, remove_mount
    from PyFedfs.domainroot.exports import add_export, remove_export

    from PyFedfs.run import EXIT_SUCCESS, EXIT_FAILURE
    from PyFedfs.run import check_for_daemon
    from PyFedfs.userinput import confirm
    from PyFedfs.utilities import make_directory, list_directory
    from PyFedfs.utilities import remove_directory
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)


def prepare_domainroot(domainroots_dir_path):
    """
    Ensure domainroot infrastructure is set up

    Returns a shell exit status value
    """

    try:
        os.mkdir(DOMAINROOT_PATH)
    except OSError as inst:
        if inst.errno != 17:
            log.exception('Failed to make directory "%s"',
                          DOMAINROOT_PATH)
            return EXIT_FAILURE

    parent = os.path.dirname(domainroots_dir_path)
    if not os.path.isdir(parent):
        log.error('"%s" does not exist', parent)
        return EXIT_FAILURE

    try:
        os.mkdir(domainroots_dir_path)
    except OSError as inst:
        if inst.errno != 17:
            log.exception('Failed to make directory "%s"',
                          domainroots_dir_path)
            return EXIT_FAILURE

    return EXIT_SUCCESS


def do_add(export_pathname, bind_pathname):
    """
    Add a domain root directory

    Returns a shell exit status value
    """
    ret = make_directory(bind_pathname, 0755)
    if ret != EXIT_SUCCESS:
        return ret

    ret = add_mount(bind_pathname, export_pathname, 'bind')
    if ret != EXIT_SUCCESS:
        return ret

    return add_export(export_pathname)


def do_remove(export_pathname, bind_pathname, force):
    """
    Remove a domain root directory

    Returns a shell exit status value
    """
    ret = remove_export(export_pathname, force)
    if ret != EXIT_SUCCESS:
        return ret

    ret = remove_mount(export_pathname, force)
    if ret != EXIT_SUCCESS:
        return ret

    ret = remove_directory(bind_pathname, force)
    if ret != EXIT_SUCCESS:
        return ret

    return EXIT_SUCCESS


# No verification of the domain argument is done.  A DNS SRV lookup
# would be surest, but that would require the SRV record exist a
# priori... Otherwise we'd need to regular expression of some kind
# that can match both ASCII and IDNA hostnames but not IP addresses.
def subcmd_add(args):
    """
    The 'add domain' subcommand

    Returns a shell exit status value
    """
    domainroots_dir_path = os.path.join(args.statedir, DOMAINROOTS_DIR_PATH)

    ret = prepare_domainroot(domainroots_dir_path)
    if ret != EXIT_SUCCESS:
        return ret

    if not check_for_daemon('nfsd'):
        log.warn('NFSD is not running')

    export_pathname = os.path.join(DOMAINROOT_PATH, args.domainname)
    bind_pathname = os.path.join(domainroots_dir_path, args.domainname)

    ret = do_add(export_pathname, bind_pathname)
    if ret != EXIT_SUCCESS:
        do_remove(export_pathname, bind_pathname, True)
        return ret

    print('Added domain root for FedFS domain "%s"' % args.domainname)
    return EXIT_SUCCESS


def subcmd_remove(args):
    """
    The 'remove domain' subcommand

    Returns a shell exit status value
    """
    domainroots_dir_path = os.path.join(args.statedir, DOMAINROOTS_DIR_PATH)

    export_pathname = os.path.join(DOMAINROOT_PATH, args.domainname)
    bind_pathname = os.path.join(domainroots_dir_path, args.domainname)

    if not args.force:
        items = list_directory(bind_pathname)
        if len(items):
            log.error('The domain root directory is not empty')
            return EXIT_FAILURE
        print('This tool will remove the domain root directory ' \
              'for the "%s" domain' % args.domainname)
        if not confirm('Do you want to continue? [y/N] '):
            print('Command aborted')
            return EXIT_FAILURE

    ret = do_remove(export_pathname, bind_pathname, args.force)
    if ret != EXIT_SUCCESS:
        return ret

    if not args.force:
        print('Removed domain root for FedFS domain "%s"' % args.domainname)
    return EXIT_SUCCESS


__all__ = ['subcmd_add', 'subcmd_remove']
