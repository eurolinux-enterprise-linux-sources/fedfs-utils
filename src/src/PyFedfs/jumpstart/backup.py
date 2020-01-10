"""
Back up an OpenLDAP-based FedFS NSDB
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
    import datetime

    from PyFedfs.jumpstart.slapd import backup_slapd_backend
    from PyFedfs.jumpstart.slapd import make_ldap_directory
    from PyFedfs.jumpstart.slapd import get_slapd_backend_dir
    from PyFedfs.jumpstart.slapd import restore_slapd_backend
    from PyFedfs.jumpstart.transaction import Transaction

    from PyFedfs.run import EXIT_SUCCESS, EXIT_FAILURE
    from PyFedfs.run import start_service, stop_service
    from PyFedfs.userinput import confirm
    from PyFedfs.utilities import list_directory
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)

BACKUP_DIRNAME = 'nsdb-backup'


def do_backup(backup_dir, nocompress):
    """
    Backup the local NSDB

    Returns a shell exit status
    """
    ret = stop_service('slapd')
    if ret != EXIT_SUCCESS:
        return ret

    ret = backup_slapd_backend(backup_dir,
                               datetime.datetime.now().strftime("%F-%T"),
                               nocompress)
    if ret != EXIT_SUCCESS:
        return ret

    ret = start_service('slapd')
    if ret != EXIT_SUCCESS:
        return ret

    return EXIT_SUCCESS


def subcmd_backup(args):
    """
    Run the backup procedure

    Returns a shell exit status
    """
    backup_dir = os.path.join(args.statedir, BACKUP_DIRNAME)

    ret = make_ldap_directory(backup_dir, 0700)
    if ret != EXIT_SUCCESS:
        return ret

    log.info('Running NSDB backup...')

    os.umask(0277)
    ret = do_backup(backup_dir, args.nocompress)
    if ret != EXIT_SUCCESS:
        log.info('Command aborted')
        return EXIT_FAILURE
    return EXIT_SUCCESS


def list_backups(args):
    """
    List available backups

    Returns a shell exit status
    """
    backup_dir = os.path.join(args.statedir, BACKUP_DIRNAME)

    listing = list_directory(backup_dir)

    output = []
    for item in listing:
        if item.endswith('.ldif'):
            output.append(item[:-5])
        if item.endswith('.ldif.gz'):
            output.append(item[:-8])

    if len(output) == 0:
        log.info('No backups are available')
        return EXIT_SUCCESS

    log.info('Listing NSDB backups...')
    for line in list(set(output)):
        log.info(line)

    return EXIT_SUCCESS


def preserve_and_restore(args):
    """
    Restore the local NSDB

    Returns a shell exit status
    """
    backend_dir = get_slapd_backend_dir()
    if backend_dir == '':
        log.error('Failed to find local NSDB\'s backend database')
        return EXIT_FAILURE
    log.info('NSDB backend database: %s', backend_dir)

    xact = Transaction()
    xact.add(backend_dir)
    xact.checkpoint()

    backup_dir = os.path.join(args.statedir, BACKUP_DIRNAME)
    ret = restore_slapd_backend(backend_dir, backup_dir, args.backup)
    if ret != EXIT_SUCCESS:
        xact.revert()
        return EXIT_FAILURE

    xact.commit()
    return EXIT_SUCCESS


def do_restore(args):
    """
    Restore the local NSDB

    Returns a shell exit status
    """
    ret = stop_service('slapd')
    if ret != EXIT_SUCCESS:
        return ret

    ret = preserve_and_restore(args)
    if ret != EXIT_SUCCESS:
        return ret

    return start_service('slapd')


def subcmd_restore(args):
    """
    Run the backup procedure

    Returns a shell exit status
    """
    if args.backup == '':
        return list_backups(args)

    print('This command replaces all the NSDB information on this system.')
    if not confirm('Do you want to continue?'):
        log.error('Quitting...')
        return EXIT_FAILURE

    log.info('Restoring NSDB...')

    if do_restore(args) != EXIT_SUCCESS:
        log.info('Command aborted')
        return EXIT_FAILURE
    return EXIT_SUCCESS


__all__ = ['subcmd_backup', 'subcmd_restore']
