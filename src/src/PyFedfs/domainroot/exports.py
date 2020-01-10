"""
Manage NFS exports
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
    import logging as log
    import augeas
    import uuid

    from PyFedfs.domainroot.parse_file import parse_file

    from PyFedfs.run import EXIT_SUCCESS, EXIT_FAILURE
    from PyFedfs.run import run_command
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)


def filesystem_is_exported(pathname):
    """
    Predicate: is filesystem exported?

    Returns True if "pathname" is exported, otherwise returns False
    """
    exports = parse_file('/var/lib/nfs/etab')
    for export in exports:
        if export[0] == pathname:
            return True
    return False


def add_exports_entry(pathname):
    """
    Add entry to /etc/exports

    Returns a shell exit status value
    """
    log.debug('Adding entry for "%s" to /etc/exports...', pathname)

    config = augeas.augeas()

    config.set('/files/etc/exports/dir[last()+1]', pathname)
    config.set('/files/etc/exports/dir[last()]/client[1]', '*')
    config.set('/files/etc/exports/dir[last()]/client[1]/option[1]',
               'ro')
    config.set('/files/etc/exports/dir[last()]/client[1]/option[2]',
               'subtree_check')
    config.set('/files/etc/exports/dir[last()]/client[1]/option[3]',
               'insecure')
    config.set('/files/etc/exports/dir[last()]/client[1]/option[4]',
               'sec=sys:none')
    config.set('/files/etc/exports/dir[last()]/client[1]/option[5]',
               'fsid=' + str(uuid.uuid4()))

    ret = EXIT_SUCCESS
    try:
        config.save()
    except IOError:
        log.exception('Failed to save /etc/exports')
        ret = EXIT_FAILURE

    config.close()

    return ret


def exports_contains_entry(pathname):
    """
    Predicate: does /etc/exports contain an entry for "pathname" ?

    Returns True if /etc/exports contains an entry for "pathname"
    otherwise returns False
    """
    config = augeas.augeas()
    path = '/files/etc/exports/dir[.="' + pathname + '"]'
    exports = config.match(path)
    config.close()
    if len(exports):
        return True
    return False


def remove_exports_entry(pathname, force):
    """
    Remove an entry from /etc/exports

    Returns a shell exit status value
    """
    log.debug('Removing entry for "%s" from /etc/exports...', pathname)

    ret = EXIT_FAILURE
    config = augeas.augeas()

    path = '/files/etc/exports/dir[.="' + pathname + '"]'
    matches = config.match(path)
    if len(matches) == 1:
        config.remove(matches[0])
        config.save()
        ret = EXIT_SUCCESS
    else:
        if not force:
            log.error('No entry for "%s" in /etc/exports', pathname)

    config.close()

    if force:
        return EXIT_SUCCESS
    return ret


def add_export(pathname):
    """
    Add an export

    Returns a shell exit status value
    """
    ret = add_exports_entry(pathname)
    if ret != EXIT_SUCCESS:
        return ret

    return run_command(['exportfs', '*:' + pathname], False)


def display_export(pathname):
    """
    Display the status of a domain root export

    Returns no value
    """
    exports = parse_file('/var/lib/nfs/etab')
    for export in exports:
        if export[0] == pathname:
            print('\t"%s" is exported with options' % export[0])
            print('\t\t%s' % export[1])
            break
    else:
        print('\t"%s" is not exported' % pathname)


def remove_export(pathname, force):
    """
    Remove an export

    Returns a shell exit status value
    """
    ret = run_command(['exportfs', '-u', '*:' + pathname], force)
    if ret != EXIT_SUCCESS:
        return ret

    ret = remove_exports_entry(pathname, force)
    if ret != EXIT_SUCCESS:
        return ret

    return EXIT_SUCCESS
