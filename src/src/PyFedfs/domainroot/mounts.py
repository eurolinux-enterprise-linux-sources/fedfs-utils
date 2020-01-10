"""
Manage local mounts
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

    from PyFedfs.domainroot.parse_file import parse_file

    from PyFedfs.run import EXIT_SUCCESS, EXIT_FAILURE
    from PyFedfs.run import run_command
    from PyFedfs.utilities import change_mode
    from PyFedfs.utilities import make_directory, remove_directory
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)


def filesystem_is_mounted(pathname):
    """
    Predicate: is filesystem mounted?

    Returns True if "pathname" is mounted, otherwise returns False
    """
    mounts = parse_file('/proc/mounts')
    for mount in mounts:
        if mount[1] == pathname:
            return True
    return False


def add_fstab_entry(devicepath, mounted_on, fs_type):
    """
    Add entry to /etc/fstab

    Returns a shell exit status value
    """
    log.debug('Adding entry for "%s" to /etc/fstab...', devicepath)

    config = augeas.augeas()

    config.set('/files/etc/fstab/01/spec', devicepath)
    config.set('/files/etc/fstab/01/file', mounted_on)
    config.set('/files/etc/fstab/01/vfstype', fs_type)
    if fs_type == 'bind':
        config.set('/files/etc/fstab/01/opt', 'bind')
    else:
        config.set('/files/etc/fstab/01/opt', 'defaults')
    config.set('/files/etc/fstab/01/dump', '1')
    config.set('/files/etc/fstab/01/passno', '2')

    ret = EXIT_SUCCESS
    try:
        config.save()
    except IOError:
        log.exception('Failed to save /etc/fstab')
        ret = EXIT_FAILURE

    config.close()

    return ret


def fstab_contains_entry(pathname):
    """
    Predicate: does /etc/fstab contain an entry for "pathname" ?

    Returns True if /etc/fstab contains an entry for "pathname"
    otherwise returns False
    """
    config = augeas.augeas()
    path = '/files/etc/fstab/*[file="' + pathname + '"]'
    fstab = config.match(path)
    config.close()
    if len(fstab):
        return True
    return False


def remove_fstab_entry(pathname, force):
    """
    Remove an entry from /etc/fstab

    Returns a shell exit status value
    """
    log.debug('Removing entry for "%s" from /etc/fstab...', pathname)

    ret = EXIT_FAILURE
    config = augeas.augeas()

    path = '/files/etc/fstab/*[file="' + pathname + '"]'
    matches = config.match(path)
    if len(matches) == 1:
        config.remove(matches[0])
        config.save()
        ret = EXIT_SUCCESS
    else:
        if not force:
            log.error('No entry for "%s" in /etc/fstab', pathname)

    config.close()

    if force:
        return EXIT_SUCCESS
    return ret


def add_mount(pathname, mounted_on, fs_type):
    """
    Add a mount point

    Returns a shell exit status value
    """
    ret = add_fstab_entry(pathname, mounted_on, fs_type)
    if ret != EXIT_SUCCESS:
        return ret

    ret = make_directory(mounted_on, 0755)
    if ret != EXIT_SUCCESS:
        return ret

    ret = run_command(['mount', mounted_on], False)
    if ret != EXIT_SUCCESS:
        return EXIT_FAILURE

    return change_mode(mounted_on, 0755)


def remove_mount(pathname, force):
    """
    Remove a mount

    Returns a shell exit status value
    """
    ret = run_command(['umount', pathname], force)
    if ret != EXIT_SUCCESS:
        return ret

    ret = remove_directory(pathname, force)
    if ret != EXIT_SUCCESS:
        return ret

    ret = remove_fstab_entry(pathname, force)
    if ret != EXIT_SUCCESS:
        return ret

    return EXIT_SUCCESS
