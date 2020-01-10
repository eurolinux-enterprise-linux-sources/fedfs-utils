"""
Utility functions for PyFedfs
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

    from PyFedfs.run import EXIT_SUCCESS, EXIT_FAILURE
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)


def change_mode(pathname, mode):
    """
    Change permission on a local file

    Returns a shell exit status value
    """
    log.debug('Changing mode bits on "%s"...', pathname)

    ret = EXIT_FAILURE
    try:
        os.chmod(pathname, mode)
        ret = EXIT_SUCCESS
    except OSError:
        log.error('Failed to chmod "%s"', pathname)

    return ret


def list_directory(pathname):
    """
    List all entries but 'lost+found'

    Returns a list containing one entry for each item in "pathname"
    """
    log.debug('Listing directory "' + pathname + '"...')

    try:
        output = os.listdir(pathname)
    except OSError as inst:
        log.error('Failed to list "%s": %s', pathname, inst)
        return []

    return [x for x in output if x != 'lost+found']


def remove_directory(pathname, force=False):
    """
    Remove a local directory

    Returns a shell exit status value
    """
    log.debug('Removing directory "%s"...', pathname)

    ret = EXIT_FAILURE
    try:
        os.rmdir(pathname)
        ret = EXIT_SUCCESS
    except OSError:
        if not force:
            log.error('Failed to remove "%s"', pathname)

    if force:
        return EXIT_SUCCESS
    return ret


def make_directory(pathname, mode):
    """
    Create a local directory

    Returns a shell exit status value
    """
    if os.path.isdir(pathname):
        log.debug('Directory "%s" exists', pathname)
        return EXIT_SUCCESS

    log.debug('Creating directory "%s"...', pathname)

    try:
        os.mkdir(pathname)
    except OSError:
        log.error('Failed to create "%s"', pathname)
        return EXIT_FAILURE

    ret = change_mode(pathname, mode)
    if ret != EXIT_SUCCESS:
        log.error('Failed to chmod "%s"', pathname)
        os.rmdir(pathname)
        return EXIT_FAILURE

    return EXIT_SUCCESS


__all__ = ['make_directory', 'list_directory', 'remove_directory',
           'change_mode']

if __name__ == '__main__':
    log.basicConfig(format='%(levelname)s: %(message)s', level=log.DEBUG)

    list_directory('/tmp')
    list_directory('/bogus')

    make_directory('/tmp/__ut__', 0755)
    make_directory('/tmp/__ut__', 0755)
    remove_directory('/tmp/__ut__')
    remove_directory('/tmp/__ut__')

    make_directory('/tmp/__ut_chmod__', 0700)
    change_mode('/tmp/__ut_chmod__', 0755)
    remove_directory('/tmp/__ut_chmod__')
