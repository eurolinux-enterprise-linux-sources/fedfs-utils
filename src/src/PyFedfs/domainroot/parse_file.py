"""
Parse a text file into a list of lists
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

import logging as log


def parse_file(pathname):
    """
    Read a configuration file into a list of lists

    I could use the csv module for this, but some files may contain
    interspersed blanks and tabs, which csv does not handle.
    Can't use augeas, as some files aren't under /etc.

    Returns a list containing each line in "pathname".
    Each line is parsed into a list of the line's fields.
    """
    try:
        file_object = open(pathname, 'r')
    except OSError as inst:
        log.debug('Failed to open "%s": %s', pathname, inst)
        return []

    ret = []
    try:
        for line in file_object:
            stripped = line.strip()
            if len(stripped):
                items = stripped.split()
                if items[0][0] != '#':
                    ret.append(items)
    finally:
        file_object.close()

    return ret
