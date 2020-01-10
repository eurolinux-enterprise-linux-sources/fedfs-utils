"""
Manage local network firewall
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
    from subprocess import Popen, PIPE

    from PyFedfs.run import EXIT_SUCCESS, EXIT_FAILURE
    from PyFedfs.run import run_command
    from PyFedfs.run import check_for_daemon
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)


def adjust_firewall():
    """
    Ensure LDAP (port 389) is allowed through the system firewall

    Returns a shell exit status value
    """
    if not check_for_daemon('firewalld'):
        log.info('firewalld is not running... skipping firewalld configuration')
        return EXIT_SUCCESS

    pathname = '/etc/firewalld/services/ldap.xml'
    if os.path.isfile(pathname):
        log.info('ldap.xml exists... skipping firewalld configuration')
        return EXIT_SUCCESS

    log.debug('Adjusting firewalld to permit LDAP service...')
    try:
        service = os.open(pathname, os.O_CREAT | os.O_WRONLY)
    except OSError:
        log.exception('Failed to create "%s"', pathname)
        return EXIT_FAILURE

    try:
        os.fchmod(service, 0640)
        os.write(service, '<?xml version="1.0" encoding="utf-8"?>\n')
        os.write(service, '<?xml version="1.0" encoding="utf-8"?>\n')
        os.write(service, '<service>\n')
        os.write(service, '  <short>LDAP</short>\n')
        os.write(service, '  <description>The Lightweight Directory '
                 'Access Protocol is an application protocol for '
                 'accessing and maintaining distributed directory '
                 'information services over an Internet Protocol (IP) '
                 'network.  Directory services may provide any '
                 'organized set of records, often with a hierarchical '
                 'structure, such as a corporate email directory.  '
                 'Enable this option if you plan to provide an LDAP '
                 'directory service (e.g. with slapd).</description>\n')
        os.write(service, '  <port protocol="tcp" port="389"/>\n')
        os.write(service, '  <port protocol="udp" port="389"/>\n')
        os.write(service, '</service>\n')
    except OSError:
        log.exception('Failed to write "%s"', pathname)
        os.close(service)
        os.remove('/etc/firewalld/services/ldap.xml')
        return EXIT_FAILURE
    os.close(service)

    ret = run_command(['firewall-cmd', '--reload'])
    if ret != EXIT_SUCCESS:
        os.remove('/etc/firewalld/services/ldap.xml')
        return ret

    # XXX: These are backwards: need the --reload after
    # XXX: setting permanent configuration settings
    return run_command(['firewall-cmd', '--permanent',
                        '--zone=public', '--add-service=ldap'])


__all__ = ['adjust_firewall']
