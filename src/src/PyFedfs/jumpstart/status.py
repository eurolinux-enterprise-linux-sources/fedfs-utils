"""
Set up a simple FedFS NSDB using OpenLDAP
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

    from PyFedfs.jumpstart.slapd import get_slapd_status
    from PyFedfs.jumpstart.slapd import check_ldap_connectivity
    from PyFedfs.jumpstart.slapd import local_nce_found, local_tls_found

    from PyFedfs.run import EXIT_SUCCESS
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)


# pylint: disable-msg=W0613
def subcmd_status(args):
    """
    Display the status of the local LDAP/NSDB service

    Returns a shell exit status value
    """
    if not os.path.isdir('/etc/openldap'):
        log.info('OpenLDAP is not installed on this system')
        return EXIT_SUCCESS

    log.info(get_slapd_status())

    if check_ldap_connectivity():
        log.info('Local LDAP service is reachable')
    else:
        log.info('Unable to contact local LDAP service')

    if not os.path.isfile('/var/log/slapd'):
        log.info('Slapd logging is not configured')

    if not os.path.isfile('/etc/openldap/schema/fedfs.schema'):
        log.info('The FedFS schema file is not installed')
        return EXIT_SUCCESS

    if local_nce_found():
        log.info('Local server is an NSDB')
    else:
        log.info('Local server is not an NSDB')

    if local_tls_found():
        log.info('TLS is enabled')
    else:
        log.info('TLS is not enabled')

    return EXIT_SUCCESS


__all__ = ['subcmd_status']
