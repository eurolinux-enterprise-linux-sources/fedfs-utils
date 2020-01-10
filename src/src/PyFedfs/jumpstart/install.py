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


import sys
import os
import logging as log
import socket
import ldap

try:
    from PyFedfs.jumpstart.cert import create_self_signed_certificate
    from PyFedfs.jumpstart.firewall import adjust_firewall
    from PyFedfs.jumpstart.slapd import slapd_config, adjust_slapd_log
    from PyFedfs.jumpstart.slapd import LDAP_UID, LDAP_GID
    from PyFedfs.jumpstart.slapd import NSDB_CERTFILE, NSDB_KEYFILE
    from PyFedfs.jumpstart.transaction import Transaction

    from PyFedfs.run import EXIT_SUCCESS, EXIT_FAILURE
    from PyFedfs.run import stop_service, enable_and_start_service
    from PyFedfs.userinput import confirm, get_password
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)


PRESERVE_LIST = ['/etc/openldap/slapd.d',
                 NSDB_CERTFILE,
                 NSDB_KEYFILE]


def get_domainname():
    """
    Get local system's domain name

    Returns a string
    """
    hostname = socket.getfqdn().split('.')
    if len(hostname) < 2:
        return ''

    domainname = '.'.join(hostname[1:])
    return domainname.lower()


def get_domaincontroller_dn(domainname):
    """
    Generate a domaincontroller DN

    Returns a string
    """
    components = domainname.split('.')
    if len(components) < 2:
        return ''

    distinguished_name = [[('dc', component, 1)] for component in components]
    return ldap.dn.dn2str(distinguished_name)


def get_nce_dn(domaincontroller):
    """
    Generate an NCE DN

    Returns a string
    """
    try:
        distinguished_name = ldap.dn.str2dn(domaincontroller)
    except ldap.ENCODING_ERROR:
        return ''

    distinguished_name.insert(0, [('ou', 'fedfs', 1)])
    return ldap.dn.dn2str(distinguished_name)


def get_full_nsdb_admin(answers):
    """
    Generate NSDB administrator DN

    Returns a string
    """
    try:
        distinguished_name = ldap.dn.str2dn(answers['domaincontroller'])
    except ldap.ENCODING_ERROR:
        return ''

    distinguished_name.insert(0, ldap.dn.str2dn(answers['nsdb_admin'])[0])
    return ldap.dn.dn2str(distinguished_name)


def ask_for_domainname(answers):
    """
    Ask for the system's domain name

    Returns True if the interview data is good
    """
    answers['domainname'] = get_domainname()
    print('Enter the name of the FedFS domain this NSDB will server')
    if answers['domainname'] == []:
        sys.stdout.write('FedFS domain: ')
        choice = raw_input().lower()
        if choice == '':
            log.error('No domainname was provided')
            return False
        answers['domainname'] = choice
    else:
        sys.stdout.write('FedFS domain [ ' + answers['domainname'] + ' ]: ')
        choice = raw_input().lower()
        if choice != '':
            answers['domainname'] = choice
    return True


def ask_for_domaincontroller(answers):
    """
    Ask for the domain controller DN

    Returns True if the interview data is good
    """
    answers['domaincontroller'] = \
        get_domaincontroller_dn(answers['domainname'])
    if answers['domaincontroller'] == '':
        log.error('An invalid domainname was provided')
        return False
    answers['nce'] = get_nce_dn(answers['domaincontroller'])
    if answers['nce'] == '':
        log.error('An invalid domainname was provided')
        return False
    log.info('Using "%s" as your FedFS domain name', answers['domainname'])
    return True


def ask_for_ldap_admin(answers):
    """
    Ask for the LDAP administrator DN and password

    Returns True if the interview data is good
    """
    answers['ldap_admin'] = \
        ldap.dn.dn2str([[('cn', 'admin', 1)], [('cn', 'config', 1)]])
    print('Enter the LDAP administrator DN for this NSDB')
    sys.stdout.write('Admin DN [ ' + answers['ldap_admin'] + ' ]: ')
    choice = raw_input()
    if choice != '':
        answers['ldap_admin'] = choice
    try:
        ldap.dn.str2dn(choice)
    except ldap.DECODING_ERROR:
        log.error('An invalid administrator DN was provided')
        return False
    log.info('Using "%s" as your LDAP administrator', answers['ldap_admin'])

    answers['ldap_password'] = \
        get_password('Enter the LDAP administrator password for this DN')
    if answers['ldap_password'] == '':
        return False

    return True


def ask_for_nsdb_admin(answers):
    """
    Ask for the NSDB administrator DN and password

    Returns True if the interview data is good
    """
    answers['nsdb_admin'] = 'cn=NSDB Manager'
    answers['full_nsdb_admin'] = get_full_nsdb_admin(answers)
    if answers['full_nsdb_admin'] == '':
        return False
    log.info('Using "%s" as your NSDB administrator',
             answers['full_nsdb_admin'])

    answers['nsdb_password'] = \
        get_password('Enter the NSDB administrator password for this DN')
    if answers['nsdb_password'] == '':
        return False

    return True


def interview(answers):
    """
    Gather information for the configuration, perform some sanity checks

    Returns True if the interview data is good
    """
    if not ask_for_domainname(answers):
        return False
    if not ask_for_domaincontroller(answers):
        return False
    if not ask_for_ldap_admin(answers):
        return False
    if not ask_for_nsdb_admin(answers):
        return False
    return True


def setup_nsdb(answers):
    """
    Run the set-up procedure

    Returns a shell exit status value
    """

    ret = slapd_config(answers)
    if ret != EXIT_SUCCESS:
        return ret

    ret = adjust_slapd_log()
    if ret != EXIT_SUCCESS:
        return ret

    return adjust_firewall()


def abort_command(xact):
    """
    Print a message and return failure

    Returns a shell exit status value
    """
    xact.revert()

    log.info('Command aborted')
    return EXIT_FAILURE


def do_setup(answers):
    """
    Interview user for configuration parameters, then run the setup

    Returns a shell exit status value
    """
    print('Last chance: about to replace the OpenLDAP configuration '
          'on this system.')
    if not confirm('Continue?'):
        log.error('Quitting...')
        return EXIT_FAILURE

    xact = Transaction()
    for item in answers['preserve_list']:
        xact.add(item)
    xact.checkpoint()

    ret = stop_service('slapd')
    if ret != EXIT_SUCCESS:
        return abort_command(xact)

    ret = setup_nsdb(answers)
    if ret != EXIT_SUCCESS:
        return abort_command(xact)

    if answers['security'] == 'tls':
        ret = create_self_signed_certificate(NSDB_CERTFILE, NSDB_KEYFILE,
                                             LDAP_UID, LDAP_GID)
        if ret != EXIT_SUCCESS:
            return abort_command(xact)

    enable_and_start_service('slapd')

    log.info('\nNSDB configuration was successful.\n')
    log.info('Slapd is enabled and running')
    log.info('The LDAP administrator DN is: ' + answers['ldap_admin'])
    log.info('The NSDB administrator DN is: ' + answers['full_nsdb_admin'])
    log.info('The NCE is: ' + answers['nce'])
    if answers['security'] == 'tls':
        log.info('Distribute the certificate in %s', NSDB_CERTFILE)

    xact.commit()

    return EXIT_SUCCESS


def openldap_is_installed():
    """
    Predicate: Is an OpenLDAP server package installed?

    Returns True if OpenLDAP server software is found;
    otherwise returns False
    """
    if not os.path.isdir('/etc/openldap'):
        log.error('No OpenLDAP configuration directory')
        return False

    if not os.path.isfile('/etc/openldap/schema/fedfs.schema'):
        log.error('The FedFS schema is not installed')
        return False

    log.info('OpenLDAP server software found, proceeding')
    return True


def subcmd_install(args):
    """
    Set up local LDAP server as NSDB based on interview responses

    Returns a shell exit status value
    """
    if not openldap_is_installed():
        log.error('Quitting...')
        return EXIT_FAILURE

    print('This command replaces the OpenLDAP configuration on this system.')
    if not confirm('Do you want to continue?'):
        log.error('Quitting...')
        return EXIT_FAILURE

    backend_dir = os.path.join(args.statedir, 'nsdb-db')
    answers = {'security': args.security, 'dc_backend': backend_dir}

    if not interview(answers):
        log.error('Quitting...')
        return EXIT_FAILURE

    answers['preserve_list'] = PRESERVE_LIST
    answers['preserve_list'].append(backend_dir)

    return do_setup(answers)


__all__ = ['subcmd_install']
