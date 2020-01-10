"""
Utility functions for interacting with slapd tools
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
import tempfile
import pwd
import grp
import ldap
import ldif
import socket

from subprocess import Popen, PIPE

try:
    from PyFedfs.run import EXIT_SUCCESS, EXIT_FAILURE
    from PyFedfs.run import run_as_user, restart_service
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)


LDAP_USERNAME = 'ldap'
LDAP_GROUPNAME = 'ldap'

LDAP_UID = pwd.getpwnam(LDAP_USERNAME).pw_uid
LDAP_GID = grp.getgrnam(LDAP_GROUPNAME).gr_gid

NSDB_CERTFILE = '/etc/openldap/nsdb-cert.pem'
NSDB_KEYFILE = '/etc/openldap/nsdb-key.pem'


def adjust_slapd_log():
    """
    Set up syslog configuration for slapd
    slapd must be restarted after this procedure.

    Returns a shell exit status value
    """
    try:
        logfile = os.open('/var/log/slapd', os.O_CREAT | os.O_EXCL)
    except OSError as inst:
        if inst.errno != 17:
            log.error('Failed to create slapd log file')
            return EXIT_FAILURE
        log.info('/var/log/slapd exists... skipping rsyslog configuration')
        return EXIT_SUCCESS
    os.close(logfile)

    log.debug('Enabling slapd logging with rsyslog...')
    try:
        os.chown('/var/log/slapd', LDAP_UID, LDAP_GID)
    except OSError:
        log.error('Failed to chown slapd log file')
        os.remove('/var/log/slapd')
        return EXIT_FAILURE

    try:
        config = os.open('/etc/rsyslog.d/slapd.conf',
                         os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except OSError:
        log.error('Failed to create slapd log file')
        os.remove('/var/log/slapd')
        return EXIT_FAILURE

    try:
        os.write(config, 'local4.*\t/var/log/slapd\n')
    except OSError:
        log.error('Failed to write rsyslog config file')
        os.close(config)
        os.remove('/etc/rsyslog.d/slapd.conf')
        os.remove('/var/log/slapd')
        return EXIT_FAILURE
    os.close(config)

    ret = restart_service('rsyslog')
    if ret != EXIT_SUCCESS:
        os.remove('/etc/rsyslog.d/slapd.conf')
        os.remove('/var/log/slapd')

    return ret


def search_ldif(blob, attribute):
    """
    Look for 'attribute' in an LDIF

    Returns the first attribute value if found, or '' if not
    """
    for line in blob.splitlines():
        record = line.split()
        if len(record) and record[0] == attribute + ':':
            return record[1]
    return ''


def local_nce_found():
    """
    Predicate: Does the local configuration contain an NCE record?

    Returns True if an NCE record is found in a local LDAP database
    """
    log.debug('Checking local configuration for an NCE record...')

    try:
        process = Popen(['slapcat', '-n2'],
                        stdout=PIPE, stderr=PIPE, shell=False)
        output = process.communicate()[0]
    except OSError:
        log.error('slapcat command failed')
        return False

    return search_ldif(output, 'fedfsNceDN') != ''


def __ut_local_nce_found():
    """
    Unit test for local_nce_found()
    """
    if local_nce_found():
        print 'Local NCE found'
    else:
        print 'Local NCE not found'


def local_tls_found():
    """
    Predicate: Is TLS enabled on the local configuration?

    Returns True if TLS is enabled
    """
    log.debug('Checking local configuration for TLS support...')
    try:
        process = Popen(['slapcat', '-n0'],
                        stdout=PIPE, stderr=PIPE, shell=False)
        output = process.communicate()[0]
    except OSError:
        log.error('slapcat command failed')
        return False

    return search_ldif(output, 'olcTLSCACertificateFile') != ''


def __ut_local_tls_found():
    """
    Unit test for local_tls_found()
    """
    if local_tls_found():
        print 'TLS is configured on local slapd service'
    else:
        print 'TLS is not configured on local slapd service'


def get_slapd_backend_dir():
    """
    Get the directory pathname of the configured backend database

    Returns a string
    """
    log.debug('Retrieving pathname of configured backend database...')

    try:
        process = Popen(['slapcat', '-n0'],
                        stdout=PIPE, stderr=PIPE, shell=False)
        output = process.communicate()[0]
    except OSError:
        log.error('slapcat command failed')
        return False

    return search_ldif(output, 'olcDbDirectory')


def __ut_get_slapd_backend_dir():
    """
    Unit test for get_slapd_backend_dir()
    """
    print get_slapd_backend_dir()


def get_slapd_status():
    """
    Display status of local LDAP service on standard out

    Returns a string
    """
    process = Popen(['systemctl', 'status', 'slapd.service'],
                    stdout=PIPE, stderr=PIPE, shell=False)
    return process.communicate()[0]


def __ut_get_slapd_status():
    """
    Unit test for get_slapd_status()
    """
    print get_slapd_status()


def check_ldap_connectivity():
    """
    Predicate: Can a basic LDAP query be performed on the local LDAP server?

    Returns True if yes, otherwise False is returned
    """
    ldap_server = ldap.initialize('ldap://' + socket.getfqdn())
    try:
        ldap_server.search_s('', ldap.SCOPE_BASE, '(objectClass=*)')
    except ldap.CONFIDENTIALITY_REQUIRED:
        log.debug('Local LDAP server requires TLS confidentiality')
        return True
    except ldap.SERVER_DOWN:
        log.debug('Local LDAP server is unreachable')
        return False
    except ldap.NO_SUCH_OBJECT:
        log.debug('Local LDAP server contains no rootDSE')
        return False
    return True


def __ut_check_ldap_connectivity():
    """
    Unit test for check_ldap_connectivity()
    """
    if check_ldap_connectivity():
        print 'Able to contact local LDAP server'
    else:
        print 'Not able to contact local LDAP server'


def temporary_ldap_file():
    """
    Create a temporary file owned by the ldap user

    Returns a file-like object or None
    """
    try:
        result = tempfile.NamedTemporaryFile(mode='w',
                                             dir='/tmp',
                                             delete=True)
        os.chown(result.name, LDAP_UID, LDAP_GID)
    except OSError:
        return None
    return result


def make_ldap_directory(pathname, mode=0755):
    """
    Create a directory owned by the ldap user

    Returns a shell exit status value
    """
    if os.path.isdir(pathname):
        log.info('Directory "%s" already exists', pathname)
        return EXIT_SUCCESS

    try:
        os.mkdir(pathname)
        os.chmod(pathname, mode)
        os.chown(pathname, LDAP_UID, LDAP_GID)
    except OSError:
        log.error('Failed to create "%s"', pathname)
        return EXIT_FAILURE
    return EXIT_SUCCESS


def wipe_slapd_d():
    """
    Clean out the slapd.d directory
    slapd must be stopped for this procedure.

    Returns a shell exit status value
    """
    log.debug('Cleaning out "/etc/openldap/"...')

    ret = make_ldap_directory('/etc/openldap/slapd.d')
    if ret != EXIT_SUCCESS:
        return ret

    try:
        if os.path.isfile(NSDB_CERTFILE):
            os.remove(NSDB_CERTFILE)
        if os.path.isfile(NSDB_KEYFILE):
            os.remove(NSDB_KEYFILE)
    except OSError:
        log.error('Failed to remove old certificates')
        return EXIT_FAILURE

    return EXIT_SUCCESS


def replace_slapd_database(pathname):
    """
    Replace the contents of the back-end database
    slapd must be stopped for this procedure.

    Returns a shell exit status value
    """
    log.debug('Replacing "%s"...', pathname)

    ret = make_ldap_directory(pathname, 0700)
    if ret != EXIT_SUCCESS:
        return ret

    try:
        dbconfig = os.open(os.path.join(pathname, 'DB_CONFIG'),
                           os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0444)
    except OSError:
        log.error('Failed to create DB_CONFIG')
        return EXIT_FAILURE

    ret = EXIT_FAILURE
    try:
        os.fchown(dbconfig, LDAP_UID, LDAP_GID)
        os.write(dbconfig, 'set_cachesize 0 268435456 1\n')
        os.write(dbconfig, 'set_lg_regionmax 262144\n')
        os.write(dbconfig, 'set_lg_bsize 2097152\n')
        ret = EXIT_SUCCESS
    except OSError:
        log.error('Failed to write DB_CONFIG')

    os.close(dbconfig)
    return ret


def generate_schema(config):
    """
    Generate set of include statements to construct server's schema
    """
    print >> config, 'include /etc/openldap/schema/corba.schema'
    print >> config, 'include /etc/openldap/schema/core.schema'
    print >> config, 'include /etc/openldap/schema/cosine.schema'
    print >> config, 'include /etc/openldap/schema/duaconf.schema'
    print >> config, 'include /etc/openldap/schema/dyngroup.schema'
    print >> config, 'include /etc/openldap/schema/inetorgperson.schema'
    print >> config, 'include /etc/openldap/schema/java.schema'
    print >> config, 'include /etc/openldap/schema/misc.schema'
    print >> config, 'include /etc/openldap/schema/nis.schema'
    print >> config, 'include /etc/openldap/schema/openldap.schema'
    print >> config, 'include /etc/openldap/schema/ppolicy.schema'
    print >> config, 'include /etc/openldap/schema/collective.schema'
    print >> config, 'include /etc/openldap/schema/fedfs.schema'
    print >> config
    print >> config, 'pidfile /var/run/openldap/slapd.pid'
    print >> config, 'argsfile /var/run/openldap/slapd.args'
    print >> config


def generate_security_config(config, answers):
    """
    Generate server's security settings
    """
    if answers['security'] == 'tls':
        print >> config, 'TLSCACertificateFile %s' % NSDB_CERTFILE
        print >> config, 'TLSCertificateFile %s' % NSDB_CERTFILE
        print >> config, 'TLSCertificateKeyFile %s' % NSDB_KEYFILE
        print >> config, 'TLSVerifyClient never'
        print >> config, 'security ssf=128 tls=1'
    else:
        print >> config, 'security tls=0'
    print >> config


def generate_config_database(config, answers):
    """
    Generate server's cn=config database
    """
    print >> config, 'database config'
    print >> config, 'rootdn "%s"' % answers['ldap_admin']
    print >> config, 'rootpw %s' % answers['ldap_password']
    print >> config, 'access to *'
    print >> config, '\tby dn.exact="gidNumber=0+uidNumber=0,' \
        'cn=peercred,cn=external,cn=auth" manage'
    print >> config, '\tby * none'
    print >> config


def generate_monitor_database(config, answers):
    """
    Generate server's cn=monitor database
    """
    print >> config, 'database monitor'
    print >> config, 'access to *'
    print >> config, '\tby dn.exact="gidNumber=0+uidNumber=0,' \
        'cn=peercred,cn=external,cn=auth" read'
    print >> config, '\tby dn.exact="%s" read' % answers['ldap_admin']
    print >> config, '\tby * none'
    print >> config


def generate_dc_database(config, answers):
    """
    Generate database for domaincontroller root suffix
    """
    print >> config, 'database hdb'
    print >> config, 'suffix "%s"' % answers['domaincontroller']
    print >> config, 'checkpoint 1024 15'
    print >> config, 'directory %s' % answers['dc_backend']
    print >> config, 'rootdn "%s"' % answers['ldap_admin']
    print >> config, 'access to filter=(objectClass=fedfsFsn)'
    print >> config, '\tby dn="%s" manage' % answers['full_nsdb_admin']
    print >> config, '\tby * read'
    print >> config, 'access to filter=(objectClass=fedfsFsl)'
    print >> config, '\tby dn="%s" manage' % answers['full_nsdb_admin']
    print >> config, '\tby * read'
    print >> config, 'access to filter=(objectClass=fedfsNsdbContainerEntry)'
    print >> config, '\tby dn="%s" manage' % answers['full_nsdb_admin']
    print >> config, '\tby * read'
    print >> config, 'access to * by * read'
    print >> config


def generate_indices(config):
    """
    Generate index definitions for this server
    """
    print >> config, 'index objectClass eq,pres'
    print >> config, 'index fedfsFsnUuid eq,pres'
    print >> config, 'index fedFsFslUuid eq,pres'


def generate_slapd_config(config, answers):
    """
    Build fresh old-style slapd configuration

    Returns a shell exit status value
    """
    log.debug('Generating fresh slapd config in "%s"...', config.name)

    ret = EXIT_FAILURE
    try:
        generate_schema(config)
        generate_security_config(config, answers)
        generate_config_database(config, answers)
        generate_monitor_database(config, answers)
        generate_dc_database(config, answers)
        generate_indices(config)
        config.flush()
        ret = EXIT_SUCCESS
    except OSError:
        log.error('Failed to write new config file')

    return ret


def replace_slapd_config(answers):
    """
    Replace slapd configuration.
    slapd must be stopped for this procedure.

    Returns a shell exit status value
    """
    log.debug('Replacing slapd configuration...')

    ret = wipe_slapd_d()
    if ret != EXIT_SUCCESS:
        return ret

    config = temporary_ldap_file()
    if config is None:
        log.error('Failed to create new config file')
        return EXIT_FAILURE

    ret = generate_slapd_config(config, answers)
    if ret != EXIT_SUCCESS:
        config.close()
        return ret

    ret = run_as_user(LDAP_USERNAME, ['slapadd', '-n2', '-l', '/dev/null',
                                      '-f', config.name])
    if ret != EXIT_SUCCESS:
        config.close()
        return ret

    ret = run_as_user(LDAP_USERNAME, ['slaptest', '-f', config.name,
                                      '-F', '/etc/openldap/slapd.d'])
    config.close()
    return ret


def add_new_record(distinguished_name, new_entry):
    """
    Add a new entry to a slapd database

    Returns a shell exit status value
    """
    tmp = temporary_ldap_file()
    if tmp is None:
        log.error('Failed to create temporary LDIF file')
        return EXIT_FAILURE

    writer = ldif.LDIFWriter(tmp)
    writer.unparse(distinguished_name, new_entry)
    tmp.flush()

    ret = run_as_user(LDAP_USERNAME, ['slapadd', '-n2', '-l', tmp.name])

    tmp.close()
    return ret


def add_domaincontroller(answers):
    """
    Add a domain controller root suffix.
    slapd must be stopped for this procedure.

    Returns a shell exit status value
    """
    log.debug('Adding root suffix for "%s"...', answers['domaincontroller'])

    components = answers['domainname'].split('.')

    entry = {}
    entry['objectClass'] = ['top', 'organization', 'dcObject',
                            'fedfsNsdbContainerInfo']
    entry['dc'] = [components[0]]
    entry['o'] = [answers['domainname']]
    entry['fedfsNceDN'] = [answers['nce']]

    return add_new_record(answers['domaincontroller'], entry)


def add_nce(answers):
    """
    Add the NSDB Container Entry.
    slapd must be stopped for this procedure.

    Returns a shell exit status value
    """
    log.debug('Adding NSDB Container Entry "%s"...', answers['nce'])

    entry = {}
    entry['objectClass'] = ['top', 'organizationalUnit',
                            'fedfsNsdbContainerEntry']
    entry['ou'] = ['fedfs']

    return add_new_record(answers['nce'], entry)


def add_nsdb_manager(answers):
    """
    Add the NSDB Manager account

    Returns a shell exit status value
    """
    log.debug('Adding NSDB Manager...')

    ava = ldap.dn.str2dn(answers['nsdb_admin'])[0][0]

    entry = {}
    entry['objectClass'] = ['top', 'person']
    entry['sn'] = ['Administrator']
    entry['cn'] = [ava[1]]
    entry['userPassword'] = [answers['nsdb_password']]

    return add_new_record(answers['full_nsdb_admin'], entry)


def slapd_config(answers):
    """
    Generate and customize slapd.conf
    slapd must be stopped for this procedure.

    Returns a shell exit status value
    """
    ret = replace_slapd_database(answers['dc_backend'])
    if ret != EXIT_SUCCESS:
        return ret

    ret = replace_slapd_config(answers)
    if ret != EXIT_SUCCESS:
        return ret

    ret = add_domaincontroller(answers)
    if ret != EXIT_SUCCESS:
        return ret

    ret = add_nce(answers)
    if ret != EXIT_SUCCESS:
        return ret

    return add_nsdb_manager(answers)


def backup_slapd_backend(backup_dir, backup, nocompress):
    """
    Backup the slapd NSDB backend

    Returns a shell exit status
    """
    ldif_file = os.path.join(backup_dir, backup + '.ldif')

    ret = run_as_user(LDAP_USERNAME, ['slapcat', '-n2', '-l', ldif_file])
    if ret != EXIT_SUCCESS:
        return ret

    if not nocompress:
        if run_as_user(LDAP_USERNAME, ['gzip', ldif_file]) != EXIT_SUCCESS:
            log.warning('Failed to compress the backup')

    log.info('Backup "%s" created successfully', backup)
    return EXIT_SUCCESS


def restore_from_ldif(backup_dir, backup):
    """
    Restore the slapd NSDB backend

    Returns a shell exit status
    """
    log.info('Restoring from backup "%s"...', backup)

    ldif_gzip = os.path.join(backup_dir, backup + '.ldif.gz')
    if os.path.isfile(ldif_gzip):
        ret = run_as_user(LDAP_USERNAME, ['gunzip', ldif_gzip])
        if ret != EXIT_SUCCESS:
            log.error('Failed to uncompress "%s"', ldif_gzip)
            return ret

    ldif_file = os.path.join(backup_dir, backup + '.ldif')
    if not os.path.isfile(ldif_file):
        log.error('Backup "%s" not found', backup)
        return EXIT_FAILURE

    return run_as_user(LDAP_USERNAME, ['slapadd', '-n2', '-l', ldif_file])


def restore_slapd_backend(backend_dir, backup_dir, backup):
    """
    Restore the slapd NSDB backend, assumes slapd is stopped

    Returns a shell exit status
    """
    ret = replace_slapd_database(backend_dir)
    if ret != EXIT_SUCCESS:
        return ret

    return restore_from_ldif(backup_dir, backup)


__all__ = ['LDAP_UID', 'LDAP_GID', 'NSDB_CERTFILE', 'NSDB_KEYFILE',
           'local_nce_found', 'local_tls_found', 'get_slapd_status',
           'check_ldap_connectivity', 'slapd_config',
           'restore_slapd_backend', 'backup_slapd_backend',
           'adjust_slapd_log', 'make_ldap_directory']

if __name__ == '__main__':
    __ut_local_nce_found()
    __ut_local_tls_found()
    __ut_get_slapd_backend_dir()
    __ut_get_slapd_status()
    __ut_check_ldap_connectivity()
