"""
Create a self-signed x.509 certificate for an LDAP server
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
    import socket
    from OpenSSL import crypto

    from PyFedfs.run import EXIT_SUCCESS
except ImportError:
    print >> sys.stderr, \
        'Could not import a required Python module:', sys.exc_value
    sys.exit(1)


def create_self_signed_certificate(certfile, keyfile, owner_uid, owner_gid):
    """
    Create a self-signed server certificate
    """
    keypair = crypto.PKey()
    keypair.generate_key(crypto.TYPE_RSA, 2048)

    ss_cert = crypto.X509()

    print('\nSetting up a self-signed x.509 certificate.  ' \
        'Please answer the following questions:\n')
    ss_cert.get_subject().C = raw_input('Country (C)? ')
    ss_cert.get_subject().ST = raw_input('State or province (ST)? ')
    ss_cert.get_subject().L = raw_input('City (L)? ')
    ss_cert.get_subject().O = raw_input('Organization (O)? ')
    ss_cert.get_subject().OU = raw_input('Organizational unit (OU)? ')
    ss_cert.get_subject().CN = socket.getfqdn()
    ss_cert.set_serial_number(1000)
    ss_cert.gmtime_adj_notBefore(0)
    ss_cert.gmtime_adj_notAfter(2 * 365 * 24 * 60 * 60)

    ss_cert.set_issuer(ss_cert.get_subject())
    ss_cert.set_pubkey(keypair)
    ss_cert.sign(keypair, 'sha1')

    cert_file = os.open(certfile, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0440)
    os.fchown(cert_file, owner_uid, owner_gid)
    os.write(cert_file, crypto.dump_certificate(crypto.FILETYPE_PEM, ss_cert))
    os.close(cert_file)

    key_file = os.open(keyfile, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0440)
    os.fchown(key_file, owner_uid, owner_gid)
    os.write(key_file, crypto.dump_privatekey(crypto.FILETYPE_PEM, keypair))
    os.close(key_file)

    return EXIT_SUCCESS


def __ut_create_certificate():
    """
    Unit tests for create_self_signed_certificate
    """
    ret = create_self_signed_certificate('/tmp/cert.pem', '/tmp/key.pem',
                                         os.geteuid(), os.getegid())
    if ret != EXIT_SUCCESS:
        return

    print('\nDone.  See /tmp/{cert,key}.pem\n')


__all__ = ['create_self_signed_certificate']


if __name__ == '__main__':
    __ut_create_certificate()
