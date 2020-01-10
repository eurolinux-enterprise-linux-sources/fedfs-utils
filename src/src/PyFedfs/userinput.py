"""
userinput - utilities to get user input

Part of the PyFedfs module
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
from getpass import getpass
from subprocess import check_output, CalledProcessError


def confirm(question):
    """
    Confirm user would like to proceed with some operation

    Returns True if user gives a "yes" answer, False if user
    gives a "no" answer or hits return.
    """
    valid = {'yes': True, 'ye': True, 'y': True, 'no': False, 'n': False}

    while True:
        sys.stdout.write(question + ' [y/N] ')
        choice = raw_input().lower()
        if choice == '':
            return False
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write('Respond "yes" or "no"\n')


def __ut_confirm():
    """
    Unit tests for confirm()
    """
    if confirm('Answer this question: '):
        print('You answered "yes"')
    else:
        print('You answered "no"')


def get_password(prompt):
    """
    Ask user for a password; use input blanking

    Returns a string
    """
    print(prompt)
    while True:
        try:
            password1 = getpass('New password: ')
            password2 = getpass('Re-enter new password: ')
        except KeyboardInterrupt:
            return ''

        if password1 == '':
            print('Empty password, try again')
        elif password1 != password2:
            print('Password values do not match, try again')
        else:
            break

    try:
        result = check_output(['slappasswd', '-n', '-s', password1])
    except CalledProcessError:
        return ''
    return result


def __ut_get_password():
    """
    Unit tests for get_password()
    """
    password = get_password('Enter a strong password: ')
    if password == '':
        print('An empty password was returned')
    else:
        print('The password you entered was "%s"' % password)


__all__ = ['confirm', 'get_password']

# unit tests
if __name__ == '__main__':
    __ut_confirm()
    __ut_get_password()
