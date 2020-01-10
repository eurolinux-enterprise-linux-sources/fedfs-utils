"""
run - utilities for running commands and managing daemons

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

# Standard Unix shell exit values
EXIT_SUCCESS = 0
EXIT_FAILURE = 1

import os
import pwd
import logging as log

from subprocess import Popen, PIPE


def __run(command, shell=False):
    """
    Run a command, ignore all command output, but return exit status

    Returns a shell exit status value
    """
    try:
        process = Popen(command, stdout=PIPE, stderr=PIPE, shell=shell)
    except OSError:
        log.error('"%s" command did not execute', ' '.join(command))
        return None
    except ValueError:
        log.error('"%s": bad arguments to Popen', ' '.join(command))
        return None
    return process


def run_command(command, force=False):
    """
    Run a command, ignore all command output, but return exit status

    Returns a shell exit status value
    """
    log.debug('Running the "%s" command...', command[0])

    process = __run(command)
    if process is None:
        return EXIT_FAILURE

    # pylint: disable-msg=E1101
    process.wait()
    # pylint: disable-msg=E1101
    if process.returncode != 0:
        if not force:
            log.error('"%s" returned %d', command[0], process.returncode)
            return EXIT_FAILURE
    return EXIT_SUCCESS


def __ut_run_command():
    """
    Unit tests for run_command
    """
    result = run_command(['ls', '-l'])
    if result == EXIT_SUCCESS:
        print('run_command("ls -l") succeeded')
    elif result == EXIT_FAILURE:
        print('run_command("ls -l") failed')
    else:
        print('run_command("ls -l"): %d' % result)


def run_shell(line, force=False):
    """
    Run a shell command, ignore all command output, but return exit status

    Returns a shell exit status value
    """
    log.debug('Running "%s"...', line)

    process = __run(line, shell=True)
    if process is None:
        return EXIT_FAILURE

    # pylint: disable-msg=E1101
    process.wait()
    # pylint: disable-msg=E1101
    if process.returncode != 0:
        if not force:
            log.error('"%s" returned %d', line, process.returncode)
            return EXIT_FAILURE
    return EXIT_SUCCESS


def __ut_run_shell():
    """
    Unit tests for run_shell
    """
    result = run_shell('ls -l')
    if result == EXIT_SUCCESS:
        print('run_shell("ls -l") succeeded')
    elif result == EXIT_FAILURE:
        print('run_shell("ls -l") failed')
    else:
        print('run_shell("ls -l"): %d' % result)


def demote(user_uid, user_gid):
    """
    Returns a function that changes the UID and GID of a process
    """
    def result():
        """
        Change the UID and GID of a process
        """
        os.setgid(user_gid)
        os.setuid(user_uid)

    return result


def run_as_user(username, command):
    """
    Run a command as a different user

    Returns a shell exit status value
    """
    log.debug('Running the "%s" command as %s...', command[0], username)

    try:
        user_uid = pwd.getpwnam(username).pw_uid
        user_gid = pwd.getpwnam(username).pw_gid
    except KeyError:
        log.error('"%s" is not a valid user', username)
        return EXIT_FAILURE

    try:
        process = Popen(command, preexec_fn=demote(user_uid, user_gid),
                        stdout=PIPE, stderr=PIPE, shell=False)
    except OSError:
        log.error('"%s" command did not execute', ' '.join(command))
        return EXIT_FAILURE
    except ValueError:
        log.error('"%s": bad arguments to Popen', ' '.join(command))
        return EXIT_FAILURE

    # pylint: disable-msg=E1101
    process.wait()
    # pylint: disable-msg=E1101
    if process.returncode != 0:
        log.error('"%s" returned %d', command[0], process.returncode)
        return EXIT_FAILURE
    return EXIT_SUCCESS


def __ut_run_as_user():
    """
    Unit tests for run_as_user()
    """
    result = run_as_user('ldap', ['echo', 'this is a test'])
    if result == EXIT_SUCCESS:
        print('run_as_user("ldap", "echo this is a test") succeeded')
    elif result == EXIT_FAILURE:
        print('run_as_user("ldap", "echo this is a test") failed')
    else:
        print('run_as_user("ldap", "echo this is a test"): %d' % result)

    result = run_as_user('bogus', ['id'])
    if result == EXIT_SUCCESS:
        print('run_as_user("bogus", "id") succeeded')
    elif result == EXIT_FAILURE:
        print('run_as_user("bogus", "id") failed')
    else:
        print('run_as_user("bogus", "id"): %d' % result)


def check_for_daemon(name):
    """
    Predicate: is a process named "name" running on the system?

    Returns True if "name" is running, otherwise returns False
    """
    process = __run(['pgrep', name])
    if process is None:
        return False

    # pylint: disable-msg=E1101
    process.wait()
    # pylint: disable-msg=E1101
    if process.returncode != 0:
        return False
    return True


def __ut_check_for_daemon():
    """
    Unit tests for check_for_daemon()
    """
    if check_for_daemon('dbus'):
        print('dbus is running')
    else:
        print('dbus is not running')

    if check_for_daemon('bogus'):
        print('bogus is running')
    else:
        print('bogus is not running')


def systemctl(command, service):
    """
    Try a systemctl command, report failure

    Returns a shell exit status value
    """
    log.debug('Trying to %s the %s service...', command, service)

    process = __run(['systemctl', command, service + '.service'])
    if process is None:
        return EXIT_FAILURE

    # pylint: disable-msg=E1101
    process.wait()
    # pylint: disable-msg=E1101
    if process.returncode != 0:
        log.error('systemctl %s %s.service failed: %d',
                  command, service, process.returncode)
        return EXIT_FAILURE
    return EXIT_SUCCESS


def __ut_systemctl():
    """
    Unit tests for run.py module
    """
    result = systemctl('status', 'network')
    if result == EXIT_SUCCESS:
        print('systemctl result: succeeded')
    elif result == EXIT_FAILURE:
        print('systemctl result: failed')
    else:
        print('systemctl result: %d' % result)

    result = systemctl('status', 'bogus')
    if result == EXIT_SUCCESS:
        print('systemctl result: succeeded')
    elif result == EXIT_FAILURE:
        print('systemctl result: failed')
    else:
        print('systemctl result: %d' % result)


def stop_service(service):
    """
    Stop a server

    Returns a shell exit status value
    """
    if systemctl('status', service) != 0:
        log.debug('"%s" is not running', service)
        return EXIT_SUCCESS

    ret = systemctl('stop', service)
    if ret != EXIT_SUCCESS:
        return ret

    log.debug('The "%s" service was stopped successfully', service)
    return EXIT_SUCCESS


def start_service(service):
    """
    Start a server

    Returns a shell exit status value
    """
    ret = systemctl('start', service)
    if ret != EXIT_SUCCESS:
        return ret

    log.debug('The "%s" service was started successfully', service)
    return EXIT_SUCCESS


def enable_and_start_service(service):
    """
    Enable and start a server

    Returns a shell exit status value
    """
    ret = systemctl('enable', service)
    if ret != EXIT_SUCCESS:
        return ret

    return start_service(service)


def restart_service(service):
    """
    Restart a server

    Returns a shell exit status value
    """
    return systemctl('restart', service)


__all__ = ['EXIT_SUCCESS', 'EXIT_FAILURE',
           'run_command', 'run_as_user',
           'check_for_daemon',
           'stop_service', 'start_service',
           'restart_service', 'enable_and_start_service']

if __name__ == '__main__':
    log.basicConfig(format='%(levelname)s: %(message)s', level=log.DEBUG)

    __ut_check_for_daemon()
    __ut_run_command()
    __ut_run_shell()
    __ut_run_as_user()
    __ut_systemctl()
