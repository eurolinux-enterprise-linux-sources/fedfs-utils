"""
transaction - a simple way to commit or revert system changes

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

import os
import time
import logging as log
from shutil import rmtree, Error

from PyFedfs.run import EXIT_SUCCESS, EXIT_FAILURE


class Transaction(object):
    """
    Represents a directory or file to be able to revert
    """
    def __init__(self):
        self.items = []
        self.unique = '%u' % int(time.time())
        self.state = 'inited'

        log.info('Created transaction %s', self.unique)

    def __backup_name(self, pathname):
        """
        Generate name of backup object

        Returns a string
        """
        return pathname + '.bak.' + self.unique

    def __iterate(self, func):
        """
        Call a function on all items in the transaction list

        Returns a shell exit status value
        """
        ret = EXIT_SUCCESS
        for item in self.items:
            if func(item) != EXIT_SUCCESS:
                ret = EXIT_FAILURE
        return ret

    def __remove_item(self, pathname):
        """
        Remove a directory tree or file

        Returns a shell exit status value
        """
        if not os.path.exists(pathname):
            log.debug('No object "%s" to remove', pathname)
            return EXIT_SUCCESS

        if os.path.isfile(pathname):
            try:
                log.debug('Removing file "%s"...', pathname)
                os.remove(pathname)
            except OSError:
                return EXIT_FAILURE
        else:
            try:
                log.debug('Removing directory "%s"...', pathname)
                rmtree(pathname)
            except Error:
                return EXIT_FAILURE
        return EXIT_SUCCESS

    def __checkpoint_item(self, pathname):
        """
        Move existing object out of the way

        Returns a shell exit status value
        """
        if not os.path.exists(pathname):
            log.warning('Checkpoint of non-existing object "%s"', pathname)
            return EXIT_SUCCESS

        if os.path.exists(self.__backup_name(pathname)):
            log.error('Checkpoint of "%s" already exists', pathname)
            return EXIT_FAILURE

        log.debug('Checkpointing "%s"...', pathname)

        try:
            os.rename(pathname, self.__backup_name(pathname))
        except OSError:
            log.error('Failed to checkpoint "%s"', pathname)
            return EXIT_FAILURE
        return EXIT_SUCCESS

    def __commit_item(self, pathname):
        """
        Remove an object's backup

        Returns a shell exit status value
        """
        if not os.path.exists(self.__backup_name(pathname)):
            log.warning('Backup of object "%s" is missing', pathname)
            return EXIT_SUCCESS

        log.debug('Committing "%s"...', pathname)

        if self.__remove_item(self.__backup_name(pathname)) != EXIT_SUCCESS:
            log.error('Failed to remove backup of "%s"', pathname)
            return EXIT_FAILURE

        return EXIT_SUCCESS

    def __revert_item(self, pathname):
        """
        Restore an object from its backup

        Returns a shell exit status value
        """
        if not os.path.exists(self.__backup_name(pathname)):
            log.error('Backup of "%s" was not found', pathname)
            return EXIT_FAILURE

        if self.__remove_item(pathname) != EXIT_SUCCESS:
            log.error('Failed to revert "%s"', pathname)
            return EXIT_FAILURE

        log.info('Reverting "%s"...', pathname)

        try:
            os.rename(self.__backup_name(pathname), pathname)
        except OSError:
            log.error('Failed to revert "%s"', pathname)
            return EXIT_FAILURE
        return EXIT_SUCCESS

    def add(self, pathname):
        """
        Add filename of an object to be controlled by this transaction

        Returns a shell exit status value
        """
        if self.state != 'inited':
            log.error('"%s" not added to transaction %s: '
                      'transaction already checkpointed',
                      pathname, self.unique)
            return EXIT_FAILURE

        if type(pathname) != str:
            log.error('Object not added to transaction %s: '
                      'not a string', self.unique)
            return EXIT_FAILURE

        if not os.path.exists(pathname):
            log.debug('"%s" not added to transacion %s: '
                     'object does not exist', pathname, self.unique)
            return EXIT_SUCCESS

        self.items.append(pathname)
        return EXIT_SUCCESS

    def checkpoint(self):
        """
        Checkpoint all items in this transaction

        Returns a shell exit status value
        """
        if self.state != 'inited':
            log.warning('Transaction %s has already been checkpointed',
                        self.unique)
            return EXIT_SUCCESS

        if len(self.items) == 0:
            log.error('Transaction %s has no items to checkpoint',
                      self.unique)
            return EXIT_FAILURE

        log.info('Checkpointing transaction %s...', self.unique)
        self.state = 'checkpointed'
        return self.__iterate(self.__checkpoint_item)

    def commit(self):
        """
        Commit all items in this transaction

        Returns a shell exit status value
        """
        if self.state == 'inited':
            log.error('Nothing to commit: transaction %s has '
                      'not been checkpointed', self.unique)
            return EXIT_FAILURE

        if self.state != 'checkpointed':
            log.warning('Transaction %s has already been committed',
                        self.unique)
            return EXIT_SUCCESS

        log.info('Committing transaction %s...', self.unique)
        self.state = 'committed'
        return self.__iterate(self.__commit_item)

    def revert(self):
        """
        Revert all items in this transaction

        Returns a shell exit status value
        """
        if self.state == 'inited':
            log.error('Nothing to commit: transaction %s has '
                      'not been checkpointed', self.unique)
            return EXIT_FAILURE

        if self.state != 'checkpointed':
            log.warning('Transaction %s has already been committed',
                        self.unique)
            return EXIT_SUCCESS

        log.info('Reverting transaction %s...', self.unique)
        self.state = 'reverted'
        return self.__iterate(self.__revert_item)

__all__ = ['Transaction']
