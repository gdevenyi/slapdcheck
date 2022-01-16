# -*- coding: utf-8 -*-
"""
slapdcheck - module package which implements OpenLDAP monitor checks
"""

from abc import ABC, abstractmethod
import sys
import os
import string
import pprint
import logging

from .state import CheckStateFile
from .cfg import CHECK_RESULT_UNKNOWN


class MonitoringCheck(ABC):
    """
    base class for a monitoring check
    """
    item_names = (())
    item_name_safe_chars = set(string.ascii_letters+string.digits+'_')

    def __init__(self, state_filename, formatters):
        self._formatters = formatters
        self._item_dict = {}
        for item_name in self.item_names:
            self.add_item(item_name)
        if state_filename is not None:
            # Initialize local state file and read old state if it exists
            self._state = CheckStateFile(state_filename)
            # Generate *new* state dict to be updated within check and stored
            # later
            self._next_state = {}
        self.script_name = os.path.basename(sys.argv[0])

    def _get_rate(self, key, current_val, time_span):
        last_val = int(self._state.data.get(key, '0'))
        if current_val < last_val:
            val1, val2 = last_val, last_val+current_val
        else:
            val1, val2 = last_val, current_val
        return (val2 - val1) / time_span

    @abstractmethod
    def checks(self):
        """
        wrapper method implementing all checks, normally invoked by run()
        """
        raise NotImplementedError(
            "method .checks() not implemented in class %s.%s" % (
                self.__class__.__module__,
                self.__class__.__name__,
            )
        )

    def run(self):
        """
        wrapper method for running all checks with outer expcetion handling
        """
        try:
            try:
                self.checks()
            except Exception:
                # Log unhandled exception
                err_lines = [
                    '----------- %s.__dict__ -----------' % (self.__class__.__name__,),
                    pprint.pformat(self.__dict__, indent=2, width=66, depth=None),
                ]
                logging.exception('\n'.join(err_lines))
        finally:
            # add default unknown result for all known check items
            # which up to now did not receive a particular result
            for i in sorted(self._item_dict.keys()):
                if not self._item_dict[i]:
                    self.result(
                        CHECK_RESULT_UNKNOWN,
                        i,
                        'No defined check result yet!',
                    )
            for formatter in self._formatters:
                formatter.output(self._item_dict)
            if self._state:
                self._state.write_state(self._next_state)

    def add_item(self, item_name):
        """
        Preregister a check item by name
        """
        # FIX ME! Protect the following lines with a lock!
        if item_name in self._item_dict:
            raise ValueError('Check item name %r already exists.' % (item_name,))
        self._item_dict[item_name] = None

    def subst_item_name_chars(self, item_name):
        """
        Replace special chars in s
        """
        s_list = []
        for char in item_name:
            if char not in self.item_name_safe_chars:
                s_list.append('_')
            else:
                s_list.append(char)
        return ''.join(s_list)  # _subst_item_name_chars()

    def result(self, status, item_name, check_output, **performance_data):
        """
        Registers check_mk result to be output later
        status
           integer indicating status
        item_name
           the check_mk item name
        """
        # Provoke KeyError if item_name is not known
        try:
            self._item_dict[item_name]
        except KeyError as err:
            raise ValueError('item_name %r not in known item names %r' % (
                item_name,
                self._item_dict.keys(),
            )) from err
        self._item_dict[item_name] = (
            status,
            item_name,
            {
                key: val
                for key, val in performance_data.items()
                if val is not None
            },
            check_output or '',
        )
        # end of result()


class CheckFormatter:
    """
    Base class for implementing different output
    """
    output_encoding = 'ascii'

    def __init__(self, output_file):
        self._output_file = output_file

    @abstractmethod
    def output(self):
        """
        Outputs all results registered before with method result()
        """
        raise NotImplementedError(
            "method .output() not implemented in class %s.%s" % (
                self.__class__.__module__,
                self.__class__.__name__,
            )
        )
