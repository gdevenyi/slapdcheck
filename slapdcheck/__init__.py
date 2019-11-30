# -*- coding: utf-8 -*-
"""
slapdcheck - module package which implements OpenLDAP monitor checks
"""

import sys
import pprint
import logging
import os.path

from .state import CheckStateFile
from .cnf import CHECK_RESULT_UNKNOWN


class NoneException(BaseException):
    """
    A dummy exception class used for disabling exception handling
    """


class MonitoringCheck:
    """
    base class for a monitoring check
    """

    item_names = None
    output_encoding = 'ascii'
    item_name_special_chars = set()

    def __init__(self, output_file, state_filename=None):
        """
        output_file
            fileobj where to write the output
        output_encoding
            encoding to use when writing output
            'ascii' is always safe, Nagios mandates 'utf-8'
        """
        self._item_dict = {}
        for item_name in self.item_names or []:
            self.add_item(item_name)
        self._output_file = output_file
        if state_filename is not None:
            # Initialize local state file and read old state if it exists
            self._state = CheckStateFile(state_filename)
            # Generate *new* state dict to be updated within check and stored
            # later
            self._next_state = {}
        self.script_name = os.path.basename(sys.argv[0])
        # end of __init__()

    def _get_rate(self, key, current_val, time_span):
        last_val = int(self._state.data.get(key, '0'))
        if current_val < last_val:
            val1, val2 = last_val, last_val+current_val
        else:
            val1, val2 = last_val, current_val
        return (val2 - val1) / time_span # end of _get_rate()

    def checks(self):
        """
        wrapper method implementing all checks, normally invoked by run()
        """
        raise Exception(
            "checks() not implemented in class %s.%s" % (
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
                err_lines = [66 * '-']
                err_lines.append(
                    '----------- %s.__class__.__dict__ -----------' % (self.__class__.__name__))
                err_lines.append(
                    pprint.pformat(self.__class__.__dict__, indent=1, width=66, depth=None))
                err_lines.append('----------- vars() -----------')
                err_lines.append(
                    pprint.pformat(vars(), indent=1, width=66, depth=None))
                logging.exception('\n'.join(err_lines))
        finally:
            self.output()
            if self._state:
                self._state.write_state(self._next_state)

    def add_item(self, item_name):
        """
        Preregister a check item by name
        """
        # FIX ME! Protect the following lines with a lock!
        if item_name in self._item_dict:
            raise ValueError('Check item name %r already exists.' % (item_name))
        self._item_dict[item_name] = None

    def subst_item_name_chars(self, item_name):
        """
        Replace special chars in s
        """
        s_list = []
        for char in item_name:
            if char in self.item_name_special_chars:
                s_list.append('_')
            else:
                s_list.append(char)
        return ''.join(s_list)  # _subst_item_name_chars()

    @staticmethod
    def serialize_perf_data(performance_data):
        return str(performance_data)

    def result(self, status, item_name, performance_data=None, check_output=None):
        """
        Registers check_mk result to be output later
        status
           integer indicating status
        item_name
           the check_mk item name
        """
        assert performance_data is None or isinstance(performance_data, dict), \
            TypeError('Expected performance_data to be None or dict, but was %r' % performance_data)
        # Provoke KeyError if item_name is not known
        try:
            self._item_dict[item_name]
        except KeyError:
            raise ValueError('item_name %r not in known item names %r' % (
                item_name,
                self._item_dict.keys(),
            ))
        self._item_dict[item_name] = (
            status,
            item_name,
            performance_data or {},
            check_output or u'',
        )
        # end of result()

    def output(self):
        """
        Outputs all results registered before with method result()
        """
        # add default unknown result for all known check items
        # which up to now did not receive a particular result
        for i in sorted(self._item_dict.keys()):
            if not self._item_dict[i]:
                self.result(
                    CHECK_RESULT_UNKNOWN,
                    i,
                    check_output='No defined check result yet!',
                )
