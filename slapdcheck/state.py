# -*- coding: utf-8 -*-
"""
slapdcheck.state - store local state
"""

import os

from .cfg import CATCH_ALL_EXC


class CheckStateFile:
    """
    Class for state file
    """
    line_sep = '\n'

    def __init__(self, state_filename):
        self._state_filename = state_filename
        if not os.path.isfile(self._state_filename):
            self.write_state({})
        self.data = self._read_state()

    def _read_state(self):
        """
        read state dict from file
        """
        try:
            state_tuple_list = []
            with open(self._state_filename, 'r', encoding='utf-8') as state_file:
                state_string_list = state_file.read().split(self.line_sep)
            state_tuple_list = [
                line.split('=', 1)
                for line in state_string_list
                if line
            ]
            return dict(state_tuple_list)
        except CATCH_ALL_EXC:
            return {}

    def write_state(self, state):
        """
        write state dict to file
        """
        state_string_list = [
            '%s=%s' % (key, val)
            for key, val in state.items()
        ]
        state_string_list.append('')
        with open(self._state_filename, 'w', encoding='utf-8') as state_file:
            state_file.write(self.line_sep.join(state_string_list))
