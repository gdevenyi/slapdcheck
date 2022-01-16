# -*- coding: utf-8 -*-
"""
slapdcheck.checkmk - generate NRPE output (e.g. for local check for check_mk)
"""

#-----------------------------------------------------------------------
# Import modules
#-----------------------------------------------------------------------

# local package imports
from . import SlapdCheck, run
from .cfg import (
    CHECK_RESULT_ERROR,
    CHECK_RESULT_OK,
    CHECK_RESULT_UNKNOWN,
    CHECK_RESULT_WARNING,
)

#-----------------------------------------------------------------------
# Classes
#-----------------------------------------------------------------------

class SlapdCheckNRPE(SlapdCheck):
    """
    slapd check for checkmk
    """
    checkmk_status = {
        CHECK_RESULT_OK: 'OK',
        CHECK_RESULT_WARNING: 'WARNING',
        CHECK_RESULT_ERROR: 'ERROR',
        CHECK_RESULT_UNKNOWN: 'UNKNOWN',
    }
    output_format = '{status_code} {name} {perf_data} {status_text} - {msg}\n'

    def __init__(self, output_file, state_filename=None):
        SlapdCheck.__init__(self, output_file, state_filename)

    @staticmethod
    def _serialize_perf_data(pdat):
        if not pdat:
            return '-'
        return '|'.join([
            '%s=%s' % (pkey, pval)
            for pkey, pval in pdat.items()
            if not pkey.endswith('_total')
        ])

    def output(self):
        """
        Outputs all check_mk results registered before with method result()
        """
        # add default unknown result for all known check items
        # which up to now did not receive a particular result
        for i in sorted(self._item_dict.keys()):
            if not self._item_dict[i]:
                self.result(
                    CHECK_RESULT_UNKNOWN,
                    i,
                    'No defined check result yet!',
                )
        # now output the result lines
        for i in sorted(self._item_dict.keys()):
            status, check_name, perf_data, check_msg = self._item_dict[i]
            self._output_file.write(
                self.output_format.format(
                    status_code=status,
                    perf_data=self._serialize_perf_data(perf_data),
                    name=self.subst_item_name_chars(check_name),
                    status_text=self.checkmk_status[status],
                    msg=check_msg,
                )
            )
        # end of output()


def cli_run():
    run(SlapdCheckNRPE)


if __name__ == '__main__':
    cli_run()
