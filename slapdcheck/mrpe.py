# -*- coding: utf-8 -*-
"""
slapdcheck.mrpe - generate MRPE output (e.g. for local check for check_mk)
See also: https://checkmk.com/integrations/mrpe
"""

# local package imports
from . import run
from .base import CheckFormatter
from .cfg import (
    CHECK_RESULT_ERROR,
    CHECK_RESULT_OK,
    CHECK_RESULT_UNKNOWN,
    CHECK_RESULT_WARNING,
)


class SlapdCheckMRPE(CheckFormatter):
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

    @staticmethod
    def _serialize_perf_data(pdat):
        if not pdat:
            return '-'
        return '|'.join([
            '%s=%s' % (pkey, pval)
            for pkey, pval in pdat.items()
            if not pkey.endswith('_total')
        ])

    def output(self, check_items):
        for i in sorted(check_items.keys()):
            status, check_name, perf_data, check_msg = check_items[i]
            self._output_file.write(
                self.output_format.format(
                    status_code=status,
                    perf_data=self._serialize_perf_data(perf_data),
                    name=check_name,
                    status_text=self.checkmk_status[status],
                    msg=check_msg,
                )
            )


def cli_run():
    run(SlapdCheckMRPE)


if __name__ == '__main__':
    cli_run()
