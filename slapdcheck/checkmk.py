# -*- coding: utf-8 -*-
"""
monitoring check script for OpenLDAP

Needs full read access to rootDSE and cn=config and cn=monitor
(or whereever rootDSE attributes 'configContext' and 'monitorContext'
are pointing to)

Copyright 2015-2019 Michael Ströder <michael@stroeder.com>

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use files and content provided on this web site except in compliance
with the License. You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

#-----------------------------------------------------------------------
# Import modules
#-----------------------------------------------------------------------

import os
import sys

# local package imports
from slapdcheck import MonitoringCheck, SlapdCheck
from slapdcheck.cnf import (
    CHECK_RESULT_ERROR,
    CHECK_RESULT_OK,
    CHECK_RESULT_UNKNOWN,
    CHECK_RESULT_WARNING,
)

#-----------------------------------------------------------------------
# Classes
#-----------------------------------------------------------------------

class CheckMkLocalCheck(MonitoringCheck):
    """
    Simple class for writing check_mk output
    """
    checkmk_status = {
        CHECK_RESULT_OK: 'OK',
        CHECK_RESULT_WARNING: 'WARNING',
        CHECK_RESULT_ERROR: 'ERROR',
        CHECK_RESULT_UNKNOWN: 'UNKNOWN',
    }
    output_format = '{status_code} {name} {perf_data} {status_text} - {msg}\n'

    def serialize_perf_data(self, pdat):
        if not pdat:
            return '-'
        return '|'.join([
            '%s=%s' % (pkey, pval)
            for pkey, pval in pdat.items()
        ])

    def output(self):
        """
        Outputs all check_mk results registered before with method result()
        """
        MonitoringCheck.output(self)
        for i in sorted(self._item_dict.keys()):
            status, check_name, perf_data, check_msg = self._item_dict[i]
            sys.stdout.write(
                self.output_format.format(
                    status_code=status,
                    perf_data=self.serialize_perf_data(perf_data),
                    name=self.subst_item_name_chars(check_name),
                    status_text=self.checkmk_status[status],
                    msg=check_msg,
                )
            )
        # end of output()


class CheckMkSlapdCheck(SlapdCheck, CheckMkLocalCheck):
    """
    slapd check for checkmk
    """

    def __init__(self, output_file, state_filename=None):
        SlapdCheck.__init__(self, output_file, state_filename)


def run():
    """
    run as check_mk local check
    """
    slapd_check = CheckMkSlapdCheck(
        output_file=sys.stdout,
        state_filename=os.path.basename(sys.argv[0][:-3]),
    )
    slapd_check.run()


if __name__ == '__main__':
    run()
