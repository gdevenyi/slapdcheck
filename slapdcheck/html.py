# -*- coding: utf-8 -*-
"""
slapdcheck.html - generate simple HTML page
"""

import socket

# local package imports
from . import SlapdCheck, run
from .__about__ import __version__
from .cfg import (
    CHECK_RESULT_ERROR,
    CHECK_RESULT_OK,
    CHECK_RESULT_UNKNOWN,
    CHECK_RESULT_WARNING,
)


HTML_STATUS_COLOR = {
    CHECK_RESULT_ERROR: 'red',
    CHECK_RESULT_OK: 'lightgreen',
    CHECK_RESULT_UNKNOWN: 'orange',
    CHECK_RESULT_WARNING: 'yellow',
}

HTML_HEADER = """<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
  <title>slapdcheck on {host}</title>
  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  <meta name="generator" content="slapd_check {version}" />
</head>
<body>
  <h1>slapdcheck on {host}</h1>
  <p>slapdcheck version: {version}</p>
  <table border="1">
  <tr>
  <th>Status</th>
  <th>Check</th>
  <th>Details</th>
  <th>Metrics</th>
  </tr>\n
"""

HTML_FOOTER = """
  </table>
</body>
</html>
"""


class SlapdCheckHTML(SlapdCheck):
    """
    slapd check for checkmk
    """
    checkmk_status = {
        CHECK_RESULT_OK: 'OK',
        CHECK_RESULT_WARNING: 'WARNING',
        CHECK_RESULT_ERROR: 'ERROR',
        CHECK_RESULT_UNKNOWN: 'UNKNOWN',
    }
    output_format = (
        '<tr>'
        '<td bgcolor="{status_color}">{status_text}</td>'
        '<td>{name}</td>'
        '<td>{msg}</td>'
        '<td>{perf_data}</td>'
        '</tr>\n'
    )

    def __init__(self, output_file, state_filename=None):
        SlapdCheck.__init__(self, output_file, state_filename)

    def _serialize_perf_data(self, pdat):
        if not pdat:
            return '&nbsp;'
        res = ['<table>']
        for pkey, pval in pdat.items():
            if not pkey.endswith('_total'):
                res.append('<tr><td>{k}</td><td>{v}</td></tr>'.format(k=pkey, v=pval))
        res.append('</table>')
        return '\n'.join(res)

    def output(self):
        """
        Outputs all check_mk results registered before with method result()
        """
        self._output_file.write(
            HTML_HEADER.format(
                version=__version__,
                host=socket.getfqdn(),
            )
        )
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
                    status_color=HTML_STATUS_COLOR[status],
                    perf_data=self._serialize_perf_data(perf_data),
                    name=self.subst_item_name_chars(check_name),
                    status_text=self.checkmk_status[status],
                    msg=check_msg,
                )
            )
        self._output_file.write(HTML_FOOTER)
        # end of output()


def cli_run():
    run(SlapdCheckHTML)


if __name__ == '__main__':
    cli_run()
