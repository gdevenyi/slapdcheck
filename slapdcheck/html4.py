# -*- coding: utf-8 -*-
"""
slapdcheck.html4 - generate simple HTML 4 output
"""

import socket

# local package imports
from . import SlapdCheck, run
from .cfg import (
    CHECK_RESULT_ERROR,
    CHECK_RESULT_OK,
    CHECK_RESULT_UNKNOWN,
    CHECK_RESULT_WARNING,
)
from .__about__ import __version__


HTML_STATUS_COLOR = {
    CHECK_RESULT_ERROR: '#FF4500',
    CHECK_RESULT_OK: '#9ACD32',
    CHECK_RESULT_UNKNOWN: '#FFA500',
    CHECK_RESULT_WARNING: '#FFD700',
}

HTML_HEADER = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html xml:lang="en" lang="en">
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
    slapd check for HTML output
    """
    checkmk_status = {
        CHECK_RESULT_OK: 'OK',
        CHECK_RESULT_WARNING: 'WARNING',
        CHECK_RESULT_ERROR: 'ERROR',
        CHECK_RESULT_UNKNOWN: 'UNKNOWN',
    }
    output_format = (
        '<tr>'
        '<td align="middle" bgcolor="{status_color}">{status_text}</td>'
        '<td>{name}</td>'
        '<td>{msg}</td>'
        '<td>{perf_data}</td>'
        '</tr>\n'
    )

    def __init__(self, output_file, state_filename=None):
        self._host = socket.getfqdn()
        SlapdCheck.__init__(self, output_file, state_filename)

    @staticmethod
    def _serialize_perf_data(pdat):
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
                host=self._host,
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
                    status_text=self.checkmk_status[status],
                    status_color=HTML_STATUS_COLOR[status],
                    name=self.subst_item_name_chars(check_name),
                    msg=check_msg,
                    perf_data=self._serialize_perf_data(perf_data),
                )
            )
        self._output_file.write(HTML_FOOTER)
        # end of output()


def cli_run():
    run(SlapdCheckHTML)


if __name__ == '__main__':
    cli_run()
