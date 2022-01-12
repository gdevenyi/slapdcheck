# -*- coding: utf-8 -*-
"""
slapdcheck.zabbix - generate output to be sent to ZABBIX trapper
"""

#-----------------------------------------------------------------------
# Import modules
#-----------------------------------------------------------------------

import socket

# from module package py-zabbix
from pyzabbix import ZabbixMetric, ZabbixSender

# local package imports
from . import SlapdCheck, run

#-----------------------------------------------------------------------
# Classes
#-----------------------------------------------------------------------

class ZabbixCheck(SlapdCheck):
    """
    slapd exporter for generating Open Metrics output
    """

    def __init__(self, output_file, state_filename=None):
        self._host = socket.getfqdn()
        SlapdCheck.__init__(self, output_file, state_filename)

    def _zabbix_metrics(self):
        """
        generator returning ZabbixMetric instances
        """
        for i in sorted(self._item_dict.keys()):
            if self._item_dict[i] is None:
                continue
            status, check_name, perf_data, _ = self._item_dict[i]
            if perf_data:
                for key, val in perf_data.items():
                    if key.endswith('_rate'):
                        continue
                    try:
                        yield ZabbixMetric(
                            self._host,
                            '{}[{}]'.format(check_name, key),
                            val,
                        )
                    except ValueError:
                        pass
            yield ZabbixMetric(self._host, 'test[{}]'.format(check_name), status)
        # end of _metrics()

    def output(self):
        """
        Outputs all results registered before with method result()
        """
        zabbix_pkt = list(self._zabbix_metrics())
        ZabbixSender(use_config=True).send(zabbix_pkt)
        # end of output()


def cli_run():
    run(ZabbixCheck)


if __name__ == '__main__':
    cli_run()
