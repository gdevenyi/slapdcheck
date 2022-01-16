# -*- coding: utf-8 -*-
"""
slapdcheck.zabbix - generate output to be sent to ZABBIX trapper
"""

import socket

# from module package py-zabbix
from pyzabbix import ZabbixMetric, ZabbixSender

# local package imports
from . import run
from .base import CheckFormatter


class SlapdCheckZabbix(CheckFormatter):
    """
    ZABBIX sender
    """

    def __init__(self, output_file):
        self._host = socket.getfqdn()
        CheckFormatter.__init__(self, output_file)

    def output(self, check_items):
        zabbix_items = []
        for i in sorted(check_items.keys()):
            if check_items[i] is None:
                continue
            status, check_name, perf_data, _ = check_items[i]
            if perf_data:
                for key, val in perf_data.items():
                    if key.endswith('_rate'):
                        continue
                    try:
                        zabbix_items.append(
                            ZabbixMetric(
                                self._host,
                                '{}[{}]'.format(check_name, key),
                                val,
                            )
                        )
                    except ValueError:
                        pass
            zabbix_items.append(
                ZabbixMetric(
                    self._host,
                    'test[{}]'.format(check_name),
                    status
                )
            )
        ZabbixSender(use_config=True).send(zabbix_items)


def cli_run():
    run(SlapdCheckZabbix)


if __name__ == '__main__':
    cli_run()
