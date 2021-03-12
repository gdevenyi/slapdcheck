# -*- coding: utf-8 -*-
"""
slapdcheck.checkmk - local check for check_mk
"""

#-----------------------------------------------------------------------
# Import modules
#-----------------------------------------------------------------------

import os
import sys

# from module package prometheus_client
from prometheus_client import Gauge, CollectorRegistry
from prometheus_client.openmetrics.exposition import generate_latest

# local package imports
from slapdcheck import SlapdCheck

#-----------------------------------------------------------------------
# Classes
#-----------------------------------------------------------------------

class OpenMetricsCheck(SlapdCheck):
    """
    slapd exporter for generating Open Metrics output
    """

    def __init__(self, output_file, state_filename=None):
        SlapdCheck.__init__(self, output_file, state_filename)

    def output(self):
        """
        Outputs all check_mk results registered before with method result()
        """
        registry = CollectorRegistry()
        check_mk_performance = Gauge(
            'check_mk_performance_metrics', 'slapd performance metrics', ['name', 'metric_name'],
            registry=registry,
        )
        check_mk_status = Gauge(
            'check_mk_status',
            'slapd status metrics',
            ['name'],
            registry=registry,
        )
        for i in sorted(self._item_dict.keys()):
            if self._item_dict[i] is None:
                continue
            status, check_name, perf_data, _ = self._item_dict[i]
            if perf_data:
                for k, v in perf_data.items():
                    if k.endswith('_rate'):
                        continue
                    try:
                        check_mk_performance.labels(name=check_name, metric_name=k).set(v)
                    except ValueError:
                        pass
            check_mk_status.labels(name=check_name).set(status)
        sys.stdout.write(generate_latest(registry).decode('utf-8'))
        # end of output()


def run():
    """
    run as check_mk local check
    """
    slapd_check = OpenMetricsCheck(
        output_file=sys.stdout,
        state_filename=os.path.basename(sys.argv[0][:-3]),
    )
    slapd_check.run()


if __name__ == '__main__':
    run()
