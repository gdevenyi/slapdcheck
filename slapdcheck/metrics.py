# -*- coding: utf-8 -*-
"""
slapdcheck.checkmk - local check for check_mk
"""

#-----------------------------------------------------------------------
# Import modules
#-----------------------------------------------------------------------

# from module package prometheus_client
from prometheus_client import Gauge, CollectorRegistry
from prometheus_client.openmetrics.exposition import generate_latest

# local package imports
from . import SlapdCheck, run

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
                for key, val in perf_data.items():
                    if key.endswith('_rate'):
                        continue
                    try:
                        check_mk_performance.labels(name=check_name, metric_name=key).set(val)
                    except ValueError:
                        pass
            check_mk_status.labels(name=check_name).set(status)
        self._output_file.write(generate_latest(registry).decode('utf-8'))
        # end of output()


def cli_run():
    run(OpenMetricsCheck)


if __name__ == '__main__':
    cli_run()
