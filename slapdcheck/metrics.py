# -*- coding: utf-8 -*-
"""
slapdcheck.metrics - Open Metrics output
"""

# from module package prometheus_client
from prometheus_client import Gauge, CollectorRegistry
from prometheus_client.openmetrics.exposition import generate_latest

# local package imports
from . import run
from .base import CheckFormatter


class OpenMetricsCheck(CheckFormatter):
    """
    slapd exporter for generating Open Metrics output
    """

    def output(self, check_items):
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
        for i in sorted(check_items.keys()):
            if check_items[i] is None:
                continue
            status, check_name, perf_data, _ = check_items[i]
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
