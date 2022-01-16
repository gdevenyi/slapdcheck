# -*- coding: utf-8 -*-
"""
slapdcheck.json - generate JSON output
"""

import json

# local package imports
from . import run
from .base import CheckFormatter


class SlapdCheckJSON(CheckFormatter):
    """
    for generating JSON output
    """

    def output(self, check_items):
        self._output_file.write(json.dumps(check_items))


def cli_run():
    run(SlapdCheckJSON)


if __name__ == '__main__':
    cli_run()
