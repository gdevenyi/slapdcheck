# -*- coding: utf-8 -*-
"""
slapdcheck.json - generate JSON output
"""

import json

# local package imports
from . import SlapdCheck, run


class SlapdCheckJSON(SlapdCheck):
    """
    for generating JSON output
    """

    def __init__(self, output_file, state_filename=None):
        SlapdCheck.__init__(self, output_file, state_filename)

    def output(self):
        """
        Outputs all results registered before with method result()
        """
        self._output_file.write(json.dumps(self._item_dict))
        # end of output()


def cli_run():
    run(SlapdCheckJSON)


if __name__ == '__main__':
    cli_run()
