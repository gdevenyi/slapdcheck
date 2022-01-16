# -*- coding: utf-8 -*-
"""
package/install module package slapdcheck
"""

import sys
import os
from setuptools import setup, find_packages

PYPI_NAME = 'slapdcheck'

BASEDIR = os.path.dirname(os.path.realpath(__file__))

sys.path.insert(0, os.path.join(BASEDIR, PYPI_NAME))
import __about__

setup(
    name=PYPI_NAME,
    license=__about__.__license__,
    version=__about__.__version__,
    description='OpenLDAP monitoring check',
    author=__about__.__author__,
    author_email=__about__.__mail__,
    maintainer=__about__.__author__,
    maintainer_email=__about__.__mail__,
    url='https://code.stroeder.com/ldap/slapdcheck',
    download_url='https://pypi.org/project/%s/#files' % (PYPI_NAME),
    keywords=['LDAP', 'OpenLDAP', 'slapd', 'monitoring'],
    packages=find_packages(exclude=['tests']),
    package_dir={'': '.'},
    test_suite='tests',
    python_requires='>=3.6',
    include_package_data=True,
    data_files=[],
    install_requires=[
        'setuptools',
        'ldap0>=0.6.4',
        'asn1crypto',
        'psutil',
    ],
    extras_require = {
        'metrics':  ['prometheus_client>=0.7.1'],
        'zabbix':  ['py-zabbix'],
    },
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'slapd_checkmk = slapdcheck.checkmk:cli_run',
            'slapdcheck_html = slapdcheck.html4:cli_run',
            'slapdcheck_json = slapdcheck.json:cli_run',
            'slapd_metrics = slapdcheck.metrics:cli_run',
            'slapd_zabbix_send = slapdcheck.zabbix:cli_run',
        ],
    },
)
