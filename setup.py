#!/usr/bin/python2
# -*- coding: utf-8 -*-
"""
package/install module package slapdcheck
"""

import sys
import os
from setuptools import setup, find_packages

PKG_NAME = 'slapdcheck'
BASEDIR = os.path.dirname(os.path.realpath(__file__))

sys.path.insert(0, os.path.join(BASEDIR, PKG_NAME))
import __about__

setup(
    name=PKG_NAME,
    license=__about__.__license__,
    version=__about__.__version__,
    description='OpenLDAP monitoring check',
    author=__about__.__author__,
    author_email='michael@stroeder.com',
    maintainer=__about__.__author__,
    maintainer_email='michael@stroeder.com',
    url='https://pypi.org/project/%s/' % (PKG_NAME),
    download_url='https://pypi.python.org/pypi/%s/' % (PKG_NAME),
    keywords=[
        'LDAP',
        'OpenLDAP',
        'slapd',
        'monitoring',
    ],
    packages=find_packages(exclude=['tests']),
    package_dir={'': '.'},
    test_suite='tests',
    python_requires='==2.7.*',
    include_package_data=True,
    install_requires=[
        'setuptools',
        'ldap0>=0.2.6',
    ],
    entry_points={
        'console_scripts': [
            'slapd_checkmk = slapdcheck.checkmk:run',
        ],
    },
    zip_safe=False,
)
