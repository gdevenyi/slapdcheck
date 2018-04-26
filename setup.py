#!/usr/bin/python2
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
    long_description='Check script for monitoring OpenLDAP server (slapd)',
    author=__about__.__author__,
    author_email=__about__.__mail__,
    maintainer=__about__.__author__,
    maintainer_email=__about__.__mail__,
    url='https://www.stroeder.com/software.html',
    download_url='https://pypi.python.org/pypi/'+PYPI_NAME,
    keywords=['OpenLDAP', 'slapd', 'Monitoring'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
    ],
    packages=find_packages(exclude=['tests']),
    package_dir={'': '.'},
    test_suite='tests',
    python_requires='==2.7.*',
    include_package_data=True,
    install_requires=[
        'setuptools',
        'ldap0',
    ],
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'slapd_checkmk = slapdcheck.checkmk:run',
        ],
    }
)
