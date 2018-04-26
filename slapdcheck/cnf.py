# -*- coding: utf-8 -*-
"""
slapdcheck.cnf - Configuration constants
"""

from __future__ import absolute_import

import sys
import os

import ldap0

# constants for the check result codes
CHECK_RESULT_OK = 0
CHECK_RESULT_WARNING = 1
CHECK_RESULT_ERROR = 2
CHECK_RESULT_UNKNOWN = 3

# which check result to return in case server responds with
# ldap0.UNAVAILABLE_CRITICAL_EXTENSION for no-op search control
# set this to CHECK_RESULT_ERROR if certain your server supports the control
CHECK_RESULT_NOOP_SRCH_UNAVAILABLE = CHECK_RESULT_OK

# Timeout in seconds when connecting to local and remote LDAP servers
# used for ldap0.OPT_NETWORK_TIMEOUT and ldap0.OPT_TIMEOUT
LDAP_TIMEOUT = 4.0

# Timeout in seconds when connecting to slapd-sock listener
SLAPD_SOCK_TIMEOUT = 2.0

# Time in seconds for searching all entries with the noop search control
NOOP_SEARCH_TIMEOUT = 6.0
# at least search root entry should be present
MINIMUM_ENTRY_COUNT = 20

# acceptable time-delta [sec] of replication
# Using None disables checking the warn/critical level
SYNCREPL_TIMEDELTA_WARN = 5.0
SYNCREPL_TIMEDELTA_CRIT = 300.0
# hysteresis for syncrepl conditions
SYNCREPL_HYSTERESIS_WARN = 0.0
SYNCREPL_HYSTERESIS_CRIT = 10.0

# maximum percentage of failed syncrepl providers when to report error
SYNCREPL_PROVIDER_ERROR_PERCENTAGE = 50.0

# acceptable count of all outstanding operations
# Using None disables checking the warn/critical level
OPS_WAITING_WARN = 30
OPS_WAITING_CRIT = 60

# number of minimum connections expected
# if real connection count falls below this treshold it could mean
# that slapd is not reachable from LDAP clients
CONNECTIONS_WARN_LOWER = 3
# too many connections are bad too - depends on your expected number
# of LDAP clients with persistent connections
CONNECTIONS_WARN_UPPER = 1000

# Tresholds for thread-count-related warnings
# There should always be at least one active thread
THREADS_ACTIVE_WARN_LOWER = 1
# This should likely match what's configured in slapd.conf
THREADS_ACTIVE_WARN_UPPER = 6
# Too many pending threads should not occur
THREADS_PENDING_WARN = 5

CATCH_ALL_EXC = (Exception, ldap0.LDAPError)
#CATCH_ALL_EXC = None

# days to warn/error when checking server cert validity
CERT_ERROR_DAYS = 10
CERT_WARN_DAYS = 50

# set debug parameters for development (normally not needed)
PYLDAP_TRACE_LEVEL = int(os.environ.get('PYLDAP_TRACE_LEVEL', '0'))
ldap0._trace_level = PYLDAP_TRACE_LEVEL
ldap0._trace_file = sys.stderr
# ldap0.set_option(ldap0.OPT_DEBUG_LEVEL,255)
