"""
slapdcheck.cnf - Configuration
"""

import os
import socket
import logging
from configparser import ConfigParser

import ldap0

__all__ = (
    'CHECK_RESULT_OK',
    'CHECK_RESULT_WARNING',
    'CHECK_RESULT_ERROR',
    'CHECK_RESULT_UNKNOWN',
    'CATCH_ALL_EXC',
    'CFG',
)

# name of default section in .ini file
DEFAULT_SECTION = 'slapdcheck'

# constants for the check result codes
CHECK_RESULT_OK = 0
CHECK_RESULT_WARNING = 1
CHECK_RESULT_ERROR = 2
CHECK_RESULT_UNKNOWN = 3

class DummyException(BaseException):
    pass

# catch-all exception
CATCH_ALL_EXC = (Exception, ldap0.LDAPError)
#CATCH_ALL_EXC = DummyException


class ConfigParameters:
    """
    method-less class containing all config params
    """
    __slots__ = (
        'cert_error_days',
        'cert_warn_days',
        'check_result_error',
        'check_result_ok',
        'check_result_unknown',
        'check_result_warning',
        'connections_warn_lower',
        'connections_warn_percentage',
        'ldap0_trace_level',
        'ldapi_uri',
        'ldaps_authz_id',
        'ldaps_uri',
        'ldap_timeout',
        'log_level',
        'minimum_entry_count',
        'ops_waiting_crit',
        'ops_waiting_warn',
        'server_id_min',
        'server_id_max',
        'slapd_sock_timeout',
        'state_file',
        'syncrepl_hysteresis_crit',
        'syncrepl_hysteresis_warn',
        'syncrepl_provider_error_percentage',
        'syncrepl_timedelta_crit',
        'syncrepl_timedelta_warn',
        'threads_active_warn_lower',
        'threads_active_warn_upper',
        'threads_pending_warn',
    )
    cfg_type_map = {
        'cert_error_days': int,
        'cert_warn_days': int,
        'connections_warn_lower': int,
        'connections_warn_percentage': float,
        'ldap_timeout': float,
        'minimum_entry_count': int,
        'ops_waiting_crit': int,
        'ops_waiting_warn': int,
        'server_id_min': int,
        'server_id_max': int,
        'slapd_sock_timeout': float,
        'syncrepl_hysteresis_crit': float,
        'syncrepl_hysteresis_warn': float,
        'syncrepl_provider_error_percentage': float,
        'syncrepl_timedelta_crit': float,
        'syncrepl_timedelta_warn': float,
        'threads_active_warn_lower': int,
        'threads_active_warn_upper': int,
        'threads_pending_warn': int,
        'ldap0_trace_level': int,
    }


    def __init__(self):

        # log level
        self.log_level = logging.WARN

        # path of state file
        self.state_file = 'slapdcheck.state'

        # LDAP URI for local connection over IPC (Unix domain socket)
        self.ldapi_uri = 'ldapi://'

        # LDAPS URL for checking local TLS connection
        self.ldaps_uri = 'ldaps://{}'.format(socket.getfqdn())

        # expected authz-Id returned for LDAPS connection
        self.ldaps_authz_id = 'dn:'

        # Timeout in seconds when connecting to local and remote LDAP servers
        # used for ldap0.OPT_NETWORK_TIMEOUT and ldap0.OPT_TIMEOUT
        self.ldap_timeout = 4.0

        # trace_level used for LDAPObject instances
        self.ldap0_trace_level = 0

        # Timeout in seconds when connecting to slapd-sock listener
        self.slapd_sock_timeout = 2.0

        # at least search root entry should be present
        self.minimum_entry_count = 20

        # acceptable time-delta [sec] of replication
        # Using None disables checking the warn/critical level
        self.syncrepl_timedelta_warn = 5.0
        self.syncrepl_timedelta_crit = 300.0
        # hysteresis for syncrepl conditions
        self.syncrepl_hysteresis_warn = 0.0
        self.syncrepl_hysteresis_crit = 10.0

        # maximum percentage of failed syncrepl providers when to report error
        self.syncrepl_provider_error_percentage = 50.0

        # acceptable count of all outstanding operations
        # Using None disables checking the warn/critical level
        self.ops_waiting_warn = 30
        self.ops_waiting_crit = 60

        # number of minimum connections expected
        # if real connection count falls below this treshold it could mean
        # that slapd is not reachable from LDAP clients
        self.connections_warn_lower = 3
        # warn if this percentage of max. file descriptors is reached
        self.connections_warn_percentage = 80.0

        # Tresholds for thread-count-related warnings
        # There should always be at least one active thread
        self.threads_active_warn_lower = 1
        # This should likely match what's configured in slapd.conf
        self.threads_active_warn_upper = 6
        # Too many pending threads should not occur
        self.threads_pending_warn = 5

        # days to warn/error when checking server cert validity
        self.cert_error_days = 10
        self.cert_warn_days = 50

        # minimum and maximum of valid serverID values
        # error status in case of unexpected values
        self.server_id_min = 1
        self.server_id_max = 4095

    def read_config(self, cfg_filename):
        """
        read and parse config file into dict
        """
        if not os.path.exists(cfg_filename):
            raise SystemExit('Configuration file %r is missing!' % (cfg_filename))
        cfg_parser = ConfigParser(
            interpolation=None,
            default_section=DEFAULT_SECTION,
        )
        cfg_parser.read([cfg_filename])
        for key in sorted(cfg_parser.defaults()):
            if not hasattr(self, key):
                raise ValueError('Unknown config key-word %r' % (key))
            type_func = self.cfg_type_map.get(key, str)
            raw_val = cfg_parser.get(DEFAULT_SECTION, key)
            try:
                val = type_func(raw_val)
            except ValueError as err:
                raise ValueError('Invalid value for %r. Expected %s string, but got %r' % (
                    key, type_func.__name__, raw_val
                )) from err
            setattr(CFG, key, val)
        # end of read_config()


CFG = ConfigParameters()
