# -*- coding: utf-8 -*-
"""
slapdcheck - module package which implements OpenLDAP monitor checks
"""

import sys
import socket
import string
import pprint
import logging
import os
import os.path
import time
from datetime import datetime, timezone
import shlex

import psutil

try:
    import lmdb
except ImportError:
    lmdb = None

import asn1crypto.pem
import asn1crypto.x509
import asn1crypto.keys

os.environ['LDAPNOINIT'] = '1'

# from ldap0 package
import ldap0
from ldap0.ldif import LDIFParser

# from internal sub-modules
from .__about__ import __version__
from .openldap import (
    SyncreplProviderTask,
    OpenLDAPMonitorCache,
    SlapdConnection,
)
from .cnf import (
    CATCH_ALL_EXC,
    CERT_ERROR_DAYS,
    CERT_WARN_DAYS,
    CHECK_RESULT_ERROR,
    CHECK_RESULT_NOOP_SRCH_UNAVAILABLE,
    CHECK_RESULT_OK,
    CHECK_RESULT_UNKNOWN,
    CHECK_RESULT_WARNING,
    CONNECTIONS_WARN_LOWER,
    CONNECTIONS_WARN_PERCENTAGE,
    LDAP_TIMEOUT,
    MINIMUM_ENTRY_COUNT,
    NOOP_SEARCH_TIMEOUT,
    OPS_WAITING_CRIT,
    OPS_WAITING_WARN,
    SLAPD_SOCK_TIMEOUT,
    SYNCREPL_HYSTERESIS_CRIT,
    SYNCREPL_HYSTERESIS_WARN,
    SYNCREPL_PROVIDER_ERROR_PERCENTAGE,
    SYNCREPL_TIMEDELTA_CRIT,
    SYNCREPL_TIMEDELTA_WARN,
    THREADS_ACTIVE_WARN_LOWER,
    THREADS_ACTIVE_WARN_UPPER,
    THREADS_PENDING_WARN,
)
from .state import CheckStateFile


class NoneException(BaseException):
    """
    A dummy exception class used for disabling exception handling
    """


class MonitoringCheck:
    """
    base class for a monitoring check
    """
    item_names = (())
    output_encoding = 'ascii'
    item_name_safe_chars = set(string.ascii_letters+string.digits+'_')

    def __init__(self, output_file, state_filename=None):
        """
        output_file
            fileobj where to write the output
        output_encoding
            encoding to use when writing output
            'ascii' is always safe, Nagios mandates 'utf-8'
        """
        self._item_dict = {}
        for item_name in self.item_names:
            self.add_item(item_name)
        self._output_file = output_file
        if state_filename is not None:
            # Initialize local state file and read old state if it exists
            self._state = CheckStateFile(state_filename)
            # Generate *new* state dict to be updated within check and stored
            # later
            self._next_state = {}
        self.script_name = os.path.basename(sys.argv[0])

    def _get_rate(self, key, current_val, time_span):
        last_val = int(self._state.data.get(key, '0'))
        if current_val < last_val:
            val1, val2 = last_val, last_val+current_val
        else:
            val1, val2 = last_val, current_val
        return (val2 - val1) / time_span

    def checks(self):
        """
        wrapper method implementing all checks, normally invoked by run()
        """
        raise Exception(
            "checks() not implemented in class %s.%s" % (
                self.__class__.__module__,
                self.__class__.__name__,
            )
        )

    def run(self):
        """
        wrapper method for running all checks with outer expcetion handling
        """
        try:
            try:
                self.checks()
            except Exception:
                # Log unhandled exception
                err_lines = [66 * '-']
                err_lines.append(
                    '----------- %s.__class__.__dict__ -----------' % (self.__class__.__name__,)
                )
                err_lines.append(
                    pprint.pformat(self.__class__.__dict__, indent=1, width=66, depth=None))
                err_lines.append('----------- vars() -----------')
                err_lines.append(
                    pprint.pformat(vars(), indent=1, width=66, depth=None))
                logging.exception('\n'.join(err_lines))
        finally:
            self.output()
            if self._state:
                self._state.write_state(self._next_state)

    def add_item(self, item_name):
        """
        Preregister a check item by name
        """
        # FIX ME! Protect the following lines with a lock!
        if item_name in self._item_dict:
            raise ValueError('Check item name %r already exists.' % (item_name,))
        self._item_dict[item_name] = None

    def subst_item_name_chars(self, item_name):
        """
        Replace special chars in s
        """
        s_list = []
        for char in item_name:
            if char not in self.item_name_safe_chars:
                s_list.append('_')
            else:
                s_list.append(char)
        return ''.join(s_list)  # _subst_item_name_chars()

    def serialize_perf_data(self, performance_data):
        """
        return str representation of :performance_data: specific
        for a certain monitoring system
        """
        return str(performance_data)

    def result(self, status, item_name, check_output, **performance_data):
        """
        Registers check_mk result to be output later
        status
           integer indicating status
        item_name
           the check_mk item name
        """
        # Provoke KeyError if item_name is not known
        try:
            self._item_dict[item_name]
        except KeyError:
            raise ValueError('item_name %r not in known item names %r' % (
                item_name,
                self._item_dict.keys(),
            ))
        self._item_dict[item_name] = (
            status,
            item_name,
            {
                key: val
                for key, val in performance_data.items()
                if val is not None
            },
            check_output or '',
        )
        # end of result()

    def output(self):
        """
        Outputs all results registered before with method result()
        """


class SlapdCheck(MonitoringCheck):
    """
    Check class for OpenLDAP's slapd
    """
    item_names = (
        'SlapdCert',
        'SlapdCheckTime',
        'SlapdConfig',
        'SlapdMonitor',
        'SlapdConns',
        'SlapdDatabases',
        'SlapdStart',
        'SlapdOps',
        'SlapdProviders',
        'SlapdProc',
        'SlapdReplTopology',
        'SlapdSASLHostname',
        'SlapdSelfConn',
        'SlapdSock',
        'SlapdStats',
        'SlapdThreads',
        'SlapdVersion',
    )
    vendor_info_prefix = 'OpenLDAP: slapd '

    def __init__(self, output_file, state_filename=None):
        MonitoringCheck.__init__(self, output_file, state_filename)
        self._ldapi_conn = None
        self._config_attrs = {}
        self._monitor_cache = {}
        self._proc_info = {}

    def _check_sasl_hostname(self):
        """
        check whether SASL hostname is resolvable
        """
        try:
            olc_sasl_host = self._config_attrs['olcSaslHost'][0]
        except (KeyError, IndexError):
            self.result(
                CHECK_RESULT_OK,
                'SlapdSASLHostname',
                'olcSaslHost not set'
            )
        else:
            try:
                _ = socket.getaddrinfo(olc_sasl_host, None)
            except socket.gaierror as socket_err:
                self.result(
                    CHECK_RESULT_WARNING,
                    'SlapdSASLHostname',
                    'olcSaslHost %r not found: %r' % (olc_sasl_host, socket_err),
                )
            else:
                self.result(
                    CHECK_RESULT_OK,
                    'SlapdSASLHostname',
                    'olcSaslHost %r found' % (olc_sasl_host,),
                )
        # end of _check_sasl_hostname()

    def _check_tls_file(self):
        # try to read CA and server cert/key files
        file_read_errors = []
        tls_pem = {}
        for tls_attr_name in (
                'olcTLSCACertificateFile',
                'olcTLSCertificateFile',
                'olcTLSCertificateKeyFile',
            ):
            try:
                fname = self._config_attrs[tls_attr_name][0]
            except KeyError:
                file_read_errors.append(
                    'Attribute %r not set' % (tls_attr_name,)
                )
                continue
            try:
                with open(fname, 'rb') as tls_pem_file:
                    tls_pem[tls_attr_name] = asn1crypto.pem.unarmor(
                        tls_pem_file.read(),
                        multiple=False,
                    )
            except CATCH_ALL_EXC as exc:
                file_read_errors.append(
                    'Error reading %r: %s' % (fname, exc)
                )
        if file_read_errors:
            # no crypto modules present => abort
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdCert',
                ' / '.join(file_read_errors)
            )
            return
        cert = asn1crypto.x509.Certificate.load(tls_pem['olcTLSCertificateFile'][2])
        key = asn1crypto.keys.RSAPrivateKey.load(tls_pem['olcTLSCertificateKeyFile'][2])
        cert_not_before = cert['tbs_certificate']['validity']['not_before'].native
        cert_not_after = cert['tbs_certificate']['validity']['not_after'].native
        breakpoint()
        cert_modulus = cert['tbs_certificate']['subject_public_key_info']['public_key'].parsed['modulus'].native
        key_modulus = key['modulus'].native
        modulus_match = cert_modulus == key_modulus
        utc_now = datetime.now(tz=timezone.utc)
        cert_validity_rest = cert_not_after - utc_now
        if modulus_match is False or cert_validity_rest.days <= CERT_ERROR_DAYS:
            cert_check_result = CHECK_RESULT_ERROR
        elif cert_validity_rest.days <= CERT_WARN_DAYS:
            cert_check_result = CHECK_RESULT_WARNING
        else:
            cert_check_result = CHECK_RESULT_OK
        # less exact usage of .days because of older
        # Python versions without timedelta.total_seconds()
        elapsed_percentage = 100 - 100*cert_validity_rest.days/(cert_not_after-cert_not_before).days
        self.result(
            cert_check_result,
            'SlapdCert',
            (
                'Server cert %r valid until %s UTC '
                '(%d days left, %0.1f %% elapsed), '
                'modulus_match==%r'
            ) % (
                self._config_attrs['olcTLSCertificateFile'][0],
                cert_not_after,
                cert_validity_rest.days,
                elapsed_percentage,
                modulus_match,
            ),
            not_after=cert_not_after.timestamp(),
            not_before=cert_not_before.timestamp(),
        )
        # end of _check_tls_file()

    def _check_local_ldaps(self, ldaps_uri, my_authz_id):
        """
        Connect and bind to local slapd like a remote client
        mainly to check whether LDAPS with client cert works and maps expected authz-DN
        """
        client_tls_options = {
            # Set TLS connection options from TLS attribute read from
            # configuration context
            # path name of file containing all trusted CA certificates
            'cacert_filename': self._config_attrs['olcTLSCACertificateFile'][0],
            # Use slapd server cert/key for client authentication
            # just like used for syncrepl
            'client_cert_filename': self._config_attrs['olcTLSCertificateFile'][0],
            'client_key_filename': self._config_attrs['olcTLSCertificateKeyFile'][0],
        }
        try:
            ldaps_conn = SlapdConnection(
                ldaps_uri,
                tls_options=client_tls_options,
            )
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdSelfConn',
                'Error connecting to %r: %s / client_tls_options = %r' % (
                    ldaps_uri,
                    exc,
                    client_tls_options,
                )
            )
        else:
            # Send LDAP Who Am I ? extended operation and check whether
            # returned authz-DN is correct
            try:
                wai = ldaps_conn.whoami_s()
            except CATCH_ALL_EXC as exc:
                self.result(
                    CHECK_RESULT_ERROR,
                    'SlapdSelfConn',
                    'Error during Who Am I? ext.op. on %r: %s' % (
                        ldaps_conn.uri,
                        exc,
                    ),
                )
            else:
                if wai != my_authz_id:
                    self.result(
                        CHECK_RESULT_ERROR,
                        'SlapdSelfConn',
                        'Received unexpected authz-DN from %r: %r' % (
                            ldaps_conn.uri,
                            wai,
                        ),
                        connect_latency=ldaps_conn.connect_latency,
                    )
                else:
                    self.result(
                        CHECK_RESULT_OK,
                        'SlapdSelfConn',
                        'successfully bound to %r as %r' % (
                            ldaps_conn.uri,
                            wai,
                        ),
                        connect_latency=ldaps_conn.connect_latency,
                    )
            ldaps_conn.unbind_s()
        # end of _check_local_ldaps()

    def _check_slapd_sock(self):
        """
        Send MONITOR request to all back-sock listeners
        """
        def _read_sock_monitor(sock_path):
            """
            Send MONITOR request to Unix domain socket in `sock_path'
            """
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as _sock:
                _sock.connect(sock_path)
                _sock.settimeout(SLAPD_SOCK_TIMEOUT)
                _sock_f = _sock.makefile('rwb')
                _sock_f.write(b'MONITOR\n')
                _sock_f.flush()
                res = _sock_f.read()
            return res
            # end of _read_sock_monitor

        def _parse_sock_response(sock_response):
            # strip ENTRY\n from response and parse the rest as LDIF
            _, sock_monitor_entry = LDIFParser.frombuf(
                sock_response[6:],
                ignored_attr_types=[b'sockLogLevel'],
                max_entries=1
            ).list_entry_records()[0]
            sock_perf_data = {}
            # only add numeric monitor data to performance metrics
            for metric_key in sock_monitor_entry.keys():
                try:
                    sock_perf_data[metric_key.decode('ascii')] = float(sock_monitor_entry[metric_key][0])
                except ValueError:
                    continue
            return sock_perf_data # end of _parse_sock_response()

        try:
            sock_listeners = self._ldapi_conn.get_sock_listeners()
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdSock',
                'error retrieving back-sock listeners: %s' % (exc,)
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdSock',
                'Found %d back-sock listeners' % (len(sock_listeners),)
            )
            for item_name, sock_listener in sock_listeners.items():
                self.add_item(item_name)
                sock_path, sock_ops = sock_listener
                try:
                    sock_response = _read_sock_monitor(sock_path)
                except CATCH_ALL_EXC as exc:
                    self.result(
                        CHECK_RESULT_ERROR,
                        item_name,
                        'Connecting to %s listener %r failed: %s' % (
                            sock_ops, sock_path, exc,
                        ),
                    )
                else:
                    check_msgs = ['Connected to %s listener %r and received %d bytes' % (
                        sock_ops,
                        sock_path,
                        len(sock_response),
                    )]
                    try:
                        sock_perf_data = _parse_sock_response(sock_response)
                    except (IndexError, ValueError) as err:
                        sock_perf_data = {}
                        check_result = CHECK_RESULT_ERROR
                        check_msgs.append('parsing error: %s' % (err,))
                    else:
                        check_result = CHECK_RESULT_OK
                    self.result(
                        check_result,
                        item_name,
                        ', '.join(check_msgs),
                        **sock_perf_data,
                    )
        # end of _check_slapd_sock()

    def _read_pid(self):
        """
        read slapd's PID from file
        """
        pid_filename = self._config_attrs['olcPidFile'][0]
        try:
            with open(pid_filename, 'r', encoding='utf-8') as pid_file:
                slapd_pid = int(pid_file.read().strip())
        except IOError:
            slapd_pid = None
        return slapd_pid
        # end of _read_pid()

    def _check_version(self):
        """
        extract version/build-time tuple
        """
        vendor_info = self._monitor_cache.get_value('', 'monitoredInfo')
        check_res = CHECK_RESULT_OK
        if not vendor_info.startswith(self.vendor_info_prefix):
            check_res = CHECK_RESULT_ERROR
        try:
            slapd_version, rest = vendor_info[len(self.vendor_info_prefix):].split(' ', 1)
        except ValueError:
            check_res = CHECK_RESULT_ERROR
        if not (rest[0] == '(' and rest[-1] == ')'):
            check_res = CHECK_RESULT_ERROR
        else:
            try:
                build_time = datetime.strptime(rest[1:-1], '%b %d %Y %H:%M:%S').timestamp()
            except ValueError:
                build_time = 0.0
                check_res = CHECK_RESULT_ERROR
        self.result(
            check_res,
            'SlapdVersion',
            vendor_info,
            version=slapd_version,
            build_time=build_time,
        )

    def _get_proc_info(self):
        self._proc_info = psutil.Process(self._read_pid()).as_dict()
        pmem = self._proc_info['memory_info']
        ctx_sw = self._proc_info['num_ctx_switches']
        self.result(
            CHECK_RESULT_OK,
            'SlapdProc',
            '%d process information items' % (len(self._proc_info),),
            pmem_rss=pmem.rss,
            pmem_vms=pmem.vms,
            pmem_shared=pmem.shared,
            pmem_text=pmem.text,
            pmem_lib=pmem.lib,
            pmem_dirty=pmem.dirty,
            ctx_switches_voluntary=ctx_sw.voluntary,
            ctx_switches_involuntary=ctx_sw.involuntary,
        )

    def _check_slapd_start(self):
        """
        check whether slapd should be restarted
        """
        start_time = self._monitor_cache.get_value(
            'cn=Start,cn=Time',
            'monitorTimestamp'
        ).replace(tzinfo=timezone.utc)
        utc_now = datetime.now(tz=timezone.utc)
        newer_files = []
        check_filenames = [
            self._config_attrs[fattr][0]
            for fattr in (
                'olcConfigDir',
                'olcConfigFile',
                'olcTLSCACertificateFile',
                'olcTLSCertificateFile',
                'olcTLSCertificateKeyFile',
                'olcTLSDHParamFile',
            )
            if fattr in self._config_attrs
        ]
        # optionally extend the list of files to be checked with slapd exec
        # file read from the argument file if present
        if 'olcArgsFile' in self._config_attrs:
            with open(self._config_attrs['olcArgsFile'][0]) as args_file:
                check_filenames.append(shlex.split(args_file.read())[0])
        for check_filename in check_filenames:
            try:
                check_file_stat = os.stat(check_filename)
                check_file_mtime = datetime.fromtimestamp(
                    int(max(check_file_stat.st_mtime, check_file_stat.st_ctime)),
                    timezone.utc,
                )
            except OSError:
                pass
            else:
                if check_file_mtime > start_time:
                    newer_files.append('%s (%s)' % (check_filename, check_file_mtime))
        if newer_files:
            self.result(
                CHECK_RESULT_WARNING,
                'SlapdStart',
                'slapd[%d] needs restart! Started at %s, %s ago, files with newer status: %s' % (
                    self._read_pid(),
                    start_time,
                    utc_now-start_time,
                    ', '.join(newer_files),
                )
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdStart',
                'slapd[%s] started at %s, %s ago' % (
                    self._read_pid(),
                    start_time,
                    utc_now-start_time,
                ),
                start_time=start_time.timestamp(),
            )
        # end of _check_slapd_start()

    def _get_local_csns(self, syncrepl_list):
        local_csn_dict = {}
        for db_num, db_suffix, _ in syncrepl_list:
            local_csn_dict[db_suffix] = []
            item_name = '_'.join((
                'SlapdSyncRepl',
                str(db_num),
                self.subst_item_name_chars(db_suffix),
            ))
            self.add_item(item_name)
            try:
                local_csn_dict[db_suffix] = self._ldapi_conn.get_context_csn(db_suffix)
            except CATCH_ALL_EXC as exc:
                self.result(
                    CHECK_RESULT_ERROR,
                    item_name,
                    'Error while retrieving local contextCSN of %r: %s' % (
                        db_suffix,
                        exc,
                    ),
                )
            else:
                if not local_csn_dict[db_suffix]:
                    self.result(
                        CHECK_RESULT_UNKNOWN,
                        item_name,
                        'no local contextCSN values for %r' % (
                            db_suffix,
                        ),
                    )
        return local_csn_dict # end of _get_local_csns()

    def _check_conns(self):
        """
        check whether current connection count is healthy
        """
        current_connections = self._monitor_cache.get_value(
            'cn=Current,cn=Connections',
            'monitorCounter',
        )
        max_connections = self._monitor_cache.get_value(
            'cn=Max File Descriptors,cn=Connections',
            'monitorCounter',
        )
        current_connections_percentage = 100.0 * current_connections / max_connections
        state = CHECK_RESULT_WARNING * int(
            current_connections < CONNECTIONS_WARN_LOWER or
            current_connections_percentage >= CONNECTIONS_WARN_PERCENTAGE
        )
        self.result(
            state,
            'SlapdConns',
            '%d open connections (max. %d)' % (current_connections, max_connections),
            count=current_connections,
            percent=current_connections_percentage,
        )
        # end of _check_conns()

    def _check_threads(self):
        """
        check whether current thread count is healthy
        """
        threads_active = self._monitor_cache.get_value(
            'cn=Active,cn=Threads',
            'monitoredInfo',
        )
        threads_pending = self._monitor_cache.get_value(
            'cn=Pending,cn=Threads',
            'monitoredInfo',
        )
        threads_max = self._monitor_cache.get_value(
            'cn=Max,cn=Threads',
            'monitoredInfo',
        )
        state = int(
            threads_active < THREADS_ACTIVE_WARN_LOWER or
            threads_active > THREADS_ACTIVE_WARN_UPPER or
            threads_pending > THREADS_PENDING_WARN
        )
        self.result(
            state,
            'SlapdThreads',
            'Thread counts active:%d pending: %d' % (threads_active, threads_pending),
            threads_active=threads_active,
            threads_pending=threads_pending,
            threads_max=threads_max,
        )
        # end of _check_threads()

    def _get_slapd_perfstats(self):
        """
        Get operation counters
        """
        # For rate calculation we need the timespan since last run
        ops_counter_time = time.time()
        last_ops_counter_time = float(
            self._state.data.get(
                'ops_counter_time',
                ops_counter_time-60.0
            )
        )
        last_time_span = ops_counter_time - last_ops_counter_time
        self._next_state['ops_counter_time'] = ops_counter_time
        stats_bytes = self._monitor_cache.get_value(
            'cn=Bytes,cn=Statistics', 'monitorCounter')
        stats_entries = self._monitor_cache.get_value(
            'cn=Entries,cn=Statistics', 'monitorCounter')
        stats_pdu = self._monitor_cache.get_value(
            'cn=PDU,cn=Statistics', 'monitorCounter')
        stats_referrals = self._monitor_cache.get_value(
            'cn=Referrals,cn=Statistics', 'monitorCounter')
        stats_bytes_rate = self._get_rate('stats_bytes', stats_bytes, last_time_span)
        stats_entries_rate = self._get_rate('stats_entries', stats_entries, last_time_span)
        stats_pdu_rate = self._get_rate('stats_pdu', stats_pdu, last_time_span)
        stats_referrals_rate = self._get_rate('stats_referrals', stats_pdu, last_time_span)
        self._next_state['stats_bytes'] = stats_bytes
        self._next_state['stats_entries'] = stats_entries
        self._next_state['stats_pdu'] = stats_pdu
        self._next_state['stats_referrals'] = stats_referrals
        self.result(
            CHECK_RESULT_OK,
            'SlapdStats',
            (
                'Stats: %d bytes (%0.1f bytes/sec) /'
                ' %d entries (%0.1f entries/sec) /'
                ' %d PDUs (%0.1f PDUs/sec) /'
                ' %d referrals (%0.1f referrals/sec)'
            ) % (
                stats_bytes,
                stats_bytes_rate,
                stats_entries,
                stats_entries_rate,
                stats_pdu,
                stats_pdu_rate,
                stats_referrals,
                stats_referrals_rate,
            ),
            stats_bytes_total=stats_bytes,
            stats_entries_total=stats_entries,
            stats_bytes_rate=stats_bytes_rate,
            stats_entries_rate=stats_entries_rate,
            stats_pdu_total=stats_pdu,
            stats_pdu_rate=stats_pdu_rate,
            stats_referrals=stats_referrals_rate,
        )
        monitor_ops_counters = self._monitor_cache.operation_counters()
        if monitor_ops_counters:
            ops_all_initiated = 0
            ops_all_completed = 0
            ops_all_waiting = 0
            for ops_name, ops_initiated, ops_completed in monitor_ops_counters:
                item_name = 'SlapdOps_%s' % (ops_name,)
                self.add_item(item_name)
                self._next_state[ops_name+'_ops_initiated'] = ops_initiated
                self._next_state[ops_name+'_ops_completed'] = ops_completed
                ops_waiting = ops_initiated - ops_completed
                ops_all_waiting += ops_waiting
                ops_all_completed += ops_completed
                ops_all_initiated += ops_initiated
                ops_initiated_rate = self._get_rate(
                    ops_name+'_ops_initiated',
                    ops_initiated,
                    last_time_span,
                )
                ops_completed_rate = self._get_rate(
                    ops_name+'_ops_completed',
                    ops_completed,
                    last_time_span,
                )
                self.result(
                    CHECK_RESULT_OK,
                    item_name,
                    (
                        'completed %d of %d operations '
                        '(%0.2f/s completed, %0.2f/s initiated, %d waiting)'
                    ) % (
                        ops_completed,
                        ops_initiated,
                        ops_completed_rate,
                        ops_initiated_rate,
                        ops_waiting,
                    ),
                    ops_completed_total=ops_completed,
                    ops_initiated_total=ops_initiated,
                    ops_completed_rate=ops_completed_rate,
                    ops_initiated_rate=ops_initiated_rate,
                    ops_waiting=ops_waiting,
                )
            ops_all_initiated_rate = self._get_rate(
                'ops_all_initiated',
                ops_all_initiated,
                last_time_span,
            )
            ops_all_completed_rate = self._get_rate(
                'ops_all_completed',
                ops_all_completed,
                last_time_span,
            )
            self._next_state['ops_all_initiated'] = ops_all_initiated
            self._next_state['ops_all_completed'] = ops_all_completed
            if OPS_WAITING_CRIT is not None and ops_all_waiting > OPS_WAITING_CRIT:
                state = CHECK_RESULT_ERROR
            elif OPS_WAITING_WARN is not None and ops_all_waiting > OPS_WAITING_WARN:
                state = CHECK_RESULT_WARNING
            else:
                state = CHECK_RESULT_OK
            self.result(
                state, 'SlapdOps',
                (
                    '%d operation types /'
                    ' completed %d of %d operations (%0.2f/s completed,'
                    ' %0.2f/s initiated,'
                    ' %d waiting)'
                ) % (
                    len(monitor_ops_counters),
                    ops_all_completed,
                    ops_all_initiated,
                    ops_all_completed_rate,
                    ops_all_initiated_rate,
                    ops_all_waiting,
                ),
                ops_completed_total=ops_all_completed,
                ops_initiated_total=ops_all_initiated,
                ops_completed_rate=ops_all_completed_rate,
                ops_initiated_rate=ops_all_initiated_rate,
                ops_waiting=ops_all_waiting,
            )
        # end of _get_slapd_perfstats()

    def _check_mdb_entry_count(self, db_num, db_suffix, db_dir):
        """
        returns number of entries in id2e sub-DB of MDB env in :db_dir:
        """
        try:
            mdb_entry_count = self._monitor_cache.get_value(
                'cn=Database %d,cn=Databases' % (db_num,),
                'olmMDBEntries',
            )
            mdb_entries_source = 'olmMDBEntries'
        except KeyError:
            if lmdb is None:
                # fall-back to directly access .mdb files not possible
                return
            mdb_env = lmdb.open(db_dir, max_dbs=2)
            with mdb_env.begin() as mdb_txn:
                mdb_id2e_subdb = mdb_env.open_db(b'id2e', txn=mdb_txn, create=False)
                mdb_id2e_stat = mdb_txn.stat(mdb_id2e_subdb)
            mdb_entry_count = mdb_id2e_stat['entries']
            mdb_entries_source = 'mdb_env'
        item_name = '_'.join((
            'SlapdEntryCount',
            str(db_num),
            self.subst_item_name_chars(db_suffix),
        ))
        self.add_item(item_name)
        self.result(
            CHECK_RESULT_WARNING*(mdb_entry_count < MINIMUM_ENTRY_COUNT),
            item_name,
            '%r has %d entries (%s)' % (
                db_suffix,
                mdb_entry_count,
                mdb_entries_source,
            ),
            mdb_entry_count=mdb_entry_count,
        )
        # end of _check_mdb_entry_count()

    def _check_mdb_size(self, db_num, db_suffix, db_dir):
        """
        Checks free MDB pages

        If ITS#7770 is not available (prior to OpenLDAP 2.4.48) then
        this does nothing.
        """
        try:
            mdb_pages_max = self._monitor_cache.get_value(
                'cn=Database %d,cn=Databases' % (db_num,),
                'olmMDBPagesMax',
            )
            mdb_pages_used = self._monitor_cache.get_value(
                'cn=Database %d,cn=Databases' % (db_num,),
                'olmMDBPagesUsed',
            )
        except KeyError:
            return
        item_name = '_'.join((
            'SlapdMDBSize',
            str(db_num),
            self.subst_item_name_chars(db_suffix),
        ))
        self.add_item(item_name)
        mdb_use_percentage = 100 * float(mdb_pages_used) / float(mdb_pages_max)
        if mdb_use_percentage <= 70.0:
            check_result = CHECK_RESULT_OK
        elif mdb_use_percentage <= 90.0:
            check_result = CHECK_RESULT_WARNING
        else:
            check_result = CHECK_RESULT_ERROR
        self.result(
            check_result,
            item_name,
            'LMDB in %r uses %d of max. %d pages (%0.1f %%)' % (
                db_dir,
                mdb_pages_used,
                mdb_pages_max,
                mdb_use_percentage,
            ),
            mdb_pages_used=mdb_pages_used,
            mdb_pages_max=mdb_pages_max,
            mdb_use_percentage=mdb_use_percentage,
        )
        # end of _check_mdb_size()

    def _check_databases(self):
        try:
            db_suffixes = self._ldapi_conn.db_suffixes()
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdDatabases',
                'error retrieving DB suffixes: %s' % (exc,)
            )
            return
        self.result(
            CHECK_RESULT_OK,
            'SlapdDatabases',
            'Found %d real databases: %s' % (
                len(db_suffixes),
                ' / '.join([
                    '{%d}%s: %s' % (n, t, s)
                    for n, s, t, _ in db_suffixes
                ]),
            ),
            count=len(db_suffixes),
        )
        for db_num, db_suffix, db_type, db_dir in db_suffixes:
            # Check file sizes of MDB database files
            if db_type == 'mdb':
                self._check_mdb_size(db_num, db_suffix, db_dir)
                self._check_mdb_entry_count(db_num, db_suffix, db_dir)
        # end of _check_databases()

    def _check_providers(self, syncrepl_topology):
        """
        test connection to each provider
        """
        remote_csn_dict = {}
        syncrepl_target_fail_msgs = []
        task_dict = {}
        task_connect_latency = {}

        for syncrepl_target_uri in syncrepl_topology.keys():
            # start separate threads for parallelly connecting to slapd providers
            task_dict[syncrepl_target_uri] = SyncreplProviderTask(
                self,
                syncrepl_topology,
                syncrepl_target_uri,
            )
            task_dict[syncrepl_target_uri].start()

        # now wait for the spawned threads to finish and collect the results
        for syncrepl_target_uri in syncrepl_topology.keys():
            task = task_dict[syncrepl_target_uri]
            task.join()
            if task.remote_csn_dict:
                remote_csn_dict[syncrepl_target_uri] = task.remote_csn_dict
            if task.err_msgs:
                syncrepl_target_fail_msgs.extend(task.err_msgs)
            if task.connect_latency is not None:
                task_connect_latency[syncrepl_target_uri] = task.connect_latency

        if syncrepl_target_fail_msgs or \
           len(remote_csn_dict) < len(syncrepl_topology):
            slapd_provider_percentage = 100 * len(remote_csn_dict) / len(syncrepl_topology)
            if slapd_provider_percentage >= SYNCREPL_PROVIDER_ERROR_PERCENTAGE:
                check_result = CHECK_RESULT_WARNING
            else:
                check_result = CHECK_RESULT_ERROR
        else:
            slapd_provider_percentage = 100.0
            check_result = CHECK_RESULT_OK
        self.result(
            check_result,
            'SlapdProviders',
            'Connected to %d of %d (%0.1f%%) providers: %s' % (
                len(remote_csn_dict),
                len(syncrepl_topology),
                slapd_provider_percentage,
                ' / '.join(syncrepl_target_fail_msgs),
            ),
            count=len(remote_csn_dict),
            total=len(syncrepl_topology),
            percent=slapd_provider_percentage,
            avg_latency=(
                sum(task_connect_latency.values())/len(task_connect_latency)
                if task_connect_latency
                else 0.0
            ),
            max_latency=(
                max(task_connect_latency.values())
                if task_connect_latency
                else 0.0
            ),
        )
        return remote_csn_dict # end of _check_providers()

    def _get_syncrepl_topology(self):
        """
        retrieve syncrepl topology
        """
        syncrepl_topology = {}
        syncrepl_list = []
        try:
            syncrepl_list, syncrepl_topology = self._ldapi_conn.get_syncrepl_topology()
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdReplTopology',
                'Error getting syncrepl topology on %r: %s' % (
                    self._ldapi_conn.uri,
                    exc,
                ),
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdReplTopology',
                'successfully retrieved syncrepl topology with %d items: %s' % (
                    len(syncrepl_topology),
                    syncrepl_topology,
                )
            )
        return syncrepl_list, syncrepl_topology
        # end of _get_syncrepl_topology()

    def _check_provider_conns(self, local_csn_dict, syncrepl_list, syncrepl_topology):
        """
        Connect and bind to all replicas to check whether they are
        reachable and retrieve their context CSNs
        """

        remote_csn_dict = self._check_providers(syncrepl_topology)

        state = CHECK_RESULT_WARNING

        now = time.time()

        for db_num, db_suffix, _ in syncrepl_list:

            item_name = '_'.join((
                'SlapdSyncRepl',
                str(db_num),
                self.subst_item_name_chars(db_suffix),
            ))
            issues = []

            if not local_csn_dict[db_suffix]:
                # Message output done before => silent here
                state = CHECK_RESULT_UNKNOWN
                issues.append('no local CSNs avaiable => skip')
                continue

            max_csn_timedelta = 0.0

            for syncrepl_target_uri in syncrepl_topology:

                try:
                    remote_csn_parsed_dict = remote_csn_dict[syncrepl_target_uri][db_suffix]
                except KeyError as key_error:
                    issues.append(
                        'KeyError for %r / %r: %s' % (
                            syncrepl_target_uri,
                            db_suffix,
                            key_error,
                        )
                    )
                    continue

                for server_id, local_csn_timestamp in local_csn_dict[db_suffix].items():

                    if not server_id in remote_csn_parsed_dict:
                        state = CHECK_RESULT_WARNING
                        issues.append(
                            'contextCSN of %s missing on replica %r' % (
                                server_id,
                                syncrepl_target_uri,
                            )
                        )
                        continue

                    remote_csn_timestamp = remote_csn_parsed_dict[server_id]

                    csn_timedelta = abs(local_csn_timestamp-remote_csn_timestamp)

                    if csn_timedelta > max_csn_timedelta:
                        max_csn_timedelta = csn_timedelta
                    if csn_timedelta:
                        issues.append(
                            '%s contextCSN delta for %s: %0.1f s' % (
                                syncrepl_target_uri,
                                server_id,
                                csn_timedelta
                            )
                        )

            if SYNCREPL_TIMEDELTA_CRIT is not None and \
               max_csn_timedelta > SYNCREPL_TIMEDELTA_CRIT:
                old_critical_timestamp = float(
                    self._state.data.get(
                        item_name+'_critical',
                        str(now))
                    )
                if now - old_critical_timestamp > SYNCREPL_HYSTERESIS_CRIT:
                    state = CHECK_RESULT_ERROR
                self._next_state[item_name+'_critical'] = old_critical_timestamp
            else:
                self._next_state[item_name + '_critical'] = -1.0
            if SYNCREPL_TIMEDELTA_WARN is not None and \
                max_csn_timedelta > SYNCREPL_TIMEDELTA_WARN:
                old_warn_timestamp = float(
                    self._state.data.get(
                        item_name + '_warning',
                        str(now)
                    )
                )
                if now - old_warn_timestamp > SYNCREPL_HYSTERESIS_WARN:
                    state = CHECK_RESULT_WARNING
                self._next_state[item_name+'_warning'] = old_warn_timestamp
            else:
                self._next_state[item_name+'_warning'] = -1.0

            if not issues:
                state = 0
                issues.append('no replication issues determined')

            self.result(
                state,
                item_name,
                '%r max. contextCSN delta: %0.1f / %s' % (
                    db_suffix,
                    max_csn_timedelta,
                    ' / '.join(issues),
                ),
                max_csn_timedelta=max_csn_timedelta,
            )

        # end of _check_provider_conns()

    def checks(self):

        check_started = time.time()

        # Get command-line arguments
        ldaps_uri = sys.argv[2] or 'ldaps://%s' % socket.getfqdn()
        my_authz_id = sys.argv[3]

        local_ldapi_url = sys.argv[1] or 'ldapi:///'
        try:
            self._ldapi_conn = SlapdConnection(local_ldapi_url)
            # Find out whether bind worked
            local_wai = self._ldapi_conn.whoami_s()
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdConfig',
                'Error while connecting to %r: %s' % (
                    local_ldapi_url,
                    exc,
                )
            )
            return

        # read cn=config
        #---------------
        try:
            _ = self._ldapi_conn.get_naming_context_attrs()
            self._config_attrs = self._ldapi_conn.read_s(
                self._ldapi_conn.configContext[0],
                attrlist=[
                    'olcArgsFile',
                    'olcConfigDir',
                    'olcConfigFile',
                    'olcPidFile',
                    'olcSaslHost',
                    'olcServerID',
                    'olcThreads',
                    'olcTLSCACertificateFile',
                    'olcTLSCertificateFile',
                    'olcTLSCertificateKeyFile',
                    'olcTLSDHParamFile',
                ],
            ).entry_s
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdConfig',
                'Error getting local configuration on %r: %s' % (
                    self._ldapi_conn.uri,
                    exc,
                ),
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdConfig',
                'Successfully connected to %r as %r found %r and %r%s' % (
                    self._ldapi_conn.uri,
                    local_wai,
                    self._ldapi_conn.configContext[0],
                    self._ldapi_conn.monitorContext[0],
                    (
                        ' server ID: {0:d} (0x{0:x})'.format(int(self._config_attrs['olcServerID'][0]))
                        if 'olcServerID' in self._config_attrs
                        else ''
                    ),
                ),
                server_id=(
                    int(self._config_attrs['olcServerID'][0])
                    if 'olcServerID' in self._config_attrs
                    else None
                ),
            )

            self._check_sasl_hostname()
            self._check_tls_file()

        # read cn=Monitor
        #----------------------------------------------------------------------
        try:
            self._monitor_cache = OpenLDAPMonitorCache(
                self._ldapi_conn.get_monitor_entries(),
                self._ldapi_conn.monitorContext[0],
            )
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdMonitor',
                'Error getting local monitor data on %r: %s' % (
                    self._ldapi_conn.uri,
                    exc,
                ),
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdMonitor',
                'Retrieved %d entries from %r on %r' % (
                    len(self._monitor_cache),
                    self._ldapi_conn.monitorContext[0],
                    self._ldapi_conn.uri,
                ),
                monitor_entries=len(self._monitor_cache),
            )

        self._check_version()
        self._check_slapd_start()
        self._get_proc_info()
        self._check_conns()
        self._check_threads()
        self._check_slapd_sock()
        self._check_databases()
        self._get_slapd_perfstats()

        syncrepl_list, syncrepl_topology = self._get_syncrepl_topology()

        local_csn_dict = self._get_local_csns(syncrepl_list)

        # Close LDAPI connection
        self._ldapi_conn.unbind_s()

        self._check_local_ldaps(ldaps_uri, my_authz_id)

        # Write current performance data to disk
        self._state.write_state(self._next_state)

        # Check remote provider connections
        self._check_provider_conns(local_csn_dict, syncrepl_list, syncrepl_topology)

        check_finished = time.time()
        check_duration = check_finished - check_started

        # Finally output the check's start and end times
        self.result(
            CHECK_RESULT_OK,
            'SlapdCheckTime',
            '%s %s took %0.2f secs to run' % (__name__, __version__, check_duration,),
            check_started=check_started,
            check_finished=check_finished,
            check_duration=check_duration,
        )

        # end of checks()
