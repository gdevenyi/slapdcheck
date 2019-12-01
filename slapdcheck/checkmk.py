# -*- coding: utf-8 -*-
"""
monitoring check script for OpenLDAP

Needs full read access to rootDSE and cn=config and cn=monitor
(or whereever rootDSE attributes 'configContext' and 'monitorContext'
are pointing to)

Copyright 2015-2019 Michael Ströder <michael@stroeder.com>

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use files and content provided on this web site except in compliance
with the License. You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

#-----------------------------------------------------------------------
# Import modules
#-----------------------------------------------------------------------

import os
import sys
import socket
import time
import datetime

import cryptography.x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
import cryptography.hazmat.primitives.asymmetric.rsa

# from ldap0 package
import ldap0
from ldap0.ldif import LDIFParser

# local package imports
from slapdcheck import MonitoringCheck
from slapdcheck.openldap import SyncreplProviderTask
from slapdcheck.openldap import OpenLDAPMonitorCache, SlapdConnection, slapd_pid_fromfile
from slapdcheck.cnf import (
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

#-----------------------------------------------------------------------
# Classes
#-----------------------------------------------------------------------

class CheckMkLocalCheck(MonitoringCheck):
    """
    Simple class for writing check_mk output
    """
    checkmk_status = {
        CHECK_RESULT_OK: 'OK',
        CHECK_RESULT_WARNING: 'WARNING',
        CHECK_RESULT_ERROR: 'ERROR',
        CHECK_RESULT_UNKNOWN: 'UNKNOWN',
    }
    output_format = '{status_code} {name} {perf_data} {status_text} - {msg}\n'
    item_name_special_chars = set(',!:$%=/\\')

    def serialize_perf_data(self, pdat):
        if not pdat:
            return '-'
        return '|'.join([
            '%s=%s' % (pkey, pval)
            for pkey, pval in pdat.items()
        ])

    def output(self):
        """
        Outputs all check_mk results registered before with method result()
        """
        MonitoringCheck.output(self)
        for i in sorted(self._item_dict.keys()):
            status, check_name, perf_data, check_msg = self._item_dict[i]
            sys.stdout.write(
                self.output_format.format(
                    status_code=status,
                    perf_data=self.serialize_perf_data(perf_data),
                    name=self.subst_item_name_chars(check_name),
                    status_text=self.checkmk_status[status],
                    msg=check_msg,
                )
            )
        # end of output()


class SlapdCheck(CheckMkLocalCheck):
    """
    Check class for OpenLDAP's slapd
    """
    item_names = (
        'SlapdCert',
        'SlapdConfig',
        'SlapdMonitor',
        'SlapdConns',
        'SlapdDatabases',
        'SlapdStart',
        'SlapdOps',
        'SlapdProviders',
        'SlapdReplTopology',
        'SlapdSASLHostname',
        'SlapdSelfConn',
        'SlapdSock',
        'SlapdStats',
        'SlapdThreads',
    )

    def __init__(self, output_file, state_filename=None):
        CheckMkLocalCheck.__init__(self, output_file, state_filename)
        # make pylint happy
        self._ldapi_conn = None
        self._config_attrs = {}
        self._monitor_cache = {}

    def _check_sasl_hostname(self, config_attrs):
        """
        check whether SASL hostname is resolvable
        """
        try:
            olc_sasl_host = config_attrs['olcSaslHost'][0]
        except (KeyError, IndexError):
            self.result(
                CHECK_RESULT_OK,
                'SlapdSASLHostname',
                check_output='olcSaslHost not set'
            )
        else:
            try:
                _ = socket.getaddrinfo(olc_sasl_host, None)
            except socket.gaierror as socket_err:
                self.result(
                    CHECK_RESULT_WARNING,
                    'SlapdSASLHostname',
                    check_output='olcSaslHost %r not found: %r' % (olc_sasl_host, socket_err),
                )
            else:
                self.result(
                    CHECK_RESULT_OK,
                    'SlapdSASLHostname',
                    check_output='olcSaslHost %r found' % (olc_sasl_host),
                )
        # end of _check_sasl_hostname()

    def _check_tls_file(self, config_attrs):
        # try to read CA and server cert/key files
        file_read_errors = []
        tls_pem = {}
        for tls_attr_name in (
                'olcTLSCACertificateFile',
                'olcTLSCertificateFile',
                'olcTLSCertificateKeyFile',
            ):
            try:
                fname = config_attrs[tls_attr_name][0]
            except KeyError:
                file_read_errors.append(
                    'Attribute %r not set' % (tls_attr_name)
                )
            try:
                with open(fname, 'rb') as tls_pem_file:
                    tls_pem[tls_attr_name] = tls_pem_file.read()
            except CATCH_ALL_EXC as exc:
                file_read_errors.append(
                    'Error reading %r: %s' % (fname, exc)
                )
        if file_read_errors:
            # no crypto modules present => abort
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdCert',
                check_output=' / '.join(file_read_errors)
            )
            return
        server_cert_obj = cryptography.x509.load_pem_x509_certificate(
            tls_pem['olcTLSCertificateFile'],
            crypto_default_backend(),
        )
        server_key_obj = cryptography.hazmat.primitives.serialization.load_pem_private_key(
            tls_pem['olcTLSCertificateKeyFile'],
            None,
            crypto_default_backend(),
        )
        cert_not_after = server_cert_obj.not_valid_after
        cert_not_before = server_cert_obj.not_valid_before
        modulus_match = server_cert_obj.public_key().public_numbers().n == server_key_obj.public_key().public_numbers().n
        utc_now = datetime.datetime.now(cert_not_after.tzinfo)
        cert_validity_rest = cert_not_after - utc_now
        if modulus_match is False or cert_validity_rest.days <= CERT_ERROR_DAYS:
            cert_check_result = CHECK_RESULT_ERROR
        elif cert_validity_rest.days <= CERT_WARN_DAYS:
            cert_check_result = CHECK_RESULT_WARNING
        else:
            cert_check_result = CHECK_RESULT_OK
        # less exact usage of .days because of older
        # Python versions without timedelta.total_seconds()
        elapsed_percentage = 100-100*float(cert_validity_rest.days)/float((cert_not_after-cert_not_before).days)
        self.result(
            cert_check_result,
            'SlapdCert',
            check_output=(
                'Server cert %r valid until %s UTC '
                '(%d days left, %0.1f %% elapsed), '
                'modulus_match==%r'
            ) % (
                config_attrs['olcTLSCertificateFile'][0],
                cert_not_after,
                cert_validity_rest.days,
                elapsed_percentage,
                modulus_match,
            ),
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
                check_output='Error connecting to %r: %s / client_tls_options = %r' % (
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
                    check_output='Error during Who Am I? ext.op. on %r: %s' % (
                        ldaps_conn.uri,
                        exc,
                    ),
                )
            else:
                if wai != my_authz_id:
                    self.result(
                        CHECK_RESULT_ERROR,
                        'SlapdSelfConn',
                        performance_data={'connect_latency': ldaps_conn.connect_latency},
                        check_output='Received unexpected authz-DN from %r: %r' % (
                            ldaps_conn.uri,
                            wai,
                        ),
                    )
                else:
                    self.result(
                        CHECK_RESULT_OK,
                        'SlapdSelfConn',
                        performance_data={'connect_latency': ldaps_conn.connect_latency},
                        check_output='successfully bound to %r as %r' % (
                            ldaps_conn.uri,
                            wai,
                        ),
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
                ignored_attr_types=['sockLogLevel'],
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
                check_output='error retrieving back-sock listeners: %s' % (exc)
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdSock',
                check_output='Found %d back-sock listeners' % (len(sock_listeners))
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
                        check_output='Connecting to %s listener %r failed: %s' % (
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
                        check_msgs.append('parsing error: %s' % (err))
                    else:
                        check_result = CHECK_RESULT_OK
                    self.result(
                        check_result,
                        item_name,
                        performance_data=sock_perf_data,
                        check_output=', '.join(check_msgs),
                    )
        # end of _check_slapd_sock()

    def _check_slapd_start(self, config_attrs):
        """
        check whether slapd should be restarted
        """
        start_time = self._monitor_cache.get_value('cn=Start,cn=Time', 'monitorTimestamp')
        utc_now = datetime.datetime.now()
        newer_files = []
        for fattr in (
                'olcConfigDir',
                'olcConfigFile',
                'olcTLSCACertificateFile',
                'olcTLSCertificateFile',
                'olcTLSCertificateKeyFile',
                'olcTLSDHParamFile',
            ):
            if not fattr in config_attrs:
                continue
            check_filename = config_attrs[fattr][0]
            try:
                check_file_mtime = datetime.datetime.utcfromtimestamp(int(os.stat(check_filename).st_mtime))
            except OSError:
                pass
            else:
                if check_file_mtime > start_time:
                    newer_files.append('%r (%s)' % (check_filename, check_file_mtime))
        if newer_files:
            self.result(
                CHECK_RESULT_WARNING,
                'SlapdStart',
                check_output='slapd[%s] needs restart! Started at %s, %s ago, now newer config: %s' % (
                    slapd_pid_fromfile(config_attrs),
                    start_time,
                    utc_now-start_time,
                    ' / '.join(newer_files),
                )
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdStart',
                check_output='slapd[%s] started at %s, %s ago' % (
                    slapd_pid_fromfile(config_attrs),
                    start_time,
                    utc_now-start_time,
                )
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
                    check_output='Error while retrieving local contextCSN of %r: %s' % (
                        db_suffix,
                        exc,
                    ),
                )
            else:
                if not local_csn_dict[db_suffix]:
                    self.result(
                        CHECK_RESULT_UNKNOWN,
                        item_name,
                        check_output='no local contextCSN values for %r' % (
                            db_suffix,
                        ),
                    )
        return local_csn_dict # end of _get_local_csns()

    def _open_ldapi_conn(self, local_ldapi_url):
        """
        Open local LDAPI connection, exits on error
        """
        try:
            self._ldapi_conn = SlapdConnection(local_ldapi_url)
            # Find out whether bind worked
            local_wai = self._ldapi_conn.whoami_s()
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdConfig',
                check_output='Error while connecting to %r: %s' % (
                    local_ldapi_url,
                    exc,
                )
            )
            sys.exit(1)
        return local_wai # end of _open_ldapi_conn()

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
            performance_data={
                'count': current_connections,
                'percent': current_connections_percentage,
            },
            check_output='%d open connections (max. %d)' % (current_connections, max_connections),
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
        state = int(
            threads_active < THREADS_ACTIVE_WARN_LOWER or
            threads_active > THREADS_ACTIVE_WARN_UPPER or
            threads_pending > THREADS_PENDING_WARN
        )
        self.result(
            state,
            'SlapdThreads',
            performance_data={
                'threads_active': threads_active,
                'threads_pending': threads_pending,
            },
            check_output='Thread counts active:%d pending: %d' % (
                threads_active, threads_pending)
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
            performance_data={
                'bytes': stats_bytes_rate,
                'entries': stats_entries_rate,
                'pdu': stats_pdu_rate,
                'referrals': stats_referrals_rate,
            },
            check_output='Stats: %d bytes (%0.1f bytes/sec) / %d entries (%0.1f entries/sec) / %d PDUs (%0.1f PDUs/sec) / %d referrals (%0.1f referrals/sec)' % (
                stats_bytes,
                stats_bytes_rate,
                stats_entries,
                stats_entries_rate,
                stats_pdu,
                stats_pdu_rate,
                stats_referrals,
                stats_referrals_rate,
            )
        )
        monitor_ops_counters = self._monitor_cache.operation_counters()
        if monitor_ops_counters:
            ops_all_initiated = 0
            ops_all_completed = 0
            ops_all_waiting = 0
            for ops_name, ops_initiated, ops_completed in monitor_ops_counters:
                item_name = 'SlapdOps_%s' % (ops_name)
                self.add_item(item_name)
                self._next_state[ops_name+'_ops_initiated'] = ops_initiated
                self._next_state[ops_name+'_ops_completed'] = ops_completed
                ops_waiting = ops_initiated - ops_completed
                ops_all_waiting += ops_waiting
                ops_all_completed += ops_completed
                ops_all_initiated += ops_initiated
                ops_initiated_rate = self._get_rate(ops_name+'_ops_initiated', ops_initiated, last_time_span)
                ops_completed_rate = self._get_rate(ops_name+'_ops_completed', ops_completed, last_time_span)
                self.result(
                    CHECK_RESULT_OK,
                    item_name,
                    performance_data={
                        'ops_completed_rate': ops_completed_rate,
                        'ops_initiated_rate': ops_initiated_rate,
                        'ops_waiting': ops_waiting,
                    },
                    check_output='completed %d of %d operations (%0.2f/s completed, %0.2f/s initiated, %d waiting)' % (
                        ops_completed,
                        ops_initiated,
                        ops_completed_rate,
                        ops_initiated_rate,
                        ops_waiting,
                    ),
                )
            ops_all_initiated_rate = self._get_rate('ops_all_initiated', ops_all_initiated, last_time_span)
            ops_all_completed_rate = self._get_rate('ops_all_completed', ops_all_completed, last_time_span)
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
                performance_data={
                    'ops_completed_rate': ops_all_completed_rate,
                    'ops_initiated_rate': ops_all_initiated_rate,
                    'ops_waiting': ops_all_waiting,
                },
                check_output='%d operation types / completed %d of %d operations (%0.2f/s completed, %0.2f/s initiated, %d waiting)' % (
                    len(monitor_ops_counters),
                    ops_all_completed,
                    ops_all_initiated,
                    ops_all_completed_rate,
                    ops_all_initiated_rate,
                    ops_all_waiting,
                ),
            )
        # end of _get_slapd_perfstats()

    def _check_mdb_size(self, db_num, db_suffix, db_dir):
        """
        Checks free MDB pages

        If ITS#7770 is not available (prior to OpenLDAP 2.4.48) then
        this does nothing.
        """
        try:
            mdb_pages_max = self._monitor_cache.get_value(
                'cn=Database %d,cn=Databases' % (db_num),
                'olmMDBPagesMax',
            )
            mdb_pages_used = self._monitor_cache.get_value(
                'cn=Database %d,cn=Databases' % (db_num),
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
        self.result(
            CHECK_RESULT_OK,
            item_name,
            check_output='LMDB in %r uses %d of max. %d pages (%0.1f %%)' % (
                db_dir,
                mdb_pages_used,
                mdb_pages_max,
                mdb_use_percentage,
            ),
            performance_data=dict(
                mdb_pages_used=mdb_pages_used,
                mdb_pages_max=mdb_pages_max,
                mdb_use_percentage=mdb_use_percentage,
            ),
        )
        # end of _check_mdb_size()

    def _check_databases(self):
        try:
            db_suffixes = self._ldapi_conn.db_suffixes()
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdDatabases',
                check_output='error retrieving DB suffixes: %s' % (exc)
            )
            return
        self.result(
            CHECK_RESULT_OK,
            'SlapdDatabases',
            check_output='Found %d real databases: %s' % (
                len(db_suffixes),
                ' / '.join([
                    '{%d}%s: %s' % (n, t, s)
                    for n, s, t, _ in db_suffixes
                ]),
            )
        )
        for db_num, db_suffix, db_type, db_dir in db_suffixes:
            # Check file sizes of MDB database files
            if db_type == 'mdb':
                self._check_mdb_size(db_num, db_suffix, db_dir)

            # Count LDAP entries with no-op search controls
            item_name = '_'.join((
                'SlapdEntryCount',
                str(db_num),
                self.subst_item_name_chars(db_suffix),
            ))
            self.add_item(item_name)
            try:
                noop_start_timestamp = time.time()
                noop_result = self._ldapi_conn.noop_search(
                    db_suffix,
                    timeout=NOOP_SEARCH_TIMEOUT,
                )
            except ldap0.TIMEOUT:
                self.result(
                    CHECK_RESULT_WARNING,
                    item_name,
                    check_output='Request timeout %0.1f s reached while retrieving entry count for %r.' % (
                        LDAP_TIMEOUT,
                        db_suffix,
                    )
                )
            except ldap0.TIMELIMIT_EXCEEDED:
                self.result(
                    CHECK_RESULT_WARNING,
                    item_name,
                    check_output='Search time limit %0.1f s exceeded while retrieving entry count for %r.' % (
                        NOOP_SEARCH_TIMEOUT,
                        db_suffix,
                    )
                )
            except ldap0.UNAVAILABLE_CRITICAL_EXTENSION:
                self.result(
                    CHECK_RESULT_NOOP_SRCH_UNAVAILABLE,
                    item_name,
                    check_output='no-op search control not supported'
                )
            except CATCH_ALL_EXC as exc:
                self.result(
                    CHECK_RESULT_ERROR,
                    item_name,
                    check_output='Error retrieving entry count for %r: %s' % (db_suffix, exc)
                )
            else:
                noop_response_time = time.time() - noop_start_timestamp
                if noop_result is None:
                    self.result(
                        CHECK_RESULT_WARNING,
                        item_name,
                        check_output='Could not retrieve entry count (result was None)',
                    )
                else:
                    num_all_search_results, num_all_search_continuations = noop_result
                    if num_all_search_continuations:
                        self.result(
                            CHECK_RESULT_ERROR,
                            item_name,
                            performance_data={
                                'count': num_all_search_results,
                            },
                            check_output='%r has %d referrals! (response time %0.1f s)' % (
                                db_suffix,
                                num_all_search_continuations,
                                noop_response_time,
                            )
                        )
                    elif num_all_search_results < MINIMUM_ENTRY_COUNT:
                        self.result(
                            CHECK_RESULT_WARNING,
                            item_name,
                            performance_data={
                                'count': num_all_search_results,
                            },
                            check_output='%r only has %d entries (response time %0.1f s)' % (
                                db_suffix,
                                num_all_search_results,
                                noop_response_time,
                            )
                        )
                    else:
                        self.result(
                            CHECK_RESULT_OK,
                            item_name,
                            performance_data={
                                'count': num_all_search_results,
                            },
                            check_output='%r has %d entries (response time %0.1f s)' % (
                                db_suffix,
                                num_all_search_results,
                                noop_response_time,
                            )
                        )
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
            slapd_provider_percentage = float(len(remote_csn_dict))/float(len(syncrepl_topology))*100
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
            performance_data={
                'count': len(remote_csn_dict),
                'total': len(syncrepl_topology),
                'percent': slapd_provider_percentage,
                'avg_latency': sum(task_connect_latency.values())/len(task_connect_latency) if task_connect_latency else 0.0,
                'max_latency': max(task_connect_latency.values()) if task_connect_latency else 0.0,
            },
            check_output='Connected to %d of %d (%0.1f%%) providers: %s' % (
                len(remote_csn_dict),
                len(syncrepl_topology),
                slapd_provider_percentage,
                ' / '.join(syncrepl_target_fail_msgs),
            ),
        )
        return remote_csn_dict # end of _check_providers()

    def checks(self):

        # Get command-line arguments
        ldaps_uri = sys.argv[2] or 'ldaps://%s' % socket.getfqdn()
        my_authz_id = sys.argv[3]

        local_wai = self._open_ldapi_conn(sys.argv[1] or 'ldapi:///')

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
                check_output='Error getting local configuration on %r: %s' % (
                    self._ldapi_conn.uri,
                    exc,
                ),
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdConfig',
                check_output='Successfully connected to %r as %r found %r and %r' % (
                    self._ldapi_conn.uri,
                    local_wai,
                    self._ldapi_conn.configContext[0],
                    self._ldapi_conn.monitorContext[0],
                )
            )

            self._check_sasl_hostname(self._config_attrs)
            self._check_tls_file(self._config_attrs)

        syncrepl_topology = {}
        try:
            syncrepl_list, syncrepl_topology = self._ldapi_conn.get_syncrepl_topology()
        except CATCH_ALL_EXC as exc:
            self.result(
                CHECK_RESULT_ERROR,
                'SlapdReplTopology',
                check_output='Error getting syncrepl topology on %r: %s' % (
                    self._ldapi_conn.uri,
                    exc,
                ),
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdReplTopology',
                check_output='successfully retrieved syncrepl topology with %d items: %s' % (
                    len(syncrepl_topology),
                    syncrepl_topology,
                )
            )

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
                check_output='Error getting local monitor data on %r: %s' % (
                    self._ldapi_conn.uri,
                    exc,
                ),
            )
        else:
            self.result(
                CHECK_RESULT_OK,
                'SlapdMonitor',
                check_output='Successfully retrieved %d entries from %r on %r' % (
                    len(self._monitor_cache),
                    self._ldapi_conn.monitorContext[0],
                    self._ldapi_conn.uri,
                ),
            )

        self._check_slapd_start(self._config_attrs)
        self._check_conns()
        self._check_threads()
        self._check_slapd_sock()
        self._check_databases()
        self._get_slapd_perfstats()

        local_csn_dict = self._get_local_csns(syncrepl_list)

        # Close LDAPI connection
        self._ldapi_conn.unbind_s()

        self._check_local_ldaps(ldaps_uri, my_authz_id)

        # Write current state to disk
        self._state.write_state(self._next_state)

        # 2. Connect and bind to all replicas to check whether they are reachable
        #----------------------------------------------------------------------

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
                performance_data={
                    'max_csn_timedelta': max_csn_timedelta
                },
                check_output='%r max. contextCSN delta: %0.1f / %s' % (
                    db_suffix,
                    max_csn_timedelta,
                    ' / '.join(issues),
                ),
            )

        # end of checks()


def run():
    """
    run as check_mk local check
    """
    slapd_check = SlapdCheck(
        output_file=sys.stdout,
        state_filename=os.path.basename(sys.argv[0][:-3]),
    )
    slapd_check.run()


if __name__ == '__main__':
    run()
