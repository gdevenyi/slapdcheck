# -*- coding: utf-8 -*-
"""
slapdcheck.openldap - OpenLDAP helper classes
"""

import socket
import time
import datetime
import threading

import ldap0
from ldap0.ldapobject import LDAPObject
from ldap0.ldapurl import LDAPUrl
from ldap0.openldap import SyncReplDesc
from ldap0.functions import strf_secs

from .cfg import (
    CATCH_ALL_EXC,
    CHECK_RESULT_ERROR,
    CHECK_RESULT_OK,
)
from .cfg import CFG


SLAPD_VENDOR_PREFIX = 'OpenLDAP: slapd '

# attribute to read directory from cn=config
SLAPD_CONFIG_ROOT_ATTRS = [
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
]


class OpenLDAPMonitorCache:
    """
    Cache object for data read from back-monitor
    """

    def __init__(self, monitor_entries, monitor_context):
        self._ctx = monitor_context
        self._data = dict(monitor_entries)

    def __len__(self):
        return len(self._data)

    def get_value(self, dn_prefix, attribute):
        """
        Get a single monitoring value from entry cache
        """
        if dn_prefix:
            mon_dn = ','.join((dn_prefix, self._ctx))
        else:
            mon_dn = self._ctx
        attr_value = self._data[mon_dn][attribute][0]
        if attribute == 'monitorTimestamp':
            res = datetime.datetime.strptime(attr_value, '%Y%m%d%H%M%SZ')
        else:
            try:
                res = int(attr_value)
            except ValueError:
                res = attr_value
        return res # end of get_value()

    def operation_counters(self):
        """
        return list of monitoring counters for various LDAP operations
        """
        op_counter_suffix_lower = ','.join(
            ('', 'cn=Operations', self._ctx)).lower()
        return [
            (
                entry['cn'][0],
                int(entry['monitorOpInitiated'][0]),
                int(entry['monitorOpCompleted'][0]),
            )
            for dn, entry in self._data.items()
            if dn.lower().endswith(op_counter_suffix_lower)
        ]


class OpenLDAPObject:
    """
    mix-in class for LDAPObject and friends which provides methods useful
    for OpenLDAP's slapd
    """
    syncrepl_filter = (
        '(&'
          '(objectClass=olcDatabaseConfig)'
          '(olcDatabase=*)'
          '(olcSyncrepl=*)'
          '(olcSuffix=*)'
        ')'
    )
    slapd_sock_filter = (
        '(&'
          '(|'
            '(objectClass=olcDbSocketConfig)'
            '(objectClass=olcOvSocketConfig)'
          ')'
          '(olcDbSocketPath=*)'
        ')'
    )
    naming_context_attrs = [
        'configContext',
        'namingContexts',
        'monitorContext',
    ]
    all_real_db_filter = (
        '(&'
          '(objectClass=olcMdbConfig)'
          '(olcDatabase=*)'
          '(olcDbDirectory=*)'
          '(olcSuffix=*)'
        ')'
    )
    all_monitor_entries_filter = (
        '(|'
          '(objectClass=monitorServer)'
          '(objectClass=monitorOperation)'
          '(objectClass=monitoredObject)'
          '(objectClass=monitorCounterObject)'
        ')'
    )
    all_monitor_entries_attrs = [
        'cn',
        'monitorCounter',
        'monitoredInfo',
        'monitorOpCompleted',
        'monitorOpInitiated',
        'monitorTimestamp',
        'namingContexts'
        'seeAlso',
        # see OpenLDAP ITS#7770
        'olmMDBPagesMax',
        'olmMDBPagesUsed',
        'olmMDBPagesFree',
        'olmMDBReadersMax',
        'olmMDBReadersUsed',
    ]

    def __getattr__(self, name):
        if name not in self.__dict__ and name in self.naming_context_attrs:
            self.get_naming_context_attrs()
        return self.__dict__[name]

    def get_monitor_entries(self):
        """
        returns dict of all monitoring entries
        """
        return {
            res.dn_s: res.entry_s
            for res in self.search_s(
                self.monitorContext[0],
                ldap0.SCOPE_SUBTREE,
                self.all_monitor_entries_filter,
                attrlist=self.all_monitor_entries_attrs,
            )
        }

    def get_naming_context_attrs(self):
        """
        returns all naming contexts including special backends
        """
        rootdse = self.read_rootdse_s(attrlist=self.naming_context_attrs)
        for nc_attr in self.naming_context_attrs:
            if nc_attr in rootdse.entry_s:
                setattr(self, nc_attr, rootdse.entry_s[nc_attr])
        return rootdse

    def get_sock_listeners(self):
        """
        search `self.configContext[0]' for back-sock listeners (DB and overlay)
        """
        ldap_result = self.search_s(
            self.configContext[0],
            ldap0.SCOPE_SUBTREE,
            self.slapd_sock_filter,
            attrlist=['olcDbSocketPath', 'olcOvSocketOps'],
        )
        result = {}
        for ldap_res in ldap_result:
            socket_path = ldap_res.entry_s['olcDbSocketPath'][0]
            result['SlapdSock_'+socket_path] = (
                socket_path,
                '/'.join(sorted(ldap_res.entry_s['olcOvSocketOps'])),
            )
        return result

    def get_context_csn(self, naming_context):
        """
        read the contextCSN values from the backends root entry specified
        by `naming_context'
        """
        ldap_result = self.read_s(
            naming_context,
            '(contextCSN=*)',
            attrlist=['objectClass', 'contextCSN'],
        )
        csn_dict = {}
        try:
            context_csn_vals = ldap_result.entry_s['contextCSN']
        except KeyError:
            pass
        else:
            for csn_value in context_csn_vals:
                timestamp, _, server_id, _ = csn_value.split("#")
                csn_dict[server_id] = time.mktime(
                    time.strptime(timestamp, '%Y%m%d%H%M%S.%fZ')
                )
        return csn_dict

    def get_syncrepl_topology(self):
        """
        returns list, dict of syncrepl configuration
        """
        ldap_result = self.search_s(
            self.configContext[0],
            ldap0.SCOPE_ONELEVEL,
            self.syncrepl_filter,
            attrlist=['olcDatabase', 'olcSuffix', 'olcSyncrepl'],
        )
        syncrepl_list = []
        for ldap_res in ldap_result:
            db_num = int(ldap_res.entry_s['olcDatabase'][0].split('}')[0][1:])
            srd = [
                SyncReplDesc(attr_value)
                for attr_value in ldap_res.entry_s['olcSyncrepl']
            ]
            syncrepl_list.append((
                db_num,
                ldap_res.entry_s['olcSuffix'][0],
                srd,
            ))
        syncrepl_topology = {}
        for db_num, db_suffix, sr_obj_list in syncrepl_list:
            for sr_obj in sr_obj_list:
                provider_uri = sr_obj.provider
                try:
                    syncrepl_topology[provider_uri].append(
                        (db_num, db_suffix, sr_obj)
                    )
                except KeyError:
                    syncrepl_topology[provider_uri] = [
                        (db_num, db_suffix, sr_obj)
                    ]
        return syncrepl_list, syncrepl_topology

    def db_suffixes(self):
        """
        Returns suffixes of all real database backends
        """
        ldap_result = self.search_s(
            self.configContext[0],
            ldap0.SCOPE_ONELEVEL,
            self.all_real_db_filter,
            attrlist=['olcDatabase', 'olcSuffix', 'olcDbDirectory'],
        )
        result = []
        for res in ldap_result:
            db_num, db_type = res.entry_s['olcDatabase'][0][1:].split('}', 1)
            db_num = int(db_num)
            db_suffix = res.entry_s['olcSuffix'][0]
            db_dir = res.entry_s['olcDbDirectory'][0]
            result.append((db_num, db_suffix, db_type, db_dir))
        return result


class SlapdConnection(LDAPObject, OpenLDAPObject):
    """
    LDAPObject derivation especially for accesing OpenLDAP's slapd
    """

    def __init__(
            self,
            uri,
            trace_level=0,
            tls_options=None,
            network_timeout=None,
            timeout=None,
            bind_method='sasl',
            sasl_mech='EXTERNAL',
            who=None,
            cred=None,
        ):
        self.connect_latency = None
        LDAPObject.__init__(
            self,
            uri,
            trace_level=trace_level,
        )
        # Set timeout values
        if network_timeout is None:
            network_timeout = CFG.ldap_timeout
        if timeout is None:
            timeout = CFG.ldap_timeout
        self.set_option(ldap0.OPT_NETWORK_TIMEOUT, network_timeout)
        self.set_option(ldap0.OPT_TIMEOUT, timeout)
        tls_options = tls_options or {}
        self.set_tls_options(**tls_options)
        conect_start = time.time()
        # Send SASL/EXTERNAL bind which opens connection
        if bind_method == 'sasl':
            self.sasl_non_interactive_bind_s(sasl_mech)
        elif bind_method == 'simple':
            self.simple_bind_s(who or '', cred or '')
        else:
            raise ValueError('Unknown bind_method %r' % bind_method)
        self.connect_latency = time.time() - conect_start

    def set_tls_options(
            self,
            cacert_filename=None,
            client_cert_filename=None,
            client_key_filename=None,
            req_cert=ldap0.OPT_X_TLS_DEMAND,
        ):
        if isinstance(cacert_filename, bytes):
            cacert_filename = cacert_filename.decode('utf-8')
        if isinstance(client_cert_filename, bytes):
            client_cert_filename = client_cert_filename.decode('utf-8')
        if isinstance(client_key_filename, bytes):
            client_key_filename = client_key_filename.decode('utf-8')
        LDAPObject.set_tls_options(
            self,
            cacert_filename=cacert_filename,
            client_cert_filename=client_cert_filename,
            client_key_filename=client_key_filename,
            req_cert=req_cert,
        )


class SyncreplProviderTask(threading.Thread):
    """
    thread for connecting to a slapd provider
    """

    def __init__(
            self,
            check_instance,
            syncrepl_topology,
            syncrepl_target_uri,
            local_csn_dict,
            ldap0_trace_level=0,
        ):
        threading.Thread.__init__(
            self,
            group=None,
            target=None,
            name=None,
            args=(()),
            kwargs={}
        )
        self._ldap0_trace_level = ldap0_trace_level
        self.check_instance = check_instance
        self.syncrepl_topology = syncrepl_topology
        self.syncrepl_target_uri = syncrepl_target_uri
        syncrepl_target_lu_obj = LDAPUrl(self.syncrepl_target_uri)
        self.syncrepl_target_hostport = syncrepl_target_lu_obj.hostport.lower()
        self.name = '-'.join((self.__class__.__name__, self.syncrepl_target_hostport))
        self._local_csn_dict = local_csn_dict
        self.remote_csn_dict = {}
        self.connect_latency = None

    def _contextcsn_item_name(self, db_num, db_suffix):
        return '_'.join((
            'SlapdSyncRepl',
            str(db_num),
            self.check_instance.subst_item_name_chars(db_suffix),
            self.check_instance.subst_item_name_chars(self.syncrepl_target_hostport),
        ))

    def run(self):
        """
        connect to provider replica and retrieve contextCSN values for databases
        """

        syncrepl_target_uri = self.syncrepl_target_uri.lower()

        # register the check items
        for db_num, db_suffix, _ in self.syncrepl_topology[syncrepl_target_uri]:
            self.check_instance.add_item(self._contextcsn_item_name(db_num, db_suffix))

        # Resolve hostname separately for fine-grained error message
        syncrepl_target_hostname = self.syncrepl_target_hostport.rsplit(':', 1)[0]
        try:
            syncrepl_target_ipaddr = socket.gethostbyname(syncrepl_target_hostname)
        except CATCH_ALL_EXC as exc:
            for db_num, db_suffix, _ in self.syncrepl_topology[syncrepl_target_uri]:
                self.check_instance.result(
                    CHECK_RESULT_ERROR,
                    self._contextcsn_item_name(db_num, db_suffix),
                    'Error resolving hostname %r: %s' % (
                        syncrepl_target_hostname,
                        exc,
                    )
                )
            return

        syncrepl_obj = self.syncrepl_topology[self.syncrepl_target_uri][0][2]

        # Connect to remote replica
        try:
            ldap_conn = SlapdConnection(
                self.syncrepl_target_uri,
                trace_level=self._ldap0_trace_level,
                tls_options=dict(
                    # path name of file containing all trusted CA certificates
                    cacert_filename=(
                        syncrepl_obj.tls_cacert
                        or self.check_instance._config_attrs['olcTLSCACertificateFile'][0]
                    ),
                    # Use slapd server cert/key for client authentication
                    # just like used for syncrepl
                    client_cert_filename=(
                        syncrepl_obj.tls_cert
                        or self.check_instance._config_attrs['olcTLSCertificateFile'][0]
                    ),
                    client_key_filename=(
                        syncrepl_obj.tls_key
                        or self.check_instance._config_attrs['olcTLSCertificateKeyFile'][0]
                    ),
                ),
                network_timeout=syncrepl_obj.network_timeout,
                timeout=syncrepl_obj.timeout,
                bind_method=syncrepl_obj.bindmethod,
                sasl_mech=syncrepl_obj.saslmech,
                who=syncrepl_obj.binddn,
                cred=syncrepl_obj.credentials,
            )
        except CATCH_ALL_EXC as exc:
            for db_num, db_suffix, _ in self.syncrepl_topology[syncrepl_target_uri]:
                self.check_instance.result(
                    CHECK_RESULT_ERROR,
                    self._contextcsn_item_name(db_num, db_suffix),
                    'Error connecting to %r (%s): %s' % (
                        self.syncrepl_target_uri,
                        syncrepl_target_ipaddr,
                        exc,
                    )
                )
            return

        for db_num, db_suffix, _ in self.syncrepl_topology[syncrepl_target_uri]:
            try:
                self.remote_csn_dict[db_suffix] = ldap_conn.get_context_csn(db_suffix)
            except CATCH_ALL_EXC as exc:
                self.check_instance.result(
                    CHECK_RESULT_ERROR,
                    self._contextcsn_item_name(db_num, db_suffix),
                    'Exception while retrieving remote contextCSN for %r from %r: %s' % (
                        db_suffix,
                        ldap_conn.uri,
                        exc,
                    )
                )
                continue

            if not self.remote_csn_dict[db_suffix]:
                self.check_instance.result(
                    CHECK_RESULT_ERROR,
                    self._contextcsn_item_name(db_num, db_suffix),
                    'no attribute contextCSN for %r on %r' % (
                        db_suffix,
                        ldap_conn.uri,
                    ),
                    num_csn_values=len(self.remote_csn_dict[db_suffix]),
                    connect_latency=ldap_conn.connect_latency,
                )
                continue

            if not (self._local_csn_dict and self._local_csn_dict[db_suffix]):
                self.check_instance.result(
                    CHECK_RESULT_ERROR,
                    self._contextcsn_item_name(db_num, db_suffix),
                    'No local contextCSN attribute for suffix %r' % (db_suffix,),
                    num_csn_values=len(self.remote_csn_dict[db_suffix]),
                    connect_latency=ldap_conn.connect_latency,
                    local_csn_missing=len(self.remote_csn_dict[db_suffix]),
                )
                continue

            # compare contextCSN values pair-wise for each serverID value
            missing_local = []
            csn_deltas = {}
            for sid, remote_csn_timestamp in sorted(self.remote_csn_dict[db_suffix].items()):
                if sid not in self._local_csn_dict[db_suffix]:
                    missing_local.append(sid)
                    continue
                csn_delta = abs(self._local_csn_dict[db_suffix][sid]-remote_csn_timestamp)
                csn_deltas[sid] = csn_delta

            sum_csn_delta=sum([abs(val) for val in csn_deltas.values()])
            avg_csn_delta=sum_csn_delta / len(csn_deltas)
            max_csn_delta=max([abs(val) for val in csn_deltas.values()])

            self.check_instance.result(
                (
                    CHECK_RESULT_OK
                    if (
                        db_suffix in self._local_csn_dict
                        and not missing_local
                        and sum_csn_delta == 0
                    )
                    else CHECK_RESULT_ERROR
                ),
                self._contextcsn_item_name(db_num, db_suffix),
                '%d remote contextCSN values found for %r on %r: %s' % (
                    len(self.remote_csn_dict[db_suffix]),
                    db_suffix,
                    ldap_conn.uri,
                    ' / '.join([
                        '{0}={1} ({2:0.1f})'.format(
                            int(sid, 16),
                            strf_secs(csn_time),
                            csn_deltas.get(sid, 0.0),
                        )
                        for sid, csn_time in sorted(self.remote_csn_dict.get(db_suffix, {}).items())
                    ]),
                ),
                num_csn_values=len(self.remote_csn_dict[db_suffix]),
                connect_latency=ldap_conn.connect_latency,
                avg_csn_delta=avg_csn_delta,
                max_csn_delta=max_csn_delta,
                local_csn_missing=len(missing_local),
            )

        # Close the LDAP connection to the remote replica
        try:
            ldap_conn.unbind_s()
        except CATCH_ALL_EXC as exc:
            pass

        # end of run()
