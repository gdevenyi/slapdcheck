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

from .cnf import (
    CATCH_ALL_EXC,
    CHECK_RESULT_ERROR,
    CHECK_RESULT_OK,
    LDAP0_TRACE_LEVEL,
    LDAP_TIMEOUT,
)


def slapd_pid_fromfile(config_attrs):
    """
    read slapd's PID from file
    """
    pid_filename = config_attrs['olcPidFile'][0]
    try:
        with open(pid_filename, 'r', encoding='utf-8') as pid_file:
            slapd_pid = pid_file.read().strip()
    except IOError:
        slapd_pid = None
    return slapd_pid # end of slapd_pid_fromfile()


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
        attr_value = self._data[','.join((dn_prefix, self._ctx))][attribute][0]
        if attribute == 'monitorTimestamp':
            res = datetime.datetime.strptime(attr_value, '%Y%m%d%H%M%SZ')
        else:
            res = int(attr_value)
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
          '(|'
            '(objectClass=olcBdbConfig)'
            '(objectClass=olcHdbConfig)'
            '(objectClass=olcMdbConfig)'
          ')'
            '(olcDatabase=*)'
            '(olcDbDirectory=*)'
            '(olcSuffix=*)'
        ')'
    )
    all_monitor_entries_filter = (
        '(|'
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
        return syncrepl_list, syncrepl_topology  # get_syncrepl_topology()

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
        return result  # db_suffixes()


class SlapdConnection(LDAPObject, OpenLDAPObject):
    """
    LDAPObject derivation especially for accesing OpenLDAP's slapd
    """
    tls_fileoptions = set((
        ldap0.OPT_X_TLS_CACERTFILE,
        ldap0.OPT_X_TLS_CERTFILE,
        ldap0.OPT_X_TLS_KEYFILE,
    ))

    def __init__(
            self,
            uri,
            trace_level=LDAP0_TRACE_LEVEL,
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
            network_timeout = LDAP_TIMEOUT
        if timeout is None:
            timeout = LDAP_TIMEOUT
        self.set_option(ldap0.OPT_NETWORK_TIMEOUT, network_timeout)
        self.set_option(ldap0.OPT_TIMEOUT, timeout)
        tls_options = {key: val.encode('utf-8') for key, val in (tls_options or {}).items()}
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


class SyncreplProviderTask(threading.Thread):
    """
    thread for connecting to a slapd provider
    """

    def __init__(
            self,
            check_instance,
            syncrepl_topology,
            syncrepl_target_uri,
        ):
        threading.Thread.__init__(
            self,
            group=None,
            target=None,
            name=None,
            args=(),
            kwargs={}
        )
        self.check_instance = check_instance
        self.syncrepl_topology = syncrepl_topology
        self.syncrepl_target_uri = syncrepl_target_uri
        syncrepl_target_lu_obj = LDAPUrl(self.syncrepl_target_uri)
        self.syncrepl_target_hostport = syncrepl_target_lu_obj.hostport.lower()
        self.setName(
            '-'.join((
                self.__class__.__name__,
                self.syncrepl_target_hostport,
            ))
        )
        self.remote_csn_dict = {}
        self.err_msgs = []
        self.connect_latency = None

    def run(self):
        """
        connect to provider replica and retrieve contextCSN values for databases
        """
        # Resolve hostname separately for fine-grained error message
        syncrepl_target_hostname = self.syncrepl_target_hostport.rsplit(':', 1)[0]
        try:
            syncrepl_target_ipaddr = socket.gethostbyname(
                syncrepl_target_hostname
            )
        except CATCH_ALL_EXC as exc:
            self.err_msgs.append('Error resolving hostname %r: %s' % (
                syncrepl_target_hostname,
                exc,
            ))
            return

        syncrepl_obj = self.syncrepl_topology[self.syncrepl_target_uri][0][2]
        try:
            ldap_conn = SlapdConnection(
                self.syncrepl_target_uri,
                tls_options={
                    # Set TLS connection options from TLS attribute read from
                    # configuration context
                    # path name of file containing all trusted CA certificates
                    'cacert_filename': syncrepl_obj.tls_cacert,
                    # Use slapd server cert/key for client authentication
                    # just like used for syncrepl
                    'client_cert_filename': syncrepl_obj.tls_cert,
                    'client_key_filename': syncrepl_obj.tls_key,
                },
                network_timeout=syncrepl_obj.network_timeout,
                timeout=syncrepl_obj.timeout,
                bind_method=syncrepl_obj.bindmethod,
                sasl_mech=syncrepl_obj.saslmech,
                who=syncrepl_obj.binddn,
                cred=syncrepl_obj.credentials,
            )
        except CATCH_ALL_EXC as exc:
            self.err_msgs.append('Error connecting to %r (%s): %s' % (
                self.syncrepl_target_uri,
                syncrepl_target_ipaddr,
                exc,
            ))
            return
        else:
            syncrepl_target_uri = self.syncrepl_target_uri.lower()
            self.connect_latency = ldap_conn.connect_latency

        for db_num, db_suffix, _ in self.syncrepl_topology[syncrepl_target_uri]:
            item_name = '_'.join((
                'SlapdContextCSN',
                str(db_num),
                self.check_instance.subst_item_name_chars(db_suffix),
                self.check_instance.subst_item_name_chars(self.syncrepl_target_hostport),
            ))
            self.check_instance.add_item(item_name)
            try:
                self.remote_csn_dict[db_suffix] = \
                    ldap_conn.get_context_csn(db_suffix)
            except CATCH_ALL_EXC as exc:
                self.check_instance.result(
                    CHECK_RESULT_ERROR,
                    item_name,
                    check_output='Exception while retrieving remote contextCSN for %r from %r: %s' % (
                        db_suffix,
                        ldap_conn.uri,
                        exc,
                    )
                )
                continue
            else:
                if not self.remote_csn_dict[db_suffix]:
                    self.check_instance.result(
                        CHECK_RESULT_ERROR,
                        item_name,
                        performance_data=dict(
                            num_csn_values=len(self.remote_csn_dict[db_suffix]),
                            connect_latency=ldap_conn.connect_latency,
                        ),
                        check_output='no attribute contextCSN for %r on %r' % (
                            db_suffix,
                            ldap_conn.uri,
                        )
                    )
                else:
                    self.check_instance.result(
                        CHECK_RESULT_OK,
                        item_name,
                        performance_data=dict(
                            num_csn_values=len(self.remote_csn_dict[db_suffix]),
                            connect_latency=ldap_conn.connect_latency,
                        ),
                        check_output='%d contextCSN attribute values retrieved for %r from %r' % (
                            len(self.remote_csn_dict[db_suffix]),
                            db_suffix,
                            ldap_conn.uri,
                        )
                    )
        # Close the LDAP connection to the remote replica
        try:
            ldap_conn.unbind_s()
        except CATCH_ALL_EXC as exc:
            pass
        # end of SyncreplProviderTask.run()
