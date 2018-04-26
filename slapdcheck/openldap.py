# -*- coding: utf-8 -*-
"""
slapdcheck.openldap - OpenLDAP helper classes
"""

from __future__ import absolute_import

import sys
import time
import datetime

import ldap0
from ldap0.ldapobject import LDAPObject
from ldap0.openldap import SyncReplDesc

from .cnf import LDAP_TIMEOUT, PYLDAP_TRACE_LEVEL


def slapd_pid_fromfile(config_attrs):
    """
    read slapd's PID from file
    """
    pid_filename = config_attrs['olcPidFile'][0]
    try:
        pid_file = open(pid_filename, 'rb')
    except IOError:
        slapd_pid = None
    else:
        slapd_pid = pid_file.read().strip()
    return slapd_pid # end of _get_slapd_pid()


class OpenLDAPMonitorCache(object):
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


class OpenLDAPObject(object):
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
    ]

    def __getattr__(self, name):
        if name in self.naming_context_attrs:
            if not name in self.__dict__:
                self.get_naming_context_attrs()
            return self.__dict__[name]

    def get_monitor_entries(self):
        """
        returns dict of all monitoring entries
        """
        return self.search_s(
            self.monitorContext[0],
            ldap0.SCOPE_SUBTREE,
            self.all_monitor_entries_filter,
            attrlist=self.all_monitor_entries_attrs,
        )

    def get_naming_context_attrs(self):
        """
        returns all naming contexts including special backends
        """
        rootdse = self.read_rootdse_s(attrlist=self.naming_context_attrs)
        for nc_attr in self.naming_context_attrs:
            if nc_attr in rootdse:
                self.__setattr__(nc_attr, rootdse[nc_attr])
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
        for _, sock_entry in ldap_result:
            socket_path = sock_entry['olcDbSocketPath'][0]
            result['SlapdSock_'+socket_path] = (
                socket_path,
                '/'.join(sorted(sock_entry['olcOvSocketOps'])),
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
            context_csn_vals = ldap_result['contextCSN']
        except (KeyError, IndexError):
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
        for _, ldap_entry in ldap_result:
            db_num = int(ldap_entry['olcDatabase'][0].split('}')[0][1:])
            srd = [
                SyncReplDesc(attr_value)
                for attr_value in ldap_entry['olcSyncrepl']
            ]
            syncrepl_list.append((
                db_num,
                ldap_entry['olcSuffix'][0],
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
        for _, entry in ldap_result:
            db_num, db_type = entry['olcDatabase'][0][1:].split('}', 1)
            db_num = int(db_num)
            db_suffix = entry['olcSuffix'][0]
            db_dir = entry['olcDbDirectory'][0]
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
            trace_level=PYLDAP_TRACE_LEVEL,
            trace_file=sys.stderr,
            trace_stack_limit=8,
            tls_options=None,
            network_timeout=None,
            timeout=None,
            bind_method='sasl',
            sasl_mech='EXTERNAL',
            who=None,
            cred=None,
        ):
        LDAPObject.__init__(
            self,
            uri,
            trace_level=trace_level,
            trace_file=trace_file,
            trace_stack_limit=trace_stack_limit,
        )
        # Set timeout values
        if network_timeout is None:
            network_timeout = LDAP_TIMEOUT
        if timeout is None:
            timeout = LDAP_TIMEOUT
        self.set_option(ldap0.OPT_NETWORK_TIMEOUT, network_timeout)
        self.set_option(ldap0.OPT_TIMEOUT, timeout)
        tls_options = tls_options or {}
        self.set_tls_options(**tls_options)
        # Send SASL/EXTERNAL bind which opens connection
        if bind_method == 'sasl':
            self.sasl_non_interactive_bind_s(sasl_mech)
        elif bind_method == 'simple':
            self.simple_bind_s(who or '', cred or '')
        else:
            raise ValueError('Unknown bind_method %r' % bind_method)
