# slapdcheck

Monitoring [OpenLDAP](https://www.openldap.org) *slapd*.

## Supported monitoring systems

  * [MRPE for checkmk](https://checkmk.com/integrations/mrpe)
  * [OpenMetrics](https://openmetrics.io/) e.g. for Prometheus
  * Send data to Zabbix trapper similar to _zabbix_sender_
  * Simple colored HTML output
  * JSON output

## Requirements

  * Python 3.6+
  * Module [ldap0](https://pypi.org/project/ldap0/)
  * Module [psutil](https://pypi.org/project/psutil/)
  * Config backend (aka cn=config) has to be configured and readable.
  * Monitoring backend (aka cn=monitor) has to be configured and readable.
  * Optionally used Python modules:
    - [prometheus_client](https://pypi.org/project/prometheus_client/)
    - [py-zabbix](https://pypi.org/project/py-zabbix/)

## Project resources

  * [git repo python-ldap0](https://code.stroeder.com/ldap/slapdcheck)
  * [PyPI](https://pypi.org/project/slapdcheck)
  * [openSUSE/SLE packages](https://build.opensuse.org/package/show/home:stroeder:iam/slapdcheck)

## See also

  * [Talk at LDAPcon 2017](https://ldapcon.org/2017/monitoring-openldap/)
  * [Talk at FOSDEM 2019](https://archive.fosdem.org/2019/schedule/event/slapdcheck/)
  * [slapd-config(5)](https://www.openldap.org/software/man.cgi?query=slapd-config)
  * [slapd-monitor(5)](https://www.openldap.org/software/man.cgi?query=slapd-monitor)

## Installation

Create a virtual environment:

```
python3 -m venv /opt/slapdcheck
```

Pip-based installation from [PyPI](https://pypi.org/project/slapdcheck/)
with all optional dependencies:

```
/opt/slapdcheck/bin/pip install slapdcheck[all]
```

## Simple Usage

Command for generating MRPE output for check_mk:

```
/opt/slapdcheck/bin/python -m slapdcheck.mrpe /etc/slapdcheck.cfg
```

[example slapdcheck.cfg](https://code.stroeder.com/ldap/slapdcheck/src/branch/master/config/slapdcheck-example.cfg)

## Example MRPE output

```
0 SlapdCert not_after=1624052194.0|not_before=1592516194.0 OK - Server cert '/opt/ae-dir/etc/tls/ae-dir-suse-p1.example.com.crt' valid until 2021-06-18 21:36:34+00:00 UTC (92 days left, 74.8 % elapsed), modulus_match==True
0 SlapdCheckTime check_started=1616066981.2070713|check_finished=1616066984.3250916|check_duration=3.1180202960968018 OK - slapdcheck 3.8.0 took 3.12 secs to run
0 SlapdConfig server_id=3 OK - Successfully connected to 'ldapi://%2Frun%2Fae-dir%2Fslapd%2Fldapi' as 'dn:cn=root,ou=ae-dir' found 'cn=config' and 'cn=Monitor' server ID: 3 (0x3)
0 SlapdConns count=11|percent=8.59375 OK - 11 open connections (max. 128)
0 SlapdContextCSN_2_ou_ae_dir_ae_dir_centos_p1_vnet1_local num_csn_values=10|connect_latency=0.02228546142578125 OK - 10 contextCSN attribute values retrieved for 'ou=ae-dir' from 'ldaps://ae-dir-centos-p1.example.com'
0 SlapdContextCSN_2_ou_ae_dir_ae_dir_centos_p2_vnet1_local num_csn_values=10|connect_latency=0.022634029388427734 OK - 10 contextCSN attribute values retrieved for 'ou=ae-dir' from 'ldaps://ae-dir-centos-p2.example.com'
0 SlapdContextCSN_2_ou_ae_dir_ae_dir_deb_p1_vnet1_local num_csn_values=10|connect_latency=0.01251530647277832 OK - 10 contextCSN attribute values retrieved for 'ou=ae-dir' from 'ldaps://ae-dir-deb-p1.example.com'
0 SlapdContextCSN_2_ou_ae_dir_ae_dir_ubu_p1_vnet1_local num_csn_values=10|connect_latency=0.023425817489624023 OK - 10 contextCSN attribute values retrieved for 'ou=ae-dir' from 'ldaps://ae-dir-ubu-p1.example.com'
0 SlapdDatabases count=2 OK - Found 2 real databases: {1}mdb: cn=accesslog-ae-dir / {2}mdb: ou=ae-dir
0 SlapdEntryCount_1_cn_accesslog_ae_dir mdb_entry_count=4606 OK - 'cn=accesslog-ae-dir' has 4606 entries
0 SlapdEntryCount_2_ou_ae_dir mdb_entry_count=127 OK - 'ou=ae-dir' has 127 entries
0 SlapdMDBSize_1_cn_accesslog_ae_dir mdb_pages_used=2898|mdb_pages_max=122070|mdb_use_percentage=2.3740476775620545 OK - LMDB in '/opt/ae-dir/slapd-db/accesslog' uses 2898 of max. 122070 pages (2.4 %)
0 SlapdMDBSize_2_ou_ae_dir mdb_pages_used=246|mdb_pages_max=24414|mdb_use_percentage=1.0076185795035635 OK - LMDB in '/opt/ae-dir/slapd-db/um' uses 246 of max. 24414 pages (1.0 %)
0 SlapdMonitor monitor_entries=65 OK - Retrieved 65 entries from 'cn=Monitor' on 'ldapi://%2Frun%2Fae-dir%2Fslapd%2Fldapi'
0 SlapdOps ops_completed_rate=1.467956429036148|ops_initiated_rate=1.467956429036148|ops_waiting=1 OK - 10 operation types / completed 159 of 160 operations (1.47/s completed, 1.47/s initiated, 1 waiting)
0 SlapdOps_Abandon ops_completed_rate=0.0|ops_initiated_rate=0.0|ops_waiting=0 OK - completed 0 of 0 operations (0.00/s completed, 0.00/s initiated, 0 waiting)
0 SlapdOps_Add ops_completed_rate=0.0|ops_initiated_rate=0.0|ops_waiting=0 OK - completed 0 of 0 operations (0.00/s completed, 0.00/s initiated, 0 waiting)
0 SlapdOps_Bind ops_completed_rate=0.3454015127143878|ops_initiated_rate=0.3454015127143878|ops_waiting=0 OK - completed 29 of 29 operations (0.35/s completed, 0.35/s initiated, 0 waiting)
0 SlapdOps_Compare ops_completed_rate=0.0|ops_initiated_rate=0.0|ops_waiting=0 OK - completed 0 of 0 operations (0.00/s completed, 0.00/s initiated, 0 waiting)
0 SlapdOps_Delete ops_completed_rate=0.0|ops_initiated_rate=0.0|ops_waiting=0 OK - completed 0 of 0 operations (0.00/s completed, 0.00/s initiated, 0 waiting)
0 SlapdOps_Extended ops_completed_rate=0.1727007563571939|ops_initiated_rate=0.1727007563571939|ops_waiting=0 OK - completed 23 of 23 operations (0.17/s completed, 0.17/s initiated, 0 waiting)
0 SlapdOps_Modify ops_completed_rate=0.0|ops_initiated_rate=0.0|ops_waiting=0 OK - completed 0 of 0 operations (0.00/s completed, 0.00/s initiated, 0 waiting)
0 SlapdOps_Modrdn ops_completed_rate=0.0|ops_initiated_rate=0.0|ops_waiting=0 OK - completed 0 of 0 operations (0.00/s completed, 0.00/s initiated, 0 waiting)
0 SlapdOps_Search ops_completed_rate=0.7771534036073725|ops_initiated_rate=0.7771534036073725|ops_waiting=1 OK - completed 85 of 86 operations (0.78/s completed, 0.78/s initiated, 1 waiting)
0 SlapdOps_Unbind ops_completed_rate=0.1727007563571939|ops_initiated_rate=0.1727007563571939|ops_waiting=0 OK - completed 22 of 22 operations (0.17/s completed, 0.17/s initiated, 0 waiting)
0 SlapdProc pmem_rss=38883328|pmem_vms=863850496|pmem_shared=11632640|pmem_text=876544|pmem_lib=0|pmem_dirty=0|ctx_switches_voluntary=134|ctx_switches_involuntary=166 OK - 30 process information items
1 SlapdProviders count=4|total=7|percent=57.142857142857146|avg_latency=0.020215153694152832|max_latency=0.023425817489624023 WARNING - Connected to 4 of 7 (57.1%) providers: Error connecting to 'ldaps://ae-dir-deb-p2.example.com' (10.54.1.32): {'result': -1, 'desc': b"Can't contact LDAP server", 'errno': 107, 'ctrls': [], 'info': b'Transport endpoint is not connected'} / Error connecting to 'ldaps://ae-dir-suse-p2.example.com' (10.54.1.42): {'result': -1, 'desc': b"Can't contact LDAP server", 'errno': 107, 'ctrls': [], 'info': b'Transport endpoint is not connected'} / Error connecting to 'ldaps://ae-dir-suse-p3.example.com' (10.54.1.45): {'result': -1, 'desc': b"Can't contact LDAP server", 'errno': 107, 'ctrls': [], 'info': b'Transport endpoint is not connected'}
0 SlapdReplTopology - OK - successfully retrieved syncrepl topology with 7 items: {'ldaps://ae-dir-deb-p1.example.com': [(2, 'ou=ae-dir', SyncReplDesc(rid=001))], 'ldaps://ae-dir-deb-p2.example.com': [(2, 'ou=ae-dir', SyncReplDesc(rid=002))], 'ldaps://ae-dir-suse-p2.example.com': [(2, 'ou=ae-dir', SyncReplDesc(rid=003))], 'ldaps://ae-dir-centos-p1.example.com': [(2, 'ou=ae-dir', SyncReplDesc(rid=004))], 'ldaps://ae-dir-centos-p2.example.com': [(2, 'ou=ae-dir', SyncReplDesc(rid=005))], 'ldaps://ae-dir-ubu-p1.example.com': [(2, 'ou=ae-dir', SyncReplDesc(rid=006))], 'ldaps://ae-dir-suse-p3.example.com': [(2, 'ou=ae-dir', SyncReplDesc(rid=007))]}
0 SlapdSASLHostname - OK - olcSaslHost 'ae-dir-suse-p1.example.com' found
0 SlapdSelfConn connect_latency=0.0058252811431884766 OK - successfully bound to 'ldaps://ae-dir-suse-p1.example.com' as 'dn:uid=ae-dir-slapd_ae-dir-suse-p1.example.com,cn=ae,ou=ae-dir'
0 SlapdSock - OK - Found 1 back-sock listeners
0 SlapdSock__run_ae_dir_hotp_validator_socket sockAvgResponseTime=0.0002|sockBytesReceived=96.0|sockBytesSent=6379.0|sockHOTPKeyCount=4.0|sockHOTPMaxLookAheadSeen=0.0|sockMaxResponseTime=0.01285|sockRequestAll=12.0|sockRequestMonitorCount=12.0|sockThreadCount=1.0 OK - Connected to bind/compare listener '/run/ae-dir/hotp_validator/socket' and received 582 bytes
0 SlapdStart start_time=1616066819.0 OK - slapd[600] started at 2021-03-18 11:26:59+00:00, 0:02:42.219736 ago
0 SlapdStats stats_bytes_rate=2442.5931475379716|stats_entries_rate=6.735329497930562|stats_pdu_rate=8.203285926966709|stats_referrals=85.83227590952536 OK - Stats: 193360 bytes (2442.6 bytes/sec) / 854 entries (6.7 entries/sec) / 994 PDUs (8.2 PDUs/sec) / 0 referrals (85.8 referrals/sec)
1 SlapdSyncRepl_2_ou_ae_dir max_csn_timedelta=0.0 WARNING - 'ou=ae-dir' max. contextCSN delta: 0.0 / KeyError for 'ldaps://ae-dir-deb-p2.example.com' / 'ou=ae-dir': 'ldaps://ae-dir-deb-p2.example.com' / KeyError for 'ldaps://ae-dir-suse-p2.example.com' / 'ou=ae-dir': 'ldaps://ae-dir-suse-p2.example.com' / KeyError for 'ldaps://ae-dir-suse-p3.example.com' / 'ou=ae-dir': 'ldaps://ae-dir-suse-p3.example.com'
0 SlapdThreads threads_active=1|threads_pending=0|threads_max=8 OK - Thread counts active:1 pending: 0
0 SlapdVersion version=2.4.58|build_time=1615849200.0 OK - OpenLDAP: slapd 2.4.58 (Mar 16 2021 00:00:00)
```
