#!/usr/bin/python3
# Copyright 2021 BlueCat Networks (USA) Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# version 5.6 Michael 7 July 2021
#     Wait if psmd is not yet accepting commands
#
# version 5.0 Michael 19 May 2021
#     Upgrade to 9.3 and python3. Move most functions to earlier in boot.
#
# version 4.14 Michael 23 December 2019
#     Add support for syslog_servers_fixed_hostname with IPv6 and syslog_mon
#
# version 4.12 Michael 6 December 2019
#     Add support for IPv6 syslog destinations
#
# version 4.6 Michael 28 June 2019
#     Disable SNMPv3 secrets workaround, because this has been fixed in 9.1
#
# version 4.5 Michael 20 June 2019
#     Add syslog_servers_fixed_hostname
#
# version 4.4 Michael 21 May 2019
#     Add anycast configuration
#
# version 2.8 Michael 6 August 2018
# Updates: Retain any existing network routes (as discovered by PSM)
#
# version 2.4 Michael 16 April 2018
# Updates: Remove plaintext passwords also for SNMPv3 traps
#
# version 2.3 Michael 16 April 2018
# Updates: Bypass PSM database for SNMPv3 secrets
#
# version 2.2 Michael 6 March 2018
# Updates: Resolve bugs in BAM database initialization
#
# version 2.0 Michael 29 January 2018
# Updates: Remove loading of config drive. This is now handled by cloudinit.
#          Remove most interface configuration. This is handled earlier in the boot.
#          Add explicit "enable-dedicated-management" option.
#
# version 1.14 Michael 31 October 2017
# Updates: Delete BlueCat metadata file after loading contents (it can contain passwords)
#
# version 1.13 Michael 21 October 2017
# Updates: On BAM, allow eth0 address to be configured using mgmt_ip4 or service_ip4
#          Call updateDBHistoryRecordInterface after restoring BAM database
#
# version 1.12 Michael 17 October 2017
# Updates: Add options to disable root login and enable STIG
#          If provided, use backup to initialize BAM database
#
# version 1.10 Michael 31 August 2017
# Updates: Fix sshd AllowUsers update on BAM by using TACACS UID range for new users
#
# version 1.9 Michael 18 August 2017
# Updates: Add timezone support
#
# version 1.7 Michael 16 August 2017
# Updates: Use inject file for metadata if available
#          Add support for additional user accounts
#          Add work-around for syslog permissions
#
# version 1.6 Michael 28 July 2017
# Updates: Perform PSM node restart after configuring dedicated management
#
# version 1.5 Michael 20 July 2017
# Updates: Use PsmClient to update interfaces.
#          Remove logging module -- post_update script captures stdout.
#          Add error checking.
#          Update pg_hba.conf if it exists.
#
# version 1.4 Eric 01 July 2017
# Updates: fixed snmp is not enabled issue. 
#
# version 1.3 Eric 01 July 2017
# Updates: move config hostname after config interface 
#
# version 1.2 Timothy Noel 20 June 2017
# UPDATES:
# 	Reorder clish commands to perform settings in this order
#	1) license
#	2) hostname
#	3) interfaces
#	4) static routes
#
# version 1.1 Michael Nonweiler 07 May 2017

import os
import shutil
import subprocess
import re
import json
import sys
import pwd
import time
from textwrap import dedent
from socket import gethostname
from pwd import getpwnam
from grp import getgrnam

sys.path.append('/usr/local/cli/scripts')
# Note: cli modules log to /var/log/cli.log
from cliShellCommand import cCliShellCommand
from cliSystemEnv import cCliSystemEnv
from cliBam import cCliBam
from psmRequestResponse import cPsmRequestResponse
from psmInterface import cPsmInterface
from psmRoutes import cPsmRoutes
from psmHostname import cPsmHostname

bluecat_metadata_filename = '/etc/bcn/init-config.json'
bam_init_database_filename = '/etc/bcn/init-database.bak'
fw_rules_filename = '/etc/bcn/custom_fw_rules'
syslog_filters_filename = '/usr/share/syslog-ng/include/scl/syslog_mon/filters.conf'

# Load BlueCat meta_data from a separate inject file
meta = {}
if os.path.isfile(bluecat_metadata_filename):
    try:
        with open(bluecat_metadata_filename, 'r') as metadata_file:
            meta = json.load(metadata_file)
        # Do not use any more configuration from the global metadata file
    except Exception as e:
        print('Cannot read BlueCat metadata - %s' % e)
    try:
        os.remove(bluecat_metadata_filename)
    except Exception as e:
        print('Failed to remove BlueCat metadata - %s' % e)

# Check that psmd is ready to receive commands
for _ in range(10):
    cmdout = subprocess.run(
        ['/usr/local/bluecat/PsmClient','node','get','manual-override'],
        stdout = subprocess.PIPE, stderr = subprocess.STDOUT, text = True).stdout
    if 'Could not connect to psmd' in cmdout:
        # If psmd is not yet accepting commands, PsmClient returns just:
        # ERROR:  Could not connect to psmd
        print('Waiting - psmd not available')
        # sleep then retry
        time.sleep(1.0)
    else:
        # continue with script
        break
else:
    # maximum retries exceeded
    print('Aborting - psmd not available')
    sys.exit(1)

if 'custom_fw_rules' in meta:
    try:
        with open(fw_rules_filename, 'w') as rulesfile:
            for rule in meta['custom_fw_rules'].split(';'):
                rulesfile.write(rule + '\n')
    except Exception as e:
        print('Failed to create custom firewall rules file: %s' % e)

systemEnv = cCliSystemEnv()
# custom firewall rules are only valid on BDDS
if systemEnv.isBdds() and os.path.isfile(fw_rules_filename):
    sCmd = cCliShellCommand('/usr/local/bluecat/custom_fw_rules --import-rules ' + fw_rules_filename)
    sCmd.exe('Import custom firewall rules')
    # now the firewall rules have imported in to the PSM db, the import file can be removed
    try:
        os.remove(fw_rules_filename)
    except Exception as e:
        print('Failed to remove fw rules file - %s' % e)

psm_overrides = set()

if 'syslog_servers_fixed_hostname' in meta or 'implement_log_permissions_workaround' in meta:
    psm_overrides.add('syslog')
    sCmd = cCliShellCommand('')
    sCmd.psmSetExe('manual-override',','.join(psm_overrides))

# Temporary work-around for problem with log file permissions
if 'implement_log_permissions_workaround' in meta and meta['implement_log_permissions_workaround']:
    subprocess.call(['sed','-i.bak','/perm/s/(0600)/(0644)/', '/etc/syslog-ng/syslog-ng.conf'])
    subprocess.call(['service','syslog','reload'])

# hostname is added to the metadata file by generate_init_config, ONLY for use with syslog_servers_fixed_hostname
# This script no longer updates the hostname, which is set during initial network configuration
hostname = None
if 'hostname' in meta:
    hostname = meta['hostname']

# Send logs using original VM name, instead of the hostname configured by BAM
if hostname and 'syslog_servers_fixed_hostname' in meta and meta['syslog_servers_fixed_hostname']:
    try:
        with open('/etc/syslog-ng/syslog-ng.conf','r') as oldfile:
            with open('/etc/syslog-ng/syslog-ng.conf.new','w') as newfile:
                rewrite_rule_defined = False
                for line in oldfile:
                    m = re.match(r'# BlueCat filters', line)
                    if not rewrite_rule_defined and m:
                        newfile.write('# BlueCat rewrite rule to replace hostname, added by init script\n')
                        newfile.write(('rewrite r_replace_hostname { set ("%s", value("HOST")); };\n\n' % hostname))
                        rewrite_rule_defined = True
                    # standard destination name is dest_udp_<ip4> or dest_udp6_<ip6>
                    m = re.match(r'\s*destination\(dest_(udp|tcp)(.*)\);', line)
                    if m:
                        newfile.write('\trewrite(r_replace_hostname);\n')
                    newfile.write(line)
        shutil.copy('/etc/syslog-ng/syslog-ng.conf','/etc/syslog-ng/syslog-ng.conf.bak')
        os.rename('/etc/syslog-ng/syslog-ng.conf.new','/etc/syslog-ng/syslog-ng.conf')

        # Update also syslog_mon pre-defined log rules
        if os.path.isfile(syslog_filters_filename):
            with open(syslog_filters_filename,'r') as oldfile:
                with open(syslog_filters_filename + '.new','w') as newfile:
                    newfile.write('# BlueCat rewrite rule to replace hostname, added by init script\n')
                    newfile.write('rewrite r_rewrite_hostname { set ("%s", value("HOST")); };\n\n' % hostname)
                    for line in oldfile:
                        newfile.write(line)
                        m = re.match(r'\s*source\(local\);', line.decode('utf-8'))
                        if m:
                            newfile.write("\trewrite(r_rewrite_hostname);\n")
            shutil.copy(syslog_filters_filename, syslog_filters_filename + '.bak')
            os.rename(syslog_filters_filename + '.new', syslog_filters_filename)

        subprocess.call(['service','syslog','reload'])
    except Exception as e:
        print("Failed to update syslog configuration: %s" % e)




def run_psmclient_cmd(cmd, msg):
    sCmd = cCliShellCommand('/usr/local/bluecat/PsmClient ' + cmd)
    sCmd.exe(msg)

# Get server primary IP addresses (service interface on BDDS and management on BAM)
# This is for use in anycast configuration on BDDS
# and HTTPS configuration when restoring a database on BAM
interface = cPsmInterface("eth0")
interface.getInterface("Failed to get primary IP",unsaved=False)
eth0_ip4 = interface.getPrimary("v4")
eth0_ip6 = interface.getPrimary("v6")
# Get CIDR representation with network prefix length for eth0_ip4
for ipcidr in interface.getAllAddress(False).split():
    address = ipcidr.split('/')[0]
    if address == eth0_ip4:
        eth0_ip4_cidr = ipcidr
    if address == eth0_ip6:
        eth0_ip6_cidr = ipcidr

# Configure anycast
if systemEnv.isBdds() and 'anycast' in meta:
    anycast_config = meta['anycast']

    list_ipv4 = ','.join(anycast_config['anycast_ipv4'])
    cmd = 'anycast set component=common vtysh-enable=1'
    cmd += ' anycast-ipv4=' + list_ipv4
    if 'anycast_ipv6' in anycast_config and eth0_ip6:
        list_ipv6 = ','.join(anycast_config['anycast_ipv6'])
        cmd += ' anycast-ipv6=' + list_ipv6 + ' service-ipv6=' + eth0_ip6_cidr
    run_psmclient_cmd(cmd, 'Setting anycast common configuration')

    cmd = 'anycast set component=zebra authenticate=0'
    run_psmclient_cmd(cmd, 'Setting anycast zebra configuration')

    # Note: only tested with OSPFv3
    if anycast_config['anycast_protocol'] == 'ospf':
        # Convert boolean to 1/0 representation
        anycast_config['ospf_stub'] = 1 if anycast_config['ospf_stub'] else 0
        # Note: anycast set operation automatically clears manual-override
        cmd = "anycast set component=ospfd enabled=1 \
        authenticate=0 \
        area={ospf_area} \
        dead-interval={ospf_dead_interval} \
        hello-interval={ospf_hello_interval} \
        stub={ospf_stub}".format(**anycast_config)
        run_psmclient_cmd(cmd, 'Setting anycast OSPF configuration')

        if 'anycast_ipv6' in anycast_config and eth0_ip6:
            # IPv4 IP address is used as router ID also for v6
            anycast_config['router_id'] = eth0_ip4
            anycast_config['service_interface'] = 'eth0'

            try:
                path = '/etc/quagga/ospf6d.conf'
                with open(path, 'w') as conffile:
                    conffile.write(dedent("""\
                        ! -- ospf6d.conf generated by BlueCat cloud init script
                        debug ospf6 lsa unknown
                        !
                        interface {service_interface}
                         ipv6 ospf6 hello-interval {ospfv3_hello_interval}
                         ipv6 ospf6 dead-interval {ospfv3_dead_interval}
                         ipv6 ospf6 network broadcast
                        !
                        router ospf6
                         router-id {router_id}
                         area {ospfv3_area} range {ospfv3_range}
                         interface {service_interface} area {ospfv3_area}
                        !
                        line vty
                        """.format(**anycast_config)))
                quagga_uid = getpwnam('quagga').pw_uid
                quagga_gid = getgrnam('quagga').gr_gid
                os.chown(path, quagga_uid, quagga_gid)
                os.chmod(path, 0o644)
            except Exception as e:
                print('Failed to create quagga configuration files: %s' % e)

            # Configure systemd to start ospf6d when zebra is started by PSM
            try:
                wants_dir = '/etc/systemd/system/zebra.service.wants'
                if not os.path.isdir(wants_dir):
                    os.mkdir(wants_dir)
                if not os.path.exists(wants_dir + '/ospf6d.service'):
                    os.symlink('/lib/systemd/system/ospf6d.service', wants_dir + '/ospf6d.service')
            except Exception as e:
                print('Failed to configure systemd to start ospf6d with zebra: %s' % e)

    elif anycast_config['anycast_protocol'] == 'bgp':
        # In this version, BGP is untested
        # The configuration format will need to change to support multiple neighbors with prefix lists
        cmd = "anycast set component=bgpd enabled=1 authenticate=0 \
        asn={bgp_local_asn} keepalive={bgp_keepalive_time} holdtime={bgp_hold_time} \
        neighbors-ipv4={bgp_ipv4_address} \
        neighbors-ipv6={bgp_ipv6_address}".format(**anycast_config)
        if anycast_config['prefix_lists']:
            prefix_lists = []
            for list in anycast_config['prefix_lists']:
                if list['name'] not in prefix_lists:
                    prefix_lists.append(list['name'])
            cmd += " prefix-lists={}".format(','.join(prefix_lists))
        run_psmclient_cmd(cmd, 'Setting anycast BGP configuration')

        if anycast_config['prefix_lists']:
            for list in anycast_config['prefix_lists']:
                for item in list['networks']:
                    # Set prefix-list command adds or updates one entry, identified by a unique sequence number, in the prefix list
                    cmd = "anycast set component=bgpd prefix-list={}".format(list['name'])
                    # action is permit or deny
                    cmd += " seq={seq} action={action} network={network}".format(**item)
                    run_psmclient_cmd(cmd, 'Adding entry to anycast BGP prefix list')

        # Convert boolean to 1/0 representation
        anycast_config['bgp_next_hop_self_ipv4'] = 1 if anycast_config['bgp_next_hop_self_ipv4'] else 0
        anycast_config['bgp_next_hop_self_ipv6'] = 1 if anycast_config['bgp_next_hop_self_ipv6'] else 0

        # Set neighbor-ip4 command
        # Does not yet support multiple neighbors, prefix-list in and prefix-list out
        cmd = "anycast set component=bgpd neighbor-ipv4={bgp_ipv4_address} \
        asn={bgp_remote_asn_in_ipv4} \
        ebgp-multihop={bgp_ipv4_hop_limit} next-hop-self={bgp_next_hop_self_ipv4} \
        password={bgp_md5_ipv4}".format(**anycast_config)
        run_psmclient_cmd(cmd, 'Set anycast BGP IPv4 neighbor configuration')

        # Set neighbor-ip6 command
        # Does not yet support multiple neighbors, prefix-list in and prefix-list out
        cmd = "anycast set component=bgpd neighbor-ipv6={bgp_ipv6_address} \
        asn={bgp_remote_asn_in_ipv6} \
        ebgp-multihop={bgp_ipv6_hop_limit} next-hop-self={bgp_next_hop_self_ipv6} \
        password={bgp_md5_ipv6}".format(**anycast_config)
        run_psmclient_cmd(cmd, 'Set anycast BGP IPv6 neighbor configuration')

    elif anycast_config['anycast_protocol'] == 'rip':
        cmd = "anycast set component=ripd enabled=1 authenticate=0"
        run_psmclient_cmd(cmd, 'Setting anycast RIP configuration')

    if anycast_config['enabled']:
        cmd = 'node set anycast-enable=1'
        run_psmclient_cmd(cmd, 'Enable anycast')

if 'disable-root-login' in meta and meta['disable-root-login']:
    sCmd = cCliShellCommand('/usr/local/bluecat/disableRootLogin.sh')
    sCmd.exe('Disable root login')

if 'enable-pam-login-restrictions' in meta and meta['enable-pam-login-restrictions']:
    sCmd = cCliShellCommand('/usr/local/bluecat/enablePamLogin.sh')
    sCmd.exe('Enable PAM login restrictions')

if (os.path.isfile(bam_init_database_filename) and
    os.path.isfile('/usr/local/bluecat/restoreDB-nostart.sh')):
    print("Initializing database from backup file")
    # restoreDB-nostart.sh is created from restoreDB.sh with:
    # sed '/systemctl start proteusServer/d;/proteusServer.sh stopwait/d' < /usr/local/bluecat/restoreDB.sh > /usr/local/bluecat/restoreDB-nostart.sh
    # If we call systemctl start proteusServer from this script it just hangs
    sCmd = cCliShellCommand('bash /usr/local/bluecat/restoreDB-nostart.sh ' + bam_init_database_filename)
    sCmd.exe('Restore database backup')

    SERVER_IP_INIT_BACKUP = "192.168.1.2"
    if eth0_ip4 and eth0_ip4 != SERVER_IP_INIT_BACKUP:
        # Update IP address in HTTP/HTTPS config restored from backup
        cliBam = cCliBam()
        cliBam.updateDBHistoryRecordInterface(SERVER_IP_INIT_BACKUP,eth0_ip4)


# Enabling STIG compliance forces a reboot
# Unfortunately, this happens before the output of this script is logged
# It could work better to call this separately from cloudinit
# TODO: Check how STIG is handled during upgrades
try:
    if 'enable-stig-compliance' in meta and meta['enable-stig-compliance']:
        sCmd = cCliShellCommand('/usr/local/bluecat/enableStigCompliance.sh')
        sCmd.exe('Enable STIG compliance')
except Exception as ex:
    print('Enable STIG Error: {}'.format(str(ex)))

if systemEnv.isBam() and os.path.isfile('/usr/local/cli/scripts/cliBam.py'):
    print("UpdateDBConfiguration (called from updateMainAddress) ..")
    sCmd = cCliShellCommand('/usr/local/cli/scripts/cliBam.py')
    sCmd.exe('Update DB Configuration ..')