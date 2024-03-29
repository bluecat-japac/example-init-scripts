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
# 2021-05-19 Updated to use new psmdbset in 9.3
#            Now loads JSON config and enables dedicated-management if required
#            Many configuration steps moved from openstack-initial-config.py to this stage

import os
import subprocess
import sys
import pwd
import shutil
import re
import json
import ipaddress

sys.path.append('/usr/local/cli/scripts')
# Note: cli modules log to /var/log/cli.log
from cliShellCommand import cCliShellCommand


# "psmdbset snmp" outputs entire JSON config to stdout, so we discard stdout to prevent logging of secrets
def psmdbset(*args):
    subprocess.call(['/usr/local/bluecat/psmdbset', *args], stdout = subprocess.DEVNULL)

# Check that input data has the correct syntax,
# by comparing it with a template
def templateMatch(template, data):
    try:
        etype = type(template)
        if etype == type:
            assert isinstance(data, template)
        elif etype == dict:
            assert isinstance(data, dict)
            # The items in a data dict must match items in the template,
            # but it is not necessary for the data to contain all template items.
            for k, v in iter(data.items()):
                assert k in template
                templateMatch(template[k], v)
        elif etype == list:
            assert isinstance(data, list)
            # A list in the template should have one item.
            # This item is the template for every item in the data list.
            # The list in the data can be empty or have any number of elements.
            assert len(template) == 1
            for x in data:
                templateMatch(template[0], x)
        elif etype == str:
            assert isinstance(data, str)
            assert re.match(template, data)
        else:
            assert False
    except AssertionError:
        print("template:", template, "data:", data, "data type:", type(data))
        raise

input_template = {
   "hostname" : ".*",
   "interfaces" : [
      {
         "name" : "(eth[0-4]|eth0:[0-9]+)",
         "v4addresses" : [
            {
               "address" : "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$",
               "cidr" : int
            }
         ],
         "v6addresses" : [
            {
               "address" : "[0-9a-fA-F:]+$",
               "cidr" : int
            }
         ]
      }
   ],
   "default_routes" : [
      {
         "cidr" : int,
         "gateway" : "([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F:]+)$",
         "network" : "([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F:]+|default)$"
      }
   ]
}

# Get input data from file
bluecat_metadata_filename = "/etc/bcn/init-config.json"
initdata = {}
try:
    with open(bluecat_metadata_filename, 'r') as metadata_file:
        meta = initdata = json.load(metadata_file)
except Exception as e:
    print('Cannot read init configuration file - %s' % e)
    raise

# Identify if we are running on BAM or BDDS
if subprocess.call(['dpkg','-l','adonis-app'], stdout = subprocess.DEVNULL) == 0:
    is_bam = False
    is_bdds = True
elif subprocess.call(['dpkg','-l','proteus-app'], stdout = subprocess.DEVNULL) == 0:
    is_bam = True
    is_bdds = False
else:
    assert False

DB_CONF = "/data/pgdata/pg_hba.conf"
HOSTS = "/etc/hosts"

hostname = 'new'
if 'hostname' in initdata:
    hostname = initdata['hostname']

# Find the primary IP address. This may be a VLAN interface
# We make the first IPv4 address on eth0 the primary address
eth0_subnet = 32
eth0_data = next(x for x in initdata['interfaces'] if x['name'].split('.')[0] == 'eth0')
eth0_address = eth0_data['v4addresses'][0]['address'] if eth0_data['v4addresses'] else {}
if not eth0_address:
    eth0_address = eth0_data['v6addresses'][0]['address']
    eth0_address = ipaddress.IPv6Address(eth0_address).compressed
    eth0_subnet = 128

# update database configuration on BAM to reflect IP address change
# Note slony/database.conf does not exist yet; it will be created when postgres is started for the first time
if os.path.exists(DB_CONF):
    # ("Updating pg_hba.conf with address %s", eth0_address)
    subprocess.call(["sed", "-i",
         "-e", "/^host all postgres/ c\\host all postgres %s\\/%s trust" % (eth0_address, eth0_subnet),
          DB_CONF])

    # ("Updating proteusdb.bluecatnetworks.corp with address %s", eth0_address)
    subprocess.call(["sed", "-i",
         "-e", "/proteusdb.bluecatnetworks.corp/ c\\%s proteusdb.bluecatnetworks.corp" % eth0_address,
          HOSTS])

    # ("Updating proteuscluster.bluecatnetworks.corp with address %s", eth0_address)
    subprocess.call(["sed", "-i",
         "-e", "/proteuscluster.bluecatnetworks.corp/ c\\%s proteuscluster.bluecatnetworks.corp" % eth0_address,
          HOSTS])

# update /etc/hosts to reflect new IP address on new hostname (both BAM and BDDS)
# Note: not sure this is necessary, because PSM may do this automatically
# ("Updating /etc/hosts  with address %s", eth0_address)
subprocess.call(["sed", "-i",
     "-e", "/new/ c\\%s %s" % (eth0_address, hostname), HOSTS])

# dbus is not yet available in 8.3, so we cannot use hostnamectl

# update /etc/hostname
with open("/etc/hostname","w") as etc_hostname:
    etc_hostname.write( "{}\n".format(hostname) )

subprocess.call(["hostname", hostname])


# Support DHCP
enable_dhcp_v4 = meta.get('enable_dhcp_v4', False)
enable_dhcp_v6 = meta.get('enable_dhcp_v6', False)


def get_dhcp_address(ip_type, if_name):
    result = address = netmask = ''
    try:
        if ip_type == 'v4':
            dhcp_v4_data = subprocess.run('/usr/bin/ip addr show dev {} | /usr/bin/grep "inet.*global"'.format(if_name),
                                          shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
            dhcp_v4_re = re.search('.*inet (.*)scope.*', dhcp_v4_data.decode("utf-8"))
            result = dhcp_v4_re.group(1).strip()
            try:
                netmask = result.split('/')[1]
                netmask = int(netmask) if not isinstance(netmask, int) else netmask
            except Exception as ex:
                print("ERROR: Get DHCPv4 address netmask: {}".format(str(ex)))
                netmask = 32
        if ip_type == 'v6':
            dhcp_v6_data = subprocess.run('/usr/bin/ip addr show dev {} | /usr/bin/grep "inet6.*global"'.format(if_name),
                                          shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
            dhcp_v6_re = re.search('.*inet6(.*)scope.*', dhcp_v6_data.decode("utf-8"))
            result = dhcp_v6_re.group(1).strip()
            try:
                netmask = result.split('/')[1]
                netmask = int(netmask) if not isinstance(netmask, int) else netmask
            except Exception as ex:
                print("ERROR: Get DHCP address netmask: {}".format(str(ex)))
                netmask = 128
        address = result.split('/')[0]
    except Exception as ex:
        print("ERROR: Get DHCP Address: {}".format(str(ex)))
    return address, netmask


# Support DHCP
def check_interface(if_name):
    is_check = subprocess.run(
        ['/usr/bin/ip', 'addr', 'show', if_name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
    if 'does not exist' not in is_check:
        return True
    return False


def run_dhclient(dhcp_type):
    cmd = '/usr/sbin/dhclient -6 ' if dhcp_type == 'v6' else '/usr/sbin/dhclient '
    subprocess.run(cmd + 'eth0', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if check_interface('eth2'):
        subprocess.run(cmd + 'eth2', shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    if is_bdds:
        if check_interface('eth1'):
            subprocess.run(cmd + 'eth1', shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        if check_interface('eth4'):
            subprocess.run(cmd + 'eth4', shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)


def get_interface_data(if_name, enable_dhcp_v4, enable_dhcp_v6, if_data=''):
    if if_name == 'eth0' or check_interface(if_name):
        if_data += "auto {}\n".format(if_name)
        if enable_dhcp_v4:
            if_data += "\tiface {} inet dhcp\n".format(if_name)
        if enable_dhcp_v6:
            if_data += "\tiface {} inet6 dhcp\n".format(if_name)
    return if_data

# Use psmdbset tool to initialize PSM databases, and to set hostname
# We use dummy addresses here, then replace them in the database below
# psmdbset netconf -a <ip> -c <cidr> -g <gw> [-n <host>]
psmdbset('netconf', '-a', '192.168.1.2', '-c', '24', '-g', '192.168.1.1', '-n', hostname)

if enable_dhcp_v4 or enable_dhcp_v6:
    with open('/etc/network/interfaces', 'w') as interfaces:
        lo_data = 'auto lo\n\tiface lo inet loopback\n\tiface lo inet6 loopback\n'
        interfaces.write(get_interface_data('eth0', enable_dhcp_v4, enable_dhcp_v6, if_data=lo_data))

        if_data = get_interface_data('eth2', enable_dhcp_v4, enable_dhcp_v6)
        if is_bdds:
            if_data = get_interface_data('eth1', enable_dhcp_v4, enable_dhcp_v6, if_data=if_data)
            if_data = get_interface_data('eth4', enable_dhcp_v4, enable_dhcp_v6, if_data=if_data)
        interfaces.write(if_data)

    try:
        if enable_dhcp_v4:
            run_dhclient('v4')
        if enable_dhcp_v6:
            run_dhclient('v6')
    except Exception as ex:
        print("ERROR: Restart service networking: {}".format(str(ex)))

# Get available interfaces
interfaces = {}
with subprocess.Popen(['ip','link','show'], stdout=subprocess.PIPE) as iplinkcmd:
    for link in iplinkcmd.stdout:
        m = re.match(r'^[0-9]: *(lo|eth[0-4]):', link.decode("utf-8"))
        if m:
            ifname = m[1]
            interfaces[ifname] = {
                 "active" : 0,
                 "description" : "",
                 "name" : ifname,
                 "parents" : [],
                 "type" : "physical",
                 "v4addresses" : [],
                 "v6addresses" : []
            }

interfaces['eth0']['active'] = 1
interfaces['lo']['active'] = 1
interfaces['lo']['type'] = 'loopback'

primary_ipv4_address = None
primary_ipv6_address = None

for ifdata in initdata['interfaces']:
    fullname = ifdata['name']

    if '.' in fullname:
        vlanid = int(fullname.split('.')[1])
        ifname = fullname.split('.')[0]
    else:
        vlanid = None
        ifname = fullname

    for addr in ifdata['v4addresses'] + ifdata['v6addresses']:
        assert set(addr.keys()) == set(['address','cidr'])

    if ifname == 'lo':
        if ifdata['v4addresses']:
            assert len(ifdata['v4addresses']) <= 1
        lov4_address = ifdata['v4addresses'][0] if ifdata['v4addresses'] else {}
        lov6_address = ifdata['v6addresses'][0] if ifdata['v6addresses'] else {}

    if ifname == 'eth0' and is_bdds:
        if not primary_ipv4_address:
            # Make first address in each list the primary address
            if ifdata['v4addresses']:
                primary_ipv4_address = ifdata['v4addresses'][0]
                ifdata['v4addresses'][0]['flags'] = 1 # primary service interface flag
            if len(ifdata['v6addresses']) >= 1:
                primary_ipv6_address = ifdata['v6addresses'][0]
                ifdata['v6addresses'][0]['flags'] = 1 # primary service interface flag
    if ifname == 'eth0' and is_bam:
        # Allow only one IPv4 address on the BAM interface
        if ifdata['v4addresses']:
            assert len(ifdata['v4addresses']) <= 1
        primary_ipv4_address = ifdata['v4addresses'][0] if ifdata['v4addresses'] else {}

        if ifdata['v4addresses']:
            ifdata['v4addresses'][0]['flags'] = 1 # primary interface flag on BAM

        if ifdata['v6addresses'] and not ifdata['v4addresses']:
            ifdata['v6addresses'][0]['flags'] = 1 # primary interface flag on BAM

    if ifname == 'eth2' and is_bdds:
        # Allow only one IPv4 address on the BDDS management interface
        # This is flagged as the management address, even though dedicated management is not yet enabled
        if ifdata['v4addresses']:
            assert len(ifdata['v4addresses']) == 1
            ifdata['v4addresses'][0]['flags'] = 4 # management interface flag

        if ifdata['v6addresses'] and not ifdata['v4addresses']:
            ifdata['v6addresses'][0]['flags'] = 4 # management interface flag

    if vlanid: # Add new VLAN interface
        assert(ifname == 'eth0')
        interfaces[fullname] = {
            'name' : fullname,
            'description' : ifname + ' VLAN ' + str(vlanid),
            'parents' : [ ifname ],
            'type' : 'vlan',
            'vlanid' : vlanid
        }

    if ifname != 'lo' and (enable_dhcp_v4 or enable_dhcp_v6):
        if enable_dhcp_v4:
            ifdata['v4addresses'][0]['address'] = get_dhcp_address('v4', ifname)[0]
            ifdata['v4addresses'][0]['cidr'] = get_dhcp_address('v4', ifname)[1]
        if enable_dhcp_v6:
            ifdata['v6addresses'][0]['address'] = get_dhcp_address('v6', ifname)[0]
            ifdata['v6addresses'][0]['cidr'] = get_dhcp_address('v6', ifname)[1]

    if interfaces.get(fullname):
        interfaces[fullname]['active'] = 1
        interfaces[fullname]['v4addresses'] = ifdata['v4addresses']
        interfaces[fullname]['v6addresses'] = ifdata['v6addresses']

# gateway_ip4 in metadata is NOT supported
if 'gateway_ip4' in meta:
    print("Ignoring gateway_ip4 {} in metadata".format(meta['gateway_ip4']))

# Use default routes from initdata
routes_list = initdata['default_routes']

metadata_routes = []
if 'routes' in meta and meta['routes']:
    metadata_routes = meta['routes']

# Configure additional routes
if 'route1_network' in meta and 'route1_gateway' in meta:
    metadata_routes.append({
        "network" : meta['route1_network'],
        "gateway" : meta['route1_gateway']
    })

for route in metadata_routes:
    networkWithCidr = route['network']
    cidr = 0
    try:
        cidr = int(networkWithCidr.split('/')[1])
    except Exception as e:
        print('Failed to get CIDR: %s' % e)

    routes_list.append({
        "network": networkWithCidr.split('/')[0],
        "cidr": cidr,
        "gateway": route['gateway']
    })

interfaces_list = [ interfaces[ifname] for ifname in sorted(interfaces.keys()) ]

optargs = []
if is_bdds and 'enable-dedicated-management' in meta and meta['enable-dedicated-management']:
    optargs.append("--dedicated-management")

psmdbset("network-interfaces",
    "--interfaces", json.dumps({ 'interfaces' : interfaces_list }),
    "--routes", json.dumps({ 'routes' : routes_list }),
    *optargs)


# Support configure MTU
srv_mtu = meta.get('srv_mtu', '')
om_mtu = meta.get('om_mtu', '')
mtu_template = '/usr/bin/ip link set dev {} mtu {}'
post_up_template = 'post-up {}'.format(mtu_template)
is_eth2 = is_eth4 =False
if om_mtu:
    if is_bam:
        print("Configure MTU: {} for BAM: eth0".format(om_mtu))
        subprocess.run(mtu_template.format('eth0', om_mtu), shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
        cmdout = subprocess.run(
            ['/usr/bin/ip', 'addr', 'show', 'eth2'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
        if 'does not exist' not in cmdout:
            print("Configure MTU: {} for BAM: eth2".format(om_mtu))
            subprocess.run(mtu_template.format('eth2', om_mtu), shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
            is_eth2 = True
    elif is_bdds:
        cmdout = subprocess.run(
            ['/usr/bin/ip', 'addr', 'show', 'eth2'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
        if 'does not exist' not in cmdout:
            print("Configure MTU: {} for DDS: eth2".format(om_mtu))
            subprocess.run(mtu_template.format('eth2', om_mtu), shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
            is_eth2 = True

        cmdout = subprocess.run(
            ['/usr/bin/ip', 'addr', 'show', 'eth4'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
        if 'does not exist' not in cmdout:
            print("Configure MTU: {} for DDS: eth4".format(om_mtu))
            subprocess.run(mtu_template.format('eth4', om_mtu), shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
            is_eth4 = True

    # support configure mtu for the future reboot
    with open('/etc/network/interfaces', 'a+') as interfaces:
        interfaces.write('\n')
        if is_bam:
            interfaces.write(post_up_template.format('eth0', om_mtu) + '\n')
        if is_eth2:
            interfaces.write(post_up_template.format('eth2', om_mtu) + '\n')
        if is_bdds and is_eth4:
            interfaces.write(post_up_template.format('eth4', om_mtu) + '\n')


if srv_mtu:
    if is_bdds:
        print("Configure MTU: {} for DDS: eth0".format(srv_mtu))
        subprocess.run(mtu_template.format('eth0', srv_mtu), shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    print("Configure MTU: {} in lo".format(srv_mtu))
    subprocess.run(mtu_template.format('lo', srv_mtu), shell=True, stdout=subprocess.PIPE,
                   stderr=subprocess.STDOUT)
    # support configure mtu for the future reboot
    with open('/etc/network/interfaces', 'a+') as interfaces:
        interfaces.write('\n')
        if is_bdds:
            interfaces.write(post_up_template.format('eth0', srv_mtu) + '\n')
        interfaces.write(post_up_template.format('lo', srv_mtu) + '\n')

resolv_conf_filename = '/etc/resolv.conf'
# Configure nameservers
if 'nameservers' in meta:
    try:
        nameservers = meta['nameservers']
        if isinstance(nameservers, str):
            nameservers = meta['nameservers'].split(',')
        with open(resolv_conf_filename, 'w') as resolvconf:
            for address in nameservers:
                resolvconf.write('nameserver ' + address + '\n')
    except Exception as e:
        print('Failed to update resolv.conf: %s' % e)

# Configure License
if 'clientid' in meta and 'license_key' in meta:
    try:
        subprocess.call(['/usr/local/bluecat/lcd',
            'installkey', meta['clientid'].upper(), meta['license_key'].upper()])
    except:
        print("Failed to set license key")

# Note: System restart is required to complete timezone changes
if 'timezone' in meta:
    tz = meta['timezone']
    srcfile = '/usr/share/zoneinfo/' + tz
    if os.path.isfile(srcfile):
        try:
            os.remove('/etc/localtime')
            os.symlink(srcfile, '/etc/localtime')
            with open('/etc/timezone','w') as timezonefile:
                timezonefile.write(tz + '\n')
            if os.path.isfile('/replicated/jail/named/etc/localtime'):
                shutil.copy(srcfile,'/replicated/jail/named/etc/localtime')
            print("Timezone set to %s" % tz)
            print("Restart system to complete the timezone changes")
        except Exception as e:
            print("Failed to set timezone: %s" % e)
    else:
        print("ERROR: Invalid timezone %s" % tz)

snmp_template = {
    "agent_service": {
        "loglevel": int,
        "pollperiod": int,
        "system": {
            "name" : str,
            "location" : str,
            "contact" : str,
            "description" : str
        },
        "v1": {
            "community": str,
            "enabled": bool
        },
        "v2c": {
            "community": str,
            "enabled": bool
        },
        "v3": {
            "securitylevel" : "noauth|auth|priv",
            "privtype" : "DES|AES128",
            "username" : str,
            "enabled" : bool,
            "privphrase": str,
            "authtype" : "MD5|SHA",
            "authphrase": str
        }
    },
    "trap_service" : {
        "trapservers" : [
            {
                "host" : str,
                "port" : int,
                "enabled" : bool,
                "v1": {
                    "community": str,
                    "enabled": bool
                },
                "v2c": {
                    "community": str,
                    "enabled": bool
                },
                "v3": {
                    "securitylevel" : "noauth|auth|priv",
                    "privtype" : "DES|AES128",
                    "username" : str,
                    "enabled" : bool,
                    "privphrase": str,
                    "authtype" : "MD5|SHA",
                    "authphrase": str
                }
            }
        ]
    }
}

snmp = None
if 'snmp' in meta:
    snmp = meta['snmp']
    templateMatch(snmp_template, snmp)

if snmp is None and 'snmp_community_string' in meta:
    snmp_community = meta['snmp_community_string']
    snmp = {
      "agent_service" : {
         "loglevel" : 6,
         "pollperiod" : 5,
         "system" : {
            "contact" : "support@bluecatnetworks.com",
            "description" : "Bluecat",
            "location" : "Toronto",
            "name" : "Bluecat"
         },
         "v1" : {
            "community" : snmp_community,
            "enabled" : True
         },
         "v2c" : {
            "community" : snmp_community,
            "enabled" : True
         },
         "v3" : {
            "authphrase" : "",
            "authtype" : "MD5",
            "enabled" : False,
            "privphrase" : "",
            "privtype" : "DES",
            "securitylevel" : "noauth",
            "username" : ""
         }
      },
      "trap_service" : {
         "trapservers" : []
      }
    }

if snmp:
    psmdbset("snmp", "--enable", "--json", json.dumps(snmp))


users = {}
newusers = []
if 'users' in meta:
    for user in meta['users']:
        username = user['name']
        users[username] = user

password = None
if 'password' in meta:
    password = meta['password']
    for username in ['root', 'admin']:
        if not username in users:
            users[username] = {}
        users[username]['passwd'] = password

for username, user in users.items():
    try:
        try:
            pwdentry = pwd.getpwnam(username)
        except KeyError:
            newusers.append(username)
            # Use UIDs 2000 - 2500. BlueCat scripts reserve these UIDs for TACACS users
            # BAM includes these TACACS users in AllowUsers when it modifies sshd_config
            # Also, we want to avoid any conflict with new system users added by an upgrade
            subprocess.call(['useradd','-m',username,'-K','UID_MIN=2000','-K','UID_MAX=2500'])
            pwdentry = pwd.getpwnam(username)

        homedir = pwdentry.pw_dir
        if 'authorized_keys' in user:
            sshdir = homedir + '/.ssh'
            try:
                os.mkdir(sshdir, 0o700)
            except OSError:
                pass
            keys_filename = sshdir + '/authorized_keys'
            with open(keys_filename, 'w') as keysfile:
                keysfile.write(user['authorized_keys'])
            os.chmod(keys_filename, 0o600)
            subprocess.call(['chown', '-R', username + ':users', sshdir])
        if 'passwd' in user:
            subprocess.run(['/sbin/chpasswd'], input = username + ':' + user['passwd'] + '\n', text = True)
        elif 'passwdhash' in user:
            subprocess.run(['/sbin/chpasswd', '-e'], input = username + ':' + user['passwdhash'] + '\n', text = True)
    except Exception as e:
        print('Failed to configure user: %s' % e)

# Update sshd_config to allow new users
# Only needed on BDDS; On BAM postgresServer.sh will change AllowUsers
if newusers:
    usernames = ''
    for user in newusers:
        usernames += ' ' + user
    with open('/etc/ssh/sshd_config','r') as configin:
      with open('/etc/ssh/sshd_config.reconfig','w') as configout:
        for line in configin:
            line = line.rstrip()
            if line.startswith('AllowUsers'):
                line += usernames
            line += '\n'
            configout.write(line)
    shutil.move('/etc/ssh/sshd_config.reconfig', '/etc/ssh/sshd_config')


syslog_servers = []
if 'syslog' in meta:
    syslog_servers = meta['syslog'].split(',')

# ADD HERE
#if syslog monitoring enabled
#    syslog_servers.append("<container IP>")

if syslog_servers:
    syslog_args = []
    for server in syslog_servers:
        server = server.lower() # convert IPv6 hexadecimal to lower-case
        if re.match(r'^[0-9.]*$', server): # IPv4 address
            syslog_args.extend(("--host", server + "|udp|514"))
        elif re.match(r'^[0-9a-f:]*$', server): # IPv6 address
            syslog_args.extend(("--host", server + "|udp6|514"))
        else:
            print('ERROR: syslog server is not an IP address: %s' % server)
    psmdbset("syslog", *syslog_args)

if hostname == 'DDS':

    #################################################
    # Deploy Syslog
    #################################################

    # Enable Docker
    sCmd = cCliShellCommand('systemctl enable docker')
    sCmd.exe('Enable Docker service')

    syslog_service_file = 'docker.syslog.service'
    syslog_container_name = 'syslog-sv'
    snmp_config_path = '/opt/syslog_monitoring/Config/snmp_config.json'
    syslog_image_path = '/opt/images/syslog_monitoring.tar'

    dns_stat_image_path = '/opt/images/dns_stat_agent.tar'
    packetbeat_image_path = '/opt/images/dns_packetbeat.tar'

    # Load images
    sCmd = cCliShellCommand('docker load -i {}'.format(syslog_image_path))
    sCmd.exe('Load Syslog Monitoring image ..')

    sCmd = cCliShellCommand('docker load -i {}'.format(dns_stat_image_path))
    sCmd.exe('Load DNS Traffic Statistic Agent image ..')

    sCmd = cCliShellCommand('docker load -i {}'.format(packetbeat_image_path))
    sCmd.exe('Load PacketBeat image ..')

    def create_logs_folder(log_name):
        try:
            logs_dir = '/var/log/{}'.format(log_name)
            if not os.path.isdir(logs_dir):
                os.mkdir(logs_dir, 0o755)
        except Exception as e:
            print('Failed to create logs folder: %s' % e)


    def enable_syslog_service(file_name):
        if os.path.isfile('/lib/systemd/system/{}'.format(file_name)):
            service_name = file_name.split('.')[1].replace('_', ' ').title() if '_' in file_name.split('.')[1] else \
            file_name.split('.')[1].title()

            reload_cmd = cCliShellCommand('systemctl daemon-reload')
            reload_cmd.exe('Daemon reload ...')

            enable_service_cmd = cCliShellCommand('systemctl enable --now {}'.format(file_name.replace('.service', '')))
            enable_service_cmd.exe('Enable {} service ...'.format(service_name))
        else:
            print('ERROR: {} file not found'.format(file_name))


    try:
        if os.path.isfile(snmp_config_path):
            # Create logs folder
            create_logs_folder('syslog_monitoring')

            # Enable Syslog Monitoring service
            enable_syslog_service(syslog_service_file)

    except Exception as e:
        print('Failed to deploy Syslog Monitoring: %s' % e)


##########################################
# Deploy DNS Traffic Agent and PacketBeat
##########################################

    dns_stat_agent_service_file = 'docker.dns_stat_agent.service'
    packetbeat_service_file = 'docker.packetbeat.service'
    mibs_dir = '/usr/share/snmp/mibs/'
    bcn_dns_agent_mib_path = '/opt/unpack/dns_traffic_statistics_agent/dns-snmp-agent/BCN-DNS-AGENT-MIB.mib'
    post_deploy_path = '/usr/local/bluecat/postDeploy.sh'
    announcement_bam_deploy_path = '/opt/unpack/dns_traffic_statistics_agent/packetbeat/announcement_bam_deploy.py'
    snmp_config_path = '/etc/snmp/snmp.conf'
    
    
    def create_logs_folder(log_name):
        try:
            logs_dir = '/var/log/{}'.format(log_name)
            if not os.path.isdir(logs_dir):
                os.mkdir(logs_dir, 0o755)
        except Exception as e:
            print('Failed to create logs folder: %s' % e)
    
    
    def enable_services(file_name):
        if os.path.isfile('/lib/systemd/system/{}'.format(file_name)):
            service_name = file_name.split('.')[1].replace('_', ' ').title() if '_' in file_name.split('.')[1] else \
            file_name.split('.')[1].title()
            reload_cmd = cCliShellCommand('systemctl daemon-reload')
            reload_cmd.exe('Daemon reload ...')
    
            enable_service_cmd = cCliShellCommand('systemctl enable {}'.format(file_name.replace('.service', '')))
            enable_service_cmd.exe('Enable {} service ...'.format(service_name))
        else:
            print('ERROR: {} file not found'.format(file_name))
    
    
    def update_config_file(file_path, text_data, on_one_line=False):
        # Create backup file
        shutil.copy(file_path, '{}.bak'.format(file_path))
    
        with open(file_path, 'r') as f:
            current_data_file = f.read()
            if text_data in current_data_file:
                return
    
        if on_one_line:
            append_data = text_data.replace('\n', '')
            current_data_file = current_data_file.replace('\n', '')
        else:
            append_data = '\n{}\n'.format(text_data)
    
        with open(file_path, 'w+') as f:
            f.write(current_data_file + append_data)
    
    

    try:
        # Create logs folder
        create_logs_folder('dns_stat_agent')
        create_logs_folder('packetbeat')

        # Copy BCN-DNS-AGENT-MIB.mib to mibs dir
        if os.path.isfile(bcn_dns_agent_mib_path):
            shutil.copy(bcn_dns_agent_mib_path, mibs_dir)
            os.chmod('{}BCN-DNS-AGENT-MIB.mib'.format(mibs_dir), 0o644)
        else:
            print('ERROR: BCN-DNS-AGENT-MIB file not found')

        # Add BCN-DNS-AGENT-MIB to snmp.conf
        if os.path.isfile(snmp_config_path):
            update_config_file(snmp_config_path, ':BCN-DNS-AGENT-MIB', True)
        else:
            print('ERROR: {} file not found'.format(snmp_config_path))

        # Update postDeploy.sh file
        if os.path.isfile(post_deploy_path) and os.path.isfile(announcement_bam_deploy_path):
            update_config_file(post_deploy_path, 'python2 {}'.format(announcement_bam_deploy_path), False)
        else:
            print('ERROR: postDeploy.sh or announcement_bam_deploy.py not found')

        # Enable DNS Statistic Agent and PacketBeat service ...
        enable_services(dns_stat_agent_service_file)
        enable_services(packetbeat_service_file)
    except Exception as e:
        print('Failed to deploy DNS Traffic Statistic Agent: %s' % e)

