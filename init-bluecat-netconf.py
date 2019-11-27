#!/usr/bin/python
# Copyright 2019 BlueCat Networks (USA) Inc. and its affiliates
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

import os
import subprocess
import sys
import re
import json
import sqlite3

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
            for k, v in data.iteritems():
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
        elif etype == str or etype == unicode:
            assert isinstance(data, basestring)
            assert re.match(template, data)
        else:
            assert False
    except AssertionError:
        print "template:", template, "data:", data, "data type:", type(data)
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
   "routes" : [
      {
         "cidr" : int,
         "gateway" : "([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F:]+)$",
         "network" : "([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F:]+|default)$"
      }
   ]
}

# Get input data from stdin
initdata = json.load(sys.stdin)
templateMatch(input_template, initdata)

DEVNULL = open(os.devnull, 'w')

# Identify if we are running on BAM or BDDS
if subprocess.call(['dpkg','-l','adonis-app'], stdout = DEVNULL) == 0:
    is_bam = False
    is_bdds = True
elif subprocess.call(['dpkg','-l','proteus-app'], stdout = DEVNULL) == 0:
    is_bam = True
    is_bdds = False
else:
    assert False

PSMDBSET_TOOL = "/usr/local/bluecat/psmdbset"
DB_CONF = "/data/pgdata/pg_hba.conf"
HOSTS = "/etc/hosts"

hostname = 'new'
if 'hostname' in initdata:
    hostname = initdata['hostname']

# Find the primary IP address. This may be a VLAN interface
# We make the first IPv4 address on eth0 the primary address
eth0_data = next(x for x in initdata['interfaces'] if x['name'].split('.')[0] == 'eth0')
eth0_ip4_address = eth0_data['v4addresses'][0]['address']

# update database configuration on BAM to reflect IP address change
# Note slony/database.conf does not exist yet; it will be created when postgres is started for the first time
if os.path.exists(DB_CONF):
    # ("Updating pg_hba.conf with address %s", eth0_ip4_address)
    subprocess.call(["sed", "-i",
         "-e", "/^host all postgres/ c\\host all postgres %s\\/32 trust" % eth0_ip4_address,
          DB_CONF])

    # ("Updating proteusdb.bluecatnetworks.corp with address %s", eth0_ip4_address)
    subprocess.call(["sed", "-i",
         "-e", "/proteusdb.bluecatnetworks.corp/ c\\%s proteusdb.bluecatnetworks.corp" % eth0_ip4_address,
          HOSTS])

    # ("Updating proteuscluster.bluecatnetworks.corp with address %s", eth0_ip4_address)
    subprocess.call(["sed", "-i",
         "-e", "/proteuscluster.bluecatnetworks.corp/ c\\%s proteuscluster.bluecatnetworks.corp" % eth0_ip4_address,
          HOSTS])

# update /etc/hosts to reflect new IP address on new hostname (both BAM and BDDS)
# Note: not sure this is necessary, because PSM may do this automatically
# ("Updating /etc/hosts  with address %s", eth0_ip4_address)
subprocess.call(["sed", "-i",
     "-e", "/new/ c\\%s %s" % (eth0_ip4_address, hostname), HOSTS])

# dbus is not yet available in 8.3, so we cannot use hostnamectl

# update /etc/hostname
with open("/etc/hostname","w") as etc_hostname:
    etc_hostname.write( "{}\n".format(hostname) )

subprocess.call(["hostname", hostname])

def readPsmDatabase(filename, table):
    conn = sqlite3.connect(filename)
    for row in conn.execute(
            'SELECT config FROM {0} WHERE id = (SELECT max(id) FROM {0})'.format(table)):
        data = json.loads(row[0])
    conn.close()
    return data

def writePsmDatabase(filename, table, data):
    conn = sqlite3.connect(filename)
    conn.execute('DELETE FROM {}'.format(table))
    conn.execute('INSERT INTO {} (config) VALUES (?)'.format(table),
                 (json.dumps(data, indent = 4, sort_keys = True),))
    conn.commit()
    conn.close()

# Use psmdbset tool to initialize PSM databases, and to set hostname
# We use dummy addresses here, then replace them in the database below
# psmdbset -a <ip> -c <cidr> -g <gw> [-n <host>]
subprocess.call([PSMDBSET_TOOL, '-a', '192.168.1.2', '-c', '24', '-g', '192.168.1.1', '-n', hostname])

routes = {}
routes['routes'] = initdata['routes']
writePsmDatabase('/etc/bcn/routes.db', 'Routes', routes)

networks = readPsmDatabase('/etc/bcn/networks.db','Networks')

interfaces = {}
for psmif in networks['interfaces']:
    ifname = psmif['name']
    interfaces[ifname] = psmif

# Remove the default address from eth0
# This is relevant only when the primary address is on a VLAN interface
interfaces['eth0']['v4addresses'] = []

primary_address_seen = False

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

    if ifname == 'eth0' and is_bdds:
        # Require a primary IPv4 address on the service interface
        assert len(ifdata['v4addresses']) >= 1
        if not primary_address_seen:
            # Make first address in each list the primary address
            ifdata['v4addresses'][0]['flags'] = 1 # primary service interface flag
            if len(ifdata['v6addresses']) >= 1:
                ifdata['v6addresses'][0]['flags'] = 1 # primary service interface flag
            primary_address_seen = True
    if ifname == 'eth0' and is_bam:
        # Allow only one IPv4 address on the BAM interface
        assert len(ifdata['v4addresses']) == 1
        ifdata['v4addresses'][0]['flags'] = 1 # primary interface flag on BAM
        primary_address_seen = True
    if ifname == 'eth2' and is_bdds:
        # Allow only one IPv4 address on the BDDS management interface
        # This is flagged as the management address, even though dedicated management is not yet enabled
        assert len(ifdata['v4addresses']) == 1
        ifdata['v4addresses'][0]['flags'] = 4 # management interface flag

    if vlanid: # Add new VLAN interface
        assert(ifname == 'eth0')
        interfaces[fullname] = {
            'name' : fullname,
            'description' : ifname + ' VLAN ' + str(vlanid),
            'parents' : [ ifname ],
            'type' : 'vlan',
            'vlanid' : vlanid
        }

    psm_if = interfaces[fullname]
    psm_if['active'] = 1
    psm_if['v4addresses'] = ifdata['v4addresses']
    psm_if['v6addresses'] = ifdata['v6addresses']

assert(primary_address_seen)

networks['interfaces'] = [ interfaces[ifname] for ifname in sorted(interfaces.keys()) ]

writePsmDatabase('/etc/bcn/networks.db', 'Networks', networks)

# hostname has been updated by psmdbset
# No further changes are required in the NetworkServiceConfiguration table
# The private interfaces list appears to be relevant only in XHA configurations
# ethtool interface settings are not supported
# writePsmDatabase('/etc/bcn/configuration.db', 'NetworkServiceConfiguration', network_service_configuration)

