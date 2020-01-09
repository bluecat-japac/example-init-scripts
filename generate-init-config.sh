#!/bin/bash
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

CFGFILE=/etc/vmse/init/config.ini
CFGFILE_BUILTIN=/etc/vmse/init/builtin.ini
BUILTIN_JSON_CFG=/etc/vmse/init/bluecat_init.builtin
STANDARD_JSON_CFG=/etc/vmse/init/bluecat_init.json
INIT_CONFIG=/etc/bcn/init-config.json
TMP_NETCONF=/tmp/init-netconf.json
INIT_KEY=/etc/bcn/init.key

function decrypt {
    echo "$1" | openssl enc -d -aes256 -md md5 -a -pass "pass:$(cat $INIT_KEY)"
}

# Set TRIAL_RUN=yes to generate configuration files, but not update the PSM database
#TRIAL_RUN=yes

# This script is only needed on the first boot
# After the initial configuration has been created, the CFGFILE file is deleted below
# This prevents any action on future reboots
if [ ! -s $CFGFILE ]
then
    exit 0
fi

echo Generating initial configuration from $CFGFILE

function getconfig {
    cat ${CFGFILE_BUILTIN} ${CFGFILE} | grep "^"$1 | tail -1 | cut -d= -f2-
}

function local_if_config {
    eth_if=$1
    local_v6_ip=$( getconfig $2 )
    if [ -n "$local_v6_ip" ]
    then
        cat <<EOF
         "v4addresses" : [],
         "v6addresses" : [
            {
               "address" : "$local_v6_ip",
               "cidr" : $( getconfig LOCAL_V6_PREFIX )
            }
         ]
EOF
    else
        netconf_generated_interfaces="/etc/network/interfaces.d/50-cloud-init.cfg"
        perl -e '
            $eth_if = "'$eth_if'";
            @v4addresses = (); @v6addresses = ();
            while (<>) {
                if (/^iface $eth_if(|:\d) inet static/) {
                    $_ = <>; /^\s+address ([0-9.]+)/;
                    $address = $1;
                    $_ = <>; /^\s+netmask ([0-9.]+)/;
                    $netmask = $1;
                    $nb = 32; # Convert to CIDR mask
                    while ($nb >= 0) {
                        $m = (2**$nb - 1) << (32 - $nb);
                        $tmask = join(".", unpack("C4", pack("N", $m)));
                        last if ($netmask eq $tmask);
                        --$nb;
                    }
                    push @v4addresses, "{
                        \"address\" : \"$address\",
                        \"cidr\" : $nb
                    }";
                }
                elsif (/^iface $eth_if(|:\d) inet6 static/) {
                    $_ = <>; /^\s+address ([0-9a-f:]+)/i;
                    $address = $1;
                    $_ = <>; /^\s+netmask ([0-9.]+)/;
                    $netmask = $1;
                    push @v6addresses, "{
                        \"address\" : \"$address\",
                        \"cidr\" : $netmask
                    }";
                }
            }
            print "
            \"v4addresses\" : [ ".join(", ", @v4addresses)." ],
            \"v6addresses\" : [ ".join(", ", @v6addresses)." ]
            ";
        ' $netconf_generated_interfaces
    fi
}

# Example vm_names:
# vBLUECAT_vBLUECAT_0001_BAM_0001
#         vm_name_prefix ^^^
# vBLUECAT_vBLUECAT_0001_DDS_0001
#                            ^^^^ vm_seq
# The separator can be '-' or '_'

vm_name=$( getconfig vm_name )
vm_name_prefix=$( getconfig vm_name | tr "-" "_" | awk -F "_" '{print $(NF - 1)}')
vm_seq=$( getconfig vm_name | tr "-" "_" | awk -F "_" '{print $NF}')
bam_vm_num=$( getconfig bam_num )

if [ "$( getconfig LOCAL_V4_DHCP )" == "yes" -a ! "$TRIAL_RUN" == "yes" ]
then
    systemctl enable --now --no-block dhcp-localif.service
fi

if [ "$( getconfig ENABLE_DNS_TRAFFIC_STATS_AGENT )" == "yes" -a ! "$TRIAL_RUN" == "yes" ]
then
    systemctl enable packetbeat.service
    systemctl enable dns_stat_agent.service
fi

rm -f $TMP_NETCONF

# BAM has only management interfaces
# On BAM the OM_IP is used for eth0
# BAM uses only the OM_GATEWAY gateway addresses

# BDDS has both service and management interfaces
# On BDDS the SERVICE_IP is used for eth0 and the OM_IP for eth2
# BDDS uses only the SERVICE_GATEWAY gateway addresses

if [ "${vm_name_prefix}" = "BAM" ]
then

cat <<EOF > $TMP_NETCONF
{
   "hostname" : "${vm_name}",
   "interfaces" : [
      {
         "name" : "eth0",
         "v4addresses" : [
            {
               "address" : "$( getconfig OM_${vm_seq} )",
               "cidr" : $( getconfig OM_NET_MASK )
            }
         ],
         "v6addresses" : [
            {
               "address" : "$( getconfig OM_V6_${vm_seq} )",
               "cidr" : $( getconfig OM_V6_PREFIX )
            }
         ]
      }
      ,
      {
         "name" : "eth2", $( local_if_config eth2 LOCAL_V6_${vm_seq} )
      }
   ],
   "routes" : [
      {
         "cidr" : 0,
         "gateway" : "$( getconfig OM_GATEWAY )",
         "network" : "default"
      },
      {
         "cidr" : 0,
         "gateway" : "$( getconfig OM_V6_GATEWAY )",
         "network" : "default"
      }
   ]
}
EOF


elif [ "${vm_name_prefix}" = "DDS" ]
then
    # BAM and BDDS VM numbers both start from 1
    # We add the number of BAM VMs to the BDDS VM number to get the index in to
    # the management interface address tables
    # Use perl printf %0<n>d to retain correct number of leading zeros
    dds_seq_suffix=$(perl -e "printf '%0'.length('${vm_seq}').'d', (${vm_seq} + ${bam_vm_num})")
    echo "bam_vm_num = ${bam_vm_num}, dds_seq_suffix = ${dds_seq_suffix}"

    SERVER_VLAN_ID=$( getconfig SERVER_VLAN_ID )
    if [ "$SERVER_VLAN_ID" ]
    then
        eth0_name="eth0.$SERVER_VLAN_ID"
    else
        eth0_name="eth0"
    fi
 
cat <<EOF > $TMP_NETCONF
{
   "hostname" : "${vm_name}",
   "interfaces" : [
      {
         "name" : "${eth0_name}",
         "v4addresses" : [
            {
               "address" : "$( getconfig SERVER_${vm_seq} )",
               "cidr" : $( getconfig SERVER_NET_MASK )
            }
         ],
         "v6addresses" : [
            {
               "address" : "$( getconfig SERVER_V6_${vm_seq} )",
               "cidr" : $( getconfig SERVER_V6_PREFIX )
            }
         ]
      }
EOF
    HA_IP=$( getconfig "HA_${vm_seq}" )
    if [ "$HA_IP" ]
    then
cat <<EOF >> $TMP_NETCONF
      ,
      {
         "name" : "eth1",
         "v4addresses" : [
            {
               "address" : "$HA_IP",
               "cidr" : $( getconfig HA_NET_MASK )
            }
         ],
         "v6addresses" : []
      }
EOF
    fi
cat <<EOF >> $TMP_NETCONF
      ,
      {
         "name" : "eth2",
         "v4addresses" : [
            {
               "address" : "$( getconfig OM_${dds_seq_suffix} )",
               "cidr" : $( getconfig OM_NET_MASK )
            }
         ],
         "v6addresses" : [
            {
               "address" : "$( getconfig OM_V6_${dds_seq_suffix} )",
               "cidr" : $( getconfig OM_V6_PREFIX )
            }
         ]
      }
      ,
      {
         "name" : "eth4",  $( local_if_config eth4 LOCAL_V6_${dds_seq_suffix} )
      }
   ],
   "routes" : [
      {
         "cidr" : 0,
         "gateway" : "$( getconfig SERVER_GATEWAY )",
         "network" : "default"
      },
      {
         "cidr" : 0,
         "gateway" : "$( getconfig SERVER_V6_GATEWAY )",
         "network" : "default"
      }
   ]
}
EOF

else
    echo -e "[`date +%F_%T.%N`]: vm name is abnormal, prefix is ${vm_name_prefix}"
    exit 1
fi

if [ ! "$TRIAL_RUN" == "yes" ]; then

    # Update network settings
    python /usr/local/bluecat/cloud/init-bluecat-netconf.py < $TMP_NETCONF
    if [ $? -gt 0 ]; then
        echo -e "[`date +%F_%T.%N`]: failed to initialize PSM network configuration"
        exit 1
    fi
    rm -f $TMP_NETCONF

fi

# Set the hostname value in the bluecat_init.json file
# (if this is not set explicitly, the hostname in meta_data.json will be used.)
cat <<EOF > $INIT_CONFIG
{
    "hostname" : "${vm_name}",
EOF
# Enable dedicated managed in the bluecat_init.json file
if [ "${vm_name_prefix}" = "DDS" ]
then
    cat <<EOF >> $INIT_CONFIG
    "enable-dedicated-management" : true,
EOF
fi

if [ "$( getconfig syslog_host1 )" ]; then
cat <<EOF >> $INIT_CONFIG
    "syslog": "$( getconfig syslog_host1 )",
EOF
fi
if [ "$( getconfig timezone )" ]; then
cat <<EOF >> $INIT_CONFIG
    "timezone" : "$( getconfig timezone )",
EOF
fi
if [ "$( getconfig route1_network )" ]; then
cat <<EOF >> $INIT_CONFIG
    "routes" : [ { "gateway": "$( getconfig route1_gateway )", "network" : "$( getconfig route1_network )" } ],
EOF
fi

if [ "$( getconfig stig_compliance )" == "yes" ]; then
cat <<EOF >> $INIT_CONFIG
    "enable-stig-compliance": true,
EOF
fi

fw_rules="iptables -A icmp_packets -p ICMP --icmp-type echo-request -j ACCEPT"
fw_rules="${fw_rules};iptables -A icmp_packets -p ICMP --icmp-type echo-request -j ACCEPT"
if [ "$( getconfig firewall_localif_v4net_1 )" ]; then
    fw_rules="${fw_rules};iptables -A INPUT -s $( getconfig firewall_localif_v4net_1 ) -i eth4 -j ACCEPT"
fi
if [ "$( getconfig firewall_localif_v6net_1 )" ]; then
    fw_rules="${fw_rules};ip6tables -A INPUT -s $( getconfig firewall_localif_v6net_1 ) -i eth4 -j ACCEPT"
fi

if [ "$( getconfig nameserver1 )" ]; then
cat <<EOF >> $INIT_CONFIG
    "nameservers" : [ "$( getconfig nameserver1 )" ],
EOF
fi

if [ "$( getconfig snmp_trap_hosts )" ]; then
cat <<EOF >> $INIT_CONFIG
    "snmp" : {
      "trap_service" : {
         "trapservers" : [
EOF
snmp_trap_hosts="$( getconfig snmp_trap_hosts | tr ',' ' ' )"
not_first=
for trap_host in ${snmp_trap_hosts}; do
    if [ "$not_first" ]; then
        echo "," >> $INIT_CONFIG
    fi
    not_first=yes
    cat <<EOF >> $INIT_CONFIG
            {
               "host" : "${trap_host}",
               "v1" : { "enabled" : false, "community" : "bcnCommunityV1"  },
               "v2c" : { "enabled" : false, "community" : "bcnCommunityV2C" },
               "v3" : {
                  "enabled" : true,
                  "username" : "Bluecat",
                  "securitylevel" : "priv",
                  "authtype" : "$( getconfig snmp_authtype )",
                  "authphrase": "$( decrypt "$( getconfig x_snmp_authphrase )" )",
                  "privtype" : "$( getconfig snmp_privtype )",
                  "privphrase": "$( decrypt "$( getconfig x_snmp_privphrase )" )"
               },
               "port" : 162,
               "enabled" : true
            }
EOF
    done
cat <<EOF >> $INIT_CONFIG
         ]
      },
      "agent_service" : {
         "pollperiod" : 5,
         "v1" : { "enabled" : false, "community" : "bcnCommunityV1"  },
         "v2c" : { "enabled" : false, "community" : "bcnCommunityV2C" },
         "v3" : {
                  "enabled" : true,
                  "username" : "Bluecat",
                  "securitylevel" : "priv",
                  "authtype" : "$( getconfig snmp_authtype )",
                  "authphrase": "$( decrypt "$( getconfig x_snmp_authphrase )" )",
                  "privtype" : "$( getconfig snmp_privtype )",
                  "privphrase": "$( decrypt "$( getconfig x_snmp_privphrase )" )"
         },
         "loglevel" : 6,
         "system" : {
            "name" : "Bluecat",
            "location" : "Toronto",
            "contact" : "support@bluecatnetworks.com",
            "description" : "Bluecat"
         }
      }
    },
EOF
fi

if [ -s "$STANDARD_JSON_CFG" ]; then

(
    # concatenate configuration from multiple sources
    if [ -s "$BUILTIN_JSON_CFG" ]
    then
        cat $BUILTIN_JSON_CFG
    fi
    cat $STANDARD_JSON_CFG
) | perl -e '
sub decrypt { $t=`echo "@_[0]" | openssl enc -d -aes256 -md md5 -a -pass "pass:'$(cat $INIT_KEY)'"` ; $t =~ s/\s+$//; return $t }
while (<>) { s/"ENCRYPTED-(.*?)" *: *"(.*?)"/"\"$1\": \"" . decrypt($2) . "\""/e; print; }
' >> $INIT_CONFIG

else # a JSON inject file has not been provided

cat <<EOF >> $INIT_CONFIG
    "custom_fw_rules" : "${fw_rules}",
    "implement_log_permissions_workaround" : true,
    "syslog_servers_fixed_hostname": true,
    "clientid": "$( decrypt "U2FsdGVkX1+ivr/nAJsuHI5D7b7iycr80n+dlYxRxqVT4A0dzglGWaJcjfE0Aumq" )",
    "license_key": "$( decrypt "U2FsdGVkX1+nv2mIeEV7JhORcmzDU4t9NjPIda9UTp9aOxmT6/zcU/YSV1ptqC7n" )",
    "users" : [
      {
            "name" : "vmse_admin",
            "authorized_keys" : "$( getconfig vmse_admin_ssh_key )"
      },
      {
            "name" : "bluecat",
            "passwd" : "$( decrypt "$( getconfig x_bluecat_password )" )"
      }
    ],
    "password": "$( decrypt "$( getconfig x_password )" )"
EOF
# Note there is no comma after the final entry

fi

cat <<EOF >> $INIT_CONFIG
}
EOF

if [ ! "$TRIAL_RUN" == "yes" ]; then
    rm -f $INIT_KEY
fi

# The INIT_CONFIG file will be processed, then deleted, by the post_install script

# Configure syslog_monitoring, if installed and trap hosts provided in config.ini
monitored_dns_servers="$( getconfig monitored_dns_servers | tr ',' ' ' )"
monitored_domain="$( getconfig monitored_domain )"
syslog_mon_trap_hosts="$( getconfig syslog_mon_trap_hosts | tr ',' ' ' )"

SYSLOG_MON_PATH=/opt/syslog_monitoring/Config
if [ "$( getconfig syslog_mon_trap_hosts )" -a -d $SYSLOG_MON_PATH -a -f $SYSLOG_MON_PATH/config.ini ]; then
    sed -i.bak "s/^vm_host_name *=.*/vm_host_name = ${vm_name}/" $SYSLOG_MON_PATH/config.ini
    if [ "${monitored_domain}" ]; then
        sed -i.bak "s/^domain *=.*/domain = ${monitored_domain}/" $SYSLOG_MON_PATH/config.ini
    fi
    true > $SYSLOG_MON_PATH/resolv.conf
    if [ "${monitored_dns_servers}" ]; then
        for server in ${monitored_dns_servers} ; do
            echo "nameserver $server" >> $SYSLOG_MON_PATH/resolv.conf
        done
    fi
    (
        echo "["
        not_first=
        for trap_host in ${syslog_mon_trap_hosts}; do
            if [ "$not_first" ]; then
                echo ","
            fi
            not_first=yes
            # authKey and privKey must be encoded as described in the syslog-monitoring README
            cat <<EOF
    {
        "transportTarget": "${trap_host}",
        "userName": "usm-user",
        "authKey": "bXlwYXNzd29yZA==",
        "privKey": "bXlwYXNzd29yZA==",
        "authProtocol": "SHA",
        "privProtocol": "AES",
        "port": 162
    }
EOF
        done
        echo "]"
    ) > $SYSLOG_MON_PATH/snmp_config.json
fi

if [ ! "$TRIAL_RUN" == "yes" ]; then
    # Remove config.ini to stop this script running again
    rm -f $CFGFILE
    # Clean-up injected JSON configuration
    rm -f $BUILTIN_JSON_CFG $STANDARD_JSON_CFG
fi
