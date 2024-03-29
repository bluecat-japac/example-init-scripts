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
INIT_KEY=/etc/bcn/init.key

#run split inject file
split_file=/etc/vmse/init/split_inject_file.sh
if [ -f ${split_file} ]
then
    /bin/bash /etc/vmse/init/split_inject_file.sh
fi

function decrypt {
    echo "$1" | openssl enc -d -aes256 -md md5 -a -pass "pass:$(cat $INIT_KEY)"
}

# Set TRIAL_RUN=yes to generate configuration files, but not update the PSM database
if [ -e /root/trial_run ]
then
    TRIAL_RUN=yes
fi

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

function convert_to_empty_string {
    lower_str=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    if [ "$lower_str" = "null" ]
    then
       echo ""
       exit 1
    fi
    echo "$1"
}

function interface_if_address {
    ip_address=$(convert_to_empty_string "$( getconfig $1 )")
    netmask_or_prefix=$( getconfig $2 )
    if [ "$ip_address" ] && [ "$netmask_or_prefix" ]
    then
        cat <<EOF >> $INIT_CONFIG
          {
             "address" : "$ip_address",
             "cidr" : $netmask_or_prefix
          }
EOF
    fi
}

function local_if_config {
    eth_if=$1
    local_v6_ip=$(convert_to_empty_string "$( getconfig $2 )")
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
        netconf_generated_interfaces="/etc/network/interfaces.d/50-cloud-init"
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
                    $_ = <>; /^\s+address ([0-9a-f:]+)\/([0-9]+)/i;
                    $address = $1;
                    $netmask = $2;
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
system_type=`arch`
if [ $system_type == x86_64 ]
then
	vm_name_prefix=$( getconfig vm_name | tr "-" "_" | awk -F "_" '{print $(NF - 1)}')
else
	vm_name_prefix=$( getconfig vm_name | tr "-" "_" | awk -F "_" '{print $(NF - 2)}')
fi


# modify 50-cloud-init mtu
if [ "$( getconfig SRV_MTU )" ]; then
    srv_mtu=$( getconfig SRV_MTU )
fi

if [ "$( getconfig OM_MTU )" ]; then
    om_mtu=$( getconfig OM_MTU )
fi

if [ "${vm_name_prefix}" = "BAM" ]
then
    if [ -f /etc/network/interfaces.d/50-cloud-init ]
    then
        init_mtu=`grep mtu /etc/network/interfaces.d/50-cloud-init | wc -l`
        if [ $init_mtu -ne 0 ]
        then
            sed -i "s/mtu.*/mtu ${om_mtu}/g" /etc/network/interfaces.d/50-cloud-init
        fi
    fi
else
    if [ -f /etc/network/interfaces.d/50-cloud-init ]
    then
        init_mtu=`grep mtu /etc/network/interfaces.d/50-cloud-init | wc -l`
        if [ $init_mtu -ne 0 ]
        then
            sed -i -z "s/mtu.*/mtu ${srv_mtu}/1m" /etc/network/interfaces.d/50-cloud-init
            sed -i -z "s/mtu.*/mtu ${om_mtu}/2m" /etc/network/interfaces.d/50-cloud-init
            sed -i -z "s/mtu.*/mtu ${om_mtu}/3m" /etc/network/interfaces.d/50-cloud-init
        fi
    fi
fi


vm_seq=$( getconfig vm_name | tr "-" "_" | awk -F "_" '{print $NF}')
bam_vm_num=$( getconfig bam_num )

if [ "$( getconfig LOCAL_V4_DHCP )" == "true" -a ! "$TRIAL_RUN" == "yes" ]
then
    systemctl enable --now --no-block dhcp-localif.service
fi

rm -f $INIT_CONFIG

# BAM has only management interfaces
# On BAM the OM_IP is used for eth0
# BAM uses only the OM_GATEWAY gateway addresses

# BDDS has both service and management interfaces
# On BDDS the SERVICE_IP is used for eth0 and the OM_IP for eth2
# BDDS uses only the SERVICE_GATEWAY gateway addresses

if [ "${vm_name_prefix}" = "BAM" ]
then

cat <<EOF >> $INIT_CONFIG
{
   "hostname" : "BAM",
   "interfaces" : [
      {
         "name" : "eth0",
         "v4addresses" : [
EOF

interface_if_address OM_${vm_seq} OM_NET_MASK
cat <<EOF >> $INIT_CONFIG
         ],
         "v6addresses" : [
EOF

interface_if_address  OM_V6_${vm_seq} OM_V6_PREFIX
cat <<EOF >> $INIT_CONFIG
         ]
      }
      ,
      {
         "name" : "eth2", $( local_if_config eth2 LOCAL_V6_${vm_seq} )
      }
    ,
    {
       "name" : "lo",
       "v4addresses" : [
EOF

interface_if_address  LOOPBACK_${vm_seq} LOOPBACK_NET_MASK
cat <<EOF >> $INIT_CONFIG
         ],
         "v6addresses" : [
EOF

 interface_if_address  LOOPBACK_V6_${vm_seq} LOOPBACK_V6_PREFIX
 cat <<EOF >> $INIT_CONFIG
      ]
    }
   ],
   "default_routes" : [
EOF

OM_GATEWAY=$(convert_to_empty_string "$( getconfig OM_GATEWAY )")
if [ "$OM_GATEWAY" ]
then
    cat <<EOF >> $INIT_CONFIG
        {
         "cidr" : 0,
         "gateway" : "$OM_GATEWAY",
         "network" : "default"
      }
EOF
fi


OM_V6_GATEWAY=$(convert_to_empty_string "$( getconfig OM_V6_GATEWAY )")
if [ "$OM_V6_GATEWAY" ]
then

    if [ "$OM_GATEWAY" ]
    then
     cat <<EOF >> $INIT_CONFIG
        ,
EOF
    fi

     cat <<EOF >> $INIT_CONFIG
        {
         "cidr" : 0,
         "gateway" : "$OM_V6_GATEWAY",
         "network" : "default"
      }
EOF
fi

cat <<EOF >> $INIT_CONFIG
   ],
EOF


elif [ "${vm_name_prefix}" = "DDS" ]
then
    # BAM and BDDS VM numbers both start from 1
    # We add the number of BAM VMs to the BDDS VM number to get the index in to
    # the management interface address tables
    # Use perl printf %0<n>d to retain correct number of leading zeros
    dds_seq_suffix=$(perl -e "printf '%0'.length('${vm_seq}').'d', ('${vm_seq}' + ${bam_vm_num})")
    echo "bam_vm_num = ${bam_vm_num}, dds_seq_suffix = ${dds_seq_suffix}"

    SERVER_VLAN_ID=$( getconfig SERVER_VLAN_ID )
    if [ "$SERVER_VLAN_ID" ] && [ "$SERVER_VLAN_ID" != "NA" ]
    then
        eth0_name="eth0.$SERVER_VLAN_ID"
    else
        eth0_name="eth0"
    fi

cat <<EOF >> $INIT_CONFIG
{
   "hostname" : "DDS",
   "interfaces" : [
      {
         "name" : "${eth0_name}",
         "v4addresses" : [
EOF

interface_if_address  SERVER_${vm_seq} SERVER_NET_MASK
cat <<EOF >> $INIT_CONFIG
         ],
         "v6addresses" : [
EOF

interface_if_address  SERVER_V6_${vm_seq} SERVER_V6_PREFIX
cat <<EOF >> $INIT_CONFIG
         ]
      }
EOF
    HA_IP=$( getconfig "HA_${vm_seq}" )
    if [ "$HA_IP" ]
    then
cat <<EOF >> $INIT_CONFIG
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

cat <<EOF >> $INIT_CONFIG
      ,
      {
         "name" : "eth2",
         "v4addresses" : [
EOF

interface_if_address  OM_${dds_seq_suffix} OM_NET_MASK
cat <<EOF >> $INIT_CONFIG
         ],
         "v6addresses" : [
EOF

interface_if_address  OM_V6_${dds_seq_suffix} OM_V6_PREFIX
cat <<EOF >> $INIT_CONFIG
         ]
      }
      ,
      {
         "name" : "eth4",  $( local_if_config eth4 LOCAL_V6_${dds_seq_suffix} )
      }
    ,
    {
       "name" : "lo",
       "v4addresses" : [
EOF

interface_if_address  LOOPBACK_${vm_seq} LOOPBACK_NET_MASK
 cat <<EOF >> $INIT_CONFIG
   ],
   "v6addresses" : [
EOF

interface_if_address  LOOPBACK_V6_${vm_seq} LOOPBACK_V6_PREFIX
cat <<EOF >> $INIT_CONFIG
     ]
    }
   ],
   "default_routes" : [
EOF

SERVER_GATEWAY=$(convert_to_empty_string "$( getconfig SERVER_GATEWAY )")
if [ "$SERVER_GATEWAY" ]
then
    cat <<EOF >> $INIT_CONFIG
        {
         "cidr" : 0,
         "gateway" : "$SERVER_GATEWAY",
         "network" : "default"
      }
EOF
fi


SERVER_V6_GATEWAY=$(convert_to_empty_string "$( getconfig SERVER_V6_GATEWAY )")
if [ "$SERVER_V6_GATEWAY" ]
then

    if [ "$SERVER_GATEWAY" ]
    then
     cat <<EOF >> $INIT_CONFIG
        ,
EOF
    fi

     cat <<EOF >> $INIT_CONFIG
        {
         "cidr" : 0,
         "gateway" : "$SERVER_V6_GATEWAY",
         "network" : "default"
      }
EOF
fi

cat <<EOF >> $INIT_CONFIG
   ],
EOF

else
    echo -e "[`date +%F_%T.%N`]: vm name is abnormal, prefix is ${vm_name_prefix}"
    exit 1
fi

if [ "${vm_name_prefix}" = "DDS" ]
then
    cat <<EOF >> $INIT_CONFIG
    "enable-dedicated-management" : true,
EOF
fi

# Support disables the per-client and per-server statistics.
PACKETBEAT_SERVICE_PATH=/lib/systemd/system/docker.packetbeat.service
if [ "$( getconfig ENABLE_PER_CLIENT_TRAFFIC_STATS )" == "false" ]; then
  sed -i '\|.*-v.*/replicated/jail/named/etc/.*|a\
                              -e ENABLE_PER_CLIENT_TRAFFIC_STATS=false              \\'  $PACKETBEAT_SERVICE_PATH
fi


# Support config MTU
if [ "$( getconfig SRV_MTU )" ]; then
cat <<EOF >> $INIT_CONFIG
    "srv_mtu": $( getconfig SRV_MTU ),
EOF
fi

if [ "$( getconfig OM_MTU )" ]; then
cat <<EOF >> $INIT_CONFIG
    "om_mtu": $( getconfig OM_MTU ),
EOF
fi

# Support DHCP
if [ "$( getconfig ENABLE_DHCP_V4 )" == "yes" ]; then
cat <<EOF >> $INIT_CONFIG
    "enable_dhcp_v4": true,
EOF
fi

if [ "$( getconfig ENABLE_DHCP_V6 )"  == "yes" ]; then
cat <<EOF >> $INIT_CONFIG
    "enable_dhcp_v6": true,
EOF
fi

if [ "$(convert_to_empty_string "$( getconfig syslog_host1 )")" ]; then
cat <<EOF >> $INIT_CONFIG
    "syslog": "$( getconfig syslog_host1 )",
EOF
fi
if [ "$( getconfig timezone )" ]; then
cat <<EOF >> $INIT_CONFIG
    "timezone" : "$( getconfig timezone )",
EOF
fi
if [ "$(convert_to_empty_string "$( getconfig route1_network )")" ]; then
cat <<EOF >> $INIT_CONFIG
    "routes" : [ { "gateway": "$(convert_to_empty_string "$( getconfig route1_gateway )")", "network" : "$( getconfig route1_network )" } ],
EOF
fi

if [ "$( getconfig stig_compliance )" == "true" ]; then
cat <<EOF >> $INIT_CONFIG
    "enable-stig-compliance": true,
EOF
fi

if [ "$(convert_to_empty_string "$( getconfig nameserver1 )")" ]; then
cat <<EOF >> $INIT_CONFIG
    "nameservers" : [ "$( getconfig nameserver1 )" ],
EOF
fi

if [ "$(convert_to_empty_string "$( getconfig snmp_trap_hosts )")" ]; then
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
sub decrypt { $t=`echo "@_[0]" | openssl enc -d -aes256 -md md5 -a -pass "pass:'"$(cat $INIT_KEY)"'"` ; $t =~ s/\s+$//; return $t }
while (<>) { s/"ENCRYPTED-(.*?)" *: *"(.*?)"/"\"$1\": \"" . decrypt($2) . "\""/e; print; }
' >> $INIT_CONFIG

else # a JSON inject file has not been provided

cat <<EOF >> $INIT_CONFIG
    "custom_fw_rules" : "$( getconfig x_iptables )",
    "implement_log_permissions_workaround" : true,
    "syslog_servers_fixed_hostname": true,
    "clientid": "$( decrypt "$( getconfig x_clientid )" )",
    "license_key": "$( decrypt "$( getconfig x_license_key )" )",
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

    # Update network settings
    # This now reads the $INIT_CONFIG file for the dedicated management setting
    python3 /usr/local/bluecat/cloud/init-bluecat-netconf.py
    if [ $? -gt 0 ]; then
        echo -e "[`date +%F_%T.%N`]: failed to initialize PSM network configuration"
        exit 1
    fi

	if [ "$( getconfig ENABLE_DNS_TRAFFIC_STATS_AGENT )" == "false" ]
	then
		systemctl disable docker.dns_stat_agent.service
		systemctl disable docker.packetbeat.service
	fi

	if [ "$( getconfig CM_SWITCH )" == "false" ]
	then
		systemctl disable docker.syslog.service
	fi

fi
# The INIT_CONFIG file will be processed, then deleted, after the post_install script runs

# Configure syslog_monitoring, if installed and trap hosts provided in config.ini
monitored_dns_servers=$(convert_to_empty_string "$( getconfig monitored_dns_servers | tr ',' ' ' )")
monitored_domain="$( getconfig monitored_domain )"
syslog_mon_trap_hosts=$(convert_to_empty_string "$( getconfig syslog_mon_trap_hosts | tr ',' ' ' )")

SYSLOG_MON_PATH=/opt/syslog_monitoring/Config

if [ "${vm_name_prefix}" = "DDS" ];then

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
        "userName": "Bluecat",
        "authKey": "bXlwYXNzd29yZA==",
        "privKey": "bXlwYXNzd29yZA==",
        "authProtocol": "SHA",
        "privProtocol": "DES",
        "port": 162
    }
EOF
            done
            echo "]"
        ) > $SYSLOG_MON_PATH/snmp_config.json
    fi

    #modify syslog config.ini dds_server ip address
    if [ -f ${SYSLOG_MON_PATH}/config.ini ]
    then
        echo "$( getconfig OM_${dds_seq_suffix})" |grep "\." >/dev/null 2>&1
        if [ $? == 0 ]
        then
            ntp_check_ip="$( getconfig OM_${dds_seq_suffix})"
        else
            ntp_check_ip=$(convert_to_empty_string "$( getconfig OM_V6_${dds_seq_suffix})")
        fi
        sed -i.bak "s/^bdds_server.*/bdds_server = ${ntp_check_ip}/" ${SYSLOG_MON_PATH}/config.ini
    fi
fi

if [ ! "$TRIAL_RUN" == "yes" ]; then
    # Remove config.ini to stop this script running again
    rm -f $CFGFILE
    # Clean-up injected JSON configuration
    rm -f $BUILTIN_JSON_CFG $STANDARD_JSON_CFG
fi
