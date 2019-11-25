#!/bin/bash
# Copyright BlueCat Networks 2019. All rights reserved.

CFGFILE=/etc/vmse/init/config.ini
BUILTIN_CFG=/etc/vmse/init/bluecat_init.builtin
STANDARD_CFG=/etc/vmse/init/bluecat_init.json
INIT_CONFIG=/etc/bcn/init-config.json
TMP_NETCONF=/tmp/init-netconf.json

# This script is only needed on the first boot
# After the initial configuration has been created, the STANDARD_CFG file is deleted below
# This prevents any action on future reboots
if [ ! -s $STANDARD_CFG ]
then
    exit 0
fi

echo Generating initial configuration from $CFGFILE and $STANDARD_CFG

if [ ! -s $CFGFILE ]
then
    echo $CFGFILE not found
    exit 1
fi

function getconfig {
    cat ${CFGFILE} | grep "^"$1 | awk -F= '{print $2}'
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
vm_name=$( getconfig vm_name )
vm_name_prefix=$( getconfig vm_name | awk -F "_" '{print $(NF - 1)}')
vm_seq=$( getconfig vm_name | awk -F "_" '{print $NF}')
bam_vm_num=$( getconfig bam_num )

if [ "$( getconfig LOCAL_V4_DHCP )" == "yes" ]
then
    systemctl enable --now --no-block dhcp-localif.service
fi

if [ "$( getconfig ENABLE_DNS_TRAFFIC_STATS_AGENT )" == "yes" ]
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
 
cat <<EOF > $TMP_NETCONF
{
   "hostname" : "${vm_name}",
   "interfaces" : [
      {
         "name" : "eth0",
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

# Update network settings
python /usr/local/bluecat/cloud/init-bluecat-netconf.py < $TMP_NETCONF
if [ $? -gt 0 ]; then
    echo -e "[`date +%F_%T.%N`]: failed to initialize PSM network configuration"
    exit 1
fi
rm -f $TMP_NETCONF

echo '{' > $INIT_CONFIG
# Set the hostname value in the bluecat_init.json file
# (if this is not set explicitly, the hostname in meta_data.json will be used.)
echo "\"hostname\" : \"${vm_name}\"," >> $INIT_CONFIG
# Enable dedicated managed in the bluecat_init.json file
if [ "${vm_name_prefix}" = "DDS" ]
then
    echo '"enable-dedicated-management" : true,' >> $INIT_CONFIG
fi
# **** Add your passphrase here ****
PASSPHRASE="### YOUR PASSPHRASE HERE ###"
(
    # concatenate configuration from multiple sources
    if [ -s "$BUILTIN_CFG" ]
    then
        cat $BUILTIN_CFG
    fi
    cat $STANDARD_CFG
) | perl -e '
sub decrypt { $t=`echo "@_[0]" | openssl enc -d -aes256 -md md5 -a -pass "pass:'$PASSPHRASE'"` ; $t =~ s/\s+$//; return $t }
while (<>) { s/"ENCRYPTED-(.*?)" *: *"(.*?)"/"\"$1\": \"" . decrypt($2) . "\""/e; print; }
' >> $INIT_CONFIG
echo '}' >> $INIT_CONFIG
rm -f $BUILTIN_CFG $STANDARD_CFG

# The INIT_CONFIG file will be processed, then deleted, by the post_install script
