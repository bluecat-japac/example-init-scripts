#!/bin/bash
# Install script for BDDS -- further changes required for BAM
set -e
set -v
# Files to be installed should be copied to /z
test -s /z/psm-dhclient-script || ( echo Files missing from /z ; exit 1 )
# Create an init.key file with:
# echo "### MY PASSPHRASE HERE ###" > init.key
test -s /z/init.key || ( echo init.key missing ; exit 1 )
# Target BDDS root should be mounted on /mnt
# For in-place testing, use mv mnt mnt.moved ; ln -s / /mnt
test -d /mnt/etc/bcn || ( echo BDDS files not found in /mnt ; exit 1 )
test -d /mnt/usr/local/bluecat || ( echo BDDS files not found in /mnt ; exit 1 )

umask 022
# Create directory for vendor scripts
mkdir -p /mnt/etc/vmse/init
# On BDDS, modify admin CLI to allow eth4 IP address to be configured
/mnt/usr/bin/patch   /mnt/usr/local/cli/scripts/cliInterface.py < /z/cliInterface.py.patch
# Install init scripts
mkdir /mnt/usr/local/bluecat/cloud/openstack
cp  /z/openstack-initial-config.py      /mnt/usr/local/bluecat/cloud/openstack/
chmod 755 /mnt/usr/local/bluecat/cloud/openstack/openstack-initial-config.py
cp /z/generate-init-config.sh  /mnt/usr/local/bluecat/cloud/
chmod 755  /mnt/usr/local/bluecat/cloud/generate-init-config.sh
cp /z/init.key /mnt/etc/bcn/init.key
cp /z/92_openstack.cfg  /mnt/etc/cloud/cloud.cfg.d/
cp /z/init-bluecat-netconf.py    /mnt/usr/local/bluecat/cloud/init-bluecat-netconf.py
chmod 755   /mnt/usr/local/bluecat/cloud/init-bluecat-netconf.py
# Configure systemd to run init scripts
cp /z/init-config*.service    /mnt/lib/systemd/system/
# Modify post_install service to pull in init-scripts
# The post_install service is disabled after the first boot
mkdir /mnt/etc/systemd/system/post_install.service.wants/
ln -s /lib/systemd/system/init-config-stage1.service /mnt/etc/systemd/system/post_install.service.wants/
ln -s /lib/systemd/system/init-config-stage2.service /mnt/etc/systemd/system/post_install.service.wants/
# Install and setup DHCPv4 client for local management interface
cp /z/dhclient-localif.conf  /mnt/etc/dhcp/dhclient-localif.conf
cp /z/psm-dhclient-script    /mnt/usr/local/bluecat/psm-dhclient-script
chmod 755 /mnt/usr/local/bluecat/psm-dhclient-script
cp /z/dhcp-localif.service   /mnt/lib/systemd/system/dhcp-localif.service
# On BAM, the DHCP interface should be changed from eth4 to eth2.
# sed -i '/dhclient/s/eth4/eth2/' /mnt/lib/systemd/system/dhcp-localif.service
