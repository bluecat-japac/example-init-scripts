#!/bin/bash
set -e
set -v

chmod 777 ~/init_install_dds.sh

# [BAM & BDDS] Create directory for vendor scripts
mkdir -p /root/example-init-scripts/
tar -xvf /root/example-init-scripts.tar.gz --directory /root/example-init-scripts/

cd /
mkdir -p z
cp -r /root/example-init-scripts/* /z

rm -rf /mnt
ln -s /  /mnt
ls /mnt
mkdir -p /mnt/etc/vmse/init/

## On BDDS, modify admin CLI to allow eth4 IP address to be configured:
##        (Below DHCP changes require this change)
/mnt/usr/bin/patch   /mnt/usr/local/cli/scripts/cliInterface.py < /z/cliInterface.py.patch
# BAM & BDDS: Create [openstack] dir  & Copy openstack-initial-config.py
umask 022
mkdir -p /mnt/usr/local/bluecat/cloud/openstack
cp  /z/openstack-initial-config.py      /mnt/usr/local/bluecat/cloud/openstack/
chmod 755 /mnt/usr/local/bluecat/cloud/openstack/openstack-initial-config.py

# BAM & BDDS: copy   generate-init-config.sh
cp /z/generate-init-config.sh  /mnt/usr/local/bluecat/cloud/
chmod 755  /mnt/usr/local/bluecat/cloud/generate-init-config.sh

# BAM & BDDS: copy   92_openstack.cfg
cp /z/92_openstack.cfg  /mnt/etc/cloud/cloud.cfg.d/

echo "### MY PASSPHRASE HERE ###" > /mnt/etc/bcn/init.key

# BAM & BDDS: copy   init-bluecat-netconf.py
cp /z/init-bluecat-netconf.py    /mnt/usr/local/bluecat/cloud/init-bluecat-netconf.py
chmod 755   /mnt/usr/local/bluecat/cloud/init-bluecat-netconf.py

# BAM & BDDS: copy "init-config-stage*.service" files
cp /z/init-config*.service    /mnt/lib/systemd/system/

# BAM & BDDS: Modify post_install.service to pull in init-config.service
mkdir /mnt/etc/systemd/system/post_install.service.wants/
ln -s /lib/systemd/system/init-config-stage1.service /mnt/etc/systemd/system/post_install.service.wants/
ln -s /lib/systemd/system/init-config-stage2.service /mnt/etc/systemd/system/post_install.service.wants/
#BAM & BDDS - Install files and setup DHCPv4 client for local management interface
cp /z/dhclient-localif.conf  /mnt/etc/dhcp/dhclient-localif.conf
cp /z/psm-dhclient-script    /mnt/usr/local/bluecat/psm-dhclient-script
chmod +x /mnt/usr/local/bluecat/psm-dhclient-script
cp /z/dhcp-localif.service   /mnt/lib/systemd/system/dhcp-localif.service

mkdir -p /etc/vmse/init/
cp /z/split_inject_file.sh /etc/vmse/init/

# Load Syslog Monitoring & DNS Traffic Agent images
# mkdir /opt/dns_stat_agent/ to save the .gz file and images
mkdir /mnt/opt/images/

# Copy and extract syslog_mon_amd64.tar.gz and dns-traffic-statistics-agent-*.tar.gz
tar  -xvf ~/syslog_mon_*.tar.gz
mkdir --parents /mnt/opt/unpack/syslog_monitoring/; mv syslog_mon_*/* $_

tar  -xvf ~/dns-traffic-statistics-agent-*.tar.gz
mkdir --parents /mnt/opt/unpack/dns_traffic_statistics_agent/; mv dns-traffic-statistics-agent-*/* $_

#Move 3 images to the images folder
mv /mnt/opt/unpack/*/syslog_monitoring.tar \
      /mnt/opt/unpack/*/*/dns_stat_agent.tar  \
      /mnt/opt/unpack/*/*/dns_packetbeat.tar  \
      /mnt/opt/images/

cp /mnt/opt/unpack/*/services/docker.*.service /mnt/lib/systemd/system/
chmod 755 /mnt/lib/systemd/system/docker.*.service

touch ~/trial_run

mkdir -p /etc/vmse/init/
