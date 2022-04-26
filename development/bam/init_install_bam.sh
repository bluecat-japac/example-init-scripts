#!/bin/bash
set -e
set -v

# Change Backup file
BAM_BACKUP_PATH=/z/init-database_9.4.0-639.GA.bcn.bak

chmod 755 ~/init_install_bam.sh

# [BAM & BDDS] Create directory for vendor scripts
# TODO
mkdir -p /root/example-init-scripts/
tar -xvf /root/example-init-scripts.tar.gz --directory /root/example-init-scripts/

cd /
mkdir -p z
cp -r /root/example-init-scripts/* /z

rm -rf /mnt
ln -s /  /mnt
ls /mnt
mkdir -p /mnt/etc/vmse/init/

# Copy database backup file to BAM
if [ -e $BAM_BACKUP_PATH ]
then
    mv $BAM_BACKUP_PATH  /z/init-database.bak
    cp /z/init-database.bak    /mnt/etc/bcn/init-database.bak
fi


# BAM & BDDS: Create [openstack] dir  & Copy openstack-initial-config.py
umask 022
mkdir -p /mnt/usr/local/bluecat/cloud/openstack
cp  /z/openstack-initial-config.py      /mnt/usr/local/bluecat/cloud/openstack/
chmod 755 /mnt/usr/local/bluecat/cloud/openstack/openstack-initial-config.py

# BAM & BDDS: copy   generate-init-config.sh
cp /z/generate-init-config.sh  /mnt/usr/local/bluecat/cloud/
chmod 755  /mnt/usr/local/bluecat/cloud/generate-init-config.sh
echo  "### MY PASSPHRASE HERE ###" > /mnt/etc/bcn/init.key

# BAM & BDDS: copy   92_openstack.cfg
cp /z/92_openstack.cfg  /mnt/etc/cloud/cloud.cfg.d/

# BAM & BDDS: copy   init-bluecat-netconf.py
cp /z/init-bluecat-netconf.py    /mnt/usr/local/bluecat/cloud/init-bluecat-netconf.py
chmod 755   /mnt/usr/local/bluecat/cloud/init-bluecat-netconf.py

# BAM & BDDS: copy "init-config-stage*.service" files
cp /z/init-config*.service    /mnt/lib/systemd/system/

# BAM & BDDS: Modify post_install.service to pull in init-config.service
mkdir /mnt/etc/systemd/system/post_install.service.wants/
ln -s /lib/systemd/system/init-config-stage1.service /mnt/etc/systemd/system/post_install.service.wants/
ln -s /lib/systemd/system/init-config-stage2.service /mnt/etc/systemd/system/post_install.service.wants/

# BAM Only: Modify config.yml to exclude protocol (TLS1.0 & TLS1.1) and CipherSuites SHA/SHA1
sed -i "/'\.\*DSS\.\*'/a\
\        - '.*SHA.*'\n\
        - '.*SHA1.*'\n"  /mnt/opt/server/proteus/config.yml

sed -i "/'SSLv3'/a\
\        - 'TLSv1' \n\
        - 'TLSv1.1' \n" /mnt/opt/server/proteus/config.yml


#BAM only (to restore database)
sed '/systemctl start proteusServer/d;/proteusServer.sh stopwait/d' < /mnt/usr/local/bluecat/restoreDB.sh > /mnt/usr/local/bluecat/restoreDB-nostart.sh
chmod 755 /mnt/usr/local/bluecat/restoreDB-nostart.sh

#BAM Only - Remove customize_for_vm_environment function from /usr/local/bluecat/shell_command.sh
sed -i '/^customize_for_vm_environment/,/^}/d' /mnt/usr/local/bluecat/shell_command.sh

mkdir -p /mnt/home/bluecat
mkdir -p /mnt/home/bluecat/preserved_scripts


#BAM Only - add custom firewall scripts to home partition sda8
cp /z/custom_firewall.start    /mnt/home/bluecat/preserved_scripts/custom_firewall.start
cp /z/custom_firewall.stop     /mnt/home/bluecat/preserved_scripts/custom_firewall.stop

#BAM & BDDS - Install files and setup DHCPv4 client for local management interface
cp /z/dhclient-localif.conf  /mnt/etc/dhcp/dhclient-localif.conf
cp /z/psm-dhclient-script    /mnt/usr/local/bluecat/psm-dhclient-script
chmod +x /mnt/usr/local/bluecat/psm-dhclient-script
cp /z/dhcp-localif.service   /mnt/lib/systemd/system/dhcp-localif.service

#BAM Only (On BAM, change DHCP interface from eth4 to eth2:)
sed -i '/dhclient/s/eth4/eth2/' /mnt/lib/systemd/system/dhcp-localif.service


mkdir -p /etc/vmse/init/
cp /z/split_inject_file.sh /etc/vmse/init/

touch ~/trial_run

