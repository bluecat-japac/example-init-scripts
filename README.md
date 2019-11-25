# Virtual Network Function Example init scripts

Modifications to BAM and BDDS VM images to enable deployment as a VNF in an OpenStack environment

# DISCLAIMER

This project is published as EXAMPLE CODE only. Do NOT use as-is. Do NOT expect this code to work in your environment.

These scripts were originally developed for use in a specific project and environment.
While elements will be relevant to other environments, some of the techniques used are dangerous, and could cause
problems when used in the wrong context.



## Main components

* generate-init-config.sh decodes configuration files early during startup. This script calls init-bluecat-netconf.py to write interface configuration to the PSM database.
* openstack-initial-config.py script runs during first startup, after adonis/proteus_post_install, to set up platform configuration in PSM
* DHCP configuration files: dhcp-localif.service, dhclient-localif.conf, psm-dhclient-script
Together these enable an additional local management interface eth4 to receive an IPv4 address via DHCP. The IPv6 address of the same interface is statically configured.

## Change History

Current BAM/BDDS version: 9.1

v4.10 (2019/11/25) Use vm_name from config.ini as hostname
    Support built-in configuration file and inject files in user_data
v4.9 (2019/11/7) Use config.ini to enable DNS traffic statistics agent
v4.8 (2019/10/1) Use config.ini to enable DHCP for local interface IPv4
v4.7 (2019/9/3) support for config Local interface by config drive.
v4.6 (2019/6/28) support for BAM/BDDS 9.1
v4.3 Add BAM 9.0 PM counter (REL-189) patch install procedure
v4.2 (script v 4.01) New script to implement DHCP for Local
	add Chinese UI war patch install guide
v4.0	Michael re-write the scripts for new BAM 9.0 VM
    Instead of patching post_install scripts, modify post_install.service to pull in
    a new service init-config.service that calls our script
v3.9	New script for setting Local IPv6 address from new inject file (Michael script v3.0)
v3.8    add descript about vmxnet3 and how to modify vmx file
v3.7	based on BAM v8.3.0 - solve route injection issue
	       add /etc/dhcp/dhclient-enter-hooks.d/no-new_routers
v3.6	fix DB repplication issue, and fix snmpv3 clear text issue
v3.5 	removed Chinese description
v3.4	disable TLS1.0 and 1.1 in /mnt/opt/server/proteus/etc/jetty-ssl.xml
v3.3	add missed cmd "copy database backup to VM"

## VM image creation instructions

========================================================================
Add new interface to BAM and BDDS image file
========================================================================
	BAM :add additional 2 NIC (Total 3 NIC)
	BDDS :add additional 2 NIC (Total 5 NIC)

	Note: for BlueCat internal VMWare test only, the NIC need to be vmxnet3.
	      If it is "e1000", modify the vmx file as following
	E.g.
	ethernet0.virtualDev = "vmxnet3"
	ethernet1.virtualDev = "vmxnet3"

========================================================================
Use BDDS 8.2.0 ISO to boot up the Target VM image
========================================================================

## Press F2 to change boot priority to CD-ROM (which use BDDS 8.2.0 ISO file)

## After boot up, select "Live system" (something like this)

========================================================================
Modify files after boot up from
========================================================================
# Login to live linux system (don't need pw)

command:
	mount /dev/sda5  /mnt

# mkdir /z to save scripts
command:
	cd /
	mkdir z
	cd z

========================================================================
Configure eth0 IP and ssh to allow sftp script to VM
========================================================================
command:
	ip link show
	ip address add 10.10.10.8/24 dev eth0
	ip link set eth0 up
	ping 10.10.10.8

# enable ssh for root (for sftp file to VM)
==========================================
Chagne root pw
==========================================
command:
	passwd root		(change root's pw as "root")

==========================================
configure ssh
==========================================
	vi /etc/ssh/sshd_config

	    ## change
	    PermitRootLogin without-passwd
	    ## to
	    PermitRootLogin yes

	    ## change
	    PasswordAuthentication no
	    ## to
	    PasswordAuthentication yes

## restart sshd
command:
	systemctl restart sshd

========================================================================
[BAM & BDDS] copy all scripts to /z in VM
========================================================================

# In windows, rename database to correct name (init-database.bak), and FTP it to BAM
#	rename init-database_8.3.0-128.GA.bak  init-database.bak


##################################################################
PSCP command to send files in Windows to VM mounted dir
##################################################################


C>pscp -r *.* root@10.10.10.8:/z/.

	92_openstack.cfg          | 0 kB |   0.1 kB/s | ETA: 00:00:00 | 100%
	adonis_post_install.patch | 0 kB |   0.7 kB/s | ETA: 00:00:00 | 100%
	adonis_post_install.sh    | 12 kB |  12.6 kB/s | ETA: 00:00:00 | 100%
	init-database.bak         | 3251 kB | 3251.6 kB/s | ETA: 00:00:00 | 100%
	modifications-to-base-vm. | 1 kB |   1.5 kB/s | ETA: 00:00:00 | 100%
	openstack-initial-config. | 13 kB |  13.6 kB/s | ETA: 00:00:00 | 100%
	proteus_post_install.patc | 0 kB |   0.6 kB/s | ETA: 00:00:00 | 100%
	proteus_post_install.sh   | 11 kB |  11.9 kB/s | ETA: 00:00:00 | 100%

    [some files may not be listed here...]

############################################################################
# Procedure working on Live VM that mount BAM/BDDS /dev/sda5 to /mnt
############################################################################

====================================================================
[BAM & BDDS] Create directory for vendor scripts
====================================================================

	mkdir -p /mnt/etc/vmse/init/

============================================================
BAM Only !!!!
============================================================

## copy database backup file to BAM
##
## remember to rename it first in Windows > rename init-database_8.3.0-128.GA.bak  init-database.bak
## if not, use the following command to rename it

mv /z/init-database_9.1.0-500.GA.bcn.bak   /z/init-database.bak

cp /z/init-database.bak    /mnt/etc/bcn/init-database.bak


=======================================================================================
BDDS only !
   2018/1224(11) On BDDS, modify admin CLI to allow eth4 IP address to be configured:
=======================================================================================

## On BDDS, modify admin CLI to allow eth4 IP address to be configured:
##        (Below DHCP changes require this change)

/mnt/usr/bin/patch   /mnt/usr/local/cli/scripts/cliInterface.py < /z/cliInterface.py.patch

==================================================================================
BAM & BDDS: Create [openstack] dir  & Copy openstack-initial-config.py
==================================================================================

	mkdir /mnt/usr/local/bluecat/cloud/openstack
	cp  /z/openstack-initial-config.py      /mnt/usr/local/bluecat/cloud/openstack/
	chmod 755 /mnt/usr/local/bluecat/cloud/openstack/openstack-initial-config.py

====================================================
BAM & BDDS: copy   generate-init-config.sh
====================================================

	cp /z/generate-init-config.sh  /mnt/usr/local/bluecat/cloud/
	chmod 755  /mnt/usr/local/bluecat/cloud/generate-init-config.sh

=====================================================
BAM & BDDS: copy   92_openstack.cfg
=====================================================

	cp /z/92_openstack.cfg  /mnt/etc/cloud/cloud.cfg.d/

=====================================================
BAM & BDDS: copy   init-bluecat-netconf.py
=====================================================

	cp /z/init-bluecat-netconf.py    /mnt/usr/local/bluecat/cloud/init-bluecat-netconf.py
	chmod 755   /mnt/usr/local/bluecat/cloud/init-bluecat-netconf.py

=====================================================
BAM & BDDS: copy "init-config.service" file
=====================================================

    cp /z/init-config.service    /mnt/lib/systemd/system/init-config.service

==================================================================================
BAM & BDDS: Modify post_install.service to pull in init-config.service
==================================================================================

sed -i '/^Wants=/s/$/ init-config.service/' /mnt/lib/systemd/system/post_install.service

==============================================================
BAM Only (9.1) - modify config.yml to exclude protocol (TLS1.0 & TLS1.1) and CipherSuites SHA/SHA1
==============================================================

vi /mnt/opt/server/proteus/config.yml

    excludeCipherSuites:    # default: .*NULL.*, .*RC4.*, .*MD5.*, .*DES.* and .*DSS.*
        - '.*NULL.*'
        - '.*RC4.*'
        - '.*MD5.*'
        - '.*DES.*'
        - '.*DSS.*'
        - '.*SHA.*'         # <---------- Add this to exclude SHA
        - '.*SHA1.*'        # <---------- add this to exclude SHA1

    excludeProtocols:       # default: SSL, SSLv2, SSLv2Hello and SSLv3
        - 'SSL'
        - 'SSLv2'
        - 'SSLv2Hello'
        - 'SSLv3'
        - 'TLSv1'           # <--------- Add this to exclude TLSv1
        - 'TLSv1.1'         # <--------- Add this to exclude TLSv1.1

================================================
BAM only (to restore database)
================================================

	sed '/systemctl start proteusServer/d;/proteusServer.sh stopwait/d' < /mnt/usr/local/bluecat/restoreDB.sh > /mnt/usr/local/bluecat/restoreDB-nostart.sh
	chmod 755 /mnt/usr/local/bluecat/restoreDB-nostart.sh

======================================================================================
BAM Only - Remove customize_for_vm_environment function from /usr/local/bluecat/shell_command.sh
======================================================================================

sed -i.bak '/^customize_for_vm_environment/,/^}/d' /mnt/usr/local/bluecat/shell_command.sh

mkdir /mnt/home/bluecat
mkdir /mnt/home/bluecat/preserved_scripts

======================================================================================
BAM Only - add custom firewall scripts to home partition sda8
======================================================================================

cp /z/custom_firewall.start    /mnt/home/bluecat/preserved_scripts/custom_firewall.start
cp /z/custom_firewall.stop     /mnt/home/bluecat/preserved_scripts/custom_firewall.stop

========================================================================
[For BlueCat internal test the VM in VMWare Only] BAM & BDDS

# This is NOT required for OpenStack / KVM environments

# When testing on VMware Workstation, to avoid errors during startup/resume,
# remove VMware tools scripts that stop and restart network interfaces on VM suspend/resume.

# This is NOT required for OpenStack / KVM environments

    ### procedure : move the file "/mnt/etc/vmware-tools/scripts/vmware/network"
    ###             to its parent dir

    mv /mnt/etc/vmware-tools/scripts/vmware/network  ..

=====================================================================================
BAM only Install files and setup DHCPv4 client for local management interface
=====================================================================================

cp /z/custom_firewall.start    /mnt/home/bluecat/preserved_scripts/custom_firewall.start

=====================================================================================
BAM & BDDS
=====================================================================================

cp /z/dhclient-localif.conf  /mnt/etc/dhcp/dhclient-localif.conf
cp /z/psm-dhclient-script    /mnt/usr/local/bluecat/psm-dhclient-script
chmod +x /mnt/usr/local/bluecat/psm-dhclient-script
cp /z/dhcp-localif.service   /mnt/lib/systemd/system/dhcp-localif.service

=====================================================================================
BAM Only (On BAM, change DHCP interface from eth4 to eth2:)
=====================================================================================

sed -i.bak '/dhclient/s/eth4/eth2/' /mnt/lib/systemd/system/dhcp-localif.service

==============================================================
Poweroff the VM
==============================================================

sync;sync
poweroff


# note in BAM VM, HTTP is disabled, can only use https to connect to BAM web.
# it is over 443 port

==============================================================
connect metadata iso file to cd-rom then boot up
==============================================================

Login as root, and the encrypted password in meta-data is: Bc4tP4ss

Linux account
id: root
pw: Bc4tP4ss

BlueCat CLI shell
id: admin
pw: Bc4tP4ss

BAM web pw (stored in database backup)
(Web) id: admin
pw: P@ssw0rd



==============================================================
Other NOTES
==============================================================



========================================
How to encrypt and decrypt string
========================================

Replace ### MY PASSPHRASE HERE ### below with your passphrase:

1) Use the folloiwng to encrypt the data
	echo "001400000123456" | openssl enc -e -aes256 -a -pass "pass:### MY PASSPHRASE HERE ###" > enc-out.txt

	root@vBDDS:/usr/local/bluecat/cloud# cat enc-out.txt
	U2FsdGVkX18nO16laeOfVuSSxFka1mcSLiDgh6GNJIzcqrURsicNDxN/vGnU9kQH

	Put the encrypted string into the meta-data

2) To verify (decode) it
	echo $(openssl enc -d -aes256 -a -pass "pass:### MY PASSPHRASE HERE ###" < enc-out.txt) EOL
	001400000123456 EOL

    Check there is no new-line between the meta-data and the EOL marker


==============================================================
How to make metadata ISO
==============================================================

1) Copy the directory structure and template file from the attached ISO to /tmp/config-2

2) Make any required changes to IP addresses, etc, in the <meta> section of
 /tmp/config-2/openstack/latest/meta_data.json

3) To create the ISO file, I used:
 genisoimage -r -V config-2 -o config-2.iso /tmp/config-2

==============================================================
BAM database customization
==============================================================
v9.1 database customization by Jerry
    for snmp & BlueCat Gateway scale-in/out function

1) Boot up a clean BAM VM
2) Do the following actions:

	1.	Disable HTTP
	2.	ADD UDF "can_scale_in" for BDDS Server
	3	Add UDF "BlueCatGateway" for Gateway
	3.	ADD User scale for Gateway
	4.	Add Chinese[zh-cn] to the Additional supported locales in the global setting
	5.	Enable SNMP monitoring for BDDS and BAM

3) Restore the default IP address for interface eth0
(This is required because the "Disable HTTP" setting is tied to the BAM IP address.)
4) Backup the database for initial script restore db

==============================================================
Injection file modifications for PoC
==============================================================
Within JSON file

1.	Update the license for the test
2.	"enable-stig-compliance" : true,
3.	Disable SNMP poll v2/v1


# License

Copyright 2019 BlueCat Networks (USA) Inc. and its affiliates

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
