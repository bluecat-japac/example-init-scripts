#!/bin/bash

systemctl stop psmd
rm -rf /root/.cache /var/lib/cloud /root/.ssh
rm -f /opt/server/proteus/etc/keystore /data/server/conf/server.cert
rm -f /etc/ssh/ssh_host_*key* /etc/bcn/{*.db,*.xml,*.config} /etc/bcn/.PsmInitiated  /etc/profile.d/productinfo.sh  /etc/network/interfaces.d/50-cloud-init.cfg  /etc/*{.bak,.bck,-}
rm -f /usr/local/cli/cli.db
true> /etc/resolv.conf
true> /etc/machine-id
rm -f  /var/lib/systemd/random-seed

rm -f /root/.bash_history
rm -f /root/image-cleanup.sh
halt
