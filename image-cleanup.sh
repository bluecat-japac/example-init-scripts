#!/bin/bash

systemctl stop psmd
rm -rf /root/.cache /var/lib/cloud /root/.ssh
rm -f /etc/ssh/ssh_host_*key* /etc/bcn/{*.db,*.xml,*.config} /etc/bcn/.PsmInitiated  /etc/profile.d/productinfo.sh  /etc/network/interfaces.d/50-cloud-init.cfg  /etc/*{.bak,.bck,-}
true> /etc/resolv.conf
true> /etc/machine-id
rm -f  /var/lib/systemd/random-seed
(
cd /var/log
rm -f cron.log dpkg.log psmd.log debug user.log setup_drbd.log audit/audit.log messages update.log auth.log vmware-vmsvc.log kern.log udev_bcn_rules.log error cloud-init.log syslog daemon.log vmware-network.log
for i in   pkg.log commandServer.log lastlog wtmp btmp fsck/checkfs fsck/checkroot shell_command.sh.log ntpd faillog dmesg alternatives.log fontconfig.log apt/term.log apt/eipp.log.xz apt/history.log bootstrap.log csync2_action.log
do true> $i
done
)

rm -f /root/.bash_history
rm -f /root/image-cleanup.sh
halt
