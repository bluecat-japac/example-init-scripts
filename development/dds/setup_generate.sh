#!/bin/bash
set -e
set -v

cat  /etc/vmse/init/alm_inject_files.ini
cat  /etc/vmse/init/config.ini
cat  /etc/vmse/init/builtin.ini

chmod 755 /etc/vmse/init/*
service psmd stop

sleep 5
/mnt/usr/local/bluecat/cloud/generate-init-config.sh
cat /etc/bcn/init-config.json

/mnt/usr/local/bluecat/cloud/init-bluecat-netconf.py
sleep 5

# check docker
docker ps -a

# Run adonis_post_install.sh
/usr/local/bluecat/adonis_post_install.sh || true
# Enable and start psmd:
systemctl enable --now runBluecat

service psmd start

