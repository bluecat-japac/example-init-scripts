#!/bin/bash
set -e
set -v

cat /etc/vmse/init/config.ini

cat /etc/vmse/init/builtin.ini

chmod 777 /etc/vmse/init/*

service psmd stop
sleep 5

# Setup and run generate-init-config.sh
/mnt/usr/local/bluecat/cloud/generate-init-config.sh
cat /etc/bcn/init-config.json
sleep 3

echo "Run proteus_post_install.sh"
/usr/local/bluecat/proteus_post_install.sh || true
sleep 5

echo "Enable and start psmd"
systemctl enable --now runBluecat

service psmd start
