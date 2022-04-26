#!/bin/bash
set -e
set -v

/mnt/usr/local/bluecat/cloud/openstack/openstack-initial-config.py
# check service
docker ps -a
