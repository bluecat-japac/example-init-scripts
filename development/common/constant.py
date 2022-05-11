#!/usr/bin/python3
# Copyright 2021 BlueCat Networks (USA) Inc. and its affiliates

VCENTER_TEMPLATE = 'Tenants-Internal/JPAC/Templates/'
VCENTER_CLONE_PATH = 'Tenants-Internal/JPAC/TEST_DHCP/'
DDS_VERSION = 'bdds_esx_9.4.0-674.GA.bcn_amd64'
BAM_VERSION = 'bam_esx_9.4.0-674.GA.bcn_amd64'

DDS_ISO_PATH = '[BCL-SIO-VOL-JPAC-101] ISO-images/JPAC-test/config-nw-i-dhcp-eth2.iso'
DDS_ETH_NAMES = ['jpac|jpac-anp|jpac-net010', 'jpac|jpac-anp|jpac-net009', 'jpac|jpac-anp|jpac-net008']

BAM_ISO_PATH = '[BCL-SIO-VOL-JPAC-101] ISO-images/JPAC-test/config-nw-i-dhcp-eth0.iso'

EXAMPLE_INIT_SCRIPT_PATH = 'example-init-scripts.tar.gz'
SYSLOG_IMAGE_NAME = 'syslog_mon_amd64.tar.gz'
DNS_STAT_IMAGE_NAME = 'dns-traffic-statistics-agent-amd64.tar.gz'

PASSWORD_KEY = '### MY PASSPHRASE HERE ###'
SUPPORT_DHCP = False


class BAM:
    BAM_USERNAME = 'root'
    BAM_PASSWORD = '<encrypted-password>'
    BAM_USERNAME_NEW = 'root'
    # Read and overwrite new pasword from configs/bam_data/buitin.ini : x_password
    BAM_PASSWORD_NEW = '<encrypted-password>'


class DDS:
    DDS_USERNAME = 'root'
    DDS_PASSWORD = '<encrypted-password>'
    DDS_USERNAME_NEW = 'root'
    # Read and overwrite new pasword from configs/dds_data/buitin.ini : x_password
    DDS_PASSWORD_NEW = '<encrypted-password>'


def get_ini_field(file_path, field_name):
    ini_file = open(file_path)
    result = None
    field_name = field_name.lower()
    try:
        for _line in ini_file:
            line = _line.strip()
            line = line.partition('#')[0]  # ignore comment
            group = line.split('=', 1)
            if len(group) != 2:
                continue
            key, value = group
            if key.strip().lower() == field_name:
                result = value
                break
    finally:
        ini_file.close()
    return result


def update_password_constant():
    bam_ini_path = "configs/bam_data/builtin.ini"
    password_field = "x_password"
    bam_password = get_ini_field(bam_ini_path, password_field)
    bdds_init_path = "configs/dds_data/builtin.ini"
    bdds_password = get_ini_field(bdds_init_path, password_field)
    if bam_password:
        BAM.BAM_PASSWORD_NEW = bam_password
    if bdds_password:
        DDS.DDS_PASSWORD_NEW = bdds_password
    return


update_password_constant()
