#!/usr/bin/python3
# Copyright 2021 BlueCat Networks (USA) Inc. and its affiliates
import requests
import time

import json, sys, os

from common.vcenter import Vcenter
from common.constant import *
from pyVmomi import vim, vmodl
import subprocess


path = os.path.abspath(os.path.dirname(sys.argv[0]))

if not path.endswith("/"):
    path = "{}/".format(path)

with open(path + "configs/credential_conf.json") as user_config:
    attr_user = json.load(user_config)
# print("User attribute: ", attr_user)

with open(path + "configs/vcenter_conf.json") as clone_config:
    attr_clone = json.load(clone_config)

# attr_clone = {}
vcenter = Vcenter(attr_user, attr_clone)
vcenter.get_conn()


def decrypt_password(pw, key):
    cmd = 'openssl enc -d -aes256 -a -md md5 -a -pass pass:{}'
    cmd = cmd.format(key)
    cmd = cmd.split()
    ps = subprocess.Popen(('echo', pw), stdout=subprocess.PIPE)
    decrypted_text = subprocess.check_output(cmd, stdin=ps.stdout, stderr=subprocess.DEVNULL)
    ps.wait()
    return decrypted_text.decode("UTF-8").strip()


def start_vm(vm_obj):
    vcenter.start_vm(vm_obj)


def get_vm_by_name(vm_name):
    try:
        vm_obj = vcenter.get_vm_by_name(vm_name)
    except Exception as e:
        if 'No VM found' in str(e):
            return None
    return vm_obj


def stop_vm(vm_obj):
    return vcenter.stop_vm(vm_obj)


def destroy_vm(vm_name):
    vm_obj = vcenter.get_vm_by_name(vm_name)
    return vcenter.destroy_vm(vm_obj)


def clone_vm(vm_name, dest_folder_name):
    vcenter.set_vcenter_attribute_for_clone()
    vcenter.set_template(vm_name)
    vcenter.set_folder(dest_folder_name)
    vm_name_relative_name = os.path.basename(vm_name)
    return vcenter.clone_vm(vm_name_relative_name)


def execute_vm(vm_obj, username, password, program_path, arguments=""):
    password = decrypt_password(password, PASSWORD_KEY)

    guest_file_path = '/tmp/stdout'
    arguments = "{} > {}".format(arguments, guest_file_path)

    creds = vim.vm.guest.NamePasswordAuthentication(username=username, password=password)
    program_spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath=program_path, arguments=arguments)

    content = vcenter.content
    profile_manager = content.guestOperationsManager.processManager
    res = profile_manager.StartProgramInGuest(vm_obj, creds, program_spec)
    # output = profile_manager.ListProcessesInGuest(vm, creds, [res]).pop()
    if res <= 0:
        return None
    time.sleep(3)
    file_manager = content.guestOperationsManager.fileManager
    temp_stdout_file = file_manager.InitiateFileTransferFromGuest(vm, creds, guest_file_path)
    file_url = temp_stdout_file.url
    data = requests.get(file_url, verify=False)
    return data.text


def upload_file(vm_obj, username, password, file_name, vm_path, is_binary=False, password_encrypt=True):
    if password_encrypt:
        password = decrypt_password(password, PASSWORD_KEY)
    content = vcenter.content
    creds = vim.vm.guest.NamePasswordAuthentication(username=username, password=password)

    if is_binary:
        infile = open(file_name, 'rb')
    else:
        infile = open(file_name, 'r')
    data_to_send = infile.read()
    infile.close()

    file_attribute = vim.vm.guest.FileManager.FileAttributes()
    url = content.guestOperationsManager.fileManager. \
        InitiateFileTransferToGuest(vm_obj, creds, vm_path,
                                    file_attribute,
                                    len(data_to_send), True)
    # When : host argument becomes https://*:443/guestFile?
    # Ref: https://github.com/vmware/pyvmomi/blob/master/docs/ \
    #            vim/vm/guest/FileManager.rst
    # Script fails in that case, saying URL has an invalid label.
    # By having hostname in place will take take care of this.
    # url = re.sub(r"^https://\*:", "https://" + str(args.host) + ":", url)
    resp = requests.put(url, data=data_to_send, verify=False)
    if not resp.status_code == 200:
        return False
    else:
        return True


def execute_python_vm(vm_obj, username, password, host_python_file_path):
    password = decrypt_password(password, PASSWORD_KEY)
    temp_python_path_in_host = '/tmp/temp.py'
    status = upload_file(vm_obj, host_python_file_path, temp_python_path_in_host, password_encrypt=False)
    if not status:
        raise AssertionError("File is not uploaded")
    content = vcenter.content
    time.sleep(3)
    file_manager = content.guestOperationsManager.fileManager

    program_path = '/usr/bin/python3'
    guest_file_path = '/tmp/stdout'
    arguments = "{} > {}".format(temp_python_path_in_host, guest_file_path)

    creds = vim.vm.guest.NamePasswordAuthentication(username=username, password=password)
    program_spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath=program_path, arguments=arguments)

    profile_manager = content.guestOperationsManager.processManager
    res = profile_manager.StartProgramInGuest(vm_obj, creds, program_spec)
    # output = profile_manager.ListProcessesInGuest(vm, creds, [res]).pop()
    if res <= 0:
        return None
    t = time.time()
    timeout = 15
    while (time.time() - t) < timeout:
        output = profile_manager.ListProcessesInGuest(vm, creds, [res]).pop()
        if output.endTime:
            break
    temp_stdout_file = file_manager.InitiateFileTransferFromGuest(vm_obj, creds, guest_file_path)
    file_url = temp_stdout_file.url
    data = requests.get(file_url, verify=False)
    return data.text


def execute_sh_vm(vm_obj, username, password, host_sh_file_path, temp_sh_path_in_host, new_username=None,
                  new_password=None):
    password = decrypt_password(password, PASSWORD_KEY)
    if new_password:
        new_password = decrypt_password(new_password, PASSWORD_KEY)
    else:
        new_password = password
    status = upload_file(vm_obj, username, password, host_sh_file_path, temp_sh_path_in_host, password_encrypt=False)
    if not status:
        raise AssertionError("SH File is not uploaded")
    content = vcenter.content
    time.sleep(3)
    file_manager = content.guestOperationsManager.fileManager

    program_path = '/usr/bin/bash'
    guest_file_path = '/tmp/stdout'
    arguments = "{} > {} 2>&1".format(temp_sh_path_in_host, guest_file_path)

    creds = vim.vm.guest.NamePasswordAuthentication(username=username, password=password)
    program_spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath=program_path, arguments=arguments)

    profile_manager = content.guestOperationsManager.processManager
    res = profile_manager.StartProgramInGuest(vm_obj, creds, program_spec)
    # output = profile_manager.ListProcessesInGuest(vm, creds, [res]).pop()
    if res <= 0:
        return None
    t = time.time()
    timeout = 300
    if new_username is None:
        new_username = username
    if new_password is None:
        new_password = password
    if new_username != username or new_password != password:
        print("Switching account: {}/{}".format(new_username, new_password))
    new_creds = vim.vm.guest.NamePasswordAuthentication(username=new_username, password=new_password)
    while (time.time() - t) < timeout:
        try:
            output = profile_manager.ListProcessesInGuest(vm_obj, new_creds, [res]).pop()
            if output.endTime:
                break
        except Exception:
            time.sleep(1)
    temp_stdout_file = file_manager.InitiateFileTransferFromGuest(vm_obj, new_creds, guest_file_path)
    file_url = temp_stdout_file.url
    data = requests.get(file_url, verify=False)
    return data.text


def copy_file_to_server(vm, file_name):
    t = time.time()
    upload_time_out = 300
    status = False
    while time.time() - t < upload_time_out:
        try:
            status = upload_file(vm, DDS.DDS_USERNAME, DDS.DDS_PASSWORD, file_name
                                 , '/root/{}'.format(file_name), is_binary=True)
            break
        except Exception:
            time.sleep(1)

    if not status:
        raise AssertionError("{} file is not uploaded".format(file_name))


# folder_name = "BETA"
# vm_full_name = 'Tenants-Internal/JPAC/Templates/TEST_CLONE_LARRY]/bdds_esx_9.4.0-639.QA.bcn_amd64'
# clone_vm(vm_full_name, folder_name)

if __name__ == "__main__":
    device = sys.argv[1].strip().lower()
    if device == "dds":
        source_vm_full_name = VCENTER_TEMPLATE + DDS_VERSION
        cloned_vm_full_name = VCENTER_CLONE_PATH + DDS_VERSION
        folder_name = os.path.dirname(cloned_vm_full_name)
        vm = get_vm_by_name(cloned_vm_full_name)
        if vm:
            try:
                stop_vm(vm)
            except Exception as e:
                print(str(e))
                pass
            destroy_vm(cloned_vm_full_name)
            vm = None
        if not vm:
            clone_vm(source_vm_full_name, folder_name)
            vm = get_vm_by_name(cloned_vm_full_name)

        # copy images to script
        copy_file_to_server(vm, EXAMPLE_INIT_SCRIPT_PATH)
        copy_file_to_server(vm, SYSLOG_IMAGE_NAME)
        copy_file_to_server(vm, DNS_STAT_IMAGE_NAME)

        host_bash_file_path = 'dds/init_install_dds.sh'
        temp_sh_path_in_host = '/root/init_install_dds.sh'
        output = execute_sh_vm(vm, DDS.DDS_USERNAME, DDS.DDS_PASSWORD, host_bash_file_path, temp_sh_path_in_host)
        print("Execute vm output: ", output)

        status = upload_file(vm, DDS.DDS_USERNAME, DDS.DDS_PASSWORD,
                             "configs/dds_data/alm_inject_files.ini", "/etc/vmse/init/alm_inject_files.ini",
                             is_binary=True)
        assert status, "alm_inject_files.ini is not uploaded"
        status = upload_file(vm, DDS.DDS_USERNAME, DDS.DDS_PASSWORD,
                             "configs/dds_data/config.ini", "/etc/vmse/init/config.ini",
                             is_binary=True)
        assert status, "config.ini is not uploaded"
        status = upload_file(vm, DDS.DDS_USERNAME, DDS.DDS_PASSWORD,
                             "configs/dds_data/builtin.ini", "/etc/vmse/init/builtin.ini",
                             is_binary=True)
        assert status, "builtin.ini is not uploaded"

        print("Start to run setup_generate_init.sh ...")
        host_bash_file_path = 'dds/setup_generate.sh'
        temp_sh_path_in_host = '/root/setup_generate.sh'
        output = execute_sh_vm(vm, DDS.DDS_USERNAME, DDS.DDS_PASSWORD, host_bash_file_path, temp_sh_path_in_host,
                               DDS.DDS_USERNAME_NEW, DDS.DDS_PASSWORD_NEW)
        print("Execute vm output: ", output)

        print("Start to run init_netconf_and_config.sh ...")
        host_bash_file_path = 'init_netconf_and_config.sh'
        temp_sh_path_in_host = '/root/init_netconf_and_config.sh'
        output = execute_sh_vm(vm, DDS.DDS_USERNAME_NEW, DDS.DDS_PASSWORD_NEW, host_bash_file_path, temp_sh_path_in_host)
        print("Execute vm output: ", output)
    elif device == "bam":
        source_vm_full_name = VCENTER_TEMPLATE + BAM_VERSION
        cloned_vm_full_name = VCENTER_CLONE_PATH + BAM_VERSION
        folder_name = os.path.dirname(cloned_vm_full_name)
        vm = get_vm_by_name(cloned_vm_full_name)
        if vm:
            try:
                stop_vm(vm)
            except Exception as e:
                print(str(e))
                pass
            destroy_vm(cloned_vm_full_name)
            vm = None
        if not vm:
            clone_vm(source_vm_full_name, folder_name)
            vm = get_vm_by_name(cloned_vm_full_name)

        # copy script to sever
        try:
            copy_file_to_server(vm, EXAMPLE_INIT_SCRIPT_PATH)
        except AssertionError as ex:
            raise ex

        print("Start to run init_install_bam.sh ...")
        host_bash_file_path = 'bam/init_install_bam.sh'
        temp_sh_path_in_host = '/root/init_install_bam.sh'
        output = execute_sh_vm(vm, BAM.BAM_USERNAME, BAM.BAM_PASSWORD, host_bash_file_path, temp_sh_path_in_host)
        print("Execute vm output: ", output)

        status = upload_file(vm, BAM.BAM_USERNAME, BAM.BAM_PASSWORD,
                             "configs/bam_data/config.ini", "/etc/vmse/init/config.ini", is_binary=True)
        assert status, "config.ini is not uploaded"

        status = upload_file(vm, BAM.BAM_USERNAME, BAM.BAM_PASSWORD,
                             "configs/bam_data/builtin.ini", "/etc/vmse/init/builtin.ini", is_binary=True)
        assert status, "builtin.ini is not uploaded"

        print("Start to run setup_generate.sh ...")
        host_bash_file_path = 'bam/setup_generate.sh'
        temp_sh_path_in_host = '/root/setup_generate.sh'
        output = execute_sh_vm(vm, BAM.BAM_USERNAME, BAM.BAM_PASSWORD, host_bash_file_path, temp_sh_path_in_host,
                                new_username=BAM.BAM_USERNAME_NEW, new_password=BAM.BAM_PASSWORD_NEW)
        # output = execute_sh_vm(vm, BAM.BAM_USERNAME, BAM.BAM_PASSWORD, host_bash_file_path, temp_sh_path_in_host)
        print("Execute vm output: ", output)

        print("Start to run init_netconf_and_config.sh ...")
        host_bash_file_path = 'init_netconf_and_config.sh'
        temp_sh_path_in_host = '/root/init_netconf_and_config.sh'
        output = execute_sh_vm(vm, BAM.BAM_USERNAME_NEW, BAM.BAM_PASSWORD_NEW, host_bash_file_path, temp_sh_path_in_host)
        # output = execute_sh_vm(vm, BAM.BAM_USERNAME, BAM.BAM_PASSWORD, host_bash_file_path, temp_sh_path_in_host)
        print("Execute vm output: ", output)
