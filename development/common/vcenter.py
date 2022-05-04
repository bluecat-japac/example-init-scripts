#!/usr/bin/python3
# Copyright 2021 BlueCat Networks (USA) Inc. and its affiliates

from pyVim.connect import SmartConnect, SmartConnectNoSSL, Disconnect
from pyVmomi import vim, vmodl
import logging
import os


def get_parent_path(path, level):
    current_path = path
    for i in range(level):
        current_path = os.path.dirname(current_path)
    return current_path


mirkwood_logger = logging.getLogger('mirkwood')

path = get_parent_path(os.path.abspath(__file__), 2)


class Vcenter:
    def __init__(self, attr_user={}, attr_clone={}):
        self.host = attr_user.get('host')
        self.user = attr_user.get('user')
        self.pwd = attr_user.get('pwd')
        self.port = attr_user.get('port')
        self.ssl = attr_user.get('ssl')
        self.template = None
        self.datacenter_name = attr_clone.get('datacenter_name')
        self.datacenter = None
        self.folder_name = attr_clone.get('folder_name')
        self.folder = None
        self.datastore_name = attr_clone.get('datastore_name')
        self.datastore = None
        self.resource_pool_name = attr_clone.get('resource_pool_name')
        self.resource_pool = None
        self.si = None
        self.content = None

    def get_conn(self, ssl=None):
        mirkwood_logger.info(f"Attempting to create a connection to vcenter {self.host}")
        if ssl:
            self.si = SmartConnect(
                host=self.host,
                user=self.user,
                pwd=self.password,
                port=self.port)
        else:
            self.si = SmartConnectNoSSL(
                host=self.host,
                user=self.user,
                pwd=self.pwd,
                port=self.port)
        mirkwood_logger.info("Connected to vcenter")
        self.content = self.si.RetrieveContent()

    def set_template(self, template_name):
        # self.template = self.get_obj([vim.VirtualMachine], template_name)
        self.template = self.get_obj_by_absolute_name([vim.VirtualMachine], template_name)
        if self.template is None:
            raise Exception('No template found')

    def get_template(self):
        return self.template

    def set_datacenter(self, datacenter_name=None):
        dtcenter_name = datacenter_name or self.datacenter_name
        self.datacenter = self.get_obj([vim.Datacenter],
                                       dtcenter_name)

    def get_datacenter(self):
        return self.datacenter

    def set_folder(self, folder_name=None):
        fd_name = folder_name or self.folder_name
        self.folder = self.get_obj_by_absolute_name([vim.Folder], fd_name)

    def get_folder(self):
        return self.folder

    def set_datastore(self, datastore_name=None):
        dtstore_name = datastore_name or self.datastore_name
        self.datastore = self.get_obj([vim.Datastore],
                                      dtstore_name)

    def get_datastore(self):
        return self.datastore

    def set_resource_pool(self, resource_pool_name=None):
        rp_name = resource_pool_name or self.resource_pool_name
        self.resource_pool = self.get_obj([vim.ResourcePool],
                                          rp_name)

    def get_resource_pool(self):
        return self.resource_pool

    # Method 

    def __repr__(self):
        return ''

    def disconnect(self):
        mirkwood_logger.info(f"Disconnecting Vcenter: {self.host}")
        Disconnect(self.si)
        mirkwood_logger.info(f"Disconnected Vcenter: {self.host}")

    def get_obj_by_absolute_name(self, vimtype, full_name):
        """
        Return an object by absolute name, if name is None the
        first found object is returned
        """
        if self.datacenter is None:
            self.set_datacenter()
        cel_container = self.get_datacenter()

        vm_folder = cel_container.vmFolder.childEntity
        full_name_path = full_name.split("/")

        for i, dir_path in enumerate(full_name_path):
            found_dir = False
            for obj in vm_folder:
                if i == len(full_name_path) - 1 and obj.name == dir_path and type(obj) in vimtype:
                    return obj
                elif isinstance(obj, vim.Folder) and obj.name == dir_path:
                    vm_folder = obj.childEntity
                    found_dir = True
                    break
            if not found_dir:
                return None
        return None

    def get_obj(self, vimtype, name):
        """
        Return an object by name, if name is None the
        first found object is returned
        """
        obj = None
        container = self.content.viewManager.CreateContainerView(self.content.rootFolder, vimtype, True)
        for c in container.view:
            if name:
                if c.name == name:
                    obj = c
                    break
            else:
                obj = c
                break
        return obj

    def wait_for_task(self, task):
        """ wait for a vCenter task to finish """
        task_done = False
        while not task_done:
            if task.info.state == 'success':
                return task.info.result

            if task.info.state == 'error':
                print("there was an error: ")
                raise AssertionError(str(task.info))
                task_done = True

    def clone_vm(self, vm_name):
        mirkwood_logger.info(f"Cloning VM : {vm_name}")
        relospec = vim.vm.RelocateSpec()
        relospec.datastore = self.datastore
        relospec.pool = self.resource_pool
        clonespec = vim.vm.CloneSpec()
        clonespec.location = relospec
        clonespec.powerOn = True
        task = self.template.Clone(self.folder, name=vm_name, spec=clonespec)
        self.wait_for_task(task)
        mirkwood_logger.info(f"Cloned")

    def destroy_vm(self, vm):
        vm_name = vm.config.name
        mirkwood_logger.info(f"Destroying VM : {vm_name}")
        task = vm.Destroy_Task()
        self.wait_for_task(task)
        mirkwood_logger.info(f"Destroyed")

    def stop_vm(self, vm):
        vm_name = vm.config.name
        mirkwood_logger.info(f"Stopping VM : {vm_name}")
        task = vm.PowerOffVM_Task()
        self.wait_for_task(task)
        mirkwood_logger.info(f"Stopped")

    def start_vm(self, vm):
        vm_name = vm.name
        mirkwood_logger.info(f"Starting VM : {vm_name}")
        task = vm.PowerOnVM_Task()
        self.wait_for_task(task)
        mirkwood_logger.info(f"Started")

    def reboot_vm(self, vm):
        task = vm.ResetVM_Task()
        self.wait_for_task(task)

    def get_vm_by_name(self, vm_name):
        mirkwood_logger.info(f"Getting VM : {vm_name}")
        # vm = self.get_obj([vim.VirtualMachine], vm_name)
        vm = self.get_obj_by_absolute_name([vim.VirtualMachine], vm_name)
        if vm is None:
            raise Exception('No VM found')
        return vm

    def set_vcenter_attribute_for_clone(self):
        self.set_datacenter()
        self.set_datastore()
        self.set_resource_pool()

    def get_vm_ip(self, vm):
        ip = vm.guest.ipAddress
        if ip is None:
            raise Exception("Failed to get ip")
        return ip

    def get_power_state(self, vm):
        mapping = {
            'poweredOn': 'on',
            'poweredOff': 'off',
            'suspended': 'suspended'
        }
        return mapping.get(vm.runtime.powerState)

    def get_profile_vm(self, vm):
        try:
            ip = self.get_vm_ip(vm)
        except Exception as e:
            if str(e) == 'Failed to get ip':
                ip = None
        template = self.template.name if self.template else None
        status = self.get_power_state(vm)
        vm_name = vm.config.name
        return {"vm_name": vm_name, "ip": ip, "template": template, "status":
            status}

    def change_network(self, vm, network_names=(), is_vds=True):
        # This code is for changing only one Interface. For multiple Interface
        # Iterate through a loop of network names.
        device_change = []
        network_names = list(network_names[::-1])
        for device in vm.config.hardware.device:
            if not network_names:
                break

            if isinstance(device, vim.vm.device.VirtualVmxnet3):
                nicspec = vim.vm.device.VirtualDeviceSpec()
                nicspec.operation = \
                    vim.vm.device.VirtualDeviceSpec.Operation.edit
                nicspec.device = device
                nicspec.device.wakeOnLanEnabled = True
                network_name = network_names.pop()
                if not is_vds:
                    nicspec.device.backing = \
                        vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
                    nicspec.device.backing.network = self.get_obj([vim.Network], network_name)
                    nicspec.device.backing.deviceName = network_name
                else:
                    network = self.get_obj([vim.dvs.DistributedVirtualPortgroup], network_name)
                    dvs_port_connection = vim.dvs.PortConnection()
                    dvs_port_connection.portgroupKey = network.key
                    dvs_port_connection.switchUuid = \
                        network.config.distributedVirtualSwitch.uuid
                    nicspec.device.backing = \
                        vim.vm.device.VirtualEthernetCard. \
                            DistributedVirtualPortBackingInfo()
                    nicspec.device.backing.port = dvs_port_connection

                nicspec.device.connectable = \
                    vim.vm.device.VirtualDevice.ConnectInfo()
                nicspec.device.connectable.startConnected = True
                nicspec.device.connectable.allowGuestControl = True

                device_change.append(nicspec)

        config_spec = vim.vm.ConfigSpec(deviceChange=device_change)
        task = vm.ReconfigVM_Task(config_spec)
        self.wait_for_task(task)
        print("Successfully changed network")