#
# Copyright (c) 2014-2016 Nutanix Inc. All rights reserved.
#
# Author: akshay@nutanix.com, amoghe@nutanix.com
#
# This module provides a DiskManager class that exposes RPC methods to
# manipulate disks on the node.
#
# NOTE
# ----
# A lot of code here is taken from existing implementations such as:=
# $TOP/serviceablility/bin/disk_replace
# $TOP/infrastructure/cluster/py/cluster/client/disk_utils.py
# $TOP/infrastructure/cluster/bin/disk_mount
# $TOP/infrastructure/cluster/bin/repartition_disks
#
# Eventually those should become RPC clients to the hades daemon. Similarly
# all other uses of the disk_utils lib should invoke RPCs on hades.
#
# pylint: disable=import-error,no-name-in-module,no-member

# This should be the first import.
from six import PY3

import collections
import concurrent.futures
import errno
import gflags
import glob
import grp
import json
import os
import pwd
import random
import re
import stat
if PY3:
  import _thread as thread
else:
  import thread
import threading
import time
import traceback

from six.moves import range, urllib

import cluster.client.consts as consts
import cluster.client.disk_consts as disk_consts
import cluster.client.genesis_utils as genesis_utils
import cluster.client.hades.flags
import cluster.client.hades.hades_utils as hades_utils
import cluster.client.hades.sed_utils as sed_utils
import cluster.client.host_upgrade_helper as host_upgrade_helper
import cluster.client.service.service_utils as utils
import cluster.disk_flags
import cluster.hades.block_store_utils as block_store_utils
import cluster.hades.disk_error_parser.consts
import cluster.hades.raid_utils as raid_utils
import sed.self_encrypting_drive as sed_commands
import util.cluster.consts
import util.cluster.info
import util.disklib.nvme_disk
import util.ndb.security.security_utils as security_utils

from alerts.notifications.notify import (
  ALERT_NOTIFY, ALERT_RESOLVE_NOTIFY, NonSelfEncryptingDriveInserted,
  PathOffline, PhysicalDiskAdd, PhysicalDiskBad, PhysicalDiskRemove,
  UnqualifiedDisk)
# pylint: disable=import-error,no-name-in-module
from cluster.client.hades.hades_config_pb2 import HadesProto, ProtoUpdate
# pylint: enable=import-error,no-name-in-module
from cluster.client.hades.disk_skew_util import DiskSkewManager
from cluster.client.hades.utils.pmem_device_util import PmemDeviceUtil
from cluster.hades import motherboard_helper
from cluster.hades.amazon_cloud_disk_util import AmazonCloudDiskUtil
from cluster.hades.cloud_helper_util import CloudHelperUtil, CloudValidator
from cluster.hades.disk_diagnostics import DiskDiagnostics, DiskHealthMonitor
from cluster.hades.disk_error_parser.disk_error_parser_client import\
  get_disk_errors_hades_proto
from cluster.hades.disk_error_parser.disk_error_parser import DiskErrorParser
from cluster.hades.disk_led_control import set_led_state
from cluster.hades.disk_size_util import DiskSizeUtil
from cluster.hades.disk_slot_helper import (recalibrate_nvme_slots,
                                            check_disks_in_config,
                                            fill_slot_info_to_config,
                                            sanitize_hades_proto_for_location,
                                            sync_slots_from_old_config)
from cluster.hades.spdk_util import SPDKUtil
from cluster.hades.utils.alert_util import AlertUtil
from cluster.hades.utils.async_rpc_util import AsyncRpcUtil
from cluster.hades.utils.container_util import ContainerUtil
from cluster.hades.utils.prepare_device_util import PrepareDeviceUtil
from cluster.hades.utils.storage_tier_util import StorageTierUtil
from cluster.hades.utils.trim_util import TrimUtil
from cluster.hades.utils.zeus_util import ZeusUtil
from util.base import log
from util.base import hcl
from util.base.command import timed_command
from util.base.command_executor import CommandExecutor
from util.base.pmem_device import PmemDevice
from util.base.types import NutanixUuid
from util.disklib.disk import Disk, Partition, get_size as get_disk_size
from util.platform.capabilities_util import is_feature_enabled
# pylint: disable=import-error,no-name-in-module
from util.platform.capabilities_pb2 import PlatformSolutionCapabilities
# pylint: enable=import-error,no-name-in-module
from util.platform.raid_lib import is_raid_available_in_hw_cfg

try:
  from util.disklib.disk_location import fill_disk_location_map
except ImportError:
  fill_disk_location_map = lambda *args, **kwargs: None
  disk_info_from_disk_location = False
else:
  disk_info_from_disk_location = True

from util.disklib.nvme_disk import NvmeDisk
from util.hardware.layout import HardwareLayout
from util.hypervisor.hyperv import HypervHost
from util.hypervisor.hypervisor import Hypervisor
from util.hypervisor.null import NullHost
from util.misc.decorators import fatal_on_exception
from util.misc.parallel_executor import ParallelExecutor
from util.misc.protobuf import safe_has_field
from util.disklib.disk_location import get_slot_count
from util.ndb.net.remote_shell import BasicRemoteShell
from util.net.rpc import RpcError, rpchandler
from util.net.hypervisor.kvm_ssh_client import KvmSSHClient
from zeus.cloud_store_info_pb2 import CloudStoreType
from zeus.component_id import allocate_component_ids
from zeus.configuration import Configuration
from zeus.configuration_pb2 import ConfigurationProto
from zeus.zookeeper_session import ZookeeperSession

gflags.DEFINE_string("stargate_directory",
                     "/home/nutanix/data/stargate-storage",
                     "Directory where stargate disks should be mounted.")
gflags.DEFINE_string("aws_cores_partition",
                     "/dev/xvdb1",
                     "Partition in which core files are stored on AWS.")
gflags.DEFINE_string("device_mapper_name",
                     "dm0",
                     "A name of the device mapper that is to be created in "
                     "case striped devices are discovered.")
gflags.DEFINE_string("sg_write_buffer_path",
                     "/usr/local/nutanix/cluster/lib/sg3utils/"
                         "bin/sg_write_buffer",
                     "Location of sg_write_buffer. The version of the current "
                     "binary used is 1.18 20141107.")
gflags.DEFINE_integer("sata_disk_firmware_upgrade_retry_count", 12,
                      "Default retry count for firmware upgrade.")
gflags.DEFINE_integer("firmware_upgrade_default_wait", 10,
                      "Default wait time after issuing firmware upgrade.")
gflags.DEFINE_integer("unmount_default_wait_sec", 5,
                      "Default wait time for unmount during disk remove.")
gflags.DEFINE_integer("unmount_timeout", 120,
                      "Default wait time for unmounting to succeed.")
gflags.DEFINE_boolean("skip_disk_remove_reboot", False,
                      "Skip reboot for bad or removed disk.")
gflags.DEFINE_string("skip_disk_remove_reboot_marker",
                     "/home/nutanix/.skip_disk_remove_reboot_marker",
                     "Skip reboot marker for bad or removed disk.")
gflags.DEFINE_integer("sas_disk_firmware_upgrade_retry_count", 60,
                      "Numter of times to retry SAS disk firmware upgrade.")
gflags.DEFINE_integer("disk_unmount_retry_count", 60,
                      "Number of times to retry unmounting the disk.")
gflags.DEFINE_string("sas3flash_location",
                     "/home/nutanix/cluster/lib/lsi-sas/sas3flash",
                     "Location of sas3flash utility.")
gflags.DEFINE_string("sas3flash_target_runtime", 300,
                     "Approximate time taken by sas3flash for upgrading HBA")
gflags.DEFINE_bool("run_wipefs", True,
                   "Clear all filesystem signatures from disk before creating "
                   "filesystem")
gflags.DEFINE_bool("populate_motherboard_info", True,
                   "Hades populates motherboard information in config proto. "
                   "This is cloud substrate dependent, this flag can be used "
                   "to skip populating motherboard information and continuing "
                   "Hades configuration correctly.")
gflags.DEFINE_integer("clean_disks_pe_pool_size", 12,
                      "How many disks to clean in parallel.")
gflags.DEFINE_integer("experimental_delay_disk_add_udev_event_max_secs", 0,
                      "Maximum time in seconds to delay Hades handling of "
                      "disk add udev events.")
gflags.DEFINE_integer("experimental_delay_disk_remove_udev_event_max_secs", 0,
                      "Maximum time in seconds to delay Hades handling of "
                      "disk remove udev events.")
gflags.DEFINE_integer("experimental_wait_for_ro_mount_intent_file_secs", 0,
                      "If set, wait for ro-mount intent file to show up "
                      "within the specified time, before trying to fix the "
                      "drive's mount state.")
gflags.DEFINE_bool("sanitize_duplicate_location", True,
                   "When same location is used with multiple logical slot, "
                   "UI may misbehave. Remove duplicate from Hades logically.")
gflags.DEFINE_bool("slot_to_disk_location", True,
                   "Use slot_to_disk_location from Disk class.")
gflags.DEFINE_bool("skip_commit_partial_disk_list", False,
                   "Skip committing partial disks discovered to Hades Proto.")
gflags.DEFINE_integer("num_software_access_mode_update_tries", 5,
                      "The number of times to try updating the software "
                      "access mode for a given disk.")
gflags.DEFINE_bool("abort_on_disk_slot_overlap", True,
                   "Abort hades operation when multiple disks are seen with the"
                   " same slot.")

DEVICE_PHYSICAL_RE    = re.compile(r"^(\d+\s+\d+\s+\d+)\s+Disk.+(\d+)$")
DISK_DEVICE_RE        = re.compile(r"^(\d+\s+\d+\s+\d+)\s+Disk\s+(\S+)\s+\S+")

FLAGS = gflags.FLAGS
FLAGS.log_thread_name = True

# Linux kernel will always use the constant ratio of 512-byte per sector
# even if the disks logical block size is larger than 512. Since our
# util/base/disk module relies heavily on sysfs for getting disk information
# we will use the same ratio. However, everything should be converted to
# bytes when we create partitions using parted.
READ_PART_TABLE_RETRIES  = 10

# Creating a new partition with parted utility can throw an error if the
# partition was in use. Running partprobe should resolve the error and the
# new partition will become visible to the Kernel. Following is the regular
# expression to detect if the new partition sync to the Kernel failed.
PART_TABLE_READ_ERROR_RE = re.compile(
  r"kernel failed to re-read the partition table|"
  "unable to inform the kernel",
  re.IGNORECASE)

DEFAULT_TIER = "DAS-SATA"
GIGA = (1000 * 1000 * 1000)

ERR_GENERIC_ERROR = 3
ERR_NO_DISKS = 5
ERR_INCONSISTENT_METADISK = 6
ERR_NO_METADATA_DISK = 7
ERR_DISKCONFIG_UPDATE_FAILED = 9

STARGATE_DISK_CONFIG = "disk_config.json"

STARGATE_DISK_DEFAULT_DATA_DIR_SUBLEVELS = 2
STARGATE_DISK_DEFAULT_DATA_DIR_SUBLEVEL_DIRS = 20

BYTE_TO_GIGA = (1024 * 1024 * 1024)


def is_old_hardware():
  """
  Returns True if hardware is old.
  """
  if os.path.exists(FLAGS.nested_esx_marker_path):
    return False

  ret, out, err = timed_command("lspci -n")
  if ret != 0:
    log.ERROR("Failed to get hardware type with ret %s out %s err %s" %
              (ret, out, err))
    return False

  out = out.decode("utf-8")
  err = err.decode("utf-8")

  if not out:
    log.WARNING("Unable to determine hardware type, assuming new hardware")
    return False

  old_scsi_controllers = ["1000:0030", "1000:0054", "15ad:07c0"]

  for old_controller in old_scsi_controllers:
    if old_controller in out:
      log.INFO("Old hardware detected")
      return True

  return False

class DiskManager(object):

  def __init__(self, node_manager_proxy, udev_handler, is_hyperv,
               cluster_manager_proxy):
    self.__model = None

    self.__slot_count = None

    self.__disk_location_map = None

    self.__node_manager = node_manager_proxy

    self.__cluster_manager = cluster_manager_proxy

    self.__host_port_list = None

    self.__initialized = False

    self.__udev_handler = udev_handler

    self.__is_hyperv = is_hyperv

    self.__stargate_disk_directory = None

    # This lock is intended to be used when mounting, unmounting disk or
    # working on mouted disks. (Currently acquired in unmount, mount and
    # add_disks_to_cluster functions.)
    self.__disk_mount_lock = threading.Lock()

    # This lock will be used to syncronize between disk add/remove thread
    # and disk_repartition thread.
    self.__disk_breakfix_lock = threading.Lock()

    # Thread to periodically check smartctl health status of all the disks
    # in the cluster.
    self.__disk_health_monitor = None

    # Thread to periodically check Hades logs for disk errors.
    self.__disk_error_parser = None

    # Boolean to track if SEDs are present on the node.
    self.__sed_devices_present = None

    # Object to prepare block devices.
    self.prep_device_util = PrepareDeviceUtil()

  def initialize(self):
    """
    Set up internal state for this object to perform disk related actions.
    Must be called at least once before other methods are invoked.

    Returns:
      self: on successful initialization of internal state
      None: otherwise.
    """
    self.__model = util.cluster.info.get_factory_config().get(
        "rackable_unit_model", None)

    # Configure PMEM device mode if it is not done already.
    # The PMEM device can be in any one of the following modes: raw, sector,
    # fsdax, or devdax. In the CVM, by default it will be in 'raw' mode. We
    # might need to change the mode based on use case (For example, Content
    # Cache on PMEM feature need PMEM device in FSDAX mode). We attempt to set
    # the mode here. We could have delayed this operation to a later stage at
    # Hades configure(). But then until Hades configure() gets executed, the
    # PMEM device will not have serial_number since the serial_number is
    # generated using PMEM UUID, which will not be there in 'raw' mode devices.
    if (FLAGS.configure_pmem_devices and
        not PmemDevice.maybe_configure_pmem_device_mode()):
      log.ERROR("Failed to configure PMEM device mode")
      return None

    # Check if SED managed devices are present on the node.
    self.__sed_devices_present = sed_utils.sed_drive_present()

    # Set minimum raid sync speed.
    if not raid_utils.set_minimum_raid_sync_speed():
      log.ERROR("Failed to set minimum raid sync speed")

    # Rebuild RAID on hades or CVM restart, if required.
    if not raid_utils.maybe_rebuild_raid():
      log.ERROR("Failure to rebuild RAID")
      return None

    log.INFO("RAID rebuild done")

    if self.__sed_devices_present:
      locked_disks = sed_utils.maybe_unlock_disks()
      if len(locked_disks) > 0:
        log.ERROR("Following disks are still locked: %s" % locked_disks)
        return None

    if not self.mount_all_disks():
      log.ERROR("Failure to mount disks. Bailing out")
      return None

    log.INFO("Finished mounting devices")

    if not self.prep_device_util.set_ssd_ra():
      log.ERROR("Failed to set default readahead for SSDs")

    reload_udev = False
    success_mseckb, reload_udev = \
      self.prep_device_util.set_default_block_params()
    if not success_mseckb:
      log.ERROR("Failed to set default block parameters for SSDs")

    if not self.prep_device_util.set_ssd_specific_block_params(reload_udev):
      log.ERROR("Failed to set specific block parameters for SSDs")

    ret = self.__node_manager.configured()
    if not isinstance(ret, RpcError):
      if ret:
        zk_map = self.__node_manager.zookeeper_mapping()
        if zk_map and not isinstance(zk_map, RpcError):
          # Connect to Zookeeper.
          host_port_list = ["zk%d:9876" % zk for zk in zk_map.values()]
          self.__host_port_list = ",".join(host_port_list)
          zk_session = genesis_utils.get_zk_session(
              host_port_list=self.__host_port_list)
          if not self.configure(zk_map, zk_session=zk_session):
            log.WARNING("Failed to setup hades config")
          # Clear any background operations.
          if not self.__clear_background_operations(zk_session=zk_session):
            log.WARNING("Failed to clear background operations")
          if not self.__start_nvme_breakfix_monitor_thread(
              zk_session=zk_session):
            log.WARNING("Failed to start nvme breakfix monitor thread")
        else:
          log.WARNING("Failed to get zookeeper mapping")
      else:
        log.WARNING("Cluster is not configured. Skipping Hades configure")
    else:
      log.WARNING("Failed to reach genesis. Skipping Hades configure")

    self.__initialized = True
    return self

  @staticmethod
  def is_hades_managed():
    """
    Returns True if hades is managing disks, else returns False.
    """

    if os.path.exists(FLAGS.disable_hades_marker_path):
      log.INFO("Hades disabled since disable Hades marker exists at :%s" %
               FLAGS.disable_hades_marker_path)
      return False

    # Hades is not supported on old hardware types.
    if is_old_hardware():
      log.INFO("Hades not supported on old hardware")
      return False
    return True

  @rpchandler
  def is_initialized(self):
    """
    Returns the value of the local variable __initialized.
    No locks are required here since this is supposed to perform the role
    of a dummy RPC to allow blocking start of Hades. The RPC server is always
    started after disk_manager.initialize so race conditions will be avoided.
    """
    return self.__initialized

  @rpchandler
  def mount_all_disks(self):
    """
    Returns True on success, False otherwise.
    This RPC replicates the entire workflow of mount_disks script. It rescans
    the SCSI bus, Intel PCIE SSDs, prepares block devices
    and mounts disks that were discovered.
    """
    self.__rescan_scsi_bus()
    disks = Disk.disks()

    log.INFO("Disabling write cache on broken HBAs")
    self.__maybe_disable_lsi_write_cache()

    # Prepare block devices.
    log.INFO("Preparing block devices")
    ret, faulty_disks = self.prep_device_util.prepare_block_devices(disks)
    if not ret:
      log.ERROR("Failed to setup all the block devices. Check the faulty ones."
                " Proceeding ahead with good ones")

    self.__nutanix_uid  = pwd.getpwnam("nutanix").pw_uid
    self.__nutanix_gid  = grp.getgrnam("nutanix").gr_gid

    # Ensure that the dir that will house the mount paths exists.
    self.__stargate_disk_directory = os.path.join(FLAGS.stargate_directory,
                                                  "disks")
    if not os.path.exists(self.__stargate_disk_directory):
      try:
        os.makedirs(self.__stargate_disk_directory)
      except OSError as ex:
        log.ERROR("Failed to make stargate disk directory %s, error %s" %
                  (self.__stargate_disk_directory, str(ex)))
        return False

    # Ensure correct ownership of the relevant directories.
    os.chown(FLAGS.stargate_directory,
             self.__nutanix_uid,
             self.__nutanix_gid)
    os.chown(self.__stargate_disk_directory,
             self.__nutanix_uid,
             self.__nutanix_gid)

    # Setup PMEM mount paths directory.
    if (FLAGS.configure_pmem_devices and
        not PmemDeviceUtil.setup_mount_directory(self.__nutanix_uid,
                                                 self.__nutanix_gid)):
      log.ERROR("Failed to setup PMEM device mount directory")
      return False

    # Refresh disk set if device mapper was created.
    disks = []

    # Remove any stale entries from disk_location.json.
    # Required only for virtual disks.
    self.clean_stale_virtual_disk_entries()
    for disk in Disk.disks():
      if not hades_utils.is_qualified_disk(disk):
        # Even though the disk is not qualified, we'll not fail to mount them
        # here. Not mounting disks that had previously been part of the cluster
        # will break Upgrades.
        # TODO: Once enough data on the number of such unqualified SSDs is
        # collected, we should revisit how we can prevent unqualified disks
        # coming up at all, while keeping it Upgrades proof.
        log.WARNING("Disk %s is not qualified by nutanix, but Hades will "
                    "continue to mount it for now" % disk)
      partition = self.get_data_partition(disk)
      if not partition:
        log.INFO("Disk %s does not have any data partition. Skipping mount" %
                 disk)
        continue
      part_obj = Partition(partition).initialize()
      if not part_obj:
        log.ERROR("Failed to create partition object for disk %s, Skipping "
                  "mount" % disk)
        continue

      disk_obj = Disk(disk)
      if self.__model == "null":
        log.INFO("Adding slot entry for disk %s in disk location json for"
                 " null cluster" % disk)
        if not self.add_disk_slot_in_disk_location(disk_obj.serial_number()):
          log.ERROR("Failed to add slot for disk %s" % disk)

      # Set default scheduler for disk.
      if not self.__set_disks_default_scheduler(disk):
        log.ERROR("Unable to set scheduler for %s" % disk)

      if part_obj.mounted():
        log.INFO("Disk %s is already mounted, skipping initialization" % disk)
        continue
      disks.append(disk)

    if len(disks) == 0:
      log.INFO("No action required on any of the disk")
      return True

    log.INFO("Mounting disks: %s" % set(disks))
    for disk in disks:
      if disk in faulty_disks:
        log.ERROR("Skipping mounting paritions on %s due to earlier errors" %
                  disk)
        continue

      log.INFO("Mounting disk: %s" % disk)
      # Do not return None if failed to mount a disk.
      if not self.mount_disk(disk):
        log.ERROR("Failed to mount disk %s" % disk)

    # Ignore disk mount errors.
    return True

  @rpchandler
  def configure(self, zk_mapping, zk_session=None):
    """
    This RPC lets callers indicate to this process that it is now in a
    configured cluster.

    Args:
      zk_mapping(dict): Dict of zk_mapping, where zk's svm IP address is key,
        and zk's ID is value.
      zk_session(ZookeeperSession): ZookeeperSession obj.

    Returns:
      bool: True if successfully configured, else False.
    """
    log.INFO("Configuring Hades")
    if not zk_mapping:
      log.WARNING("Zookeeper mapping set to null")
      self.__host_port_list = None
      return False

    host_port_list = ["zk%d:9876" % zk for zk in zk_mapping.values()]
    self.__host_port_list = ",".join(host_port_list)
    retries = 0
    zk_session = zk_session or None
    while retries < FLAGS.hades_retry_count:
      zk_session = genesis_utils.get_zk_session(
          host_port_list=self.__host_port_list)
      if not zk_session:
        log.ERROR("Unable to obtain a zookeeper session. Retrying")
        retries += 1
        continue

      if not self.__is_cluster_configured(zk_session=zk_session):
        log.ERROR("Cluster is not yet configured. Retrying")
        time.sleep(2)
        retries = retries + 1
        continue
      break
    else:
      log.ERROR("Failed to configure hades. Cluster not configured")
      return False

    log.INFO("Cluster is configured")

    # Reset HardwareLayout to get a new instance, as Genesis might have
    # updated it.
    HardwareLayout.reset_instance()

    # If this is an AWS cluster, let's attempt to repartition the devices.
    if FLAGS.enable_hades_auto_repartition_disk:
      log.INFO("Attempting to auto-repartition any unpartitioned disks")
      success = True

      for disk in self.usable_disks():
        if not PrepareDeviceUtil.can_prepare_device(disk,
                                                    zk_session=zk_session):
          log.ERROR("Unable to auto-repartition device: %s" % disk)
        else:
          log.INFO("Auto-repartioning device %s as a data disk" % disk)
          if not PrepareDeviceUtil.prepare_device(disk, self):
            log.ERROR("Unable to prepare device %s" % disk)
            success = False
          else:
            log.INFO("Device %s auto-repartitioned successfully" % disk)

      if not success and FLAGS.fail_hades_config_on_repartition_failure:
        log.ERROR("Failed to auto-repartition all the devices")
        return False
    else:
      log.INFO("Automatic repartition of cloud devices disabled")

    # Let's attempt to partition PMEM devices.
    if FLAGS.configure_pmem_devices:
      success = True
      pmem_devices = PmemDevice.devices()
      for device in pmem_devices:
        if not PrepareDeviceUtil.can_prepare_device(device):
          log.INFO("Cannot prepare PMEM device %s" % device)
        else:
          log.INFO("Preparing PMEM device %s" % device)
          if not PrepareDeviceUtil.prepare_device(device, self):
            log.ERROR("Unable to prepare PMEM device %s" % device)
            success = False
          else:
            log.INFO("Successfully prepared PMEM device %s" % device)

      if not success and FLAGS.fail_hades_config_on_pmem_partition_failure:
        log.ERROR("Failed to partition all the PMEM devices")
        return False

    # If the cluster was not configured then hades_proto was never setup.
    if not self.__setup_hades_proto(zk_session=zk_session):
      return False

    log.INFO("Setup Hades proto done")

    # If the cluster is configured and Hades proto is setup, start the
    # DiskHealthMonitor and DiskErrorParser threads. If the thread is
    # already alive, do not start it again.
    if FLAGS.enable_disk_health_monitor:
      if (self.__disk_health_monitor is not None and
          self.__disk_health_monitor.is_alive()):
        log.INFO("DiskHealthMonitor already started")
      else:
        log.INFO("Starting DiskHealthMonitor")
        self.__disk_health_monitor = DiskHealthMonitor()
        self.__disk_health_monitor.initialize(self, self.__host_port_list)
        self.__disk_health_monitor.start()

    if FLAGS.enable_disk_error_parser:
      if (self.__disk_error_parser is not None and
          self.__disk_error_parser.is_alive()):
        log.INFO("DiskErrorParser already started")
      else:
        log.INFO("Starting DiskErrorParser")
        self.__disk_error_parser = DiskErrorParser()
        self.__disk_error_parser.initialize(self.__host_port_list)
        self.__disk_error_parser.start()

    if self.__sed_devices_present:
      self.__maybe_configure_and_set_sed_password(zk_session)

    # Synchronize disks information.
    if not self.__update_hades_disks_state(zk_session=zk_session):
      log.ERROR("Failed to sync disks information between hades and zeus")
      return False

    log.INFO("Updated Hades' disk state")

    # Clear tombstone disks.
    if not self.__clear_tombstone_disks(zk_session=zk_session):
      log.ERROR("Failed to clear tombstone disks")
      return False

    # Remove stale PMEM devices.
    if (FLAGS.configure_pmem_devices and
        not PmemDeviceUtil.remove_stale_pmem_devices_from_zeus(zk_session,
                                                               pmem_devices)):
      log.ERROR("Failed to remove stale PMEM devices")
      if FLAGS.fail_hades_config_on_stale_pmem_removal_error:
        return False

    # Detect and populate motherboard information in hades config.
    if self.__model != "null":
      if not motherboard_helper.populate_motherboard_info(zk_session):
        log.ERROR("Failed to populate motherboard info in hades config")
        return False

    log.INFO("Done with populating motherboard info in Hades proto")
    return True

  def __start_nvme_breakfix_monitor_thread(self, zk_session=None):
    """
    Start NVMe breakfix monitor thread, in case any NVMe drive have been
    removed.
    """
    if not zk_session:
      zk_session = genesis_utils.get_zk_session(
          host_port_list=self.__host_port_list)
      if not zk_session:
        log.ERROR("Unable to obtain a zk session")
        return False

    nvme_breakfix_path = os.path.join(FLAGS.hades_znode_dir, "nvme_breakfix")
    zk_json = genesis_utils.get_zk_json_info(zk_session, nvme_breakfix_path)
    if zk_json:
      for disk_name, vals in zk_json.items():
        log.INFO("Start new thread to monitor breakfix for disk %s, val %s" % (
                 disk_name, vals))
        thread.start_new_thread(self.monitor_nvme_disk_removal,
                                (disk_name,))
    return True

  @rpchandler
  def unconfigure(self):
    """
    Removes the hades config zk node.
    Returns True on success, else returns False.
    """
    log.INFO("Unconfiguring Hades")
    zk_session = ZookeeperSession(host_port_list=self.__host_port_list)
    if not zk_session.wait_for_connection(None):
      log.ERROR("Failed to set up hades proto. Unable to obtain a zk session")
      return False

    cvm_id = hades_utils.get_node_cvm_id(zk_session)
    if not cvm_id:
      log.ERROR("Failed to get node id from configuration proto")
      return False

    hades_config_znode = "%s/%d" % (FLAGS.hades_config_znode_dir, cvm_id)

    if not zk_session.delete(hades_config_znode):
      log.ERROR("Failed to delete hades config from path %s with error %s" %
                (hades_config_znode, zk_session.error()))
      return False
    return True

  @rpchandler
  def is_active_raid_disk(self, disk):
    """
    Returns True if a device /dev/sdX is being used in a RAID partition, else
    returns False.
    Assumption: Only boot partitions can be RAIDed.
    """
    return raid_utils.is_active_raid_disk(disk)

  @rpchandler
  def list_raid_array_with_disk(self, disk):
    """
    Returns a list of raid arrays to which the given device is part of.
    Assumption: Only boot partitions can be RAIDed.

    Args:
      disk (string) : Name of the disk e.g. '/dev/sda/'.

    Returns:
      list: If the operation is successful, then it returns a list of RAID
        arrays to which the given device is part of. Empty list otherwise.
    """
    return raid_utils.list_raid_array_with_disk(disk)

  @rpchandler
  def get_raid_partitions(self):
    """
    Returns a list of RAID paritions if RAID is being used for the boot disks.
    Returns an empty list if RAID partitions are not found.
    """
    return raid_utils.get_raid_partitions()

  @rpchandler
  def get_mounted_raid_partitions(self):
    """
    Returns a list of mounted RAID partitions.
    """
    return raid_utils.get_mounted_raid_partitions()

  @rpchandler
  def raid_sync_in_progress(self):
    """
    Returns dictionary of True/False value for all the mounted RAID partitions.
    If RAID sync is in progress it returns True else returns False.
    """
    return raid_utils.raid_sync_in_progress()

  @rpchandler
  def raid_degraded_status(self):
    """
    Returns dictionary of True/False value for all the mounted RAID partitions.
    If RAID is degraded it returns True else returns False.
    """
    return raid_utils.raid_degraded_status()

  @rpchandler
  def is_raid_degraded(self):
    """
    Returns True if RAID is degraded else returns False.
    """
    return raid_utils.is_raid_degraded()

  @rpchandler
  def raid_sync(self):
    """
    Syncs data on partitions included in the RAID partitions.
    """
    return raid_utils.raid_sync()

  @rpchandler
  def raid_sync_status(self):
    """
    Gets the sync or rebuild action.
    Returns a map of mounted partition name to sync complete status.
    #TODO:  Check raid_sync_in_progress for robust logic.
    """
    return raid_utils.raid_sync_status()

  @rpchandler
  def is_raid_synced(self):
    """
    Returns True if no error is encountered and RAID is synced else returns
    False.
    """
    return raid_utils.is_raid_synced()

  @rpchandler
  def raid_rebuild(self, disk):
    """
    Given a disk if the disk is a boot disk this function rebuilds the RAID
    with the disk.

    Returns True on success, else returns False.
    """
    return raid_utils.raid_rebuild(disk)

  @rpchandler
  def raid_fail(self, disk):
    """
    Given a disk if the disk is a boot disk this function fails the RAID
    with the partition.

    Returns True on success, else returns False.
    """
    return raid_utils.raid_fail(disk)

  @rpchandler
  def raid_remove(self, failed=False):
    """
    Removes all failed and detached partitions from the RAID partitions
    Returns True on success, else returns False.
    """
    return raid_utils.raid_remove(failed)

  @rpchandler
  def usable_disks(self):
    """
    List usable disks.

    Returns
      list: usable disks on the local node.
      None: on failure.
    """
    return Disk.disks()

  def __get_model_from_proto(self, disk):
    """
    Get the Disk model stored in the hades proto.
    Input: disk name whole model needs to be retrieved.
    Returns: Model string if found or None
    """

    proto, _ = hades_utils.get_hades_proto()
    if not proto:
      log.ERROR("Hades proto not found")
      return None
    slot = self.__get_slot_for_disk(proto, disk)
    if not slot:
      log.ERROR("Unable to find slot for disk %s" % disk)
      return None

    if slot.disk.HasField("model"):
      return slot.disk.model
    else:
      log.ERROR("Model field not present for disk %s" % disk)
      return None

  @rpchandler
  def is_stargate_usable(self, disk):
    """
    Determines if the data partition of a disk is empty or not.

    Args:
      disk (string): Name of disk.

    Returns:
      bool: True if data partition is usable by stargate, False otherwise.
    """
    partition = self.get_data_partition(disk)

    if not partition:
      return False

    part_obj = Partition(partition).initialize()
    if not part_obj:
      log.ERROR("Failed to initialize partition object")
      return False

    if not part_obj.is_empty():
      log.DEBUG("Partition %s is not empty" % partition)
      return False

    return True

  def unmount_disk_path_retry(self, mount_path, option=None):
    """
    Tries umount disk for predefined time.
    """
    deadline = int(time.time()) + FLAGS.unmount_timeout
    while int(time.time()) < deadline:
      log.INFO("Trying to unmount %s" % mount_path)
      if self.unmount_disk_path(mount_path, option):
        log.INFO("Successfully unmounted %s" % mount_path)
        return True
      else:
        log.INFO("Failed to unmount %s, retrying in 30 secs" % mount_path)
        time.sleep(30)
    return False

  @rpchandler
  def unmount_disk_path(self, mount_path, option=None):
    """
    Unmount the stargate partition on specific disk.
    Args:
      mount_path(string)   : Mount path to unmount (e.g.
                             /home/nutanix/data/storage/disks/serial_number)
      option (string): Option is a parameter passed to unmount command.

    Returns:
      bool: True on success, False otherwise.
    """
    log.INFO("Waiting for disk mount lock for unmount disk path %s" %
              mount_path)
    with self.__disk_mount_lock:
      log.DEBUG("Got disk mount lock for unmount disk path %s" % mount_path)
      if not os.path.exists(mount_path):
        log.WARNING("Path %s for unmount does not exist" % mount_path)
        return True

      if not os.path.ismount(mount_path):
        log.WARNING("Path %s is not a mount path" % mount_path)
        return True

      log.INFO("Unmounting path %s" % mount_path)
      if option:
        cmd = "sudo umount -%s %s" % (option, mount_path)
      else:
        cmd = "sudo umount %s" % mount_path

      ret, stdout, stderr = timed_command(cmd)
      stdout = stdout.decode('utf-8')
      stderr = stderr.decode('utf-8')
      if ret != 0:
        log.ERROR(("Unable to unmount path %s, ret %s, stdout %s, stderr %s" %
                   (mount_path, ret, stdout, stderr)))

        # Log the processes still using the disk.
        ret, out, err = timed_command("lsof %s" % mount_path)
        out = out.decode('utf-8')
        err = err.decode('utf-8')
        if ret != 0:
          log.WARNING("Failed to determine processes using mount_path %s: "
                      "ret %d out %s err %s" % (mount_path, ret, out, err))
        else:
          log.INFO("Following is the lsof output on mount_path %s" % mount_path)
          log.INFO(out)
        return False

      return True

  @rpchandler
  def unmount_disk(self, disk, option=None):
    """
    Unmount the stargate partition on specific disk.
    Args:
      disk(string)   : Name of disk whose partitions to unmount (e.g. /dev/sda)
      option (string): Option is a parameter passed to unmount command.
    Returns:
      bool: True on success, False otherwise.

    """
    log.INFO("Waiting for disk mount lock for unmount disk %s" % disk)
    with self.__disk_mount_lock:
      log.DEBUG("Got disk mount lock for unmount disk %s" % disk)
      return self._unmount_disk(disk, option)

  def _unmount_disk(self, disk, option=None):
    """
    Unmount the stargate partition on specific disk. This routine presupposes
    that the disk mount lock has been acquired.

    Args:
      disk(string)   : Unmount partitions of this disk (e.g. /dev/sda).
      option (string): Option is a parameter passed to unmount command.

    Returns:
      bool: True on success, False otherwise.

    """
    if disk is None:
      log.ERROR("Invalid disk provided")
      return False

    if not os.path.exists(disk):
      log.ERROR("Disk %s for unmount does not exist" % disk)
      return True

    disk_obj = Disk(disk)
    partition = disk_obj.get_data_partition()
    if not partition:
      log.ERROR("No mountable partitions found on disk %s" % disk)
      return True

    log.INFO("Unmounting partitions on disk %s" % disk)
    part_obj = Partition(partition).initialize()

    if not part_obj:
      log.ERROR("Failed to initialize partition object")
      return False

    mount_path = part_obj.mount_path()

    success = True
    if not mount_path and block_store_utils.is_fuse_managed_disk(disk):
      mount_path = self.__get_mount_path(disk_obj.serial_number())

      # Unmount the fuse managed mountpath.
      log.INFO("Unmounting fuse mount managed mountpoint on path %s" %
               mount_path)
      if not block_store_utils.unmount_fuse_mountpath(mount_path):
        log.ERROR("Unable to unmount mountpath: %s" % mount_path)
        success = False
    else:
      log.INFO("Unmounting partition %s on path %s" %
               (partition, mount_path))
      if not part_obj.unmount(option):
        log.ERROR("Failed to unmount partition %s at mount path %s" %
                  (partition, mount_path))
        success = False

    # Log the processes still using the disk.
    if not success:
      ret, out, err = timed_command("lsof %s" % mount_path)
      out = out.decode('utf-8')
      err = err.decode('utf-8')
      if ret != 0:
        log.WARNING("Failed to determine processes using mount_path %s: "
                    "ret %d out %s err %s" % (mount_path, ret, out, err))
      else:
        log.INFO("Following is the lsof output on mount_path %s %s" %
                 (mount_path, out))
    return success

  @rpchandler
  def mount_disk(self, disk, mount_path=None, remount=False,
                 mount_options=disk_consts.DEFAULT_EXT4_MOUNT_OPTS):
    """
    Attempt to mount all stargate partitions on specified disk.

    Args:
      disk (string): Name of disk whose partitions to mount (eg - /dev/sdc)
      mount_path (string): If provided, the disk will be mounted at that
        path. Default: None.
      remount (bool): Attempt to remount with the given options. Default False.
      mount_options (string): Mount options to use. Defaults to
        DEFAULT_EXT4_MOUNT_OPTS.

    Returns:
      bool: True on success, False on failure.
    """
    # Ignore if EBADF or EAGAIN is returned. This is to ensure the mount path
    # is in other services' ownership. For ex: in ENG-373165, a race between
    # Hades and Xmount/Stargate creates issues.
    acceptable_err = [errno.EBADF, errno.EAGAIN]

    if disk is None:
      log.ERROR("Invalid disk provided")
      return False

    log.INFO("Waiting for disk mount lock for mount disk %s" % disk)
    with self.__disk_mount_lock:
      log.DEBUG("Got disk mount lock for mount disk %s" % disk)

      if not os.path.exists(disk):
        log.ERROR("Disk %s does not exist" % disk)
        return False

      disk_obj = Disk(disk)
      disk_model = disk_obj.get_disk_model()

      if not disk_model:
        log.ERROR("Failed to get the disk model of disk %s" % disk)
        return False

      partition = disk_obj.get_data_partition(disk_model=disk_model)
      if not partition:
        log.ERROR("No mountable data partitions found on disk %s" % disk)
        if disk_obj.is_svm_boot_disk(model=disk_model) and \
           len(disk_obj.partitions()) >= 3:
          log.INFO("Disk %s is a boot disk without data partition" % disk)
          return True
        else:
          return False

      if disk_obj.is_svm_boot_disk(model=disk_model):
        usable_data_disk = (hcl.is_metadata_disk(disk_model) or
                            hcl.is_data_disk(disk_model))

        if disk_obj.is_virtual_disk(model=disk_model) and \
           len(disk_obj.partitions()) in [1,4]:
          usable_data_disk = True

        if not usable_data_disk:
          partition = None
          log.INFO("Disk %s is a boot disk without a usable data partition" %
                   disk)
          return True

      log.INFO("Mounting partitions on disk %s" % disk)
      part_obj = Partition(partition).initialize()

      if not part_obj:
        log.ERROR("Failed to initialize partition object")
        return False

      if part_obj.mounted() and not remount:
        log.INFO("Partition %s already mounted, skipping..." % partition)
        return True

      if not mount_path:
        mount_path = self.__get_mount_path(disk_obj.serial_number())

      log.INFO("Mounting partition %s on path %s" % (partition, mount_path))

      # Check if we have a fuse managed mountpath.
      if block_store_utils.is_fuse_managed_mountpath(mount_path):
        log.INFO("Mount path %s for disk %s is mounted by fuse" %
                 (mount_path, disk))
        return True

      if not os.path.exists(mount_path):
        try:
          os.makedirs(mount_path)
          os.chown(mount_path, self.__nutanix_uid, self.__nutanix_gid)
        except (OSError, IOError) as ex:
          if ex.errno not in acceptable_err:
            log.ERROR("Failed to make mount directory %s, error %s" %
                      (mount_path, str(ex)))
            return False
          log.WARNING("Mount path %s not accessible. Disk owned by Stargate "\
                      "or Xmount. Skip mounting the disk" % mount_path)
          return True

      if remount:
        mount_options = mount_options + ",remount"
      if NvmeDisk.is_nvme_device(disk):
        mount_options = mount_options + " -text4"
      elif PmemDevice.is_pmem_device(disk):
        mount_options = mount_options + ",dax"

      log_msg = ("Directory %s is not empty before mounting the disk %s" %
                 (mount_path, disk_obj.serial_number()))
      if not part_obj.mounted() and len(glob.glob(mount_path + "/*")) != 0:
        log.INFO("Removing empty directories before mounting disk %s" %
                 disk_obj.serial_number())
        for root, dirs, _ in os.walk(mount_path, topdown=False):
          for dir_name in dirs:
            # Cannot just check if dirs and files size is 0 because even
            # though we are deleting the iterator isn't reading new values.
            full_dir = os.path.join(root, dir_name)
            if not len(os.listdir(full_dir)):
              log.INFO("Deleting empty dir %s in the mount path" % full_dir)
              try:
                os.rmdir(full_dir)
              except (IOError, OSError) as ex:
                log.ERROR("Unable to remove empty dir %s: %s"
                          % (full_dir, str(ex)))

      if len(glob.glob(mount_path + "/*")) != 0:
        log.WARN("Directory %s is not empty before mounting the disk %s. "
                 "Continuing with mounting the disk" %
                  (mount_path, disk_obj.serial_number()))

      partition_mounted = (
        Partition.get_partition_name_from_mount_path(mount_path))
      log_msg = ("Cannot mount %s at %s. Disk %s is already mounted there" %
                 (disk_obj.serial_number(), mount_path, partition_mounted))
      log.CHECK(partition_mounted is None or
                partition_mounted == partition, log_msg)

      if not part_obj.mount(mount_path, mount_options=mount_options):
        try:
          # part_obj.mount returns a bool, we use os.stat here to catch
          # the exception and take action.
          os.stat(mount_path)

          # Unix stat command works on FD, and unmounted path are valid FDs.
          # Do another check for unmounted paths.
          #
          # For ex: Superblock access errors would pass the stat check, but
          # would not be part of procfs.
          if not os.path.ismount(mount_path):
            log.ERROR("No valid mount at this path: %s" % mount_path)
            return False

        except (OSError, IOError) as ex:
          if ex.errno not in acceptable_err:
            log.ERROR("Failed to mount partition %s at mount path %s. "
                      "Exception: %s" % (partition, mount_path, ex))
            return False
          log.WARNING("Mount path %s not accessible. Disk owned by Stargate "\
                      "or Xmount. Skip mounting the disk" % mount_path)
          return True

      try:
        # Mount succeeded, ensure correct permissions.
        os.chown(mount_path, self.__nutanix_uid, self.__nutanix_gid)

        # Set owner for nested directories. Reference: ENG-373019.
        for disk_file in os.listdir(mount_path):
          # Just access the top-level files and directories.
          os.chown(os.path.join(mount_path, disk_file), self.__nutanix_uid,
                   self.__nutanix_gid)

        # Set permission to 750. Reference: ENG-369319.
        os.chmod(mount_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
      except OSError as ex:
        log.ERROR("Failed to set permissions on mnt directory %s, error %s" %
                  (mount_path, str(ex)))
        return False

      # Create cores directory within instance store volume for AWS if required.
      if (partition == FLAGS.aws_cores_partition and
          not AmazonCloudDiskUtil.setup_cores_symlink(mount_path,
                                                      self.__nutanix_uid,
                                                      self.__nutanix_gid)):
        return False

      return True

  @rpchandler
  def reset_partition_table(self, disks, partition_table_type="gpt"):
    """
    Wipes the partition table of all specified disks and creates a GPT partition
    table.

    Params:
      disks (list): disks to reset

    Returns:
      bool: Returns True on success, False otherwise.
    """
    ret = True

    for disk in disks:
      try:
        log.INFO("Running blkdiscard on disk %s" % disk)
        Disk.blk_discard(disk)
      except:
        log.ERROR("Failed to run blkdiscard on disk %s" % disk)
      log.INFO("Resetting partition table on disk %s" % disk)
      code, stdout, stderr = timed_command("parted -s %s mklabel %s" %
                                           (disk, partition_table_type))
      stdout = stdout.decode('utf-8')
      stderr = stderr.decode('utf-8')
      if code != 0:
        log.ERROR("Failed to wipe partition and add GPT partition table on "
                  "disk %s, ret %s, stdout %s, stderr %s" %
                  (disk, ret, stdout, stderr))
        # Mark failure, attempt to reset all disks.
        ret = False

    return ret

  @rpchandler
  def create_partition(self, disk, start=None, end=None,
                       partition_type="ext4", reserved_block_pct=1,
                       part_num=1, boot_partition=False, boot_disk=False):
    """
    Creates an ext4 partition on 'disk' from 'start' to 'end'.
    If "start" and "end" are not specified, sane defaults are used. These are
    tuned for the typical case (create a single stargate partition).

    Params:
      disk  (string) : name of disk
      start (integer): start of partition (MB)
      end   (integer): end of partition (MB)
      type  (string) : type of partition. (ext4 or xfs)
      rbp   (integer): percentage of blocks to reserve for superuser
      part_num (integer): Default partition number
      boot_partition (boolean): Whether this partition is a boot partition
      boot_disk (boolean): True if it's a boot disk.
    Returns :
      True on success, False otherwise.
    """
    disk_obj = Disk(disk)
    log.INFO("Partition type requested for disk %s: %s" %
             (disk, partition_type))
    log.CHECK(partition_type in ["ext4", "xfs"])

    if start == None:
      start = "%sb" % (consts.ALIGNMENT_GAP_SIZE)

    # If end is None or end is the full disk size then look for any specified
    # downformat size.
    if end == None or end == "100%":
      downformat_part_size = disk_obj.get_downformat_size_gb()
      if downformat_part_size:
        end = downformat_part_size

    if end == None:
      disk_model = disk_obj.get_disk_model()
      if not disk_model:
        end = "-1MB"

      if disk_model in disk_consts.MODEL_PARTITION_SIZE_MAP:
        end = disk_consts.MODEL_PARTITION_SIZE_MAP[disk_model]
      else:
        end = "-1MB"

    log.INFO("Creating a %s partition on %s (from %s to %s)" %
             (partition_type, disk, start, end))
    cmd = ("parted -s -a opt %s mkpart primary %s %s -- %s" %
           (disk, partition_type, start, end))
    ret, stdout, stderr = timed_command(cmd)
    stdout = stdout.decode('utf-8')
    stderr = stderr.decode('utf-8')

    log.INFO("Output of create partition cmd: %s, ret: %s, stdout: %s, "
             "stderr: %s" % (cmd, ret, stdout, stderr))

    if ret != 0:
      # When you create a partition the kernel has to re-read the partition
      # table on the disk, however, sometimes this fails so we need to force
      # the kernel to re-read the partition table.
      stderr = stdout + stderr
      retries = 0
      while PART_TABLE_READ_ERROR_RE.search(stderr):
        ret, stdout, stderr = timed_command("partprobe %s" % disk)
        stdout = stdout.decode('utf-8')
        stderr = stderr.decode('utf-8')
        if ret == 0:
          return True
        elif ret != 0 and retries == READ_PART_TABLE_RETRIES:
          log.ERROR("Failed to re-read partition table on disk %s, ret %s, "
                    "stdout %s, stderr %s" % (disk, ret, stdout, stderr))
          return False
        elif ret != 0 and retries < READ_PART_TABLE_RETRIES:
          log.INFO("Failed to re-read the partition table on disk, "
                   "re-reading...")

        retries += 1
        time.sleep(1)

      log.ERROR("Failed to create partition on disk %s from %s to %s, ret %s, "
                "stdout %s, stderr %s" %
                (disk, start, end, ret, stdout, stderr))
      return False

    partition = self.partition_name(disk, part_num)

    is_sed = sed_utils.is_a_self_encrypting_drive(disk)
    if is_sed and not boot_partition:
      if not sed_utils.reinitialize_sed_band(disk,
                                             disk_obj.serial_number(),
                                             partition,
                                             erase=False):
        log.ERROR("Could not initialize band on self encrypting drive")
        return False

    if not disk_obj.format_partition(partition, is_sed):
      return False
    return True

  def partition_name(self, disk_name, partiton_num):
    """
    Return the partition name, given disk name and partition number.
    """
    # Example PMEM partition name: "/dev/pmem0p1".
    if (NvmeDisk.is_nvme_device(disk_name) or (FLAGS.configure_pmem_devices \
      and PmemDevice.is_pmem_device(disk_name))):
      partition = "%sp%d" % (disk_name, partiton_num)
    else:
      partition = "%s%d" % (disk_name, partiton_num)
    return partition

  def __is_down_formatted(self, disk_name, disk_obj=None):
    """Checks if disk is down formatted.

    Args:
      disk_name: disk block device name. Ex.:- /dev/sda

    Returns:
      tuple of is_down_formatted and is_disk_empty
        is_down_formatted is:
          True: disk needs down formatting and is down formatted; disk
                does not need down formatting.
          False: disk needs down formatting and is not downformatted
          None: failure
        is_disk_empty:
          contains True or False if the disk's data partition is empty
          or not. This is checked only when is_down_formatted is False.
          We do not care if disk is empty otherwise. It is None in such
          cases.
    """
    if disk_obj is None:
      disk_obj = Disk(disk_name)

    downformat_part_size = disk_obj.get_downformat_size_gb()

    if downformat_part_size is None:
      # Disk need not be downformatted. So no need to check.
      return True, None

    # There could be a few old SSDs from depot which is not down
    # formatted due to an outdated hcl.json at the time of their
    # preparation in the factory. Repartition such disks if they
    # are empty.
    log.INFO("Disk %s is configured to be down formatted. Checking if it is "
             "down formatted" % disk_name)

    # Check if disk is downformatted by checking the end of the
    # last (data) partition matches with the size of the disk.
    # Get disk size.
    disk_size_bytes = get_disk_size(disk_name)
    disk_size_gb = disk_size_bytes // GIGA
    log.INFO("Size of disk %s: %d GB" % (disk_name, disk_size_gb))

    # Get the end sector and byte of the last (data) partition.
    data_partition = disk_obj.get_data_partition()
    if data_partition is None:
      log.ERROR("Failed to get data partition of %s" % disk_name)
      return None, None
    log.INFO("Data partition of disk %s is %s" % (disk_name, data_partition))
    data_part_obj = Partition(data_partition).initialize()
    if data_part_obj is None:
      log.ERROR("Failed to initialize data partition object for %s in disk %s"
                % (data_partition, disk_name))
      return None, None

    start_sector_no, size_in_sectors = data_part_obj.get_partition_sectors(
        data_partition)
    if start_sector_no is None or size_in_sectors is None:
      log.ERROR("Failed to get data partition sectors for %s in disk %s" %
                (data_partition, disk_name))
      return None, None
    end_bytes = (start_sector_no + size_in_sectors) * consts.SECTOR_SIZE
    end_gb = end_bytes // GIGA
    log.INFO("Data partition %s of disk %s ends at %d GB" % (data_partition,
                                                             disk_name, end_gb))

    # Check if disk is down formatted.
    # Even if the below 2 sizes vary by a few bytes, converting them to
    # GB as an integer ensures that the equality comparison holds good.
    if end_gb < disk_size_gb:
      log.INFO("Disk %s is already down formatted" % disk_name)
      return True, None
    else:
      log.INFO("Disk %s is not down formatted" % disk_name)
      if not data_part_obj.is_empty():
        log.INFO("Disk %s is empty" % disk_name)
        return False, True
      else:
        log.ERROR("Disk %s is not empty" % disk_name)
        return False, False

  def is_active_boot_disk_partition_layout_new(self):
    """
    Checks if boot partition layout new(20 GB alignment between).
    Returns: True if boot partition layout is new
           : False if boot partition layout is old
    """
    boot_drives = raid_utils.boot_disks()
    if boot_drives is None:
      log.ERROR("Failed to get boot_drives.")
      return False

    for disk in boot_drives:
      if self.is_boot_disk(disk):
        part1_start_sector_no, part1_size_in_sectors = \
          Partition.get_partition_sectors(self.partition_name(disk, 1))
        part2_start_sector_no, part2_size_in_sectors = \
          Partition.get_partition_sectors(self.partition_name(disk, 2))

        if part1_start_sector_no is None or \
           part1_size_in_sectors is None or \
           part2_start_sector_no is None:
          log.ERROR("Failed to get partition sectors for %s " % disk)
          return False

        gap_alignment = consts.ALIGNMENT_GAP_SIZE // consts.SECTOR_SIZE
        part1_total_size_in_sector = part1_start_sector_no + \
                                     part1_size_in_sectors + gap_alignment

        log.INFO("part1_start_sector_no : %d part1_size_in_sectors : %d "
                 "part2_start_sector_no : %d gap_alignment : %d " %
                 (part1_start_sector_no, part1_size_in_sectors,
                  part2_start_sector_no, gap_alignment))
        # Condition to verify that partition2 is just starting after
        # partition1 size + gap_alignment in between no extra alignment added.
        # If extra alignment is added then disk is Partition will be considered
        # as new partition layout.
        if part2_start_sector_no > part1_total_size_in_sector + 1:
          log.INFO("Disk : %s partition layout is new" % disk)
          return True
        else:
          return False

    return False

  @rpchandler
  def repartition_disk(self, disk, partition_type="ext4",
                       reserved_block_pct=1, boot_disk=False):
    """
    Wipe out any existing partition table on the disk and
    create a single partition if disk is not a boot disk.

    Create 4 partitions if it is a boot disk.
    Repartitioning a boot disk is skipped and the data partition of the
    disk is formatted in the following cases:
    i) node is a single SSD model
    ii) disk is a part of an active raid

    Note for down formatted disks:
    If the boot disk is configured to be down formatted and it is part
    of an active raid, the disk is failed and detached from the raid
    and repartitioned as per the down foramtting specification if the
    disk's data partition is empty. If it is not empty, repartition
    fails and needs manual intervention to check data.

    Params:
      disk  (string) : name of disk e.g. /dev/sda/
      type  (string) : type of partition. (ext4 or xfs)
      rbp   (integer): percentage of blocks to reserve for superuser
      boot_disk(bool): If this disk is a boot disk. Default: False.

    Returns :
      True on success, False otherwise.
    """
    to_repartition = True

    if boot_disk and not raid_utils.is_raid_configured():
      log.INFO("Requested repartitioning of disk %s as a Boot disk on a Single "
               "SSD system" % disk)
      if Disk(disk).is_active_boot_disk():
        # The existing boot disk is being added as a boot disk. This happens
        # during Single SSD Repair. We'll skip repartitioning the disk as the
        # boot partitions are already in use and proceed with cleaning the
        # data partition and adding it to the cluster.
        log.INFO("Skipping repartitioning of disk %s as it is the only boot "
                 "disk on the node" % disk)
        to_repartition = False

    # For both repartition_disk cases - boot disk or data disk, there can be
    # existing RAID on the disk. Fail RAID before repartitioning the disk.
    # Refer: ENG-381136 for different examples.
    if self.is_active_raid_disk(disk):
      log.INFO("Disk %s is part of an active raid" % disk)
      # Check if the disk needs to be down formatted and is down
      # formatted. This has to be done before unmounting as it needs
      # to check the size of the data partition and check whether
      # it is empty or not.
      is_down_formatted, _ = self.__is_down_formatted(disk)
      if is_down_formatted and boot_disk:
        # Skip failing RAID, as the boot disk will not be repartitioned.
        log.INFO("Skip repartition for downformatted boot disk: %s" % disk)
        to_repartition = False
      else:
        # If either of the checks - is_down_formatted or boot_disk - doesn't
        # fit, then it makes sense to repartition the disk. For that, we need
        # to fail the RAID.
        if raid_utils.fail_boot_raid(disk):
          log.INFO("Removed disk %s from raid to repartition" % disk)
          # to_repartition is already True
        else:
          log.ERROR("Failed to remove disk %s from raid to repartition" %
                    disk)
          return False

    if not self.unmount_disk(disk, "f"):
      log.ERROR("Failed to unmount disk %s" % disk)
      return False

    if boot_disk:
      # First check if the disk tier is eligible to be a boot disk or not.
      # To be noted: This is just a pre-requisite tier check, actual eligiblity
      # for a boot disk is done when the disk is added to the cluster, via a
      # hcl inventory check.
      if not utils.can_be_boot_disk(disk):
        log.ERROR("Disk: %s cannot be repartitioned as boot disk. Try it as a "
                  "data disk" % disk)
        return False

      if not to_repartition:
        log.INFO("Skipping repartition, going ahead with cleaning disk %s" %
                 disk)
        if not self.clean_disks([disk]):
          log.ERROR("Failed to clean disk %s" % disk)
          return False
      else:
        log.INFO("Repartitioning boot disk")
        if not self.reset_partition_table([disk]):
          log.ERROR("Failed to reset partition table for disk %s" % disk)
          return False

        # Preference order for creating boot disk partitions:
        # 1. Use active boot disk partitions' size to create new ones.
        # 2. If the above fails, stick to default boot size partitions,
        #    i.e., 10G 10G 40G.
        active_boot_disk_partitions = \
          raid_utils.get_active_boot_disk_partitions()

        boot_partitions = active_boot_disk_partitions\
                          if active_boot_disk_partitions\
                          else [FLAGS.boot_size,
                                FLAGS.boot_size,
                                FLAGS.home_nutanix_size]

        log.INFO("Boot disk %s will be repartitioned with num of sectors as "
                  "%s" % (disk, boot_partitions))
        disk_size = get_disk_size(disk)
        if disk_size == -1:
          log.ERROR("Unable to get disk size for disk %s" % disk)
          return False

        disk_size_gb = disk_size // BYTE_TO_GIGA
        log.INFO("Disk %s: size %d GB" % (disk, disk_size_gb))
        is_boot_disk_new_layout = \
          self.is_active_boot_disk_partition_layout_new()
        gap_alignment = consts.ALIGNMENT_GAP_SIZE // consts.SECTOR_SIZE
        start = gap_alignment
        part_num = 1
        for boot_partition in boot_partitions:
          start_offset = start * consts.SECTOR_SIZE
          end_offset = \
            ((start + boot_partition) * consts.SECTOR_SIZE) - 1
          ret = self.create_partition(
            disk, partition_type=partition_type,
            start="%sb" % (start_offset),
            end="%sb" % (end_offset),
            part_num=part_num,
            boot_partition=True, boot_disk=True)
          if not ret:
            log.ERROR("Failed to create boot partition on disk %s" % disk)
            return False
          part_num = part_num+1
          start += boot_partition + gap_alignment
          start = (start // gap_alignment) * gap_alignment

          # Large partitions is disabled then add extra alignment
          # This extra alignment we keep as unpartitioned space
          # ENG-313836
          if is_boot_disk_new_layout and \
            disk_size_gb >= FLAGS.minimum_disk_size_in_gb_for_extra_alignment:
            if boot_partition == FLAGS.home_nutanix_size:
              start += FLAGS.home_nutanix_size_extra_alignment
            elif boot_partition == FLAGS.boot_size:
              start += FLAGS.boot_size_extra_alignment
            else:
              log.ERROR("Disk %s has invalid boot partition size %d" %
                        (disk, boot_partition))

        if (start * consts.SECTOR_SIZE) < disk_size:
          ret = self.create_partition(
            disk, partition_type=partition_type,
            start="%sb" % (start * consts.SECTOR_SIZE),
            end="100%", part_num=part_num,
            boot_disk=True)
          if not ret:
            log.ERROR("Failed to partition extra space on disk %s" % disk)
            return False

      if not raid_utils.fix_boot_raid(disk):
        raid_utils.get_proc_mdstat()
        log.ERROR("RAID is in degraded state after repartitioning disk %s "
                  "as boot disk" % disk)
        return False

    else:
      # Not boot disk.
      log.INFO("Repartitioning regular (non-boot) disk")
      if not self.reset_partition_table([disk]):
        log.ERROR("Failed to reset partition table for disk %s" % disk)
        return False
      ret = self.create_partition(
        disk,
        partition_type=partition_type,
        reserved_block_pct=reserved_block_pct,
        boot_disk=False)
      if not ret:
        log.ERROR("Failed to create partitions on disk %s" % disk)
        return False

    ret, _ = self.prep_device_util.prepare_block_devices([disk])
    if not ret:
      log.ERROR("Failed to prepare block device %s" % disk)
      return False

    if not self.mount_disk(disk):
      log.ERROR("Failed to mount disk %s" % disk)
      return False

    return True

  @rpchandler
  def disk_repartition_add_zeus(self, disk, repartition=False,
                                add_zeus=False, partition_type="ext4",
                                reserved_block_pct=1, force=False, rma=False):
    """
    Repartition and add disk to zeus depending upon input.
    If disk is correctly partitioned then clean it.
    Params:
      disk (string)     : disk block device name e.g. /dev/sda
      repartition (bool): If true then repartition else do not
      add_zeus (bool)   : If true then add disk to zeus else do not
      type(string)      : Type of partition
      rbp (integer)     : percentage of blocks to reserve for superuser
      force(bool)       : Default behavior is that if disk is found in disk
                          list in zeus config, then it wont be reparitioned.
                          User can overwrite this behavior using the force=True
                          option.
      rma(bool)         : If this repartition is for an RMA vs. a capacity
                          upgrade. Default: False.

    Returns True if successful, False otherwise.
    """
    # Do this only if no disk add/remove task is in progress.
    log.INFO("Waiting for disk breakfix lock")
    with self.__disk_breakfix_lock:
      log.INFO("Got disk breakfix lock, no disk breakfix in progress")
      disk_serial = Disk(disk).serial_number()
      if not disk_serial:
        log.ERROR("Failed to get disk serial for disk %s" % disk)
        return False

      log.INFO("User initiated disk partition of disk:%s" % disk_serial)

      if not force:
        zeus_config = Configuration().initialize(
            host_port_list=self.__host_port_list)
        if zeus_config is None:
          log.ERROR("Unable to connect to zk, is cluster up?")
          return False
        config_proto = zeus_config.config_proto()

        for dsk in config_proto.disk_list:
          if dsk.disk_serial_id == disk_serial:
            log.ERROR("Cannot repartition. Disk %s is part of zeus config" %
                      disk_serial)
            return False

      # Check if disk is bad and early return.
      zk_session = ZookeeperSession(host_port_list=self.__host_port_list)
      if not zk_session.wait_for_connection(None):
        log.ERROR("Unable to obtain a Zookeeper session")
        return False
      hades_config, _ = hades_utils.get_hades_proto(zk_session)
      if hades_config is None:
        log.ERROR("Failed to fetch Hades proto. Aborting")
        return False
      for slot in hades_config.slot_list:
        if slot.disk.serial == disk_serial and slot.disk.is_bad:
          log.ERROR("Disk %s is marked bad in Hades proto. Not adding it" %
                    disk)
          return False

      if repartition:
        # NVMe namespace resize checks.
        if NvmeDisk.is_nvme_namespace_resize_enabled(disk):
          nvme_obj = NvmeDisk.get_instance()
          node_model = hades_utils.get_model()
          log.DEBUG("Check and perform NVMe namespace resize for disk %s"
                    % disk)
          if not nvme_obj.check_and_perform_nvme_ns_resize(disk, disk_serial,
                                                           node_model):
            log.ERROR("Failed to perform NVMe namespace resize on disk %s "
                      "with serial %s" % (disk, disk_serial))
            return False

        # TODO: Change this for sticky boot disk slots.
        disk_obj = Disk(disk)

        # Check if disk is qualified to be a Boot disk.
        is_boot_disk = disk_obj.is_svm_boot_disk()

        # We will add the disk as a Boot disk on following 4 conditions:
        # 1. The disk is a qualified boot disk as per hcl.json.
        # 2. The disk is not a HDD.
        boot_disk_required = (
          is_boot_disk and
          utils.find_storage_tier(disk) != "DAS-SATA")

        # 3. If the node has RAID configured: RAID is degraded (OR) the disk is
        # already part of RAID.
        is_raid_disks = raid_utils.is_raid_configured()
        if is_raid_disks:
          boot_disk_required = (
            boot_disk_required and
            ((self.is_raid_degraded() and not self.raid_sync_in_progress())
              or self.is_active_raid_disk(disk)))

        # 4. If the node is a single SSD system: We will add this as a boot
        # disk only if it is already being used as a boot disk.
        # This happens during Single SSD Repair in which the replaced drive is
        # dirty. In that case, the boot partitions are formatted by svmrescue
        # and CVM is booted up, but the data partition is not added to the
        # cluster since it is not empty. This necessitates 'Repartition Add' of
        # the existing Boot disk, so that its data partition can be added to the
        # Cluster.
        else:
          boot_disk_required = (
            boot_disk_required and
            Disk(disk).is_active_boot_disk())

        log.INFO("Repartitioning disk %s as a boot disk: %s" %
                 (disk, boot_disk_required))
        if not self.repartition_disk(disk, partition_type, reserved_block_pct,
                                     boot_disk_required):
          log.ERROR("Failed to repartition disk %s" % disk)
          return False

      if add_zeus:
        # Clear offline.
        if not self.change_disks_offline_paths([disk_serial],
                                               operation="clear"):
          log.ERROR("Failed to remove disk %s from offline mount paths" %
                    disk_serial)
          return False

        # Turn off LED.
        if not self.led_off(disk_serials=[disk_serial]):
          log.ERROR("Failed to turn off LED for disk %s" % disk_serial)

        if not self.__setup_hades_proto():
          log.ERROR("Failed to update hades proto")
          return False

        # If disk is new we may have to set a password before mounting.
        zk_session = ZookeeperSession(host_port_list=self.__host_port_list)
        if not zk_session.wait_for_connection(None):
          log.ERROR("Unable to obtain a zookeeper session")
          return False
        hades_config, _ = hades_utils.get_hades_proto(zk_session)

        node_disk_list = self.__get_node_disks_from_zeus(zk_session=zk_session)
        if not sed_utils.maybe_set_sed_password(disk,
                                                hades_config,
                                                node_disk_list,
                                                zk_session):
          log.ERROR("Could not detect if we had to set passwords on disk %s"
                    % disk_serial)

        # Synchronize disks information.
        if not self.__update_hades_disks_state():
          log.ERROR("Failed to update disks state in hades")
          return False

        rma_disks = [disk] if rma else []

        if not self.add_disks_to_cluster(rma_disk_list=rma_disks):
          log.ERROR("Failed to add disk with serial %s to cluster" %
                    disk_serial)
          return False

        # Workaround: Restart stargate so that disk are updated.
        # TODO: Remove this when disk addition case if properly handled
        #       by stargate.
        if not self.kill_stargate():
          # Stargate restarts itself for SSDs but not on all flash.
          # Don't declare error on failure.
          log.ERROR("Failed to kill stargate")

      # TODO(Harish) - To better handle clearing intent files, maybe this
      # portion can be moved to method calls, which will help us in clearing
      # the intent files even if there is a failure in between.

      # Clear NVMe namespace resize intent file created.
      if NvmeDisk.is_nvme_namespace_resize_enabled(disk) and \
         not NvmeDisk.clear_nvme_ns_resize_intent(disk_serial):
        log.ERROR("Failed to clear NVMe namespace resize intent file"
                  " for disk %s with serial %s" % (disk, disk_serial))

      return True

  @rpchandler
  def user_disk_repartition_add_zeus(self, disk_serial, repartition=False,
                                     add_zeus=False, partition_type="ext4",
                                     reserved_block_pct=1, rma=False,
                                     parent_task_uuid=None):
    """
    Repartition and add disk to zeus depending upon input.
    Non blocking call for prism.
    Params:
      disk_serial (string) : serial number of disk
      repartition (bool)   : If true then repartition else do not
      add_zeus    (bool)   : If true then add disk to zeus else do not
      type        (string) : Type of partition
      rbp         (integer): percentage of blocks to reserve for superuser
      rma         (bool)   : If this repartition is for an RMA vs. a capacity
                             upgrade. Default: False.
      parent_task_uuid (str): UUID of parent ergon task.

    Returns True if successful, False otherwise.
    # TODO: Add preventive checks.
    """
    # Call is not blocking, first try to commit to hades ongoing operation.
    # If successful then start a thread else return.
    disk = self.disk_serial_to_block_device(disk_serial)
    if not disk:
      log.ERROR("Failed to get disk name from disk serial %s" % disk_serial)
      return False

    if not self.__commit_operation_hades(disk,
                                         "user_disk_repartition_add_zeus"):
      log.ERROR("Failed to update operation user_disk_repartition_add_zeus "
                "disk %s in hades proto, other operation is under execution for"
                " node" % disk)
      return False

    if parent_task_uuid:
      async_rpc_util = AsyncRpcUtil(disk_manager=self)
      task_uuid = async_rpc_util.async_handler(
        func=self.__user_disk_repartition_add_zeus,
        parent_task_uuid=parent_task_uuid,
        operation_type="kDiskRepartitionAddZeus",
        disk=disk, repartition=repartition,
        add_zeus=add_zeus, partition_type=partition_type,
        reserved_block_pct=reserved_block_pct, rma=rma
      )
      return task_uuid

    else:
      thread.start_new_thread(self.__user_disk_repartition_add_zeus,
                              (disk, repartition, add_zeus, partition_type,
                               reserved_block_pct, rma))
    return True

  @rpchandler
  def user_add_old_disk_to_zeus(self, disk_serial, parent_task_uuid=None):
    """
    Add disk with given serial back to zeus configuration.
    Return True if successful, False otherwise.

    Disk is accepted back only if entry is present in zeus configuration.
    Following things have to be considered:
    1) Metadata : If disk was a metadata disk then check if any other disk is
                  selected as metadata disk. (This can happen, e.g. Metadata
                  disk was pulled out, system reboots, another disk gets
                  seleted as metadata disk and user pushes old disk and
                  click accept old disk) If no other disk was selected as
                  metadata disk then nothing to do. If yes then clear contains
                  metadata field in zeus and revert metadata reservation in
                  disk config.

    2) Oplog : Revert oplog reservation.

    # TODO: Add preventive checks.
    """
    log.INFO("Accepting disk with serial %s back in cluster" % disk_serial)

    if not self.__is_cluster_configured():
      log.ERROR("Cluster is not configured")
      return False

    node_disks = self.__get_node_disks_from_zeus(get_pmem=True)
    node_disk_serials = (
      [disk.device_serial_id if disk.DESCRIPTOR.name == "PmemDevice" else
        disk.disk_serial_id for disk in node_disks])

    if disk_serial not in node_disk_serials:
      log.INFO("Disk is no longer part of cluster")
      return False

    is_bad = self.__is_disk_bad_hades(disk_serial)

    if is_bad is None:
      log.ERROR("Could not reliably discern the state of disk with serial %s. "
                "Halting disk add back" % disk_serial)
      return False
    elif is_bad:
      log.ERROR("Disk with serial %s is marked bad. Skipping add back" %
                disk_serial)
      return False

    disk_name = self.disk_serial_to_block_device(disk_serial)
    if not disk_name:
      log.ERROR("Failed to get disk name for disk with serial %s" %
                disk_serial)
      return False

    if not self.mount_disk(disk_name):
      log.ERROR("Failed to mount disk %s" % disk_name)
      return False

    disk_id = self.disk_serial_to_disk_id(disk_serial)
    if not disk_id:
      log.ERROR("Failed to find disk id for disk with serial %s" % disk_serial)
      return False

    if parent_task_uuid:
      async_rpc_util = AsyncRpcUtil(disk_manager=self)
      task_uuid = async_rpc_util.async_handler(
        func=self.__add_old_disk_to_zeus_helper,
        parent_task_uuid=parent_task_uuid,
        operation_type="kAddOldDiskToZeus",
        disk_id=disk_id, disk_serial=disk_serial,
        disk_name=disk_name
      )
      return task_uuid

    else:
      return self.__add_old_disk_to_zeus_helper(disk_id, disk_serial, disk_name)

  def __add_old_disk_to_zeus_helper(self, disk_id, disk_serial, disk_name):
    """
    Helper function to add a disk back to zeus configuration.
    Return True if successful, False otherwise..

    Args:
      disk_id (int): ID of disk.
      disk_serial (str): Serial of disk.
      disk_name (str): Name of disk.

    Returns:
      Bool: True if able to add old disk to Zeus. False otherwise.
    """

    # Clear to_remove field for disk.
    if not self.change_to_remove_for_disks([disk_id], operation="clear"):
      log.ERROR("Failed to clear to_remove for disk %s with serial %s" %
                (disk_id, disk_serial))
      return False

    if not self.__setup_hades_proto():
      log.ERROR("Failed to update hades proto")
      return False

    # If adding old disk back we may have to set a password before mounting.
    zk_session = ZookeeperSession(host_port_list=self.__host_port_list)
    if not zk_session.wait_for_connection(None):
      log.ERROR("Unable to obtain a zookeeper session")
      return False
    hades_config, _ = hades_utils.get_hades_proto(zk_session)
    node_disk_list = self.__get_node_disks_from_zeus(zk_session=zk_session,
                                                     get_pmem=True)
    if not sed_utils.maybe_set_sed_password(disk_name,
                                            hades_config,
                                            node_disk_list,
                                            zk_session):
      log.ERROR("Could not detect if we had to set passwords on a disk %s"
                % disk_serial)

    # Synchronize disks information.
    if not self.__update_hades_disks_state():
      log.ERROR("Failed to update disks state in hades")
      return False

    # Don't raise alert for accepting a disk that was already part of cluster,
    # to not flag genuine cases of data retrieval.
    if not self.add_disks_to_cluster(raise_alert=False):
      log.ERROR("Failed to add disk %s with serial %s to cluster" %
                (disk_name, disk_serial))
      return False

    # Remove entry from offline mount path.
    if not self.change_disks_offline_paths([disk_serial], operation="clear"):
      log.ERROR("Failed to remove disk %s from offline mount paths" %
                disk_serial)
      return False

    if self.is_boot_disk(disk_name):
      log.INFO("Reconfigure raid on the boot disk {}".format(disk_name))
      if not raid_utils.fix_boot_raid(disk_name):
        log.ERROR("Raid build failed on boot disk {}".format(disk_name))
        return False

    return True

  @rpchandler
  def get_disk_partitions(self, disk):
    """
    Get all the partitions on the specified disk.

    Args:
      disk (string): name of disk.

    Returns:
      list: list of partitions on the disk
    """
    return Disk(disk).partitions()

  @rpchandler
  def get_data_partition(self, disk, ignore_fs_errors=False, disk_model=None):
    """
    Get the data partition for a disk.

    Args:
      disk (string): Name of disk whose partitions are being asked for.
      ignore_fs_errors (bool): If True, ignore file system errors. Default:
        False.
      disk_model (str): Model number of the disk. Default: None.

    Returns:
      Returns the first stargate data partition or None if the disk is
      unpartitioned.
    """
    if disk is None:
      log.ERROR("Invalid disk provided")
      return None
    return Disk(disk).get_data_partition(ignore_fs_errors, disk_model)

  def __set_led_state(self, disks=None, disk_serials=None, state="off"):
    """
    Set LED state for the given disks. Translate SPDK disks to sysfs.

    Args:
      disks (list): disks whose LEDs are to be enabled
      disk_serials (list of string) : Serial numbers of disks
      state (str): locate/fault/off

      Function considers only 1 one of disk names or serials
      If both are provided or both are None then function will return error.

    Returns:
      bool: True if we set LED state for all specified disks, False otherwise.
    """
    if (disks and disk_serials) or (not disks and not disk_serials):
      log.ERROR("Please provide either disk names or disk serials")
      return False

    # If there have PMEM device in the disk list, return False. We don't want
    # to process the disk list partially.
    if disks:
      for disk in disks:
        if PmemDevice.is_pmem_device(disk):
          log.ERROR("Set LED state is not supported for PMEM device %s" % disk)
          return False
    if disk_serials:
      for serial in disk_serials:
        if PmemDeviceUtil.is_pmem_device_serial(serial):
          log.ERROR("Set LED state is not supported for PMEM device %s"
                    % serial)
          return False

    res, spdk_serial_to_pci_path = \
      SPDKUtil.find_pcie_sysfs_paths_for_disks(self, disk_serials, disks)
    if not res:
      return False
    log.INFO("SPDK disk serial map: {}".format(spdk_serial_to_pci_path))

    # Returns {disk_serial: disk}, includes /dev/sd*, /dev/nvme*.
    serial_disk_map = self.get_disk_serial_to_block_device_mapping()

    # Filter disks for led operation.
    filtered_disk_map = {}
    if disks:
      for key, value in serial_disk_map.items():
        for disk in disks:
          if disk == value:
            filtered_disk_map.setdefault(key, {})["device_node"] = value
            break
    elif disk_serials:
      for disk_serial in disk_serials:
        if disk_serial in serial_disk_map:
          filtered_disk_map.setdefault(disk_serial, {})["device_node"] = \
            serial_disk_map.get(disk_serial)

    # Disks which requires led operation.
    filtered_disk_map.update({
      serial: {"pci_path": pci_path}
      for serial, pci_path in spdk_serial_to_pci_path.items()})

    if not filtered_disk_map:
      log.ERROR("No disk found for led operation")
      return False
    return set_led_state(filtered_disk_map, state)

  @rpchandler
  def led_on(self, disks=None, disk_serials=None, parent_task_uuid=None):
    """
    Turn ON the LOCATE LED for the given disks.

    Args:
      disks (list): disks whose LEDs are to be enabled.
      disk_serials (list of string) : Serial numbers of disks.
      parent_task_uuid (str): UUID of parent ergon task.

      Function considers only 1 one of disk names or serials
      If both are provided or both are None then function will return error.

    Returns:
      bool: True if we set LED state for all specified disks, False otherwise.
        Task UUID if parent task uuid is provided.
    """
    if parent_task_uuid:
      async_rpc_util = AsyncRpcUtil(disk_manager=self)
      task_uuid = async_rpc_util.async_handler(
        func=self.__set_led_state, parent_task_uuid=parent_task_uuid,
        operation_type="kLedOn",
        disks=disks, disk_serials=disk_serials, state="locate")
      return task_uuid

    else:
      return self.__set_led_state(disks, disk_serials, "locate")

  @rpchandler
  def led_fault(self, disks=None, disk_serials=None, parent_task_uuid=None):
    """
    Turn ON the FAULT for the given disks. Chassis that don't have a "fault"
    mode use "locate" instead.

    Args:
      disks (list): disks whose LEDs are to be disabled.
      disk_serials (list of string) : Serial numbers of disks.
      parent_task_uuid (str): UUID of parent ergon task.

      Function considers only 1 one of disk names or serials
      If both are provided or both are None then function will return error.

    Returns:
      bool: True if we set LED state for all specified disks, False otherwise.
        Task UUID if parent task uuid is provided.
    """
    if parent_task_uuid:
      async_rpc_util = AsyncRpcUtil(disk_manager=self)
      task_uuid = async_rpc_util.async_handler(
        func=self.__set_led_state, parent_task_uuid=parent_task_uuid,
        operation_type="KLedFault",
        disks=disks, disk_serials=disk_serials, state="fault")
      return task_uuid

    else:
      return self.__set_led_state(disks, disk_serials, "fault")

  @rpchandler
  def led_off(self, disks=None, disk_serials=None, parent_task_uuid=None):
    """
    Turn OFF the LED for the given disks.

    Args:
      disks (list): disks whose LEDs are to be disabled.
      disk_serials (list of string) : Serial numbers of disks.
      parent_task_uuid (str): UUID of parent ergon task.

      Function considers only 1 one of disk names or serials
      If both are provided or both are None then function will return error.

    Returns:
      bool: True if we set LED state for all specified disks, False otherwise.
        Task UUID if parent task uuid is provided.
    """
    if parent_task_uuid:
      async_rpc_util = AsyncRpcUtil(disk_manager=self)
      task_uuid = async_rpc_util.async_handler(
        func=self.__set_led_state, parent_task_uuid=parent_task_uuid,
        operation_type="kLedOff",
        disks=disks, disk_serials=disk_serials, state="off")
      return task_uuid

    else:
      return self.__set_led_state(disks, disk_serials, "off")

  @rpchandler
  def handle_tombstoned_disks(self, disk_serials):
    """
    When a disk is added into tombstoned disks list, Genesis notifies hades.
    If disk is mounted then try to unmount it. If successful return True,
    else reboot.
    Args :
      disk_serials (string) : List of disk serials.

    Return :
      bool: True if successful, False if shutdown token not granted else
        reboots.
    """
    log.INFO("Handling tombstoned disks %s" % disk_serials)

    zk_session = genesis_utils.get_zk_session(
      host_port_list=self.__host_port_list)
    if not zk_session:
      log.ERROR("Unable to obtain a Zookeeper session")
      return False

    node_disks = self.__get_node_disks_from_zeus(zk_session=zk_session)
    zeus_disk_serials = [disk.disk_serial_id for disk in node_disks]
    log.DEBUG("zeus_disk_serials: %s" % zeus_disk_serials)
    reboot_required = False
    undiscovered_disk_serials = []
    cloud_disk_serials = []
    sw_serviceable_nvme = None

    # Get Hades config for future calls.
    hades_config, _ = hades_utils.get_hades_proto(zk_session=zk_session,
                                                  retry_count=0)

    for disk_serial in disk_serials:
      log.INFO("Disk with serial %s is found in tombstoned disk list" %
                disk_serial)
      # Validating if the disk with the given disk serial is a cloud disk
      # removing the stargate data directory if cloud disk data directory
      # exists.
      # TODO: This logic does not handle the case where in the disk
      # directory entries do not exist and the disk serial is not evicted
      # from disk_tombstone_list.
      cloud_data_directory_path = \
        CloudHelperUtil.get_cloud_disk_data_directory(disk_serial)
      # If cloud disk directorties and contents are successfully removed
      # it will part of of cloud_disk_serials list else will be part of
      # undiscovered_disk_serials.
      if cloud_data_directory_path is not None:
        log.INFO("Disk serial %s is a cloud disk with contents in: %s" %
                 (disk_serial, cloud_data_directory_path))
        if not CloudHelperUtil.remove_cloud_disk_data_directory(
            cloud_data_directory_path):
          log.ERROR("Failed to remove the cloud data directory with contents "
                    "in %s for cloud disk serial %s" %
                    (cloud_data_directory_path, disk_serial))
          undiscovered_disk_serials.append(disk_serial)
        else:
          # We remove cloud disks from tombstone list iff the
          # respective cloud disk directories and its contents are removed.
          # This is to evict the disks from tombstone list in sync with the
          # removal of its directories and contents.
          cloud_disk_serials.append(disk_serial)
        continue

      # Continue only if the disk is not present in Hades or is removed from
      # node or is not an EC2 disk.
      if not (self.is_disk_present_hades(disk_serial,
                                         hades_config=hades_config,
                                         zk_session=zk_session) or
              self.disk_removed_from_node(disk_serial) or
              self.is_EC2_disk(disk_serial)):
        log.INFO("Disk %s does not belong to the node" % disk_serial)
        undiscovered_disk_serials.append(disk_serial)
        continue

      # Perform SPDK reset only if the disk is managed by SPDK.
      is_spdk_managed_disk = SPDKUtil.is_disk_serial_spdk_managed(
        disk_serial, hades_config)
      if is_spdk_managed_disk and FLAGS.spdk_enabled:
        # This flag helps to figure out true positives where spdk reset was
        # done, vs., the disks where spdk reset was not even required.
        spdk_reset_done = SPDKUtil.spdk_reset(disk_serial, hades_config)

        if not spdk_reset_done:
          # Don't add to undiscovered_disk_serials here, manage it later when
          # we check for spdk managed. For ex: Disks hotunplugged return False.
          log.ERROR("Could not reset SPDK on disk %s" % disk_serial)

        # Verify that SPDK reset has been performed.
        if SPDKUtil.is_disk_serial_spdk_managed(disk_serial, hades_config):
          log.ERROR("Disk %s is still managed by SPDK, despite running SPDK "
                    "reset" % disk_serial)
          undiscovered_disk_serials.append(disk_serial)
          continue

        # Let's ensure the disk actually shows up in the sysfs. But check only
        # for spdk disks, as the ones that were hotunplugged won't show up.
        # Their existence was already checked above.
        if spdk_reset_done:
          retries = 5
          disk_name = None
          while retries:
            disk_name = self.disk_serial_to_block_device(disk_serial)

            if disk_name is not None:
              break

            retries -= 1
            if retries:
              log.INFO("Could not find the disk name, trying again in 5 "
                       "seconds")
              time.sleep(5)
          else:
            log.ERROR("Could not discern device path from serial %s" %
                      disk_serial)
            undiscovered_disk_serials.append(disk_serial)
            continue

      if disk_serial in zeus_disk_serials:
        log.ERROR("Tombstoned disk: %s still part of node in zeus_config. "
                  "Unusual state, can be due to disk moved from another node. "
                  "If not, then something wrong. Ignore tombstone handling" % \
                  (disk_serial))
        undiscovered_disk_serials.append(disk_serial)
        continue

      # Disk not part of node's disks in zeus_config. Try to unmount it.
      mount_path = self.__get_mount_path(disk_serial)
      disk_name = self.disk_serial_to_block_device(disk_serial)

      log.INFO("Disk with serial %s has %s mount path and %s disk name" %
               (disk_serial, mount_path, disk_name))

      # For NVMe disk, remove disk from RAID. This is necessary as PCI
      # driver does not handle disk removal when disk partitions are part of
      # RAID.
      if NvmeDisk.is_nvme_device(disk_name):
        log.INFO("Remove RAID partition for nvme disk %s" % disk_name)
        if not raid_utils.fail_and_remove_disk_from_raid_if_attached(
                disk_name):
          log.ERROR("RAID fail and removal of disk: %s failed. Disk serial: "
                    "%s" % (disk_name, disk_serial))

      if not self.unmount_disk_path_retry(mount_path, "f"):
        log.ERROR("Failed to unmount tombstoned disk %s" % mount_path)
        reboot_required = True
        continue

      # Handling hypervisor managed disks.
      is_nvme_device = NvmeDisk.is_nvme_device(disk_name)

      # Set the flag sw_serviceable_nvme once on a NVMe system.
      # This flag is not required to be set for each disk, as it is node
      # property.
      if is_nvme_device:
        if sw_serviceable_nvme is None:
          log.DEBUG("Evaluating NVMe SW Serviceability")
          sw_serviceable_nvme = is_feature_enabled(
              zk_session, PlatformSolutionCapabilities.kSWServiceableNVMe)
        log.INFO("Device {} managed by SW serviceability: {}".format(
            disk_name, sw_serviceable_nvme))

      cloud_cluster = HardwareLayout.get_instance().is_cloud_cluster()
      log.INFO("Node is a cloud cluster: %s" % cloud_cluster)

      hypervisor_managed_nvme = (is_nvme_device
                                 and not NvmeDisk.is_vmd_managed(disk_name)
                                 and not sw_serviceable_nvme
                                 and not cloud_cluster)

      if hypervisor_managed_nvme:
        # Clear tombstone entry for disk. PCI Removal of disk causes disk
        # remove event. So disk will remain in zeus tombstone list as disk
        # is not present in Hades proto. This is reason clear tombstone
        # needs to be called before pci disk removal.
        log.INFO("%s is hypervisor controlled NVMe" % disk_name)
        self.__clear_tombstone_disks(zk_session=zk_session,
                                     handled_disk_serials=[disk_serial])

        host_type = Hypervisor.get_hypervisor_type()
        if (host_type == ConfigurationProto.ManagementServer.kKvm or
            host_type == ConfigurationProto.ManagementServer.kHyperv):
          is_hyperv = (
            host_type == ConfigurationProto.ManagementServer.kHyperv)
          _, tool_path = NvmeDisk.nvme_tool_path(is_hyperv=is_hyperv)
          if tool_path:
            # Get current disk serial and slot details for NVMe disk.
            nvme_disk = NvmeDisk.get_instance()
            old_disk_serial = nvme_disk.nvme_disk_serial(disk_name)
            serial_slot_id_dict = NvmeDisk.nvme_serial_slot_id(is_hyperv)
            disk_slot = serial_slot_id_dict[old_disk_serial]

            zk_path = os.path.join(FLAGS.hades_znode_dir, "nvme_breakfix")
            zk_json = {disk_name: (old_disk_serial, disk_slot)}
            if not genesis_utils.set_zk_json_info(zk_session, zk_path,
                                                  zk_json):
              log.ERROR("Unable to store NVMe drive %s info in zk, %s" % (
                        disk_name, zk_json))
            else:
              log.INFO("Stored NVMe drive %s info for breakfix %s" % (
                        disk_name, zk_json))

            log.INFO("Start new thread to monitor %s" % disk_name)
            thread.start_new_thread(self.monitor_nvme_disk_removal,
                                  (disk_name,))
          else:
            # Since nvme tool is not available, change in serial during
            # insertion of new nvme disk cannot be monitored
            log.INFO("NVMe drive %s is being removed. Run nvme_breakfix "
                     "after new drive is inserted" % disk_name)

        elif host_type == ConfigurationProto.ManagementServer.kVMware:
          # In case of ESX hypervisor, Copy all scripts required for
          # reconfiguring ESX and CVM after ESX reboot. This is done to
          # simplify manual procedure. In case any error is seen, run
          # nvme_breakfix script which automates NVMe breakfix for ESX.
          try:
            host = host_upgrade_helper.get_host()

            ret, err = host.setup_upgrade_script_after_host_reboot()
            if not ret:
              log.ERROR("Error setting up run esx_upgrade after esx boot "
                        ", err %r" % err)

            cmd = "touch %s && sync" % "/scratch/.cvm_pci_reconfig_marker"
            ret, out, err = host.get_ssh_client().execute(cmd)
            if ret != 0:
              log.ERROR("Unable to run cmd %s, ret %s out %s err %s" % (
                        cmd, ret, out, err))

            src = os.path.join(FLAGS.genesis_bin_dir, "esx_pci_reconfig_cvm")
            dest = "/scratch/esx_pci_reconfig_cvm"
            ret = host.copy_file(src, dest)
          except TypeError as ee:
            log.ERROR("Exception seen while setting up break fix scripts "
                      "for NVMe drive on ESX, err %s" % ee)
            log.ERROR(traceback.format_exc())

      if disk_name and not self.led_fault([disk_name]):
        log.ERROR("Failed to light up LED for %s" % disk_name)

      if hypervisor_managed_nvme:
        # Trigger disk removal.
        if not NvmeDisk.trigger_disk_remove(disk_name):
          log.ERROR("Removal of disk %s from PCI failed" % disk_name)

    discovered_disk_serials = list((set(disk_serials) -
                                   set(undiscovered_disk_serials)) -
                                   set(cloud_disk_serials))

    # ENG-437209 - In scenarios such as Hibernate Restore, the ephemeral disks
    # do not belong to any node. In such cases, return early, and avoid any
    # proto updates done further.
    if not discovered_disk_serials and not cloud_disk_serials:
      log.INFO("None of the tombstoned disks handled. Return early")
      return True

    # Clear those disks that are mounted in hades from tombstone list.
    # This could happen when same disk is added back after remove while
    # data migration is happening.
    self.__clear_tombstone_disks(zk_session=zk_session,
                                 handled_disk_serials=discovered_disk_serials,
                                 cloud_disk_serials=cloud_disk_serials)

    if not self.__setup_hades_proto(zk_session=zk_session):
      log.ERROR("Failed to update hades proto")

    # Synchronize disks information.
    if not self.__update_hades_disks_state(zk_session=zk_session):
      log.ERROR("Failed to update disks state in hades")

    log.INFO("Fail and Remove disks present in tombstoned list from raid")
    for disk_serial in discovered_disk_serials:
      disk_name = self.disk_serial_to_block_device(disk_serial)
      if not raid_utils.fail_and_remove_disk_from_raid_if_attached(
              disk_name):
        log.ERROR("Fail and Removal of disk: %s in RAID failed. Disk serial: "
                  "%s" % (disk_name, disk_serial))

    # Tombstone disk handling done, safe to delete stale mountpaths now. Needs
    # to be the last operation to take care of hotunplugged disks.
    self.delete_stale_mounts(discovered_disk_serials)

    # Check if SED managed devices are present on the node.
    self.__sed_devices_present = sed_utils.sed_drive_present()
    log.INFO("Tombstoned disks handled successfully: %s" %
             discovered_disk_serials)
    if undiscovered_disk_serials:
      log.ERROR("Tombstoned disks unhandled: %s" % undiscovered_disk_serials)

    if reboot_required:
      log.ERROR("Failed to unmount tombstoned disks. Try reboot")
      if not FLAGS.skip_disk_remove_reboot:
        log.INFO("Trying to get a shutdown token and reboot to handle removed "
                 "disks %s" % discovered_disk_serials)
        return self.grab_shutdown_token_and_reboot()
      log.INFO("Skipping reboot for tombstoned disks")

    return True

  def delete_stale_mounts(self, disk_serials=None):
    """
    For given disks, delete mountpaths if empty. Else ignore and proceed.
    Args:
      disk_serials (list): List of disk serials.
    """
    if not disk_serials:
      log.ERROR("No disk serial provided for mountpath delete")
      return

    for disk_serial in disk_serials:
      mount_paths = []
      mount_paths.append(self.__get_mount_path(disk_serial))
      # For ext4-blockstore filesystem (used only for internal testing), we
      # need to remove block_store_<disk_serial> as well.
      ext4_bstore_path = "block_store_" + disk_serial
      mount_paths.append(os.path.join(self.__stargate_disk_directory,
                                      ext4_bstore_path))
      try:
        for mount_path in mount_paths:
          if not os.path.isdir(mount_path):
            log.DEBUG("Mount path: %s does not exist" % mount_path)
            continue

          if not len(os.listdir(mount_path)):
            log.INFO("Deleting mount path directory: %s" % mount_path)
            os.rmdir(mount_path)
          else:
            log.WARNING("Mount path: %s is not empty. Contents:\n%s\nDefer "
                        "deleting it" % (mount_path, os.listdir(mount_path)))
      except (OSError, IOError) as ex:
        # Log an error, but don't take any action.
        log.ERROR("Error in deleting mount paths: %s, with exception: %s" %
                  (mount_paths, str(ex)))

  def monitor_nvme_disk_removal(self, disk_name):
    """
    Monitor nvme disk removal on hypervisor. When disk is inserted trigger
    CVM reboot. This workflow is only applicable for AHV and HyperV.
    """
    # Get serial/slot details from zk path.
    zk_session = genesis_utils.get_zk_session(self.__host_port_list)
    zk_path = os.path.join(FLAGS.hades_znode_dir, "nvme_breakfix")
    zk_json = genesis_utils.get_zk_json_info(zk_session, zk_path)
    if not zk_json or not zk_json.get(disk_name, None):
      log.ERROR("Unable to read breakfix params for Nvme drive %s from "
                "zookeeper, zk_json %s " % (disk_name, zk_json))
      return
    disk_serial, disk_slot = zk_json[disk_name]

    is_hyperv = (Hypervisor.get_hypervisor_type() ==
                 ConfigurationProto.ManagementServer.kHyperv)
    if NvmeDisk.monitor_nvme_disk_removal_on_host(
        disk_name, str(disk_serial), str(disk_slot), is_hyperv):
      # Get Node Details.
      node_position = "-" # Default value is blank for alert message.
      node_serial = "-" # Default value is blank for alert message.
      factory_config = util.cluster.info.get_factory_config()
      if factory_config:
        log.DEBUG("Node Factory Config: %s" % factory_config)
        node_position = factory_config.get("node_position", "-")
        node_serial = factory_config.get("node_serial", "-")

      service_vm_external_ip = self.__get_node_cvm_external_ip()
      service_vm_id = self.__get_node_cvm_id()
      disk_model = (self.__get_disk_model_hades_proto(disk_serial)
                    or "Unknown")
      disk_location = (self.get_disk_slot_designation(disk_serial)
                       or "Unknown")
      timestamp_csecs = int(time.time() * 100)

      # For NVME disk on AHV platform. since PCI device is unplugged UDEV
      # events are not visible to CVM. Thus, CVM will not get to know
      # when a disk is physically removed.
      # When a new disk is inserted, this thread is able to catch that
      # particular event. Hence, raising an alert here when the disk has
      # been swapped.
      ALERT_NOTIFY("CRITICAL", PhysicalDiskRemove,
                   disk_serial=disk_serial,
                   disk_location=disk_location,
                   service_vm_id=service_vm_id,
                   service_vm_external_ip=service_vm_external_ip,
                   timestamp_csecs=timestamp_csecs, disk_model=disk_model,
                   node_position=node_position,
                   node_serial_number=node_serial,
                   rf1_custom_message=ContainerUtil.rf1_custom_message(
                     disk_serial))
      log.INFO("%s disk has been reinserted" % disk_name)

    # Remove entry from zk json.
    zk_json = genesis_utils.get_zk_json_info(zk_session, zk_path)
    del zk_json[disk_name]
    if not genesis_utils.set_zk_json_info(zk_session, zk_path, zk_json):
      log.ERROR("Unable to remove NVMe drive %s info in zookeeper, "
                "zk_json %s" % (disk_name, zk_json))
    else:
      log.INFO("Removed NVMe drive %s info for breakfix in zookeeper, "
               "zk_json  %s" % (disk_name, zk_json))

    # For AHV nodes.
    if not is_hyperv:
      src = os.path.join(FLAGS.genesis_bin_dir, "kvm_start_cvm")
      dest = "/root/kvm_start_cvm"

      log.INFO("Copying file %s to %s" % (src, dest))
      ssh_client = KvmSSHClient(FLAGS.hypervisor_internal_ip,
                                FLAGS.hypervisor_username)
      ret, out, err = ssh_client.transfer_to(src, dest, timeout_secs=-1)
      if ret != 0:
        log.ERROR("Error copying %s to %s on host, ret %s, out %s, err %s" % (
                  src, dest, ret, out, err))
        return

      cmd = "/usr/bin/nohup %s 1>/dev/null 2>&1 &" % dest
      ret, out, err = ssh_client.execute(cmd)
      if ret != 0:
        log.ERROR("Error running cmd %s on host, ret %s, out %s, err %s" % (
                  cmd, ret, out, err))
        return
      # Powering off CVM for AHV
      shutdown_cmd = "poweroff"

    # For HyperV nodes.
    else:
      # For HyperV, we want to reboot the CVM instead of poweroff.
      shutdown_cmd = "winsh Restart-CVMAfterNvmeBreakfix"

    log.INFO("Grab shutdown and go for reboot")
    self.grab_shutdown_token_and_reboot(shutdown_cmd=shutdown_cmd)
    return

  @rpchandler
  def handle_stargate_disk_offline_event(self, disk_serial_short):
    """
    This RPC is intended to be called by NodeManager (or anyone watching the
    offline mount path). When a disk is marked offline, Hades will be notified
    (via this RPC) and will determine whether to try to re-add it back into the
    datapath, or treat it as a bad disk altogether.

    Args:
      disk_serial_short (string): Path which stargate is unhappy about

    Note about args:
      Stargate will mark a mount-path as offline, from which we have to infer
      serial_short, and from there we have to infer disk_name. We'll expect
      our caller (who is presumably watching the ZK nodes) to do this before
      calling this RPC.

    Returns:
      True if handled successfully, False otherwise.
    """
    log.INFO("Stargate is unhappy with %s. Determining course of action" %
             disk_serial_short)

    mount_path = ZeusUtil.get_mount_path_from_disk_serial(disk_serial_short)
    if mount_path and FLAGS.enable_disk_offline_alert:
      ALERT_NOTIFY("CRITICAL", PathOffline,
                   mount_path=mount_path,
                   ip_address=self.__get_node_cvm_external_ip(),
                   service_vm_id=hades_utils.get_node_cvm_id())
    else:
      log.ERROR("Failed to fetch mount path for disk: %s, failed to "
                "trigger disk offline alert for disk: %s" %
                (disk_serial_short, disk_serial_short))
    driver_discovered = True
    pcie_path_exists = False

    # Check if the disk is present in the Hades Proto.
    disk_present_in_proto = self.is_disk_present_hades(disk_serial_short)
    log.DEBUG("Disk with serial '%s' present in the proto: %s" %
              (disk_serial_short, disk_present_in_proto))

    # Check if the device is managed by PCIe. If so, we will perform SPDK
    # operations.
    pcie_managed = SPDKUtil.is_serial_pcie_managed(disk_serial_short)
    log.DEBUG("Disk with serial '%s' managed by PCIe: %s" %
              (disk_serial_short, pcie_managed))

    if FLAGS.spdk_enabled and disk_present_in_proto and pcie_managed:
      # Reset SPDK on the device.
      if not SPDKUtil.spdk_reset(disk_serial_short):
        log.ERROR("Could not reset SPDK on disk %s" % disk_serial_short)
        return False

      # Verify that SPDK reset has been performed.
      if SPDKUtil.is_disk_serial_spdk_managed(disk_serial_short):
        log.ERROR("Disk %s is still managed by SPDK, despite running SPDK "
                  "reset" % disk_serial_short)
        return False

      # Check if the PCIe path is even present. The absence reflects a disk
      # hot unplug.
      pcie_path_exists = SPDKUtil.pcie_path_exists(disk_serial_short)
      if not pcie_path_exists:
        log.ERROR("PCIe path for disk %s does not exist" % disk_serial_short)
        driver_discovered = False
        log.INFO("Invoking disk remove RPC for disk serial %s" %
                 disk_serial_short)
        return self.handle_disk_remove(disk_name="Unknown",
                                       disk_serial_short=disk_serial_short)
      else:
        # Since the PCIe path exists, check if the drive is accessible.
        if SPDKUtil.is_nvme_drive_inaccessible(disk_serial_short):
          log.ERROR("No driver discovered for disk with serial '%s'" %
                    disk_serial_short)
          driver_discovered = False
        else:
          log.INFO("Driver discovered for disk with serial '%s'" %
                   disk_serial_short)

      # Ensure the disk is discoverable in the kernel.
      retries = 5

      while driver_discovered and retries:
        blk_dev = self.disk_serial_to_block_device(disk_serial_short)
        if blk_dev is None:
          log.ERROR("Disk with serial %s not found in the kernel yet." %
                    disk_serial_short)
          retries -= 1
          if retries:
            log.ERROR("Trying again in 5 seconds")
            time.sleep(5)
          else:
            log.ERROR("Could not discover disk with serial %s in the kernel" %
                      disk_serial_short)
            return False
        else:
          log.INFO("Disk with serial %s was discovered at %s" %
                   (disk_serial_short, blk_dev))
          break

    disk_id = self.disk_serial_to_disk_id(disk_serial_short) or -1

    # Generate disk diagnostics dictionary.
    disk_diag_dict = {}
    disk_diag_dict["disk_id"] = str(disk_id)
    disk_diag_dict["disk_serial"] = str(disk_serial_short)
    disk_diag_dict["reason"] = self.__get_disk_error(disk_serial_short)
    disk_diag_dict["service_vm_id"] = hades_utils.get_node_cvm_id()
    disk_diag_dict["timestamp"] = time.strftime("%x %X")
    all_diag_disks = []

    # Ensure permissions are always set to nutanix. ASUP sender deletes the
    # file every 24 hours and we may not have restarted hades.
    open(FLAGS.disk_diagnostics_asup_path, 'a').close()
    os.chown(FLAGS.disk_diagnostics_asup_path,
             self.__nutanix_uid,
             self.__nutanix_gid)

    # Read the existing ASUP data if present.
    try:
      with open(FLAGS.disk_diagnostics_asup_path) as asup_fd:
        all_diag_disks = json.load(asup_fd)
    except:
      log.INFO("No ASUP data present")

    # Append new data to list.
    all_diag_disks.append(disk_diag_dict)

    # Dump it to the json file.
    log.INFO("Writing ASUP data for disk_serial %s for reason %s at path %s" %
             (disk_serial_short, disk_diag_dict["reason"],
              FLAGS.disk_diagnostics_asup_path))
    try:
      with open(FLAGS.disk_diagnostics_asup_path, "w") as asup_fd:
        json.dump(all_diag_disks, asup_fd)
    except:
      log.ERROR("Failed to write ASUP data")

    if self.disk_under_diagnosis(disk_serial_short):
      log.ERROR("Diagnostics test already running for disk %s" %
                disk_serial_short)
      return False

    disk_diags, disk_present = DiskDiagnostics.get_disk_diagnostics_object(
        disk_serial_short, self)

    # If disk is not present in the system, we cannot run diagnostics on the
    # disk. We cannot mark the disk bad either since we do not know
    # conclusively that the disk is bad. We have to leave the disk in the
    # offline state, additionally mark it for removal, and return.
    if not disk_present:
      # Specific case: This is a pci_managed disk which could not attach to a
      # driver. Log a specific error, leave the disk in the offline state and
      # return.
      if not driver_discovered:
        log.ERROR("Driver not discovered for disk with serial '%s', likely "
                  "resulting in disk being in an offline state. Retaining "
                  "the offline state and additionally marking it for removal" %
                  disk_serial_short)

      # General case: The disk was not found in the system but we don't know
      # why. Leave it in the offline state and return.
      else:
        log.ERROR("Cannot find disk %s in the system, leaving disk in "
                  "offline state and additionally marking it for removal" %
                  disk_serial_short)

      # Mark the disk for removal to prevent Cassandra crash loop.
      disk_id = self.disk_serial_to_disk_id(disk_serial_short)
      if not self.change_to_remove_for_disks([disk_id], operation="set"):
        log.ERROR("Failed to set to_remove for disk ids %s and serial %s" %
                  (disk_id, disk_serial_short))
      return True

    is_disk_bad = False

    if disk_diags is None:
      log.ERROR("Failed to get disk diagnostics for disk %s, marking it bad" %
                disk_serial_short)
      is_disk_bad = True

    elif disk_diags.exceeds_error_threshold():
      log.WARNING("Disk (serial %s) exceeds error thresholds. Not doing "
                  "anything more with this disk." %
                  (disk_serial_short))
      is_disk_bad = True

    else:
      if FLAGS.experimental_wait_for_ro_mount_intent_file_secs:
        # Wait for read-only mount intent file for this disk. This is best
        # effort op, i.e., even if intent file doesn't show up, proceed to fix
        # drive mount state. Why? - Sometimes, these ro-mount states could be
        # genuine, i.e., not induced by nutest.
        #
        # There'd be a unique intent file per device, prefixed by disk_serial.
        ro_mount_file = disk_serial_short + "_ro_mount_intent.txt"
        ro_mount_path = os.path.join(FLAGS.nutanix_data_dir, ro_mount_file)

        # Avoid modifying the flag itself, as, the same could be used for
        # multiple sub-tests.
        wait_time_secs = FLAGS.experimental_wait_for_ro_mount_intent_file_secs
        sleep_time_secs = 5

        log.DEBUG("Wait for %s secs for read-only mount intent file: %s" % (
          wait_time_secs, ro_mount_path))

        while wait_time_secs > 0 and not os.path.exists(ro_mount_path):
          log.DEBUG("Waiting for read-only mount intent file: %s. Check again "
                    "after %s secs" % (ro_mount_path, sleep_time_secs))
          wait_time_secs -= sleep_time_secs
          time.sleep(sleep_time_secs)
        else:
          if wait_time_secs <= 0:
            log.ERROR("Failed to detect read-only mount intent file: %s in % "
              "secs. Proceed anyway" % (ro_mount_path,
              FLAGS.experimental_wait_for_ro_mount_intent_file_secs))
          else:
            log.INFO("Detected read-only mount intent file: %s" % ro_mount_path)

      # Run short diagnostic test on the disk. After the test, the disk will be
      # added/removed from active disk list.
      #
      # This is where diagnostics are run, and, corrective actions taken to
      # recover drive's mount status, i.e., tribulations to fix drive's
      # read-only state.
      disk_diags.run_diagnostics("short")

    if is_disk_bad:
      disk_id = self.disk_serial_to_disk_id(disk_serial_short)
      if not disk_id:
        log.ERROR("Failed to get disk id for disk with serial %s" %
                  disk_serial_short)
      if not self.change_to_remove_for_disks([disk_id], operation="set"):
        log.ERROR("Failed to set to_remove for disk ids %s and serial %s" %
                  (disk_id, disk_serial_short))

      # If it is a metadata disk, defer unmount until migration completes.
      # Migration gets triggered by setting disk to_remove. Once that
      # completes, disk gets added to tombstone list and the handling of that
      # would unmount it.
      if not self.mark_bad_disk(disk_serial_short,
                                defer_unmount=self.is_metadata_disk(disk_id)):
        log.ERROR("Unable to mark disk as bad %s" % disk_serial_short)
        return False

    return True

  @rpchandler
  def mark_disks_stargate_unusable(self, disks, disk_serials=[]):
    """
    Marks disk(s) unusable for stargate. Disks and/or disk serials can be
    provided to the routine.

    Args:
      disks(list): List of disk paths. E.g.: [/dev/sda].
      disk_serials(list): List of disk serials. E.g.: ["SN12345"].

    Returns True if successful, False otherwise.
    """
    return self.__change_disks_stargate_usable_state(disks, disk_serials,
                                                     "unusable")

  @rpchandler
  def mark_disks_stargate_usable(self, disks, disk_serials=[]):
    """
    Marks disk(s) usable for stargate. Disks and/or disk serials can be
    provided to the routine.

    Args:
      disks(list): List of disk paths. E.g.: [/dev/sda].
      disk_serials(list): List of disk serials. E.g.: ["SN12345"].

    Returns True if successful, False otherwise.
    """
    return self.__change_disks_stargate_usable_state(disks, disk_serials,
                                                     "usable")

  @rpchandler
  def clean_disks(self, disks, add_can_repartition=False, mount_disk=True,
                  skip_repartition=False):
    """
    Takes a list of disks and formats each partition on disk.
    Params:
    disks (list of string): List of disk block devices e.g. /dev/sda.
    add_can_repartition (bool): Add repartition marker for older genesis.
    mount_disk (bool): If true then mount the disks, else skip mounting.
    skip_repartition (bool): If true, we skip repartition/reformat of the disk.

    Returns True if successful, False otherwise.
    """
    run_parallel = FLAGS.run_parallel

    # If we have SEDs, we will not attempt to run clean disks in parallel,
    # for there could be thread unsafe operations with the KMS.
    if run_parallel and self.__sed_devices_present:
      run_parallel = FLAGS.enable_sed_clean_disks_parallel
      log.INFO("Parallel cleanup of SED enabled: %s " % run_parallel)

    if not run_parallel:
      status = True
      for disk in disks:
        if not self.__clean_disk(
          disk, add_can_repartition, mount_disk, skip_repartition):
          log.ERROR("Failed to clean disk %s" % disk)
          status = False
      return status
    else:
      pe = ParallelExecutor(pool_size=FLAGS.clean_disks_pe_pool_size)
      log.INFO("Cleaning {} disks in parallel with pool_size: {}".\
                 format(len(disks), FLAGS.clean_disks_pe_pool_size))
      for disk in disks:
        pe.add_task(self.__clean_disk,
                    [disk, add_can_repartition, mount_disk, skip_repartition],
                    thread_name="clean_disk_{}".format(disk.split("/")[-1]),
                    use_as_prefix=False)

      failures = []
      results = pe.run()
      for (disk, res) in zip(disks, results):
        if not res['result'] or res.get('exception') is not None:
          failures.append((disk, res.get('exception')))

      if failures:
        log.ERROR("Failed to clean disk(s): {}".format(failures))
        return False

      log.DEBUG("clean_disk times in seconds: {}".\
                  format(zip(disks, pe.get_completion_times())))
      return True

  @rpchandler
  def is_boot_disk(self, disk):
    """
    Check if a disk is active boot disk.
    Returns True if it is boot disk, else False.
    """
    log.DEBUG("Find if disk %s is boot disk" % disk)

    disk_obj = Disk(disk)
    if (disk_obj.is_svm_boot_disk() and
        len(disk_obj.partitions()) in [3, 4]):
      return True
    return False

  @rpchandler
  def update_hades_planned_outage(self, disk_serial, enable):
   """
   Enable (set) or disable (clear) planned outage.
   Args:
     disk_serial (str): Serial number of the disk.
     enable (bool): True if we want to set planned outage.
       False if we want to clear.

   Returns:
     bool: False if PMEM device. Otherwise True or False depending on set/clear
           success or failure.
   """
   log.DEBUG("Program hades planned outage for disk %s with flag %s" %
             (disk_serial, enable))

   # Planned outage is not supported for PMEM devices.
   if PmemDeviceUtil.is_pmem_device_serial(disk_serial):
     log.INFO("Planned outage is not supported for PMEM devices")
     return False

   if not enable:
     ret = self.__clear_hades_planned_outage(disk_serial)
   else:
     ret = self.__set_hades_planned_outage(disk_serial)

   log.DEBUG("Program hades planned outage returned %s" % ret)
   return ret

  @rpchandler
  def validate_cloud_disks(self, cloud_disk_map_list):
    """
    Validate cloud disks config and access to the endpoints.
    Args:
      cloud_disk_map_list(list): The cloud disk map as a list.

    Returns:
      (bool, str): Return (true, error as None) if all the cloud disks
        config and access points are validated.(False, error) otherwise.

    """
    log.INFO("Validating cloud disks config and the access to the end points")
    ret, err = CloudValidator.validate_cloud_disks(cloud_disk_map_list)
    if not ret:
      log.ERROR("Validation of cloud disks: %s failed with error: %s" %
               (cloud_disk_map_list, err))
    return ret, err

  @rpchandler
  def add_cloud_disks_to_cluster(self, cloud_disk_map_list):
    """
    RPC to add cloud disks to the ConfigurationProto disk_list.

    Args:
      cloud_disk_map_list(list): The cloud disk map as a list.

    Returns:
      (bool, str): Return (true, error as None) if all the cloud disks
        are populated/add to the Configuration Proto successfully.
        (False, error) otherwise.

    """
    log.INFO("Waiting for disk lock for adding cloud disks to "
             "ConfigurationProto")
    with self.__disk_mount_lock:
      log.DEBUG("Got disk lock for adding cloud disks to ConfigurationProto")
      log.INFO("Initiating adding cloud disks to the ConfigurationProto")

      log.DEBUG("Validating the cloud disk parameters\n%s" %
                (json.dumps(cloud_disk_map_list, indent=2)))

      # Checking for cloud type to be kAmazonS3.
      cloud_type = CloudValidator.get_cloud_type(cloud_disk_map_list)

      log.INFO("Discovered device type for add: %s" % cloud_type)

      if cloud_type == CloudStoreType.kAmazonS3:
        return AmazonCloudDiskUtil().add_amazon_cloud_disks_to_cluster(
          cloud_disk_map_list)
      else:
        err = "Cloud device type %s is not supported at this time" % cloud_type
        log.ERROR(err)
        return False, err

  @rpchandler
  def remove_cloud_disks_from_cluster(self, cloud_disk_list=[],
                                      remove_all=True):
    """
    RPC to remove cloud disk entries from the ConfigurationProto.
    This RPC marks the cloud disks with to_remove: true.

    Args:
      cloud_disk_list(list): List of disk_ids of cloud devices to be marked
        for removal. Default: Empty list.
      remove_all(bool): Remove all cloud disks from cluster if True. Default:
        True.

    Returns:
      (bool, str): (True, error as None) if the cloud disks were marked
        to_remove:True successfully. (False, error) otherwise.

    """
    # Right now we are considering this operation will be supported on only
    # Amazon S3, hence we are not checking for cloud_type.
    # TODO(Vishnu): In future, we will introduce a parameter for cloud type
    # to support for other cloud vendors.
    log.INFO("Waiting for disk lock for removing cloud disks from "
             "ConfigurationProto")
    with self.__disk_mount_lock:
      log.DEBUG("Got disk lock for removing cloud disks from "
                "ConfigurationProto")
      return AmazonCloudDiskUtil().remove_amazon_cloud_disks_from_cluster(
        cloud_disk_list, remove_all)

  @rpchandler
  def add_disks_to_cluster(self, multi_disk_oplog_supported=True,
                           rma_disk_list=[], raise_alert=True):
    """
    Generate disk_config.json and disk to configuration proto if hades proto
    has marked it as mounted.

    Args:
      multi_disk_oplog_supported(bool) : True if multi disk oplog is supported.
        (By default after 4.0 multi disk oplog is supported). Default: True.
      rma_disk_list(list): List of disk names to be RMA'd. Default: Empty list.
      raise_alert(bool): If set to True, raise alert wherever suitable.)
        Default: True to help in cases where disk was added when Hades was
        down.

    Returns:
      bool: True if successfully added, else False.
    """
    log.INFO("Waiting for disk mount lock for add disks to cluster")
    with self.__disk_mount_lock:
      log.DEBUG("Got disk mount lock for add disks to cluster")

      zk_session = ZookeeperSession(host_port_list=self.__host_port_list)
      if not zk_session.wait_for_connection(None):
        log.ERROR("Failed to get hades proto. Unable to obtain a zk session")
        return False

      config_proto = ZeusUtil.fetch_config_proto(zk_session=zk_session,
                                                 host_port_list=\
                                                   self.__host_port_list,
                                                 wait_for_connection=False)
      if config_proto is None:
        log.ERROR("Failed to get configuration proto")
        zk_session = None
        return False

      disks = self.usable_disks()
      if not disks:
        log.WARNING("No valid disk found for addition to cluster")
        zk_session = None
        return True

      log.INFO("Found valid disks, adding to cluster")

      # Data structures required for adding disks to cluster.
      disk_id_dev_node_map = {}

      # Filter out disks which are not marked as mounted in hades proto.
      hades_mounted_disks = []

      hades_proto, _ = hades_utils.get_hades_proto(zk_session=zk_session)
      for disk in disks:
        disk_obj = Disk(disk)
        serial_number = disk_obj.serial_number()
        if not serial_number:
          log.ERROR("Failed to find serial number for disk %s, "
                    "skipping the disk" % disk)
          continue

        if self.__is_boot_disk_only(serial_number, hades_proto=hades_proto):
          log.INFO("Boot disk only found with serial %s. Continuing" %
                   serial_number)
          continue

        if not self.__is_disk_mounted_hades(serial_number,
                                            hades_proto=hades_proto):
          log.ERROR("Disk %s with serial %s is not mounted in hades proto, "
                    "skipping the disk" % (disk, serial_number))
          continue
        hades_mounted_disks.append(disk)

      # If no disks are mounted in Hades, there's no point in Genesis starting
      # the rest of the services on the Cluster. Return False here.
      if len(hades_mounted_disks) == 0:
        log.INFO("No disk found eligible for cluster addition")
        zk_session = None
        return False

      log.INFO("Preparing disks %s for cluster addition" % hades_mounted_disks)
      duplicate_disks = []
      DuplicateDisk = collections.namedtuple("DuplicateDisk", [
        "disk_id",
        "serial_number",
        "block_device",
      ])
      disks_failed_to_configure = []

      for disk in hades_mounted_disks:
        disk_obj = Disk(disk)
        serial_number = disk_obj.serial_number()
        if not serial_number:
          log.ERROR("Failed to find serial number for disk %s, "
                    "skipping the disk" % disk)
          continue
        existing_disk_id = self.disk_serial_to_disk_id(
          serial_number, zk_session=zk_session,
          config_proto=config_proto)

        # Here, we gather / create the disk config.
        disk_config = self.__configure_disk(
          disk, zk_session=zk_session, config_proto=config_proto,
          rma_disk_list=rma_disk_list)
        if not disk_config:
          log.ERROR("Failed to configure disk %s for cluster addition, "
                    "skipping the disk" % disk)
          disks_failed_to_configure.append(disk)
          continue

        if (existing_disk_id != None and
            int(disk_config["disk_id"]) != int(existing_disk_id)):
          # This should not happen in regular case.
          # This means we have created duplicate entries.
          # We need to mark the old disk as removed so that it can
          # be removed cleanly.
          log.ERROR("Duplicate ids %s/%s detected for %s" %
                   (existing_disk_id, disk_config["disk_id"], serial_number))
          duplicate_disks.append(DuplicateDisk(
            disk_id=existing_disk_id,
            serial_number=serial_number,
            block_device=disk,
          ))

        # Update disk id to disk name mapping.
        disk_id_dev_node_map[int(disk_config["disk_id"])] = disk

      if duplicate_disks:
        log.INFO("Refusing to add duplicate disks, "
                 "marking originals for removal: %s" % duplicate_disks)
        duplicate_disk_ids = []
        for disk in duplicate_disks:
          duplicate_disk_ids.append(disk.disk_id)
          hades_mounted_disks.remove(disk.block_device)
        if not self.change_to_remove_for_disks(duplicate_disk_ids, "set"):
          log.ERROR("Cannot mark disk(s) %s for removal" % duplicate_disk_ids)
          zk_session = None
          return False

      if not hades_mounted_disks:
        log.ERROR("No mounted disks suitable for addition")
        zk_session = None
        return False

      if disks_failed_to_configure:
        log.ERROR("Failed to configure disks: %s" % disks_failed_to_configure)

      if disks_failed_to_configure and (set(disks_failed_to_configure) ==
                                        set(hades_mounted_disks)):
        log.ERROR("Failed to configure any disks for cluster addition")
        zk_session = None
        return False

      log.INFO("Finished configuring disks")

      # Remove disks that failed to configure from usable disks.
      zeus_disks = \
        list(set(hades_mounted_disks) - set(disks_failed_to_configure))

      log.DEBUG("disk id to dev node map is %s" % disk_id_dev_node_map)
      log.DEBUG("Disks to be updated in ZK: %s" % zeus_disks)

      # Add disks to the ConfigurationProto in Zookeeper.
      rv = self.__update_stargate_disks_in_zeus(
        zeus_disks,
        disk_id_dev_node_map,
        zk_session=zk_session,
        multi_disk_oplog_supported=multi_disk_oplog_supported,
        rma_disk_list=rma_disk_list,
        raise_alert=raise_alert,
        hades_proto=hades_proto)

      zk_session = None
      return rv

  #
  # RPCs for debugging purpose.
  #
  @rpchandler
  def DEBUG_handle_disk_hotplug(self, disk_name, disk_serial_short):
    """
    Simulate disk hot plug.
    """
    return self.handle_disk_add(disk_name, disk_serial_short)

  @rpchandler
  def DEBUG_handle_disk_hotunplug(self, disk_name, disk_serial_short):
    """
    Simulate disk hot unplug.
    """
    return self.handle_disk_remove(disk_name, disk_serial_short)

  def __ignore_device(self, disk_name):
    """
    Return True if disk operations like add/delete need to be ignored for given
    disk_name, else returns False.
    """
    if disk_name is None:
      return False

    # Ignore loopback devices.
    # Ignore RAID devides also since we have seen when host is shutdown we end
    # up getting udev events for RAID devices causing false alerts.
    loop_dev_name_pattern = re.compile("/dev/(loop[0-9]*|md[0-9]*)")
    if loop_dev_name_pattern.search(disk_name):
      log.INFO("Ignore disk operation for disk %s" % disk_name)
      return True
    return False

  def update_disk_mount_state(self, disk_serial, should_mount=False,
    zk_session=None):
    """
    Routine to mark a disk mounted or unmounted in the Hades proto.

    Args:
      disk_serial(str): The serial number of the disk.
      should_mount(bool): The update to hades proto is_mounted state.
        Default: False.
      zk_session(ZookeeperSession): Zookeeper session obj. Default: None.

    Returns:
      bool: True on success, False on failure.
    """
    if not zk_session:
      zk_session = ZookeeperSession(host_port_list=self.__host_port_list)
    hades_config, version = hades_utils.get_hades_proto(zk_session)

    if hades_config is None:
      log.ERROR("Failed to get hades configuration")
      return False

    # No need to add PMem gflag here as is_pmem_device_serial internally
    # handles it.
    if PmemDeviceUtil.is_pmem_device_serial(disk_serial):
      device = PmemDeviceUtil.get_pmem_device_from_config(hades_config,
                                                          disk_serial)
      if device:
        device.is_mounted = should_mount
      else:
        log.ERROR("Could not find PMEM device with serial %s in the Hades "
                  "proto" % disk_serial)
        return False
    else:
      for slot in hades_config.slot_list:
        if slot.disk_present and slot.disk.serial == disk_serial:
          slot.disk.is_mounted = should_mount
          break
      else:
        log.ERROR("Could not find disk with serial %s in the Hades proto" %
                  disk_serial)
        return False

    # Commit the Hades proto.
    while True:
      log.INFO("Attempting to commit modified Hades proto")
      ret = hades_utils.commit_hades_proto(hades_config, version, zk_session)
      if not ret:
        log.WARNING("Failed to set new hades config. Potential CAS error. "
                    "Retrying")
        time.sleep(1)
        continue
      break

    log.INFO("Successfully marked disk serial %s with mount state: %s" %
             (disk_serial, should_mount))
    return True

  def disk_skews_tier(self, disk, zk_session):
    """
    Routine to check if a disk introduces a skew in the tier that it belongs
    to.

    Args:
      disk(str): The device path. E.g.: /dev/sda.
      zk_session(session object): The Zookeeper session object.

    Returns:
      bool: True if the disk skews the tier. False if not.
    """
    if PmemDevice.is_pmem_device(disk):
      log.DEBUG("Skipping disk skew tier check for PMEM device %s" % disk)
      return False

    dsm = DiskSkewManager()

    # Fetch the ConfigurationProto of the cluster.
    config = Configuration().initialize(
      host_port_list=self.__host_port_list, zk_session=zk_session)
    config_proto = config.config_proto()

    # Fetch the default disk_size for this disk.
    disk_serial = Disk(disk).serial_number().strip()

    mountpoint = self.__get_mount_path(disk_serial)
    statfs_size = DiskSizeUtil.get_statvfs_size_bytes(mountpoint)

    if statfs_size is None:
      log.ERROR("Unable to determine statfs size of disk %s" % disk)
      return False
    log.INFO("Statfs size of disk %s: %d bytes" % (disk, statfs_size))

    default_disk_size = DiskSizeUtil.default_disk_size(statfs_size)
    log.INFO("Default disk_size of disk %s: %d bytes" %
             (disk, default_disk_size))

    skews_tier = dsm.disk_add_skews_tier(disk, config_proto, default_disk_size)

    log.INFO("Disk %s introduces a skew: %s" % (disk, skews_tier))

    return skews_tier

  @rpchandler
  def is_node_storage_tier_skewed(self, serial):
    """
    This routine checks if disk's storage tier is skewed. This
    only works for kernel managed devices.

    Args:
      serial(str): The serial number of the device under consideration.
    Returns:
      bool: True, if the tier of the disk is skewed, False if not skewed.
      NoneType: Should an invalid serial be supplied or the cluster is
        not configured.
    """
    if serial is None:
      log.ERROR("Invalid device supplied")
      return None

    if PmemDeviceUtil.is_pmem_device_serial(serial):
      log.DEBUG("Skipping storage tier skew check for PMEM device %s" % serial)
      return False

    # Convert disk serial to disk path.
    disk = self.disk_serial_to_block_device(serial)

    if disk is None:
      log.ERROR("Could not find disk with serial %s in the kernel")
      return None

    log.INFO("Disk with serial %s is %s" % (serial, disk))

    # Check if the cluster is configured.
    is_cluster_configured = self.__is_cluster_configured()
    if not is_cluster_configured:
      log.ERROR("Cluster is not configured")
      return None

    # Fetch the cached ConfigurationProto.
    config_proto = ZeusUtil.fetch_config_proto()

    if config_proto is None:
      log.ERROR("Unable to fetch the ConfigurationProto")
      return None

    # Fetch the tier of the disk under consideration.
    tier = utils.find_storage_tier(disk)
    log.INFO("Tier of disk %s: %s" % (disk, tier))

    # Check if the tier of the node under consideration is skewed.
    dsm = DiskSkewManager()
    tier_skewed = dsm.is_tier_skewed(config_proto, tier)
    log.INFO("Tier %s of disk %s is skewed: %s" % (tier, disk, tier_skewed))

    return tier_skewed

  #
  # - - - - - [ private/non-RPC/helper methods ] - - - - -
  #
  def handle_disk_add(self, disk_name, disk_serial_short,
                      spdk_state_change=False):
    """
    Handle the hotplug/addition of a new disk in the system.

    Params:
      disk_name (string): Name of disk device (e.g.: /dev/sdc). MUST BE MOUNTED.
      disk_serial_short (string): ID_SERIAL_SHORT for this disk.
      spdk_state_change (bool): If the disk add was due to SPDK state
        change. SPDK state change is detected when there was a uio remove
        event along with this block device add event. Default False.

    Returns:
      bool: True if we could take some action on the newly added disk. False
            otherwise. Note that 'True' does necessarily mean we added the
            disk to the datapath.
    """
    # Acquire disk_breakfix_lock before adding new disk. This
    # is to avoid user trigerred repartition on the disk.

    # Delayed handling of udev events exposes interesting races (ENG-360395).
    if disk_serial_short is not None:
      disk_serial_short = disk_serial_short.strip()

      if FLAGS.experimental_delay_disk_add_udev_event_max_secs > 0:
        delay_secs = random.randint(
          1, FLAGS.experimental_delay_disk_add_udev_event_max_secs)
        log.DEBUG("Disk %s added. Delay handling by %s seconds" %
                  (disk_serial_short, delay_secs))
        time.sleep(delay_secs)
    else:
      log.ERROR("Invalid disk serial encountered for disk %s: %s" %
                (disk_name, disk_serial_short))

    # Check if disk is an NVMe and add event is triggered by NVMe namespace
    # resize.
    if NvmeDisk.is_nvme_namespace_resize_enabled(disk_name):
      # Do not ignore add/remove events triggered by SPDK state change until
      # NVMe namespace resize intent file is cleared after NVMe namespace
      # resize is complete.
      if not spdk_state_change and \
         self.is_nvme_disk_remove_add_triggered_by_ns_resize(
           disk_serial_short):
        log.INFO("NVMe disk %s add was triggered by namespace resize. "
                 "Ignoring the add event" % disk_name)
        return True

    log.INFO("Waiting to acquire disk breakfix lock for disk add: %s" %
             disk_name)
    with self.__disk_breakfix_lock:
      log.INFO("Acquired disk breakfix lock. Going ahead with adding disk: %s"
               % disk_name)
      log.INFO("Handling hot-plug event for disk %s, short serial: %s" %
               (disk_name, disk_serial_short))

      if self.__ignore_device(disk_name):
        return True

      is_cluster_configured = self.__is_cluster_configured()

      # Check if SED managed devices are present on the node.
      self.__sed_devices_present = sed_utils.sed_drive_present()

      # Check if SPDK reset was performed.
      if (is_cluster_configured and FLAGS.spdk_enabled and not
          PmemDevice.is_pmem_device(disk_name)):
        # Check if the disk is managed by SPDK. If that's the case,
        # this disk is likely already in the ConfigProto.
        if SPDKUtil.is_disk_serial_spdk_managed(disk_serial_short):
          log.ERROR("Cannot add a disk that is SPDK managed. It must already "
                    "be added to the cluster")
          # TODO: Check if this disk is already in the ConfigProto.
          return False

        zk_session = ZookeeperSession(host_port_list=self.__host_port_list)

        retries = 0
        while True:
          # Fetch the Hades config.
          hades_config, version = hades_utils.get_hades_proto(zk_session)
          if not hades_config:
            log.ERROR("Failed to get Hades configuration")
            return False

          # Update the spdk_managed field of the disk.
          for slot in hades_config.slot_list:
            if (slot.disk_present and
                slot.disk.serial == disk_serial_short):
              # spdk_state_change would be true if we detected an SPDK reset in
              # the udev layer.
              if spdk_state_change:
                log.INFO("SPDK reset detected for disk %s. Ignoring this "
                         "state transition" % disk_serial_short)
                slot.disk.spdk_managed = False
                break

              # If we failed to detect an SPDK reset in the udev layer, check
              # if the disk was previously managed by SPDK.
              elif (slot.disk.HasField("spdk_managed") and
                    slot.disk.spdk_managed):
                log.INFO("Disk with serial number %s was previously managed "
                         "by SPDK. This appears to be a state transition due "
                         "to SPDK reset. Ignoring this state transition" %
                         disk_serial_short)
                spdk_state_change = True
                slot.disk.spdk_managed = False
                break

              # This is not an SPDK state transition.
              else:
                log.INFO("No SPDK event associated with hotplug of disk %s" %
                         disk_serial_short)
                break
          else:
            log.INFO("Could not find device with serial: %s in the Hades "
                     "proto" % disk_serial_short)
            break

          if not spdk_state_change:
            log.DEBUG("No SPDK event associated with disk %s hotplug" %
                      disk_serial_short)
            break

          # If this was spdk_state_change, commit Hades proto and return.
          log.INFO("SPDK state transition detected for disk: %s" %
                   disk_serial_short)
          log.INFO("Attempting to commit changed Hades proto. Retry %s" %
                   retries)
          ret = hades_utils.commit_hades_proto(
            hades_config, version, zk_session)
          if not ret:
            retries += 1
            log.INFO("Failed to set new Hades config. Potential CAS error. "
                     "Retrying")
            continue

          log.DEBUG("SPDK state transition for disk: %s committed to Hades "
                    "proto" % disk_serial_short)
          return True

      if self.__model == "null":
        log.INFO("Adding slot entry for disk %s in disk location json for"
                 " null cluster" % disk_name)
        if not self.add_disk_slot_in_disk_location(disk_serial_short):
          log.ERROR("Failed to add slot for disk %s" % disk_name)

      # Remove detached disks if they exist.
      self.raid_remove()

      # Set default scheduler for new disk.
      if not self.__set_disks_default_scheduler(disk_name):
        log.ERROR("Unable to set scheduler for %s" % (disk_name))

      # Clear the NVMe disk name to serial/model mapping cache.
      NvmeDisk.get_instance().clear_disk_cache()

      hades_proto = None
      disk_location = None
      service_vm_external_ip = None
      service_vm_id = -1
      timestamp_csecs = int(time.time() * 100)
      disk_obj = Disk(disk_name)
      try:
        disk_model = disk_obj.get_disk_model()
      except AttributeError as attribute_err:
        # We can get AttributeError for NoneType object if we have issues in
        # host to CVM passthrough for NVMEs. There is some bug in Foundation
        # which causes the issue. Putting this exception handling in place,
        # since failing here may result in Hades crashing during disk hot plug
        # addition.
        log.ERROR("Error trying to read disk model for disk %s. Received "
                  "Attribute error: %s" % (disk_name, attribute_err))
        return False

      if is_cluster_configured:
        hades_proto = self.__discover_hades_config()
        disk_location = self.get_disk_slot_designation(disk_serial_short,
                                                       hades_proto)
        service_vm_external_ip = self.__get_node_cvm_external_ip()
        service_vm_id = self.__get_node_cvm_id()

      bad_disk = False
      current_action = ""

      if not hades_utils.is_qualified_disk(disk_name):
        log.WARNING("Disk %s, %s is not qualified by nutanix and may cause "
                    "performance issues. Hades will not add the disk, and "
                    "cause a CRITICAL alert" % (disk_name, disk_model))

        current_action = "Disk is not qualified by Nutanix"
        self.__alert_disk_add_failure(is_cluster_configured,
                                      disk_serial_short,
                                      disk_location, service_vm_id,
                                      service_vm_external_ip, current_action,
                                      timestamp_csecs, disk_name, disk_model,
                                      alert_level="CRITICAL")
        return False

      if not disk_name or not disk_serial_short:
        log.ERROR("Invalid params for hot-plug event. disk_name %s and "
                  "disk_serial %s" % (disk_name, disk_serial_short))
        bad_disk = True
        current_action = "Invalid disk provided"

      if raid_utils.is_preconfig_raid_disk(disk_name):
        log.ERROR("Hot plug disk has preconfigured raid, disk_serial %s" \
                  % disk_serial_short)
        bad_disk = True
        current_action = "Disk has preconfigured RAID. Repartition it "\
                         "manually"

      if bad_disk:
        self.__alert_disk_add_failure(is_cluster_configured,
                                      disk_serial_short,
                                      disk_location, service_vm_id,
                                      service_vm_external_ip, current_action,
                                      timestamp_csecs, disk_name, disk_model)
        return False

      # NVMe namespace resize checks.
      if NvmeDisk.is_nvme_namespace_resize_enabled(disk_name):
        nvme_obj = NvmeDisk.get_instance()
        node_model = hades_utils.get_model()
        log.DEBUG("Check and perform NVMe namespace resize for disk %s"
                  % disk_name)
        if not nvme_obj.check_and_perform_nvme_ns_resize(
           disk_name, disk_serial_short, node_model):
          log.ERROR("NVMe disk %s with serial %s add failed to perform NVMe"
                    " namespace resize" \
                    % (disk_name, disk_serial_short))
          if is_cluster_configured:
            current_action = "NVMe disk add failed to perform namespace "\
                             "resize"
            self.__alert_disk_add_failure(
              is_cluster_configured, disk_serial_short, disk_location,
              service_vm_id, service_vm_external_ip, current_action,
              timestamp_csecs, disk_name, disk_model, alert_level="CRITICAL")
          return False

      current_action = "Repartition and add"
      # Ensuring that the led is turned off.
      if not self.led_off([disk_name]):
        log.ERROR("Failed to turn off LED for disk %s" % disk_name)

      log.INFO("Verifying if disk is unpartitioned")
      is_boot_disk = (
        disk_obj.is_svm_boot_disk(model=disk_model) and
        (self.is_raid_degraded() and not self.raid_sync_in_progress()))

      if is_boot_disk:
        log.INFO("Boot disk partitioning is required to get raid out of "
                 "degraded state")

      # Repartitioning of a disk is required if disk is not partitioned at all.
      num_partitions = len(disk_obj.partitions())
      if not num_partitions:
        log.INFO("Disk %s does not have any partition. Repartitioning it"
                 % disk_name)
        if not self.repartition_disk(disk_name, boot_disk=is_boot_disk):
          log.ERROR("Failed to repartition disk %s" % disk_name)
          current_action = "Repartition failed on the disk"
          self.__alert_disk_add_failure(is_cluster_configured,
                                        disk_serial_short,
                                        disk_location, service_vm_id,
                                        service_vm_external_ip, current_action,
                                        timestamp_csecs, disk_name, disk_model)
          return False
      else:
        # Mount it.
        ret, _ = self.prep_device_util.prepare_block_devices(
          [disk_name])
        if not ret:
          log.ERROR("Failed to prepare and mount disk %s, bailing out of "
                    "hot-plug handling" % disk_name)
          if is_cluster_configured:
            if sed_utils.is_a_self_encrypting_drive(disk_name):
              current_action = "Locked disk detected. Unlock or reset disk"
          self.__alert_disk_add_failure(is_cluster_configured,
                                        disk_serial_short,
                                        disk_location, service_vm_id,
                                        service_vm_external_ip, current_action,
                                        timestamp_csecs, disk_name, disk_model)
          return False

        mount_path = self.__get_mount_path(disk_serial_short)
        partition_mounted = (
          Partition.get_partition_name_from_mount_path(mount_path))
        log_msg = ("Cannot mount %s at %s. Disk %s is already mounted there" %
                   (disk_serial_short, mount_path, partition_mounted))

        if partition_mounted or not self.mount_disk(disk_name):
          log.ERROR("Failed to mount disk %s" % disk_name)
          if partition_mounted:
            log.ERROR(log_msg)
          if is_cluster_configured:
            if sed_utils.is_a_self_encrypting_drive(disk_name):
              current_action = "Locked disk detected. Unlock or reset disk"
          self.__alert_disk_add_failure(is_cluster_configured,
                                        disk_serial_short,
                                        disk_location, service_vm_id,
                                        service_vm_external_ip, current_action,
                                        timestamp_csecs, disk_name, disk_model)
          return False

      # Repartitioning of a disk is also required in the following
      # scenarios:
      # 1) is_boot_disk is True and data partition is empty
      # 2) Disk has partitions and is supposed to be down formatted but
      #    is not down formatted and data partition is empty
      # Disk empty check can be done only when the partitions are
      # mounted.
      to_repartition = False
      if num_partitions:
        log.INFO("Disk %s has %d partitions" % (disk_name, num_partitions))
        is_down_formatted, is_empty = self.__is_down_formatted(disk_name,
                                                               disk_obj)
        if is_down_formatted is None:
          current_action = "Disk is not partitioned correctly. Repartition "\
                           "manually"
          self.__alert_disk_add_failure(is_cluster_configured,
                                        disk_serial_short, disk_location,
                                        service_vm_id, service_vm_external_ip,
                                        current_action, timestamp_csecs,
                                        disk_name, disk_model)
          return False

        elif not is_down_formatted:
          # Can be repartitioned if it contains no data.
          if not is_empty:
            log.ERROR("Disk %s is not empty. Check data and manually "
                      "repartition and add" % (disk_name))
            current_action = ("Not down formatted and has data. Check data and"
                              " manually repartition and add")
            self.__alert_disk_add_failure(is_cluster_configured,
                                          disk_serial_short, disk_location,
                                          service_vm_id, service_vm_external_ip,
                                          current_action, timestamp_csecs,
                                          disk_name, disk_model)
            return False
          else:
            log.INFO("Disk %s is empty. Going to repartition with down "
                     "formatting" % disk_name)
            to_repartition = True

      if is_boot_disk:
        # Repartitioning of a disk is also required if different partitioning
        # scheme is required to rebuild raid.
        # Whether disk is empty or not can't be checked unless disk is mounted.
        log.INFO("Verifying if disk can be partitioned as per requirement")
        data_partition = disk_obj.get_data_partition(disk_model=disk_model)
        part_obj = None
        if data_partition:
          part_obj = Partition(data_partition).initialize()

        if part_obj and part_obj.is_empty():
          to_repartition = True
        else:
          raid_utils.fix_boot_raid(disk_name)

      if to_repartition:
        log.INFO("Repartitioning disk %s" % disk_name)
        if not self.repartition_disk(disk_name, boot_disk=is_boot_disk):
          log.ERROR("Failed to repartition disk %s" % disk_name)
          current_action = "Repartition failed on the disk"
          self.__alert_disk_add_failure(is_cluster_configured,
                                        disk_serial_short,
                                        disk_location, service_vm_id,
                                        service_vm_external_ip, current_action,
                                        timestamp_csecs, disk_name, disk_model)
          return False

      if is_cluster_configured:
        if not self.__setup_hades_proto():
          log.ERROR("Failed to update hades proto")
          return False

        # If disk is new we may have to set a password before mounting.
        zk_session = ZookeeperSession(host_port_list=self.__host_port_list)
        if not zk_session.wait_for_connection(None):
          log.ERROR("Unable to obtain a zookeeper session")
          return False
        hades_config, _ = hades_utils.get_hades_proto(zk_session)
        node_disk_list = self.__get_node_disks_from_zeus(zk_session=zk_session,
                                                         get_pmem=True)
        if self.is_stargate_usable(disk_name):
          if not sed_utils.maybe_set_sed_password(disk_name,
                                                  hades_config,
                                                  node_disk_list,
                                                  zk_session):
            log.ERROR("Could not detect if we had to set passwords on a disk %s"
                      % disk_serial_short)

        # Check if this disk is okay to use. If we know that this disk has been
        # rejected by stargate many times earlier, we can avoid adding this disk.
        disk_diags, disk_present = DiskDiagnostics.get_disk_diagnostics_object(
            disk_serial_short, self)

        if not disk_present:
          log.ERROR("Disk %s is not present in the system to run diagnostics."
                    "Not adding the disk to the cluster" % disk_serial_short)
          return False

        is_disk_bad = False
        if disk_diags is None:
          log.ERROR("Failed to get disk diagnostics for disk %s, marking it bad"
                    % disk_serial_short)
          is_disk_bad = True

        # This disk has diagnostics history and has exceeded the error
        # thresholds. Mark it bad.
        elif disk_diags.exceeds_error_threshold():
          log.WARNING("Disk %s exceeds error thresholds. Marking the newly "
                      "added disk bad" % disk_serial_short)
          is_disk_bad = True

        if is_disk_bad:
          if not self.mark_bad_disk(disk_serial_short):
            log.ERROR("Unable to mark disk as bad %s" % disk_serial_short)

          current_action = "Disk diagnostics show bad disk"
          log.WARNING("Disk %s with serial %s has seen too many errors, "
                      "Ignoring ADD event" % (disk_name, disk_serial_short))
          ALERT_NOTIFY("INFO", PhysicalDiskAdd, disk_serial=disk_serial_short,
                       disk_location=disk_location, service_vm_id=service_vm_id,
                       service_vm_external_ip=service_vm_external_ip,
                       action=current_action, timestamp_csecs=timestamp_csecs,
                       disk_model=disk_model)
          return False

        if not self.__clear_disk_diagnostics(disk_serial_short):
          log.ERROR("Failed to remove diagnostics entry for disk %s" %
                    disk_serial_short)

        # Synchronize disks information.
        if not self.__update_hades_disks_state():
          log.ERROR("Failed to update disks state in hades")
          return False

        node_disks = self.__get_node_disks_from_zeus()
        node_disk_serials = [disk.disk_serial_id for disk in node_disks]

        if disk_serial_short in node_disk_serials:
          current_action = "Repartition and add | Accept old disk"
          log.INFO("Existing disk is hot plugged")
        else:
          current_action = "Repartition and add"
          log.INFO("New disk is hot plugged")

        if not self.__is_disk_mounted_hades(disk_serial_short):
          log.ERROR("Disk with serial %s was not added to cluster. "
                    "It has data or is not correctly partitioned" %
                    disk_serial_short)
          ALERT_NOTIFY("INFO", PhysicalDiskAdd, disk_serial=disk_serial_short,
                       disk_location=disk_location, service_vm_id=service_vm_id,
                       service_vm_external_ip=service_vm_external_ip,
                       action=current_action, timestamp_csecs=timestamp_csecs,
                       disk_model=disk_model)
          return False

        # Here, we check if this disk is introducing any skew to the tier.
        # If it is, we expect the user to choose between RMA and capacity
        # upgrade.
        if FLAGS.hades_mixed_capacity_enabled:
          # Add a marker file at the mountpath. This ensures that this disk is
          # not inadvertently added to the ConfigurationProto, should an abrupt
          # power cycle occur.
          mountpoint = self.__get_mount_path(disk_serial_short)
          marker_file = os.path.join(mountpoint, "README")
          log.INFO("Creating marker file: %s" % marker_file)

          with open(marker_file, 'w') as fd:
            fd.write("Please repartition and add this disk")
            fd.flush()
            os.fsync(fd.fileno())

          skews_tier = self.disk_skews_tier(disk_name, zk_session)

          if skews_tier:
            log.WARNING("Disk %s with serial %s introduces a skew. Please "
                        "perform a repartition and add" %
                        (disk_name, disk_serial_short))
            current_action = ("This device skews the tier %s. Perform "
                              "repartition and add manually." %
                              utils.find_storage_tier(disk_name))
            ALERT_NOTIFY("WARNING", PhysicalDiskAdd,
                         disk_serial=disk_serial_short,
                         disk_location=disk_location,
                         service_vm_id=service_vm_id,
                         service_vm_external_ip=service_vm_external_ip,
                         action=current_action,
                         timestamp_csecs=timestamp_csecs,
                         disk_model=disk_model)

            # Set is_mounted: false for the disk in the HadesProto.
            if not self.update_disk_mount_state(
              disk_serial=disk_serial_short, should_mount=False):
              log.ERROR("Could not update mount state of disk %s in the "
                        "Hades proto" % disk_name)
              return False

            # Unmount and remove all partitions on this disk. This allows
            # for Hades to not use this disk unless manually repartitioned.
            if not self.clean_disks([disk_name], skip_repartition=True,
                                    mount_disk=False):
              log.WARNING("Cleaning of disk %s did not succeed" % disk_name)

            return False
          else:
            log.INFO("Disk %s with serial %s does not introduce a skew" %
                     (disk_name, disk_serial_short))
            if os.path.exists(marker_file):
              log.INFO("Removing marker file: %s" % marker_file)
              os.remove(marker_file)

        if not self.add_disks_to_cluster():
          log.ERROR("Failed to add disk %s with serial %s to cluster" %
                    (disk_name, disk_serial_short))
          return False

        # Here we are in the auto add code path. Alert the user that the disk
        # should become usable soon.
        current_action = "No Action required. Disk added to data path"
        ALERT_NOTIFY("INFO", PhysicalDiskAdd, disk_serial=disk_serial_short,
                     disk_location=disk_location, service_vm_id=service_vm_id,
                     service_vm_external_ip=service_vm_external_ip,
                     action=current_action, timestamp_csecs=timestamp_csecs,
                     disk_model=disk_model)

        # Workaround: Restart stargate so that disk are updated.
        # TODO: Remove this when disk addition case if properly handled
        #       by stargate.
        if not self.kill_stargate():
          # If we fail to restart Stargate on disk addition, report so.
          log.ERROR("Failed to kill stargate")
      else:
        # Cluster is not configured, check if disk is empty.
        if not self.is_stargate_usable(disk_name):
          log.ERROR("Disk %s is not directly usable by stargate. "
                    "It may not be partitioned appropriately or "
                    "data is present on disk" % disk_name)

          if not self.unmount_disk(disk_name, "f"):
            log.ERROR("Failed to unmount disk %s" % disk_name)
          return False

      # TODO(Harish) - Can clearing intent files be handled much better?
      # Can this be moved to method calls? Which will help us in clearing
      # intent files even if there is a failure in between.

      # Clear NVMe namespace resize intent file created.
      if NvmeDisk.is_nvme_namespace_resize_enabled(disk_name) and \
         not NvmeDisk.clear_nvme_ns_resize_intent(disk_serial_short):
        log.ERROR("Failed to clear NVMe namespace resize intent file "
                  "for disk %s with serial %s"
                  % (disk_name, disk_serial_short))

      log.INFO("Disk %s with serial %s is successfully added to cluster" %
               (disk_name, disk_serial_short))
      if not self.led_off(disk_serials=[disk_serial_short]):
        log.ERROR("Failed to turn off LED for disk %s" % disk_serial_short)
      return True

  def __alert_disk_add_failure(self, is_cluster_configured, disk_serial_short,
                               disk_location, service_vm_id,
                               service_vm_external_ip, action, timestamp_csecs,
                               disk_name, disk_model, alert_level="INFO"):
    """
    Raise an alert and light up LED if disk add failed.
    """
    if is_cluster_configured:
      ALERT_NOTIFY(alert_level, PhysicalDiskAdd, disk_serial=disk_serial_short,
                   disk_location=disk_location, service_vm_id=service_vm_id,
                   service_vm_external_ip=service_vm_external_ip,
                   action=action, timestamp_csecs=timestamp_csecs,
                   disk_model=disk_model)

      if not self.__setup_hades_proto():
        log.ERROR("Failed to update hades proto")

    if not disk_name or not self.led_fault([disk_name]):
      log.ERROR("Failed to light up LED for %s" % disk_name)

  @rpchandler
  def hyperv_handle_disk_add(self, disk_serial_short, scsi_host, lun):
    """
    Handle add disk wrapper for hyperv.
    """
    if not self.__is_hyperv:
      log.INFO("Ignoring Hyperv disk add event for disk %s" % disk_serial_short)
      return True

    log.INFO("Hyperv disk add event for disk %s" % disk_serial_short)
    cmd = ("sudo /usr/bin/scsi-rescan --hosts=%s --channels=0 --ids=0 "
           "--luns=%s" % (scsi_host, lun))
    log.INFO("Executing: %s" % cmd)
    ret, out, err = timed_command(cmd)
    out = out.decode('utf-8')
    err = err.decode('utf-8')
    if ret:
      log.ERROR("Failed to rescan the scsi target to discover newly added disk")

    # Sometimes the disk name takes a few seconds to show up after lsscsi.
    # Retry a few times.
    for x in range(10):
      disk_name = self.disk_serial_to_block_device(disk_serial_short)
      if not disk_name:
        log.INFO("Unable to find disk name for %s. Retrying.." %
                 disk_serial_short)
        time.sleep(1)
      else:
        log.INFO("Found disk name %s for serial %s" %
                  (disk_name, disk_serial_short))
        break

    dev = dict()
    dev['ACTION'] = "ADD"
    dev['ID_SCSI_SERIAL'] = disk_serial_short
    dev['DEVNAME'] = disk_name
    self.__udev_handler.udev_event_cb(dev)
    return True

  def handle_disk_remove(self, disk_name, disk_serial_short,
                         spdk_state_change=False):
    """
    Handles the removal (hotunplug) of a new disk

    Params:
      disk_name (string): Name of disk device (e.g.: /dev/sdc).
      disk_serial_short (string): ID_SERIAL_SHORT for this disk.
      spdk_state_change (bool): If the disk removal was due to SPDK state
        change. SPDK state change is detected when there was a uio add
        event along with this block device remove event. Default False.

    Returns:
      bool: True if we could update our datapath with the information of the
            removed disk. False otherwise.
    """
    # Delayed handling of udev events exposes interesting races (ENG-360395).
    if disk_serial_short is not None:
      disk_serial_short = disk_serial_short.strip()

      if  FLAGS.experimental_delay_disk_remove_udev_event_max_secs > 0:
        delay_secs = random.randint(
          1, FLAGS.experimental_delay_disk_remove_udev_event_max_secs)

        log.DEBUG("Disk %s removed. Delay handling by %s seconds" %
                  (disk_serial_short, delay_secs))
        time.sleep(delay_secs)
    else:
      log.ERROR("Invalid disk serial encountered for disk %s: %s" %
                (disk_name, disk_serial_short))

    # Check if disk is an NVMe and remove event is triggered by NVMe namespace
    # resize.
    if NvmeDisk.is_nvme_namespace_resize_enabled(disk_name):
      # Do not ignore add/remove events triggered by SPDK state change until
      # NVMe namespace resize intent file is cleared after NVMe namespace
      # resize is complete.
      if not spdk_state_change and \
         self.is_nvme_disk_remove_add_triggered_by_ns_resize(
           disk_serial_short):
        log.INFO("NVMe disk %s remove was triggered by namespace resize. "
                 "Ignoring the remove event." % disk_name)
        return True

    log.INFO("Waiting to acquire disk breakfix lock for disk remove: %s" %
             disk_name)
    with self.__disk_breakfix_lock:
      log.INFO("Acquired disk breakfix lock")

      self.clean_stale_virtual_disk_entries()

      if self.__ignore_device(disk_name):
        return True

      # Check if SED managed devices are present on the node.
      self.__sed_devices_present = sed_utils.sed_drive_present()

      log.INFO("Handling hot-remove event for disk %s, short serial: %s" %
               (disk_name, disk_serial_short))

      is_cluster_configured = self.__is_cluster_configured()

      # Check if this hotplug is due to SPDK setup. We check the driver of the
      # PCIe path that manages this NVMe device. Following that, we update the
      # Hades proto to reflect that it's indeed SPDK managed. This helps
      # discern SPDK reset from Stargate stop vs. a disk offline / remove.
      if (is_cluster_configured and FLAGS.spdk_enabled):
        # spdk_state_change would be set to True if we detected an SPDK state
        # transition in the udev layer. Even if we failed, then additionally
        # check here if the disk is SPDK managed.
        spdk_state_change = spdk_state_change or \
          SPDKUtil.is_disk_serial_spdk_managed(disk_serial_short)

        if spdk_state_change:
          log.INFO("Disk %s is managed by SPDK. Ignoring this hotunplug event" %
                   disk_name)

          zk_session = ZookeeperSession(host_port_list=self.__host_port_list)

          retries = 0
          while True:
            # Fetch the Hades config.
            hades_config, version = hades_utils.get_hades_proto(zk_session)
            if not hades_config:
              log.ERROR("Failed to get Hades configuration")
              return False

            # Update the spdk_managed field of the disk.
            for slot in hades_config.slot_list:
              if slot.disk_present and slot.disk.serial == disk_serial_short:
                slot.disk.spdk_managed = True
                break
            else:
              log.ERROR("Could not find device with serial: %s in the kernel "
                        "space" % disk_serial_short)
              return False

            # Commit the Hades proto.
            log.INFO("SPDK state transition detected for disk: %s" %
                     disk_serial_short)
            log.INFO("Attempting to commit changed Hades proto. Retry: %s" %
                     retries)
            ret = hades_utils.commit_hades_proto(
              hades_config, version, zk_session)
            if not ret:
              log.INFO("Failed to set new Hades config. Potential CAS "
                       "error. Retrying")
              retries += 1
              continue

            # Exit early for this disk is managed by SPDK.
            log.DEBUG("SPDK state transition for disk: %s committed to Hades "
                      "proto" % disk_serial_short)
            return True

      # Clear the NVMe disk name to serial/model mapping cache.
      NvmeDisk.get_instance().clear_disk_cache()

      hades_proto = None
      disk_location = None
      service_vm_external_ip = None
      service_vm_id = None
      timestamp_csecs = int(time.time() * 100)
      status = True

      if is_cluster_configured:
        # Get Node Details.
        node_position = "-" # Default value is blank for alert message.
        node_serial = "-" # Default value is blank for alert message.
        factory_config = util.cluster.info.get_factory_config()
        if factory_config:
          log.DEBUG("Node Factory Config: %s" % factory_config)
          node_position = factory_config.get("node_position", "-")
          node_serial = factory_config.get("node_serial", "-")

        service_vm_external_ip = self.__get_node_cvm_external_ip()
        service_vm_id = self.__get_node_cvm_id()
        disk_location = self.get_disk_slot_designation(disk_serial_short)
        #Assumption is disk model is stored in hades.
        disk_model = (self.__get_disk_model_hades_proto(disk_serial_short)
                      or "Unknown")
        log.INFO("Disk Serial %s has been pulled out of the node.." % disk_serial_short)
        log.INFO("Proceeding to blink Rest of the HDD's LED's")
        cmd = "/usr/local/nutanix/cluster/bin/list_disks --json"
        rv, out, err = timed_command(cmd)
        out = json.loads(out)
        log.INFO(out)
        sd_devices = {k: {'Disk': v['Disk'], 'Serial': v['Serial']} 
                      for k, v in out.items() if v['Disk'].startswith('/dev/sd')}
        sd_devices_filtered = {k: v for k, v in sd_devices.items() 
                               if v['Serial'] != disk_serial_short}
        for k, v in sd_devices_filtered.items():
            serial = v['Serial']
            log.INFO("Blinking the Drive: %s" % serial)
            cmd = "disk_operator led_on %s" % serial
            rv, out, err = timed_command(cmd)
            if not rv:
                log.INFO("Failed to blink the Drive %s " % serial)
            else:
                log.INFO("LED has been Lit for the Drive %s" % serial)
        # Raise an alert that a disk has been physically removed.
        ALERT_NOTIFY("CRITICAL", PhysicalDiskRemove,
                     disk_serial=disk_serial_short,
                     disk_location=disk_location, service_vm_id=service_vm_id,
                     service_vm_external_ip=service_vm_external_ip,
                     timestamp_csecs=timestamp_csecs, disk_model=disk_model,
                     node_position=node_position,
                     node_serial_number=node_serial,
                     rf1_custom_message=\
                       ContainerUtil.rf1_custom_message(disk_serial_short))

      if not self.raid_remove(failed=True):
        log.WARNING("RAID removal failed. Repartitioning may fail")

      if not disk_serial_short:
        log.ERROR("Invalid params for hot-remove event. disk_name %s and "
                  "disk_serial %s" % (disk_name, disk_serial_short))
      else:
        mount_path = self.__get_mount_path(disk_serial_short)

        if not self.unmount_disk_path(mount_path, "f"):
          log.ERROR("Failed to unmount disk %s" % mount_path)
          status = False

      if is_cluster_configured:
        if not self.__clear_disk_diagnostics(disk_serial_short):
          log.ERROR("Failed to remove diagnostics entry for disk %s" %
                    disk_serial_short)

        disk_id = self.disk_serial_to_disk_id(disk_serial_short)
        if disk_id:
          if not self.change_to_remove_for_disks([disk_id], operation="set"):
            log.ERROR("Failed to set to_remove for disk with ids %s and "
                      "serial %s" % (disk_id, disk_serial_short))
            status = False
        else:
          log.WARNING("Failed to get disk id for disk with serial %s" %
                      disk_serial_short)

        if (disk_serial_short and not self.change_disks_offline_paths(
            [disk_serial_short], operation="set")):
          log.ERROR("Failed to add disk %s to offline mount paths" %
                    disk_serial_short)
          status = False

        self.__maybe_remove_cassandra_symlink(disk_serial_short)

        for retryc in range(FLAGS.disk_unmount_retry_count):
          if not self.unmount_disk_path(mount_path, "f"):
            time.sleep(FLAGS.unmount_default_wait_sec)
            log.ERROR("Failed to unmount %s retrying, count %s" %
                      (mount_path, retryc))
            status = False
          else:
            log.INFO("Unmount of %s successful" % mount_path)
            break

        if not self.__setup_hades_proto():
          log.ERROR("Failed to update hades proto")
          return False

        # Synchronize disks information.
        if not self.__update_hades_disks_state():
          log.ERROR("Failed to update disks state in hades")
          return False

      log.INFO("Disk %s with serial %s is successfully removed from cluster" %
               (disk_name, disk_serial_short))
      return status

  @rpchandler
  def hyperv_handle_disk_remove(self, disk_serial_short, scsi_host, lun):
    """
    Handle remove disk wrapper for hyperv.
    """
    if not self.__is_hyperv:
      log.INFO("Ignoring Hyperv disk remove event for disk %s" %
               disk_serial_short)
      return True

    log.INFO("Hyperv disk remove event for disk %s" % disk_serial_short)

    cmd = ("sudo /usr/bin/scsi-rescan --remove --hosts=%s --channels=0 --ids=0 "
           "--luns=%s" % (scsi_host, lun))
    log.INFO("Executing: %s" % cmd)
    ret, out, err = timed_command(cmd)
    out = out.decode('utf-8')
    err = err.decode('utf-8')
    if ret:
      log.ERROR("Failed to rescan the scsi target to delete the removed disk")

    dev = dict()
    dev['ACTION'] = "REMOVE"
    dev['ID_SCSI_SERIAL'] = disk_serial_short
    dev['DEVNAME'] = "/dev/null"
    self.__udev_handler.udev_event_cb(dev)
    return True

  def is_disk_offline_and_to_remove(self, disk_serial):
    """
    Return whether the disk is offline and to remove.
    Params:
      disk_serial (string): serial of the disk to be checked.

    Returns:
      (error, offline_and_to_remove)
      error (boolean) : True if there was an error while checking.
                        False otherwise.
      offline_and_to_remove : True if the disk is offline and to remove.
                              False otherwise.
    """

    log.INFO("Checking whether disk %s is offline and to remove" % disk_serial)

    log.DEBUG("Fetching configuration (proto) from Zeus config")
    config = Configuration().initialize(host_port_list=self.__host_port_list)
    if not config:
      log.ERROR("Error getting config from Zookeeper")
      return (True, False)

    proto = config.config_proto()
    if not proto:
      log.ERROR("Error getting config proto")
      return (True, False)

    # Find the config proto of the given disk.
    disk = None
    for disk_iter in proto.disk_list:
      if (disk_iter.HasField("disk_serial_id") and
          disk_iter.disk_serial_id == disk_serial):
        disk = disk_iter
        break

    if disk is None:
      log.ERROR("Unable to find a disk with disk serial %s in disk_list" %
                disk_serial)
      return (True, False)

    is_offline = disk.HasField("last_service_vm_id") and \
                   not disk.HasField("service_vm_id")
    is_to_remove = disk.HasField("to_remove") and disk.to_remove

    return (False, is_offline and is_to_remove)

  @rpchandler
  def mount_disk_with_access_mode(self, disk_serial, software_access_mode):
    """
    Mounts the given offline to-remove disk and sets its 'software_access_mode'
    mode in Zeus config.
    The following steps are followed:
    - Verfiy that the disk is offline and to remove when we want to set the
      software access mode to read_only.
    - Mount the disk (if it's not already mounted).
    - Update the Hades proto to set is_mounted to True.
    - Update the software_access_mode in Zeus config.
    - Bring the disk online in the Zeus config.

    Params:
      disk_serial (string): The serial number of the disk.
      software_access_mode (string): The new software access mode of the disk
                                     ("read_write" or "read_only").

    Returns:
      bool: True if mounting the disk with the software access mode was
            successful.
            False otherwise.
    """

    if not disk_serial:
      log.ERROR("Invalid disk serial %s provided" % software_access_mode)
      return False

    if software_access_mode not in ["read_write", "read_only"]:
      log.ERROR("Invalid operation %s for software access mode. Valid options "
                "are 'read_write' or 'read_only'" % software_access_mode)
      return False

    # Check whether the disk is actually offline and to_remove.
    error, offline_and_to_remove = \
      self.is_disk_offline_and_to_remove(disk_serial)

    if error:
      log.ERROR("Failed while checking whether the disk %s is offline and to "
                "remove" % disk_serial)
      return False

    if not offline_and_to_remove and software_access_mode == "read_only":
      log.ERROR("Setting software access mode to read_only is only supported "
                "for offline and to remove disks")
      return False

    # Mount the disk.
    disk_name = self.disk_serial_to_block_device(disk_serial)
    mounted = self.mount_disk(disk_name)
    if mounted:
      log.INFO("Successfully mounted %s\n" % disk_serial)
    else:
      log.ERROR("Failed to mount %s\n" % disk_serial)
      return False

    # Update the Hades proto to set 'is_mounted' to True.
    hades_proto_updated = \
      self.update_disk_mount_state(disk_serial, should_mount=True)

    if not hades_proto_updated:
      log.ERROR("Failed to mount %s\n" % disk_name)
      return False

    # Set the software access mode in Zeus.
    software_access_mode_updated = \
      self.update_disk_software_access_mode(disk_serial, software_access_mode)

    if not software_access_mode_updated:
      log.ERROR("Failed to update software access state for disk %s to %s" %
                (disk_serial, software_access_mode))
      return False

    # Mark the disk online.
    disk_obj = Disk(disk_name)
    if disk_obj is None:
      log.ERROR("Failed to create a disk object for the disk: %s" % disk_name)
      return False
    disk_serial_short = disk_obj.serial_number()
    self.change_disks_offline_paths([disk_serial_short], operation="clear")

    log.INFO("Successfully mounted %s with software access mode set to %s\n" %
             (disk_serial, software_access_mode))
    return True

  def update_disk_software_access_mode(self, disk_serial, operation):
    """
    Update the disk's software access mode in Zeus config.

    Params:
      disk_serial (string): The serial number of the disk.
      operation (string): The new software access mode of the disk
                          ("read_write" or "read_only").

    TOCHECK(Vishnu): Is there a better way to identify disks instead of
                     disk_serial (maybe disk uuid?).

    Returns:
      bool: False if we encounter errors while trying to set the software
            access mode.
            True otherwise.
    """

    if operation not in ["read_write", "read_only"]:
      log.ERROR("Invalid operation %s for software access mode. "
                "Valid options are 'read_write' or 'read_only'" % operation)
      return False

    log.INFO("Attempting to set the software access mode to %s in Zeus config "
             "for disk %s" % (operation, disk_serial))

    log.DEBUG("Fetching configuration (proto) from Zookeeper")
    config = Configuration().initialize(host_port_list=self.__host_port_list)
    if not config:
      log.ERROR("Error getting config from Zookeeper")
      return False

    proto = config.config_proto()
    if not proto:
      log.ERROR("Error getting config proto")
      return False

    # Find the config proto of the given disk.
    disk = None
    for disk_iter in proto.disk_list:
      if (disk_iter.HasField("disk_serial_id") and
          disk_iter.disk_serial_id == disk_serial):
        disk = disk_iter
        break

    if disk is None:
      log.ERROR("Unable to find a disk with disk serial %s in disk_list" %
                disk_serial)
      return False

    if disk.HasField("software_access_mode") and \
       disk.software_access_mode == operation :
      log.INFO("software_access_mode for disk %s is already set to %s" %
               (disk_serial, operation))
      return True

    # Verify that software access mode is only set to 'read_only' for to_remove
    # disks which are offline.
    is_to_remove = disk.HasField("to_remove") and disk.to_remove
    is_offline = disk.HasField("last_service_vm_id") and \
                   not disk.HasField("service_vm_id")

    if operation == "read_only" and not (is_to_remove and is_offline):
      log.ERROR("Cannot set software access mode to 'read_only' for disk %s "
                "which is not to remove and offline. is_to_remove: %s, "
                "is_offline: %s" % (disk_serial, is_to_remove, is_offline))
      return False

    if operation == "read_write" :
        disk.software_access_mode = \
          ConfigurationProto.Disk.SoftwareAccessMode.kReadWrite
    else:
        disk.software_access_mode = \
          ConfigurationProto.Disk.SoftwareAccessMode.kReadOnly

    num_tries = 0

    while num_tries < FLAGS.num_software_access_mode_update_tries:
      num_tries += 1
      log.DEBUG("Attempting to update the software access mode in the "
                "configuration proto for disk %s to %s; num_tries : %s"
                % (disk_serial, operation, str(num_tries)))
      last_timestamp = proto.logical_timestamp

      if not config.commit(proto):
        if proto.logical_timestamp > last_timestamp:
          log.INFO("Failed to commit updated proto. Retrying.")
          continue
        else:
          log.ERROR("Failed to update the software_access_mode in Zeus "
                    "configuration for disk %s to %s. Aborting" %
                    (disk_serial, operation))
          return False
      else:
        break
    else:
      log.ERROR("Failed to update the software access mode after %s tries; "
                "Aborting" % str(num_tries));
      return False

    log.INFO("Succesfully updated software_access_mode for disk %s to %s" %
             (disk_serial, operation))
    return True

  def change_to_remove_for_disks(self, disk_ids, operation=""):
    """
    Change to_remove field for disks as per operation.
    Disk remove should work on disk_id and not on disk_serial.
    Multiple disk entries can be present for same disk serial.
    Marking disk offline can work on disk serial.
    Params:
      disk_ids (list of string): disk_id in config proto for disks
      operation (string): Remove/ Add to_remove field as per operation.

    Returns:
      bool: False if we encounter errors in trying to update the ZK config.
            True otherwise.
    """
    if operation not in ["set", "clear"]:
      log.ERROR("Invalid operation %s for to_remove" % operation)
      return False

    if not disk_ids:
      log.ERROR("No disk ids provided")
      return False

    log.INFO("Attempting to update to_remove flag for disks with ids %s in"
             " zeus config with operation %s" % (disk_ids, operation))

    log.DEBUG("Fetching configuration (proto) from ZK")
    config = Configuration().initialize(host_port_list=self.__host_port_list)
    if not config:
      log.ERROR("Error getting config from Zookeeper")
      return False

    proto  = config.config_proto()
    if not proto:
      log.ERROR("Error getting config proto")
      return False

    while True:
      last_timestamp = proto.logical_timestamp
      log.DEBUG("Updating proto with disks %s and operation %s" % (
                 disk_ids, operation))
      ret, changed = self.__update_proto_to_remove_for_disks(proto, disk_ids,
                                                             operation)
      if not ret:
        log.ERROR("Failed to update config proto with disks %s and operation %s"
                  %(disk_ids, operation))
        return False
      if not changed:
        log.INFO("Disks %s are already is expected state" % disk_ids)
        return True

      log.DEBUG("Committing proto back to zookeeper")
      if not config.commit(proto):
        if proto.logical_timestamp > last_timestamp:
          log.INFO("Failed to commit updated proto. Retrying.")
          continue
        else:
          log.ERROR("Failed to update the to_remove in zeus configuration for "
                    "disks %s and operation %s. Aborting." %
                    (disk_ids, operation))
          return False
      else:
        break

    log.INFO("Successfully updated to_remove for disks %s with operation %s" %
             (disk_ids, operation))
    return True

  def change_disks_offline_paths(self, disk_serials_short, operation=""):
    """
    Add/ Remove disks to/ from offline mount paths.
    Params:
      disk_serials_short (list of string): ID_SERIAL_SHORT for disks
      operation (bool): Add/ Remove disks to/from offline mount paths

    Returns:
      bool: False if we encounter errors in trying to update the ZK config.
            True otherwise.
    """
    if operation not in ["set", "clear"]:
      log.ERROR("Invalid offline operation")
      return False

    log.INFO("Attempting to update offline mount paths with operation %s for "
             "disks with serial %s in zeus config" % (operation,
             disk_serials_short))

    log.DEBUG("Fetching configuration (proto) from ZK")
    config = Configuration().initialize(host_port_list=self.__host_port_list)
    if not config:
      log.ERROR("Failed to initialize config object")
      return False

    proto  = config.config_proto()

    while True:
      last_timestamp = proto.logical_timestamp
      log.DEBUG("Updating proto with offline disks %s " % disk_serials_short)
      ret, changed = self.__update_proto_with_offline_disks(proto,
                                                            disk_serials_short,
                                                            operation)
      if not ret:
        log.ERROR("Failed to update proto offline mount paths with operation=%s"
                  " and disks=%s offline disks" % (
                  operation, disk_serials_short))
        return False
      if not changed:
        log.INFO("Disks %s are already in expected state" % disk_serials_short)
        break

      log.DEBUG("Committing proto back to zookeeper")
      if not config.commit(proto):
        if proto.logical_timestamp > last_timestamp:
          log.INFO("Failed to commit updated proto. Retrying.")
          continue
        else:
          log.ERROR("Failed to update the Zeus configuration with %s"
                    "for offline mount path %s. Aborting." % (operation,
                    disk_serials_short))
          return False
      else:
        log.INFO("Successfully updated disk %s with offline mount paths and "
                 "operation %s" % (disk_serials_short, operation))
        break

    ip_address = self.__get_node_cvm_external_ip()
    service_vm_id = hades_utils.get_node_cvm_id()

    if operation == "set":
      for disk_serial_short in disk_serials_short:
        mount_path = ZeusUtil.get_mount_path_from_disk_serial(
          disk_serial_short)
        if mount_path and FLAGS.enable_disk_offline_alert:
          log.INFO("Raising PathOffline alert for %s" % disk_serial_short)
          ALERT_NOTIFY("CRITICAL", PathOffline,
                       mount_path=mount_path,
                       ip_address=ip_address,
                       service_vm_id=service_vm_id)
        else:
          log.ERROR("Failed to fetch mount path for disk: %s, failed to "
                    "trigger disk offline alert for disk: %s" %
                    (disk_serial_short, disk_serial_short))

    if operation == "clear":
      # Now that update is successful, resolve the alert for the disks
      # raised by stargate.
      for disk_serial_short in disk_serials_short:
        mount_path = ZeusUtil.get_mount_path_from_disk_serial(
          disk_serial_short)
        if mount_path and FLAGS.enable_disk_offline_alert:
          log.INFO("Resolving the PathOffline alert for %s" % disk_serial_short)
          ALERT_RESOLVE_NOTIFY("CRITICAL", PathOffline,
                               mount_path=mount_path,
                               ip_address=ip_address,
                               service_vm_id=service_vm_id)
        else:
          log.ERROR("Failed to fetch mount path for disk: %s, failed to "
                    "resolve disk offline alert for disk: %s" %
                    (disk_serial_short, disk_serial_short))
    return True

  def complete_bad_disk_processing(self, disk_serial):
    """
    Complete the bad disk processing that includes unmounting the disk, setting
    proper disk status in hades proto, lighing up the LED.
    """
    disk_name = self.disk_serial_to_block_device(disk_serial)
    mount_path = self.__get_mount_path(disk_serial)
    log.INFO("Unmounting a bad disk %s" % mount_path)
    if self.unmount_disk_path_retry(mount_path, "f"):
      log.INFO("Successfully unmounted a bad disk %s" % mount_path)

      if not self.__setup_hades_proto():
        log.ERROR("Failed to update hades proto")

      # Synchronize disks information.
      if not self.__update_hades_disks_state():
        log.ERROR("Failed to update disks state in hades")

      # Fail and remove disk if it was part of RAID.
      if not raid_utils.fail_and_remove_disk_from_raid_if_attached(
              disk_name):
        log.ERROR("RAID fail and removal of disk: %s failed. Disk serial: %s"
                  % (disk_name, disk_serial))

      if disk_name:
        if not self.led_fault([disk_name]):
          log.ERROR("Failed to light up LED for %s" % disk_name)
      return True

    log.INFO("Failed to unmount a bad disk %s" % mount_path)
    log.INFO("Trying to get a shutdown token to handle a bad disk %s" %
             disk_serial)

    if not FLAGS.skip_disk_remove_reboot:
      return self.grab_shutdown_token_and_reboot()
    else:
      log.INFO("Skipping reboot for disk remove")
      return True

  def is_metadata_disk(self, disk_id):
    """
    Given the disk id, finds out whether it is a metadata disk.
    First check in zeus proto, if that fails check in disk object.
    Returns: True if it is metadata disk, else False
    """
    disk_list = self.__get_node_disks_from_zeus()
    if disk_list is not None:
      for disk in disk_list:
        if disk.disk_id == disk_id:
          if disk.HasField("contains_metadata") and disk.contains_metadata:
            log.INFO("Disk %d is a metadata disk" % disk_id)
            return True

    log.INFO("Disk %d is not a metadata disk" % disk_id)
    return False

  def mark_bad_disk(self, disk_serial, defer_unmount=False, zk_session=None):
    """
    Marks the disk with serial number as bad in hades proto, and takes any
    further action like raising alert, changing led status etc.

    Args:
      disk_serial(str): The serial number of the disk.
      defer_unmount(bool): If True, we defer the unmount to the tombstone time.
        Default: False.
      zk_session(ZookeeperSession): Zookeeper session obj. Default: None.
    """
    # If a disk is being marked bad, remove maybe_bad flag. Continue even if
    # there be any issues.
    hades_utils.clear_hades_proto_maybe_bad_disk(disk_serial=disk_serial)

    # If we cannot commit in hades proto, return
    if not self.__set_hades_proto_bad_disk(disk_serial, defer_unmount):
      return False

    # Get Node Details.
    node_position = "-" # Default value is blank for alert message.
    node_serial = "-" # Default value is blank for alert message.
    factory_config = util.cluster.info.get_factory_config()
    if factory_config:
      # Factory config path: /etc/nutanix/factory_config.json
      # Factory config sample output:
      # {
      #   "rackable_unit_serial": "18SM6F170156",
      #   "node_uuid": "0234cf84-785d-486f-9dc5-45f9f4e1b233",
      #   "node_serial": "ZM183S001448",
      #   "node_position": "D",
      #   "cluster_id": 113009,
      #   "rackable_unit_model": "USE_LAYOUT"
      # }
      log.DEBUG("Node Factory Config: %s" % factory_config)
      node_position = factory_config.get("node_position", "-")
      node_serial = factory_config.get("node_serial", "-")

    # Default disk id to 0 so that alert notify does not crash and UI does
    # not show alert on any disk.
    disk_id = self.disk_serial_to_disk_id(disk_serial) or 0
    disk_location = self.get_disk_slot_designation(disk_serial)
    disk_model = self.__get_disk_model_hades_proto(disk_serial) or "Unknown"
    service_vm_id = self.__get_node_cvm_id()
    timestamp_csecs = int(time.time() * 100)

    ALERT_NOTIFY(
        "CRITICAL", PhysicalDiskBad, disk_location=disk_location,
        disk_serial=disk_serial, disk_model=disk_model, disk_id=disk_id,
        service_vm_id=service_vm_id, timestamp_csecs=timestamp_csecs,
        node_position=node_position, node_serial_number=node_serial,
        rf1_custom_message=ContainerUtil.rf1_custom_message(disk_serial))

    if defer_unmount:
      # ENG-414861: Fail and remove the disk from active RAID before deferring
      # unmount, so that a bad disk will not be a part of RAID anymore.
      disk_name = self.disk_serial_to_block_device(disk_serial)
      if not raid_utils.fail_and_remove_disk_from_raid_if_attached(disk_name):
        log.ERROR("RAID fail and removal of disk from RAID: %s failed. Disk "
                  "serial: %s" % (disk_name, disk_serial))

      log.INFO("Deferring unmount disk")
      return True
    return self.complete_bad_disk_processing(disk_serial)

  def __boot_disks(self):
    """
    Returns a list of boot disks in the system.
    """
    boot_disks = []
    for disk in Disk.disks():
      disk_obj = Disk(disk)
      if disk_obj.is_svm_boot_disk():
        if len(disk_obj.partitions()) < 3:
          continue
        boot_disks.append(disk)
    return boot_disks

  def __clean_disk(self, disk, add_can_repartition=False, mount_disk=True,
                   skip_repartition=False):
    """
    Takes a disk (e.g. /dev/sda) and formats data partition on the disk.
    add_can_repartition add repartition marker for old genesis.
    mount_disk tells whether to mount disk or not.
    skip_repartition If true, we skip repartition / reformat of the disk.
    Returns True on success and False otherwise.
    """
    if disk not in Disk.disks():
      log.ERROR("Invalid disk name %s provided" % disk)
      return False

    partition = self.get_data_partition(disk, ignore_fs_errors=True)
    if not partition:
      log.WARNING("No suitable data partitions on disk %s" % disk)
      return True

    if not self.__clean_partitions([partition], add_can_repartition,
                                   mount_disk, skip_repartition):
      log.ERROR("Failed to clean disk %s" % disk)
      return False

    # Turn off LED if disk is clean.
    if not PmemDevice.is_pmem_device(disk) and not self.led_off([disk]):
      log.ERROR("Failed to turn off LED for disk %s" % disk)

    return True

  def __clean_partitions(self, partitions, add_can_repartition=False,
                         mount_disk=True, skip_repartition=False):
    """
    Takes a list of partitions and formats each partition in the list.
    Args:
      partitions (list): List of partitions to be cleaned.
      add_can_repartition (bool): Add repartition marker for old genesis.
        Default: False.
      mount_disk (bool): Tells whether to mount disk or not. Default: True.
      skip_repartition (bool): If true, we skip repartition / reformat of the
        disk. Default: False.

    Returns:
      bool: True on success and False otherwise.
    """
    UNMOUNT_RETRIES = 5
    TEMP_MOUNT_DIR = "/mnt/clean_disks_mnt"

    disks = set()

    # Every partition is tried to be cleaned. For first failure corresponding
    # disk is mounted back and call is returned.
    status = True
    try:
      for partition in partitions:
        part_obj = Partition(partition).initialize()
        if not part_obj:
          log.ERROR("Failed to initialize partition object for partition %s" %
                    partition)
          status = False
          return False
        disk_name = part_obj.get_disk_name()
        disk = Disk(disk_name)

        disks.add(disk_name)

        mount_path = part_obj.mount_path()

        if (part_obj.mounted() or
            block_store_utils.is_fuse_managed_disk(disk_name)):
          log.INFO("Unmounting partition %s" % partition)
          unmounted = False
          for _ in range(UNMOUNT_RETRIES):
            if (not self.unmount_disk(disk_name, option="f") or
                block_store_utils.is_fuse_managed_disk(disk_name)):
              log.ERROR("Failed to umount partition %s" % partition)
            else:
              unmounted = True
              break
            time.sleep(1)
          if not unmounted:
            log.ERROR("Tried %s times to umount partition %s and failed" %
                      (UNMOUNT_RETRIES, partition))
            status = False
            return False

        is_sed = sed_utils.is_a_self_encrypting_drive(disk_name)
        if is_sed:
          if not sed_utils.reinitialize_sed_band(disk_name,
                                                 disk.serial_number(),
                                                 partition):
            log.ERROR("Could not initialize band on self encrypting drive")
            status = False
            return False

        # Run wipefs before creating partition to clear FS signatures.
        # We have seen cases where we see ZFS/EXT4 signatures on disk even
        # after creating partition. Since we do lazy partition create, it can
        # happen.
        wipefs_success = True
        if FLAGS.run_wipefs:
          cmd = "sudo wipefs -a %s" % partition
          log.INFO("Running cmd %s" % cmd)
          ret, stdout, stderr = timed_command(cmd)
          stdout = stdout.decode('utf-8')
          stderr = stderr.decode('utf-8')
          if ret:
            log.ERROR("Error running cmd %s, ret %s out %s err %s" %
                      (cmd, ret, stdout, stderr))
            wipefs_success = False

        # Skip the re-format / re-partition of the disk if skip_repartition is
        # set to True.
        if skip_repartition:
          log.INFO("Skipping reformat of partition %s" % partition)
          return wipefs_success

        try:
          log.INFO("Running blkdiscard on partition %s" % partition)
          Disk.blk_discard(partition)
        except:
          log.ERROR("Failed to run blkdiscard on partition %s" % partition)
        log.INFO("Formatting partition %s with ext4" % partition)
        if not disk.format_partition(partition, is_sed):
          log.ERROR("Failed to format partition %s with ext4" % partition)
          status = False
          return False
        if add_can_repartition:
          if not os.path.exists(TEMP_MOUNT_DIR):
            os.makedirs(TEMP_MOUNT_DIR)
            os.chown(TEMP_MOUNT_DIR, self.__nutanix_uid, self.__nutanix_gid)

          if not part_obj.mount(TEMP_MOUNT_DIR):
            log.ERROR("Failed to mount partition %s at %s" %
                      (partition, TEMP_MOUNT_DIR))
            status = False
            return False

          # Create the can_partition file on the disk. This is used by the disk
          # add/replace procedure so that for older versions of the code Genesis
          # will be able to add the disk to the cluster.
          can_repartition_path = os.path.join(TEMP_MOUNT_DIR, "can_repartition")
          try:
            with open(can_repartition_path, "w") as can_repartition_fd:
              can_repartition_fd.flush()
              os.fsync(can_repartition_fd.fileno())
          except IOError as ex:
            log.ERROR("Failed to write out can_repartition file on "
                      "partition %s, error %s" % (partition, str(ex)))
            status = False
            return False

          os.chown(can_repartition_path, self.__nutanix_uid, self.__nutanix_gid)

          os.chmod(can_repartition_path,
                   stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
          if not part_obj.unmount():
            log.ERROR("Failed to unmount partition %s" % partition)
            status = False

          os.rmdir(TEMP_MOUNT_DIR)
      status = True
      return True
    finally:
      if mount_disk and disks:
        log.INFO("Mounting disks %s" % disks)
        for disk in disks:
          if not self.mount_disk(disk):
            log.ERROR("Failed to mount disks %s" % disk)
            status = False
    return status

  def __run_lsiutil(self, cmd):
    """
    Wrapper for running lsiutil locally (KVM/ESX) or on hypervisor.
    """
    if self.__is_hyperv and HypervHost.is_windows_2012():
      cmd = "&\"%s\" %s" % (
        FLAGS.hyperv_nutanix_path + FLAGS.hyperv_lsiutil_relative_path, cmd)
      log.INFO("Executing cmd: " + cmd)
      stdout = self.__run_hyperv_cmd(cmd)
      return stdout == None, stdout
    else:
      cmd = "%s %s" % (FLAGS.lsiutil_location, cmd)
      log.INFO("Executing cmd: " + cmd)
      ret, stdout, stderr = timed_command(cmd)
      stdout = stdout.decode("utf-8")
      stderr = stderr.decode("utf-8")
      return ret, stdout

  def __set_disks_default_scheduler(self, disk_name):
    """
    Set the default disk scheduler for a given disk.

     HDD: mq-deadline
     NVMe or SSD: none

    @return:
      True on success else returns False.
    """
    if PmemDevice.is_pmem_device(disk_name):
      log.INFO("Not setting disk scheduler for PMEM device %s" % disk_name)
      return True

    # Determine storage tier.
    tier = utils.find_storage_tier(disk_name)
    if not tier:
      log.ERROR("Failed to find storage tier for %s" % disk_name)
      return False

    # ENG-232483: Purposely shorting the SSD-SATA and SSD-PCIe case to avoid
    # the high iostat numbers due to a bug in the Linux Kernel 957.10.
    # Please use https://access.redhat.com/solutions/3901291 to decide when to
    # do away with the `and False` clause here.
    if tier in ["SSD-SATA", "SSD-PCIe", "SSD-MEM-NVMe"] and False:
      # Change the scheduler for each SSD/NVMe to "none".
      value = "none"
    else:
      # Change the scheduler for each HDD to "mq-deadline".
      value = "mq-deadline"

    log.CHECK(disk_name.startswith("/dev"))
    disk_name = os.path.basename(disk_name)

    tunable = "/sys/block/%s/queue/scheduler" % disk_name

    log.INFO("Setting %s to %s" % (tunable, value))
    ret, out, err = timed_command("sh -c 'echo %s > %s'" %
                                    (value, tunable))
    out = out.decode('utf-8')
    err = err.decode('utf-8')
    if ret != 0:
      log.ERROR("Failed to set %s to %s, ret %s, out %s err %s" % (
                tunable, value, ret, out, err))
      return False
    return True

  def __maybe_disable_lsi_write_cache(self):
    cmd = "-i"
    ret, stdout = self.__run_lsiutil(cmd)
    if ret:
      log.ERROR("Failed to query lsiutil for HBAs ('%s')" % cmd)
      return
    matches = re.findall(r"^(?:ioc|Scsi Port )(\d)\s+LSI Logic (\S+)",
                         stdout, re.MULTILINE)
    for index, name in matches:
      index = int(index)
      if not self.__is_hyperv:
        index += 1
      log.INFO("Found HBA %d: %s" % (index, name))
      if name in ["SAS3008", "SAS2308"]:
        if self.__is_hyperv:
          cmd = "-p%d -a \",,0\" 14" % index
        else:
          cmd_read = "-p%d -a ,,, 14" % index
          ret_read, stdout_read = self.__run_lsiutil(cmd_read)
          pattern = r"^(SATA Write Caching.*default is) (\d*)"
          matches = re.findall(pattern, stdout_read, re.MULTILINE)
          if len(matches) == 1 and int(matches[0][1]) == 0:
            log.INFO("Write cache already disabled for hba_index %s" %index)
            continue
          cmd = "-p%d -a ,,0,0,0 14" % index
        ret, stdout = self.__run_lsiutil(cmd)
        if ret:
          log.ERROR("Failed to disable HBA write cache ('%s')" % cmd)
        cmd = "-p%d 99" % index
        ret2, stdout = self.__run_lsiutil(cmd)
        if ret2:
          log.ERROR("Failed to reset HBA asic ('%s')" % cmd)
        if not ret and not ret2:
          log.INFO("Disabled write cache on controller %d" % index)

  def __rescan_scsi_bus(self):
    """
    Rescans all scsi buses present on the local node.
    """
    for scan in glob.glob("/sys/class/scsi_host/host*/scan"):
      try:
        with open(scan, "w") as scan_fd:
          scan_fd.write("- - -")
      except IOError as ex:
        log.WARNING("Failed to rescan scsi bus %s, error %s" % (scan, str(ex)))

  def __update_proto_to_remove_for_disks(self, proto, disk_ids, operation):
    """
    Update the provided config proto object with the disks to_remove param.

    Params:
      proto: config_proto object to be updated
      disks_ids (list of strings): disk id from config proto for disks.
      operation (string): Mark disk to_remove = True/False
                          if operation is Remove/Add.
    Returns:
      bool, bool: status, changed
      1) status = True if successful, False otherwise.
      2) changed = If proto was modified or not.
    """
    if operation not in ["set", "clear"]:
      log.ERROR("Invalid operation %s for to_remove" % operation)
      return False, False

    disk_list = self.__get_node_disks_from_zeus(config_proto=proto,
                                                get_pmem=True)
    changed = False
    for disk_id in disk_ids:
      for disk in disk_list:
        stored_disk_id = (
          disk.device_id if disk.DESCRIPTOR.name == "PmemDevice" else
          disk.disk_id)
        if stored_disk_id == disk_id:
          if operation == "clear" and disk.to_remove:
            log.INFO("Clearing to_remove tag from disk %s" % disk_id)
            disk.to_remove = False
            changed = True

          if operation == "set" and not disk.to_remove:
            log.INFO("Setting to_remove tag to disk %s" % disk_id)
            disk.to_remove = True
            changed = True

    return True, changed

  def __update_proto_with_offline_disks(self, proto, disk_serials_short,
                                        operation):
    """
    Update the provided config proto object with newly offline disk.
    Do not mark disk as to_remove. This routine will attempt to update
    all the disk serials or none of them, should any issues be encountered.

    Params:
      proto: The Zookeeper ConfigurationProto object to be updated.
      disk_serials_short (list of string): ID_SERIAL_SHORT for disks.
      operation (string): Remove/Add disks from/to offline mount paths.

    Returns:
      bool, bool: status, changed
      1) status = True if successful, False otherwise. Additionally, if device
         is not found in the ConfigurationProto, True, False is returned.
      2) changed = If proto was modified or not.
    """
    changed = False

    if proto is None:
      log.ERROR("Invalid ConfigurationProto encountered. Skipping changes to "
                "the offline devices")
      return False, changed

    for disk_serial_short in disk_serials_short:

      # Gather the mount_path for finding the device in the disk_list.
      # Furthermore, mount_path will be used to update the node_list's
      # offline_disk_mount_paths.
      mount_path = self.__get_mount_path(disk_serial_short)

      found_disk = None
      for disk in proto.disk_list:
        if disk.mount_path == mount_path:
          found_disk = disk
          break
      else:
        log.ERROR("Skipping disk mount path %s since its not a part of zeus" %
                  mount_path)
        return True, False

      node = None
      for node_iter in proto.node_list:
        if (found_disk.HasField("last_service_vm_id") and
            node_iter.service_vm_id == found_disk.last_service_vm_id):
          node = node_iter
          break
        elif (found_disk.HasField("service_vm_id") and
              node_iter.service_vm_id == found_disk.service_vm_id):
          node = node_iter
          break
      else:
        log.ERROR("Unable to find node for disk serial %s. Disk proto: %s" %
                  (disk_serial_short, found_disk))
        return False, False

      # Order of steps:
      # 1. Add/Remove mount path to offline_disk_mount_paths.
      #    Stargate stops using the disk after this.
      # 2. Set last service vm id for the disk.

      if operation == "set":
        # (1) add to node.offline_disk_mount_paths
        if mount_path not in node.offline_disk_mount_paths:
          log.INFO("Adding %s (for disk with serial %s) to "
                   "offline_disk_mount_paths" %
                   (mount_path, disk_serial_short))
          node.offline_disk_mount_paths.append(mount_path)
          changed = True

        # (2) Add the last service vm id for the disk. Remove service vm id.
        if (found_disk is not None and
            found_disk.HasField("service_vm_id")):
          found_disk.last_service_vm_id = found_disk.service_vm_id
          found_disk.last_node_uuid = found_disk.node_uuid
          found_disk.ClearField("service_vm_id")
          found_disk.ClearField("node_uuid")
          changed = True

      elif operation == "clear":
        # (1) Remove node.offline_disk_mount_paths
        if mount_path in node.offline_disk_mount_paths:
          log.INFO("Removing %s (for disk with serial %s) from "
                   "offline_disk_mount_paths" %
                   (mount_path, disk_serial_short))
          node.offline_disk_mount_paths.remove(mount_path)
          changed = True

        # (2) Add the service vm id for the disk. Remove last_service vm id.
        if (found_disk is not None and
            found_disk.HasField("last_service_vm_id")):
          found_disk.service_vm_id = found_disk.last_service_vm_id
          found_disk.node_uuid = found_disk.last_node_uuid
          found_disk.ClearField("last_service_vm_id")
          found_disk.ClearField("last_node_uuid")
          changed = True

    return True, changed

  def __clear_tombstone_disks(self, zk_session=None, handled_disk_serials=None,
                              cloud_disk_serials=None):
    """
    Identifies disks mounted in hades proto and removes them from config proto
    disk tombstone list. If is_mounted is absent, we clear the disk from the
    tombstone list as well.

    Args:
      zk_session (ZookeeperSession): Zookeeper session.
      handled_disk_serials (list): List of disks that needs to be cleared from
        zeus proto. Usage:
        []: Empty list would mean none of the disks handled.
        [<disk_serial>] : List of disk_serials that were handled, they can be
          safely cleared.
        None (Default): No need to check for arg then, clear all disks from
          proto's tombstone_list.
      cloud_disk_serials (list): List of cloud disks that need to be cleared
        from zeus proto.
        []: Empty list would mean none of the cloud disks handled.
        None (Default): None would mean none of the cloud disks handled.
        [<disk_serial>] : List of cloud disk_serials that were handled, they
          can be safely cleared.

    Returns:
      bool: True if successful, False otherwise.
    """
    if (handled_disk_serials is not None and len(handled_disk_serials) == 0
        and cloud_disk_serials is None):
      log.ERROR("None of the tombstoned disks whitelisted for removal. Skip")
      return False

    log.INFO("Tombstoned disk serials that needs to be handled "
             "(None denotes all): %s" % handled_disk_serials)

    config = Configuration().initialize(host_port_list=self.__host_port_list,
                                        zk_session=zk_session)
    if not config:
      log.ERROR("Failed to initialize config object")
      return False

    proto = config.config_proto()

    if len(proto.disk_tombstone_list) == 0:
      log.INFO("No disks are tombstoned in zeus config")
      return True

    hades_config, version = hades_utils.get_hades_proto(
      zk_session=zk_session, config_proto=proto)

    # The disk should just be present in Hades proto as Hades just intends to
    # clear local tombstoned disks. We need not check for disk mount status.
    # Refer: ENG-378940.
    present_disks_serial = [slot.disk.serial for slot in hades_config.slot_list
                            if slot.disk_present]
    log.DEBUG("Devices marked disk_present: True in Hades proto: %s" %
      present_disks_serial)

    all_disks_mount_path = [serial for serial in
                            os.listdir(self.__stargate_disk_directory)
                            if os.path.isdir(os.path.join(
                              self.__stargate_disk_directory, serial))]
    log.DEBUG("Disks with a mountpath dir: %s" % all_disks_mount_path)

    # Take a deep copy as the same list would be used for deletion.
    tombstone_lst = proto.disk_tombstone_list[:]
    log.DEBUG("Current tombstone list: %s" % tombstone_lst)

    while True:
      changed = False
      last_timestamp = proto.logical_timestamp

      # Different levels to check before removing a disk from tombstone list:
      #
      # -- The disk can still be part of Hades proto (graceful disk removal).
      #
      # -- If above condition fails, the disk can still have an active mount
      #    directory (hotunplugged disk).
      #
      # -- If above conditions fail, check if it's an EC2 disk. EC2 disks are
      #    not part of Hades proto. To be noted: Non-local disks can also make
      #    the cut, which is expected behavior.
      #
      # -- In the end, validate if the disk is part of handled_disk_serials.
      #    This ensures that only handled devices are removed. Multiple devices
      #    of the same node could be in tombstone handling (they could be in
      #    different stages of disk removal).

      for tombstoned_disk_serial in tombstone_lst:
        if (tombstoned_disk_serial in present_disks_serial or
            tombstoned_disk_serial in all_disks_mount_path or
            self.is_EC2_disk(tombstoned_disk_serial)):

          # If reached here, the disk is eligible to be handled by this node.
          if (handled_disk_serials is not None and
              tombstoned_disk_serial not in handled_disk_serials):
            log.INFO("Disk %s is not handled yet, skip to remove from zeus "
                      "proto tombstoned list" % tombstoned_disk_serial)
            continue

          proto.disk_tombstone_list.remove(tombstoned_disk_serial)
          log.INFO("Removing disk %s from tombstone list" %
            tombstoned_disk_serial)
          changed = True

      # Cloud disks will not be populated in Hades proto hence we will
      # not check Hades proto for cloud disks tombstone workflow.
      if cloud_disk_serials:
        for disk_serial in cloud_disk_serials:
          if disk_serial in proto.disk_tombstone_list:
            proto.disk_tombstone_list.remove(disk_serial)
            log.INFO("Removing cloud disk %s from tombstone list" %
                     disk_serial)
            changed = True

      if changed:
        if not config.commit(proto):
          if proto.logical_timestamp > last_timestamp:
            continue
          log.ERROR("Failed to update the Zeus configuration with disk "
                    "tombstone list changes")
          return False
        log.INFO("Successfully updated the Zeus configuration with disk "
                 "tombstone list changes")
        return True

      log.INFO("No change in disk tombstone list")
      return True

  def is_EC2_disk(self, disk_serial):
    """
    Method to check if the given disk serial is an EC2 disk.
    Args:
      disk_serial (str): The serial number of the disk.

    Returns:
      (bool): True if the disk with given disk serial is an EC2 disk.
              False otherwise.

    """
    if disk_serial is None:
      log.ERROR("Found empty disk serial id")
      return False
    # The current way to filter an EC2 disk is if the disk serial for the disk
    # starts with "AWS".
    # TODO(Vishnu): With tombstone 2.0 we do not need to filter for EC2 in
    #  specific.
    is_ec2_disk = disk_serial.startswith("AWS")

    log.DEBUG("Disk serial %s fits for an EC2 disk: %s" % (disk_serial,
      is_ec2_disk))
    return is_ec2_disk

  def __run_hyperv_cmd(self, cmd, ignore_error=False):
    """
    Private helper to run command on hyperv shell.

    Returns:
      string: stdout from the command that was invoked. None otherwise.
    """
    rshell = BasicRemoteShell()
    rv, stdout, stderr = rshell.execute(cmd)

    stdout = stdout.decode("utf-8")
    stderr = stderr.decode("utf-8")

    if not ignore_error and (rv or stderr.strip()):
      log.ERROR("Could not execute command '%s' on the hypervisor"
                " via remote shell: %s" % (cmd, stderr))
      return None

    return stdout

  def __change_disks_stargate_usable_state(self, disks, disk_serials, state):
    """
    Adds disks in offline mount path if state is unusable.
    Removes disks from offline mount path if state is usable.
    Mark disk as offline if state is offline. This is not supported on cloud
    disks.

    Args:
      disks(list): List of disk paths. E.g.: [/dev/sda].
      disk_serials(list): List of disk serials. E.g.: ["SN12345"].
      state(str): State to set the disk to. Acceptable values are
        "usable" or "unusable".

    Returns True if successful, False if the disk is a cloud disk or PMEM
            device or otherwise.

    TODO: Persist state of planned outage across restarts.
    """
    if state not in ["usable", "unusable"]:
      log.ERROR("Invalid state %s for stargate usable state" % state)
      return False

    if not disks and not disk_serials:
      log.ERROR("No valid disks provided for changing stargate usable status")
      return False

    valid_disk_serials = []
    for disk_serial in disk_serials:
      if CloudHelperUtil.is_cloud_disk(disk_serial_id=disk_serial):
        log.ERROR("Disk with serial %s is a cloud disk which does not "
                  "support this operation. Skipping" % disk_serial)
        continue
      valid_disk_serials.append(disk_serial)

    # Verifying is disks with the given disk_serials are all cloud disks.
    # If yes setting the Stargate usable state is not supported.
    if not valid_disk_serials and disk_serials:
      log.ERROR("Disks with the given disk serial id(s) are cloud disks, "
                "Set Stargate usable state is not supported on cloud disks")
      return False

    disk_serials = valid_disk_serials
    disk_serials_short = []
    for disk in disks:
      if not disk.startswith("/dev/"):
        log.ERROR("Disk %s is not a valid disk" % disk)
        continue
      disk_obj = Disk(disk)
      disk_serial_short = disk_obj.serial_number()
      disk_serials_short.append(disk_serial_short)

    disk_serials_short.extend(disk_serials)

    # If there have PMEM device in the disk list, return False. We don't want
    # to process the disk list partially.
    for disk_serial in disk_serials_short:
      if PmemDeviceUtil.is_pmem_device_serial(disk_serial):
        log.ERROR("Marking usable/unusable is not supported for PMEM device %s"
                  % disk_serial)
        return False

    if not disk_serials_short:
      log.ERROR("No valid disks found in [%s, %s]" % (disks, disk_serials))
      return False

    if state == "usable":
      return self.change_disks_offline_paths(disk_serials_short,
                                             operation="clear")
    elif state == "unusable":
      return self.change_disks_offline_paths(disk_serials_short,
                                             operation="set")

  def __update_hades_disks_state(self, zk_session=None):
    """
    Update hades disk state depending upon whether disks are present
    in zeus, if are partitioned and if have any data on them.

    Return True if successful, False otherwise.

    Cases need to be handled here are:
    1) Disk is not present in zeus configuration.
      1.1) Disk is not correctly partitioned, mark disk unmounted in hades,
           proto, raise an alert, prism will call repartition and mount RPC.)
      1.2) Disk is correctly partitioned, mark disk mounted in hades proto
        1.2.1) If data is present, then unmount disk, mark disk as unmounted in
               hades proto, raise alert, prism will call RPC to repartition.)
        1.2.2) If data is not present, then turn off leds, add disk to
               zeus configuration if required else disk_service will
               add disk to zeus.
    2) Disk is present in zeus configuration:
       2.1) If disk is marked to_remove, raise an alert, prism will call)
            RPC to mark disk usable again.
    """
    if not zk_session:
      zk_session = genesis_utils.get_zk_session(
        host_port_list=self.__host_port_list)
      if not zk_session:
        log.ERROR("Unable to obtain a zookeeper session")
        return False

    serial_number_to_disk_obj_map = (
      self.get_disk_serial_to_block_device_mapping())

    # Check if SED managed devices are present on the node.
    self.__sed_devices_present = sed_utils.sed_drive_present()

    while True:
      log.INFO("Preparing hades proto with updated disk state")
      changed = False

      hades_config, version = hades_utils.get_hades_proto(zk_session)

      if not hades_config:
        log.ERROR("Failed to get hades configuration")
        return False

      log.DEBUG("Hades configuration for node is %s" % str(hades_config))

      zeus_config = self.__get_zk_config_proto(zk_session)
      if zeus_config is None:
        log.ERROR("Unable to fetch zeus_config")
        return False

      node_disk_list = self.__get_node_disks_from_zeus(
        zk_session, config_proto=zeus_config)
      node_disk_serials = [disk.disk_serial_id for disk in node_disk_list]
      log.DEBUG("Current node has disks with following serials %s" %
                node_disk_serials)

      # Figure out if the node is configured for encryption.
      allow_only_sed_drives = (
        sed_utils.allow_only_self_encrypting_disks_in_node(zk_session,
                                                           hades_config))
      log.INFO("Only allow SED drives: %s" % allow_only_sed_drives)
      for slot in hades_config.slot_list:
        if not slot.disk_present:
          log.INFO("Slot %s does not have any disk" % slot.location)
          continue
        disk = slot.disk
        if disk.HasField("boot_disk_only") and disk.boot_disk_only:
          log.INFO("Boot disk only found in slot location %d. Continuing "
                   "with next disk" % slot.location)
          continue
        spdk_managed = False
        if FLAGS.spdk_enabled and disk.HasField("nvme_pcie_path"):
          spdk_managed = SPDKUtil.is_path_spdk_managed(disk.nvme_pcie_path)
        log.INFO("Device with serial number %s managed by SPDK: %s" %
                 (disk.serial, spdk_managed))

        # Check disk type matches the rest of the cluster, if it doesn't
        # then we don't want to add it to the cluster.
        disk_block_device = serial_number_to_disk_obj_map.get(disk.serial,
                                                              None)
        slot_designation = self.get_disk_slot_designation(disk.serial,
                                                          hades_config)

        if disk_block_device is None and not spdk_managed:
          log.ERROR("Could not find device corresponding to serial: %s" %
                    disk.serial)

        if (not spdk_managed and
            disk_block_device is not None and
            not hades_utils.is_qualified_disk(disk_block_device)):
          disk_model = Disk(disk_block_device).get_disk_model()
          log.WARNING("Disk %s, %s is not qualified by nutanix and may cause "
                      "performance issues. Hades will continue to try to use "
                      "the disk, and cause a CRITICAL alert"
                      % (disk_block_device, disk_model))
          current_action = "Disk is not qualified by Nutanix"
          ALERT_NOTIFY("CRITICAL", UnqualifiedDisk,
            disk_serial=disk.serial,
            disk_location=slot_designation,
            service_vm_id=self.__get_node_cvm_id(),
            service_vm_external_ip=self.__get_node_cvm_external_ip(),
            action=current_action, timestamp_csecs=int(time.time() * 100),
            disk_model=disk_model)

        if (not spdk_managed and
            allow_only_sed_drives and
            not sed_utils.is_a_self_encrypting_drive(disk_block_device)):
          log.ERROR("Disk %s is a regular drive in a node configured for "
                    "encryption, unmounting" % disk.serial)
          ALERT_NOTIFY("CRITICAL", NonSelfEncryptingDriveInserted,
                       disk_location=slot_designation,
                       disk_serial=disk.serial,
                       service_vm_id=self.__get_node_cvm_id())
          if not disk.HasField("is_mounted") or disk.is_mounted:
            disk.is_mounted = False
            changed = True
          path = self.__get_mount_path(disk.serial)
          if not self.unmount_disk_path(path, "f"):
            log.INFO("Failed to unmount a disk %s" % path)
          else:
            if not self.led_fault(disk_serials=[disk.serial]):
              log.ERROR("Failed to light up LED for %s" % disk.serial)
          continue

        # If the disk is a SED but not protected, don't add it to the cluster,
        # unless it is being used for QA purposes.
        if (security_utils.is_sed_encryption_enabled(zk_session=zk_session) and
            not sed_utils.disk_has_password_set(hades_config,
                                                disk.serial) and
            not self.qa_skip_unmount(disk.serial)):
          log.ERROR("Disk %s is a self encrypting drive with no password set "
                    "in a node with protection enabled, unmounting"
                    % disk.serial)
          if not disk.HasField("is_mounted") or disk.is_mounted:
            disk.is_mounted = False
            changed = True
          path = self.__get_mount_path(disk.serial)
          if not self.unmount_disk_path(path, "f"):
            log.INFO("Failed to unmount a disk %s" % path)
          else:
            if not self.led_fault(disk_serials=[disk.serial]):
              log.ERROR("Failed to light up LED for %s" % disk.serial)
          continue


        # If disk is marked bad then it should not be mounted.
        # This is required when state machine is updated after disk is
        # marked bad e.g. after reboot.
        if disk.is_bad:
          # If it is metadata disk present in zeus proto and marked for removal
          # don't unmount as it could be in middle of migration. Unmount would
          # eventually happen once it moves to tombstone list.
          metadata_disk_to_remove = False
          disk_id = self.disk_serial_to_disk_id(disk.serial)
          if disk_id:
            for zeus_disk in node_disk_list:
              if zeus_disk.disk_id == disk_id:
                if (zeus_disk.HasField("contains_metadata")
                    and zeus_disk.contains_metadata and zeus_disk.to_remove):
                  metadata_disk_to_remove = True
                  log.INFO("Bad disk is metadata disk - don't unmount")

          if not metadata_disk_to_remove:
            log.INFO("Disk %s is marked bad, skipping mounting disk" %
                     disk.serial)
            if not disk.HasField("is_mounted") or disk.is_mounted:
              disk.is_mounted = False
              changed = True

            path = self.__get_mount_path(disk.serial)
            if not self.unmount_disk_path(path, "f"):
              log.INFO("Failed to unmount a disk %s" % path)
            else:
              if not self.led_fault(disk_serials=[disk.serial]):
                log.ERROR("Failed to light up LED for %s" % disk.serial)

            continue

        if not disk_block_device and not spdk_managed:
          log.ERROR("Failed to get block device name for disk serial %s" %
                    disk.serial)
          path = self.__get_mount_path(disk.serial)
          if not self.unmount_disk_path(path, "f"):
            log.ERROR("Failed to unmount %s" % path)
          else:
            if not self.led_fault(disk_serials=[disk.serial]):
              log.ERROR("Failed to light up LED for %s" % disk.serial)

          if not disk.HasField("is_mounted") or disk.is_mounted:
            disk.is_mounted = False
            changed = True
          continue

        # 1) Disk is present in hades but not in zeus configuration.
        if disk.serial not in node_disk_serials:
          log.INFO("Disk %s is not present in zeus configuration" % disk.serial)

          data_partition = self.get_data_partition(disk_block_device)

          # If disk is not correctly partitioned then mark as not mounted
          # in hades proto.

          # TODO: Check if disk is brand new and auto repartition.
          if not data_partition:
            log.INFO("Failed to get partition information for disk %s with "
                     "serial %s, disk is not partitioned correctly. "
                     "Repartition required" % (disk_block_device, disk.serial))

            if not self.unmount_disk(disk_block_device, "f"):
              log.ERROR("Failed to unmount %s" % disk_block_device)
            else:
              if not self.led_fault([disk_block_device]):
                log.ERROR("Failed to light up LED for %s" % disk.serial)

            if not disk.HasField("is_mounted") or disk.is_mounted:
              disk.is_mounted = False
              changed = True

            # TODO: Raise an alert depending upon input.
            continue

          part_obj = Partition(data_partition).initialize()
          if not part_obj.mounted():
            if not disk.HasField("is_mounted") or disk.is_mounted:
              disk.is_mounted = False
              changed = True

            log.INFO("Disk %s is not present in zeus configuration and is not "
                     "partitioned correctly. Repartition and mount required" %
                      disk.serial)
            # TODO: Raise an alert depending upon input.
            continue

          # Check if data is present on disk, if yes mark as not mounted in
          # hades proto, cleaning/ repartitioning is required on the disk.
          if not self.is_stargate_usable(disk_block_device):
            log.INFO("Disk %s with serial %s is not stargate usable, unmounting"
                     % (disk_block_device, disk.serial))

            skip_unmount = self.qa_skip_unmount(disk.serial)
            if not skip_unmount:
              if not self.unmount_disk(disk_block_device, "f"):
                log.ERROR("Failed to unmount %s" % disk_block_device)
              else:
                if not self.led_fault([disk_block_device]):
                  log.ERROR("Failed to light up LED for %s" % disk.serial)

            # Mark disk as unmounted in hades.
            if not disk.HasField("is_mounted") or disk.is_mounted:
              disk.is_mounted = False
              changed = True

            log.INFO("Disk %s is not present in zeus configuration, but data"
                     " is present. Cleaning of disk is required" % disk.serial)

          # If data is not present on disk then mark as mounted in hades and
          # add this disk to zeus configuration.
          else:
            log.INFO("Disk %s with serial %s is stargate usable" %
                     (disk_block_device, disk.serial))
            # TODO: Add disk in zeus configuration depending upon input.
            if not self.mount_disk(disk_block_device):
              log.ERROR("Failed to mount %s" % disk_block_device)
            if not disk.HasField("is_mounted") or disk.is_mounted:
              disk.is_mounted = True
              changed = True

        # 2) Disk is present in both hades and zeus configuration.
        else:
          log.INFO("Disk %s is present in zeus configuration" % disk.serial)
          # Check if disk is empty, make it ready to be added in cluster.
          if spdk_managed or self.is_stargate_usable(disk_block_device):
            if (disk_block_device is not None and
                not self.mount_disk(disk_block_device)):
              log.ERROR("Failed to mount %s" % disk_block_device)

            if not disk.HasField("is_mounted") or not disk.is_mounted:
              disk.is_mounted = True
              changed = True

          else:
            disk_marked_to_remove = (
                self.__are_all_disks_marked_to_remove(
                disk.serial, zk_session=zk_session))
            log.INFO("Disk %s is marked for removal: %s" %
                (disk.serial, disk_marked_to_remove))

            # If the disk is present in zeus_config and not marked to_remove,
            # then the disk should be mounted. If it is not mounted, make a
            # last ditch effort to mount the disk. If this fails, then we mark
            # the disk for removal.
            if not disk_marked_to_remove:
              log.INFO("Ensuring Disk %s is mounted" % disk_block_device)
              disk.is_mounted = self.mount_disk(disk_block_device)
              if not disk.is_mounted:
                log.ERROR("Disk %s is present in zeus_config but we are "
                          "unable to mount it. Marking the disk for removal" %
                          disk_block_device)
                disk_serial_short = Disk(disk_block_device).serial_number()
                disk_id = self.disk_serial_to_disk_id(disk_serial_short)

                # Mark disk to_remove before marking it offline. This will
                # ensure Genesis does not notify Hades for running diagnostics
                # on this disk.
                if not self.change_to_remove_for_disks([disk_id],
                                                       operation="set"):
                  log.ERROR("Failed to set to_remove for disk id %s and "
                            "serial %s" % (disk_id, disk_serial_short))

                if not self.change_disks_offline_paths([disk_serial_short],
                                                       operation="set"):
                  log.ERROR("Failed to offline disk %s" % disk_serial_short)
              changed = True

      if FLAGS.configure_pmem_devices:
        success, hades_pmem_device_changed = (
          PmemDeviceUtil.update_hades_pmem_device_state(hades_config,
                                                        zeus_config))
        if not success:
          log.ERROR("Failed to update Hades proto with PMEM device state")
          return False

        if hades_pmem_device_changed:
          changed = True

      if not changed:
        log.INFO("No disk update is required in hades proto")
        return True

      log.DEBUG("Hades proto to be committed : %s" % str(hades_config))
      ret = hades_utils.commit_hades_proto(hades_config, version,
                                           zk_session=zk_session)
      if not ret:
        log.WARNING("Failed to set new hades config. Potential CAS error. "
                    "Retrying")
        continue

      log.INFO("Successfully updated hades proto")
      return True

  def __populate_firmware_config(self, hades_config):
    """
    Populates the given hades_config proto object with information from
    firmware_config.json.
    """
    fw_config = hades_utils.get_firmware_config()
    if not fw_config:
      log.ERROR("Unable to read firmware configuration")
    else:
      try:
        if "bios" in fw_config:
          hades_config.bios.model = fw_config["bios"]["model"]
          hades_config.bios.firmware_version = (
              fw_config["bios"]["firmware_version"])
        if "bmc" in fw_config:
          hades_config.bmc.model = fw_config["bmc"]["model"]
          hades_config.bmc.firmware_version = (
              fw_config["bmc"]["firmware_version"])
        if "motherboard_model" in fw_config:
          hades_config.motherboard.model = fw_config["motherboard_model"]
      except KeyError as ex:
        log.ERROR("Firmware config file not well formed, got exception: %s"
                  % ex)

  def __populate_hba_firmware_config(self, hades_config):
    """
    Populates the given hades_config proto object with information about HBA
    obtained from storcli.
    """
    storcli_path = FLAGS.storcli64_location
    if not os.path.exists(storcli_path):
      log.ERROR("storcli doesn't exist at: %s" % storcli_path)
      return
    # Check for all available controllers, which support storcli.
    cmd = "%s show all J" % storcli_path
    ret, stdout, stderr = timed_command(cmd)
    stdout = stdout.decode('utf-8')
    stderr = stderr.decode('utf-8')
    if ret:
      log.ERROR("Failed to query details using storcli for HBA ('%s'), "
                "ret: %s, stdout: %s, stderr: %s" % (cmd, ret, stdout, stderr))
      return
    try:
      data = json.loads(stdout)
    except ValueError as exc:
      log.ERROR("Failed to parse storcli output %s due to %s" % (stdout, exc))
      return
    controllers = data.get("Controllers")
    if not controllers:
      log.ERROR("storcli output doesn't have controller information, "
                "output: %s" % stdout)
      return
    # "IT System Overview" is the key to carry data of controller.
    # This key will be missing if the controller on node is not supported
    # by storcli OR no controller is available.
    overview = controllers[0]["Response Data"].get("IT System Overview")
    if not overview:
      overview = controllers[0]["Response Data"].get("System Overview")
      if not overview:
        log.ERROR("'IT System Overview' not found in storcli output: %s" % stdout)
        return
    for controller in overview:
      index = controller.get("Ctl")
      model = controller.get("Model")
      name = controller.get("AdapterType", model)
      if None in (index, name, model):
        log.ERROR("Model/AdapterType/Ctl detail not found in storcli output: "
                  " %s" % controller)
        return
      # Strip Chip SKU from Adapter information.
      name = re.sub(r"\(.*\)", "", name.strip())
      name = " ".join([model, name])
      log.DEBUG("HBA controller information at index %s: %s" % (index, name))

      # Query information about the HBA controller to find the firmware.
      version_chk_cmd = "%s /c%d show all" % (storcli_path, index)
      ret, stdout, stderr = timed_command(version_chk_cmd)
      stdout = stdout.decode('utf-8')
      stderr = stderr.decode('utf-8')
      if ret:
        log.ERROR("Failed to query the firmware image of HBA indexed %s with "
                  "name %s, ret: %s, stdout: %s, stderr: %s" % (index, name,
                                                                ret, stdout,
                                                                stderr))
        continue

      # From output, we can just parse Firmware Version.
      # e.g.
      # Product Name = SMC3816i
      # Serial Number = 5003048023b461f0
      # SAS Address =  5003048023b461f0
      # PCI Address = 00:98:00:00
      # System Time = 07/22/2021 20:22:18
      # FW Package Build = 14.00.02.01
      # FW Version = 14.00.02.00
      # BIOS Version = 09.27.00.00_14.00.01.00
      # NVDATA Version = 14.11.00.07
      # Driver Name = mpt3sas
      # Driver Version = 31.100.01.00

      hba_fw_version_re = re.compile(r"^Firmware Version = (.*)?$", re.M)
      version_match = hba_fw_version_re.search(stdout)
      version = None
      if version_match is not None:
        version = version_match.group(1)
      if version is None:
        # Seems like the regex failed to extract the firmware from storcli
        # output, for any change in output, hba_fw_version_re might require
        # an improvement.
        log.ERROR("Failed to obtain the version for HBA indexed %s with name %s"
                  " from %s" % (index, name, stdout))
        continue
      hba = hades_config.hba_list.add()
      hba.index = index
      hba.model = name
      hba.current_firmware_version = version
      hba.target_firmware_version = version

  def __populate_hostbootdisk_config(self, hades_config, host=None):
    """
    Populates the given hades_config proto object with information about
    active host bootdisk obtained from smartctl commands.

    Args:
      hades_config (HadesProto): HadesProto object to update active host
        bootdisk information.
      host (Hypervisor): Hyperisor object to use. Default: None.

    Returns:
      None.
    """
    nested_node = False
    if hades_utils.check_platform_is_nested():
      # Nested platform is supported on AHV, so using KvmSSHClient.
      nested_node = True
      ssh_client = KvmSSHClient(FLAGS.hypervisor_internal_ip,
                                FLAGS.hypervisor_username)
      ret, stdout, stderr = ssh_client.execute(
              "lsblk --nodeps -no serial,model /dev/sda")
      if ret != 0:
        log.ERROR("Failed to determine model & serial-id "
                  "for hypervisor boot disk")
        return

      tokens = stdout.split(" ")
      bootdisk_info = {}
      bootdisk_info["device_model"] = tokens[1]
      bootdisk_info["serial_number"] = tokens[0]

    if not nested_node:
      host = host if host else Hypervisor.create(do_load=False)
      if not host:
        log.ERROR("Failed to get hypervisor object")
        return

      ret, active_bootdisk = host.get_active_bootdisk()
      if not ret:
        log.ERROR("Failed to get active host bootdisk")
        return

      ret, bootdisk_info = host.get_bootdisk_info(active_bootdisk)
      if not ret:
        log.ERROR("Failed to get bootdisk information")
        return

    try:
      hades_config.hostbootdisk.device_model = bootdisk_info["device_model"]
      hades_config.hostbootdisk.serial_number = bootdisk_info["serial_number"]
    except KeyError as ex:
      log.ERROR("Host bootdisk information could not be populated, got "
                "exception : %s" %ex)

  def __populate_raid_hostbootdisk_config(self, old_hades_config,
                                          hades_config, host=None):
    """
    Populates the given hades_config proto object with information about
    active raid host bootdisk obtained from mvcli commands.

    Args:
      old_hades_config (HadesProto): HadesProto object with active raid host
        bootdisk information to use.
      hades_config (HadesProto): HadesProto object to update active raid host
        bootdisk information.
      host (Hypervisor): Hyperisor object to use. Default: None.

    Returns:
      None.
    """
    try:
      host = host if host else Hypervisor.create(do_load=False)
      if not host:
        log.ERROR("Failed to get hypervisor object")
        return

      ret, raid_bootdisk_info = host.get_raid_bootdisk_info()
      if not ret:
        log.WARNING("Failed to get raid bootdisk info")

      ret, raid_serial_number = host.get_raid_serial_number()
      if not ret:
        log.WARNING("Failed to get raid serial number")

      ret, raid_model = host.get_raid_model()
      if not ret:
        log.WARNING("Failed to get raid model number")

      old_raid_model0, old_raid_model1, old_raid_model2, old_raid_model3 = \
          "", "", "", ""
      old_raid_serial0, old_raid_serial1, old_raid_serial2, old_raid_serial3 = \
          "", "", "", ""
      if old_hades_config:
        old_raid_model0 = (old_hades_config.raidhostbootdisk.raid_disk_p0.
         device_model)
        old_raid_model1 = (old_hades_config.raidhostbootdisk.raid_disk_p1.
         device_model)
        old_raid_model2 = (old_hades_config.raidhostbootdisk.raid_disk_p2.
         device_model)
        old_raid_model3 = (old_hades_config.raidhostbootdisk.raid_disk_p3.
         device_model)
        old_raid_serial0 = (old_hades_config.raidhostbootdisk.raid_disk_p0.
         serial_number)
        old_raid_serial1 = (old_hades_config.raidhostbootdisk.raid_disk_p1.
         serial_number)
        old_raid_serial2 = (old_hades_config.raidhostbootdisk.raid_disk_p2.
         serial_number)
        old_raid_serial3 = (old_hades_config.raidhostbootdisk.raid_disk_p3.
         serial_number)

      hades_config.raidhostbootdisk.raid_card.serial_number = raid_serial_number
      hades_config.raidhostbootdisk.raid_card.device_model = raid_model

      if raid_bootdisk_info:
        hades_config.raidhostbootdisk.raid_disk_p0.device_model = (
         raid_bootdisk_info.get('0', {}).get('model', old_raid_model0))
        hades_config.raidhostbootdisk.raid_disk_p0.serial_number = (
         raid_bootdisk_info.get('0', {}).get('serial', old_raid_serial0))
        hades_config.raidhostbootdisk.raid_disk_p1.device_model = (
         raid_bootdisk_info.get('1', {}).get('model', old_raid_model1))
        hades_config.raidhostbootdisk.raid_disk_p1.serial_number = (
         raid_bootdisk_info.get('1', {}).get('serial', old_raid_serial1))
        hades_config.raidhostbootdisk.raid_disk_p2.device_model = (
         raid_bootdisk_info.get('2', {}).get('model', old_raid_model2))
        hades_config.raidhostbootdisk.raid_disk_p2.serial_number = (
         raid_bootdisk_info.get('2', {}).get('serial', old_raid_serial2))
        hades_config.raidhostbootdisk.raid_disk_p3.device_model = (
         raid_bootdisk_info.get('3', {}).get('model', old_raid_model3))
        hades_config.raidhostbootdisk.raid_disk_p3.serial_number = (
         raid_bootdisk_info.get('3', {}).get('serial', old_raid_serial3))

      hades_config.raidhostbootdisk.raid_disk_p0.functional = False
      hades_config.raidhostbootdisk.raid_disk_p1.functional = False
      hades_config.raidhostbootdisk.raid_disk_p2.functional = False
      hades_config.raidhostbootdisk.raid_disk_p3.functional = False

      if '0' in raid_bootdisk_info:
        hades_config.raidhostbootdisk.raid_disk_p0.functional = True
      if '1' in raid_bootdisk_info:
        hades_config.raidhostbootdisk.raid_disk_p1.functional = True
      if '2' in raid_bootdisk_info:
        hades_config.raidhostbootdisk.raid_disk_p2.functional = True
      if '3' in raid_bootdisk_info:
        hades_config.raidhostbootdisk.raid_disk_p3.functional = True

    except KeyError as ex:
      log.ERROR("Host raid bootdisk info can not be populated: %s" % ex)

  def __discover_hades_config(self, host=None):
    """
    Discovers the hades configuration from the current state of the system.

    Args:
      host (Hypervisor): Hyperisor object to use. Default: None.

    Returns:
      HadesProto: Discovered hades config.
    """
    hades_config = HadesProto()

    if self.__model is None or self.__model.lower() == "null":
      factory_config = util.cluster.info.get_factory_config()
      log.CHECK(factory_config != None, "Failed to get the factory_config")

      self.__model = factory_config.get(
          "rackable_unit_model")
      log.CHECK(self.__model != None, "Failed to fetch rackable unit model")

    is_hyperv = (Hypervisor.get_hypervisor_type() ==
                 ConfigurationProto.ManagementServer.kHyperv)

    self.__slot_count = get_slot_count(self.__model, is_hyperv)
    # What is the significance of this condition when __slot_count
    # cannot be figured out? Is that indicator of non-skeumorphic?
    if not self.__slot_count:
      log.WARNING("Unable to determine total number of slots. Empty disk slots"
                  " will not have entries")

    if not disk_info_from_disk_location or not FLAGS.slot_to_disk_location:
      nvme_pcie_map = NvmeDisk.get_nvme_pcie_map()
      hardware_layout = HardwareLayout.get_instance()

      # Refresh disk location map. This will only return and record kernel
      # managed devices. SPDK managed devices will not be accounted for in
      # here. We will be using the last updated kernel entry for SPDK managed
      # entries.
      disk_location = Disk.disk_location(self.__model, refresh=True,
                                         is_hyperv=is_hyperv).items()

      self.__disk_location_map = dict((loc, disk)
                                      for (disk, loc) in disk_location)

      # This is a hack for the bug in the SMC backplane for 1020 models only.
      # Nodes B and D show disks in slot 1, 2 and 3 as 5,6 and 7. 1020 models
      # have only 3 disks which should be in the 1st 3 locations.
      if self.__model == "NX-1020":
        self.__disk_location_map = dict((loc % 4, disk)
                                       for (disk, loc) in disk_location)

      # Remove all CUSE devices, for the CUSE devices will not be able to help
      # fetch the PCIe path of the managing device. Also, CUSE devices are not
      # be relied on, for they may disappear if Stargate is powered off.
      if FLAGS.spdk_enabled:
        log.INFO("SPDK is enabled. Ignore CUSE managed devices in the location "
                 "map")
        # Get SPDK attached CUSE devices and serial path mappings.
        cuse_serial_map = NvmeDisk.get_cuse_device_serial_path_map()
        log.INFO("CUSE Map: %s" % cuse_serial_map)

        disk_location = self.__disk_location_map
        self.__disk_location_map = dict(
          (loc, disk) for (loc, disk) in disk_location.items()
            if not SPDKUtil.is_cuse_disk(disk))

      log.INFO("Disk location map:\n%s" % self.__disk_location_map)

      # When supporting multiple storage controller in single node AND when
      # that controller have ability to drive same slot, we need to use
      # distinct slot_id to differentiate. So far it used to work since
      # slot_id was perceived as physical slot id. In reality, slot_id
      # is really unified handle to access any index! And using indexed
      # location, we really get correct value of slot_id all the way to
      # zeus so that disk location and associated disk can be accessed.
      indexed_location = self.__disk_location_map.keys()
      log.DEBUG("indexed_location: %s" % indexed_location)
      num_slots = (self.__slot_count if self.__slot_count
                   else (max(self.__disk_location_map.keys()) + 1))
      self.__slot_count = num_slots

      # Pad if physical slots are more than currently found disks.
      # This shall happen when all conditions are met:
      # 1. Same slot is being referred by two entities (different slot_id
      #    but same X/Y location).
      # 2. Those entities are supported to be swapped run time (i.e.
      #    swapping NVMe to SATA/SAS or vice-e-versa).
      # 3. All slots are not fully populated.
      if num_slots > len(indexed_location):
        # Get list of dummy slots - which is practically all valid range.
        dummy_slots = set(range(1, num_slots+1))
        # Example:
        #   Now it is possible that indexed_location contains "7" for system that
        # have 1 to 6 slots. 7 could be aliased with "1". We need to make sure
        # "1" is also removed from the list.
        for occupied_id in indexed_location:
          # While indexed_location shall be excluded from pad, we want to
          # make sure all aliases are also excluded from the pad.
          # So shrink dummy list more by removing aliased list as well.
          used_ids = hardware_layout.get_aliased_logical_slot_id(occupied_id)
          dummy_slots = dummy_slots - used_ids

        log.DEBUG("Effective dummy_slots: %s" % dummy_slots)
        # Remove all those which are already included in indexed_location.
        pad_slot_values = list(dummy_slots - set(indexed_location))
        indexed_location = indexed_location + pad_slot_values

      # Add -1 to denote invalid (0th) location (Internal PCIe SSD),
      # which we stopped supporting, but code is here to stay.
      # For complete understanding of issue, search with
      # "Special case slot 0 for internal PCIe SSD." in same file.
      indexed_location.insert(0, -1)
      log.DEBUG("Adjusted indexed_location: %s" % indexed_location)
      log.DEBUG("Number of slots: %s" % num_slots)
      for slot_location in range(1, num_slots+1):
        slot = hades_config.slot_list.add()
        # At very high level, instead of having location as "index" of
        # iteration, now it is indirect access presented by disk location.
        # Consumer of this call should use location as association and not
        # index. So far UI is using that way.
        logical_slot_id = indexed_location[slot_location]
        # UI shall use lower index only. So Hades and Zeus shall use location
        # information that is lowest in all found value.
        # However, original value (logical) is preserved in logical_slot_id.
        alt_slot_ids = \
                hardware_layout.get_aliased_logical_slot_id(logical_slot_id)
        min_at_same_loc = min(set([logical_slot_id]) | alt_slot_ids)
        slot.location = min_at_same_loc
        slot.logical_slot_id = logical_slot_id
        disk = self.__disk_location_map.get(indexed_location[slot_location])

        spdk_managed = False
        disk_serial = None
        if not disk:
          slot.disk_present = False
          slot.disk.is_mounted = False
          continue

        slot.disk_present = True
        disk_obj = Disk(disk)
        if self.is_boot_disk(disk):
          slot.disk.is_boot_disk = True
          # This is a special case where the boot disk is not used for data.
          disk_model = disk_obj.get_disk_model()
          used_for_data = (hcl.is_metadata_disk(disk_model) or
                           hcl.is_data_disk(disk_model))
          if disk_obj.is_virtual_disk(model=disk_model) and \
             len(disk_obj.partitions()) == 4:
            used_for_data = True

          if not used_for_data:
            slot.disk.boot_disk_only = True
            slot.disk.is_mounted = True

        disk_serial = disk_obj.serial_number(allow_generated=False)
        if not disk_serial:
          # This is probably a bad disk. query udev adm is probably failing.
          # TODO: Maybe raise disk bad alert?
          log.ERROR("Failed to get serial number for disk in slot %d" %
                    slot.location)
          slot.disk.is_bad = True
          slot.disk.is_mounted = False
          continue

        slot.disk.serial = disk_serial
        slot.disk.model = disk_obj.get_full_disk_model()
        slot.disk.vendor_info = disk_obj.get_vendor_information()
        if disk_serial in nvme_pcie_map:
          log.INFO("Disk %s is a NVMe device managed at %s" %
                   (disk_serial, nvme_pcie_map[disk_serial]))
          slot.disk.nvme_pcie_path = nvme_pcie_map[disk_serial]
          slot.disk.spdk_managed = False

        raw_capacity = disk_obj.get_raw_size()
        if raw_capacity != -1:
          slot.disk.raw_capacity = raw_capacity
        disk_fw_ver = disk_obj.get_firmware_version()
        if disk_fw_ver:
          slot.disk.current_firmware_version = disk_fw_ver
          slot.disk.target_firmware_version = disk_fw_ver

        if sed_utils.is_a_self_encrypting_drive(disk):
          sed = HadesProto.Disk.SelfEncryptingDrive()
          slot.disk.self_encrypting_drive.CopyFrom(sed)

      # Special case slot 0 for internal PCIe SSD.
      disk = self.__disk_location_map.get(0)
      if disk:
        slot = hades_config.slot_list.add()
        slot.location = 0
        slot.disk_present = True
        disk_obj = Disk(disk)
        slot.disk.serial = disk_obj.serial_number()
        slot.disk.model = disk_obj.get_disk_model()
        slot.disk.vendor_info = disk_obj.get_vendor_information()
        disk_fw_ver = disk_obj.get_firmware_version()
        if disk_fw_ver:
          slot.disk.current_firmware_version = disk_fw_ver
          slot.disk.target_firmware_version = disk_fw_ver
    else:
      # Refresh disk location map. This will only return and record kernel
      # managed devices. SPDK managed devices will not be accounted for in
      # here. We will be using the last updated kernel entry for SPDK managed
      # entries.
      log.INFO("Using disk information from disk_location utility.")
      # TODO: Remove getattr once new disk location flow is active.
      self.__disk_location_map = getattr(Disk, "slot_to_disk_location")(
        self.__model, refresh=True, is_hyperv=is_hyperv)

      # Remove all CUSE devices, for the CUSE devices will not be able to help
      # fetch the PCIe path of the managing device. Also, CUSE devices are not
      # be relied on, for they may disappear if Stargate is powered off.
      if FLAGS.spdk_enabled:
        log.INFO("SPDK is enabled. Ignore CUSE managed devices in the location "
                 "map")
        disk_location = self.__disk_location_map
        self.__disk_location_map = dict(
          (loc, disk) for (loc, disk) in disk_location.items()
          if not SPDKUtil.is_cuse_disk(disk))

      # For AWS environments, do not account for devices that are boot volumes.
      # For Native AOS, there will be devices that'll have /dev/termination-log
      # and those will be ignored from the Hades proto as well. In summary,
      # those devices that do not have more than 1 partition will be
      # disregarded.
      if HardwareLayout.get_instance().is_aws_cluster():
        log.INFO("Discovered EBS boot volume environment")
        disk_location = self.__disk_location_map
        self.__disk_location_map = dict()
        for (loc, disk) in disk_location.items():
          if len(Disk(disk).partitions()) > 1:
            log.INFO("Ignoring disk %s at slot %s from Hades Proto "
                     "population" % (disk, loc))
            continue
          self.__disk_location_map[loc] = disk

      log.INFO("Disk location map:\n%s" % self.__disk_location_map)
      self.__disk_location_map, self.__slot_count = fill_disk_location_map(
        self.__disk_location_map, self.__slot_count)
      fill_slot_info_to_config(self.__disk_location_map, hades_config)

    self.__populate_misc_to_config(hades_config, discover_pmem=True,
                                   host=host)
    log.DEBUG("Hades Config discovered: {}".format(hades_config))
    return hades_config


  def __populate_misc_to_config(self, hades_config, discover_pmem=False,
                                host=None):
    """
    Populate HBA Firmware, RAID, BIOS FW, Motherboard, PMEM details into hades
    proto.
    Params:
      hades_config (HadesProto): HadesProto instance to be updated.
      discover_pmem (bool): Discover PMEM for proto update.
      host (Hypervisor): Hyperisor object to use. If None, will create a new
        Hypervisor object. Default: None.
    Returns:
      None
    """
    if discover_pmem:
      if (FLAGS.configure_pmem_devices and
            not PmemDeviceUtil.populate_pmem_device_config(hades_config)):
        log.ERROR("Failed to populate Hades config proto with PMEM device "
                  "information")

    self.__populate_hba_firmware_config(hades_config)
    self.__populate_firmware_config(hades_config)
    host = host if host else Hypervisor.create(do_load=False)

    try:
      is_raid_available = False
      # We skip this step for NullHost.
      if not isinstance(host, NullHost):
        is_raid_available = is_raid_available_in_hw_cfg()

      if is_raid_available:
        self.__populate_raid_hostbootdisk_config(None, hades_config,
                                                   host=host)
      else:
        self.__populate_hostbootdisk_config(hades_config, host=host)
    except Exception as err:
      log.ERROR("Failed to populate Hades config proto with host boot device "
                "information. Error {}".format(err))

  def __commit_operation_hades(self, disk_name, operation=""):
    """
    Return True if no operation is in execution on node and current operation
    was recorded in hades proto successfully.
    Return False otherwise.
    Params:
      disk_name : disk name (e.g. /dev/sda/)
      operation (string): operation intended to be done.
    """
    disk_serial = Disk(disk_name).serial_number()
    if not disk_serial:
      return False

    if not self.__is_cluster_configured():
      log.INFO("Cluster is not configured, Skipping hades proto changes for "
               "operation %s on disk %s with serial %s" %
               (operation, disk_name, disk_serial))
      return True

    zk_session = ZookeeperSession(host_port_list=self.__host_port_list)
    if not zk_session.wait_for_connection(None):
      log.ERROR("Unable to obtain a zk session")
      return False

    while True:
      changed = False
      if operation:
        log.INFO("Setting operation %s on disk %s with serial %s" %
                 (operation, disk_name, disk_serial))
      else:
        log.INFO("Clearing ongoing operation on disk %s with serial %s" %
                 (disk_name, disk_serial))

      hades_config, version = hades_utils.get_hades_proto(zk_session)
      if not hades_config:
        log.ERROR("Failed to get hades configuration")
        return False

      # If operation is other than clearing, then check for other operations.
      if operation:
        # Currently only one operation is permitted per node.
        # TODO: Check if this can be optimized to per disk.
        for slot in hades_config.slot_list:
          if slot.disk_present and slot.disk.background_operation:
            log.INFO("Disk %s is performing %s operation" % (
                     slot.disk.serial, slot.disk.background_operation))
            return False

      for slot in hades_config.slot_list:
        if slot.disk_present and slot.disk.serial == disk_serial:
          slot.disk.background_operation = operation
          changed = True
          break

      if not changed:
        return True

      ret = hades_utils.commit_hades_proto(hades_config, version, zk_session)
      if not ret:
        log.WARNING("Failed to set new hades config. Potential CAS error. "
                    "Retrying")
        continue

      return True

  def __clear_background_operation_disk(self, disk_name):
    """
    Clear ongoing operation for disk in hades proto.
    Returns True if successful, False otherwise.
    Params:
      disk_name: disk name e.g. /dev/sda
    """
    return self.__commit_operation_hades(disk_name, operation="")

  def __clear_background_operations(self, zk_session=None):
    """
    Clear all ongoing operations for all disks in hades proto.
    Returns True if successful, False otherwise.
    """
    if not zk_session:
      zk_session = genesis_utils.get_zk_session(
          host_port_list=self.__host_port_list)
      if not zk_session:
        log.ERROR("Unable to obtain a zk session")
        return False

    while True:
      hades_config, version = hades_utils.get_hades_proto(zk_session)
      if not hades_config:
        log.ERROR("Failed to get hades configuration")
        return False

      changed = False
      for slot in hades_config.slot_list:
        if (slot.disk.HasField("background_operation") and
            slot.disk.background_operation):
          slot.disk.background_operation = ""
          changed = True

      if not changed:
        log.INFO("No ongoing operation found in hades proto")
        return True

      ret = hades_utils.commit_hades_proto(hades_config, version, zk_session)
      if not ret:
        log.WARNING("Failed to set new hades config. Potential CAS error. "
                    "Retrying")
        continue
      return True

  def __setup_hades_proto(self, zk_session=None):
    """
    Sets up the hades proto based on the available disks.
    This updates information discovered from current node.

    Returns:
      True on success, False otherwise.
    """
    # Check if SED managed devices are present on the node.
    self.__sed_devices_present = sed_utils.sed_drive_present()

    if not zk_session:
      zk_session = genesis_utils.get_zk_session(
        host_port_list=self.__host_port_list)
      if not zk_session:
        log.ERROR("Failed to set up hades proto. Unable to obtain a zk "
                  "session")
        return False

    cvm_id = hades_utils.get_node_cvm_id(zk_session)
    if not cvm_id:
      log.ERROR("Failed to get node id from configuration proto")
      return False

    hades_config_znode = "%s/%d" % (FLAGS.hades_config_znode_dir, cvm_id)

    # Creating Hypervisor object here to avoid creating multiple Hypervisor
    # objects and executing similar commands to populate host bootdisk
    # information to HadesProto.
    hypervisor_obj = Hypervisor.create(do_load=False)

    hades_config, version = hades_utils.get_hades_proto(zk_session)
    discovered_hades_config = self.__discover_hades_config(
      host=hypervisor_obj)

    if hades_config is None:
      ret = sanitize_hades_proto_for_location(discovered_hades_config)
      if FLAGS.abort_on_disk_slot_overlap and ret is None:
        log.ERROR("Skipping proto commit due to fault on a slot")
        return False

      if not check_disks_in_config(discovered_hades_config):
        log.WARNING("Disks discovered in Hades doesn't match count with the "
                    "enumerated disks, it will result in unsolicited behavior.")
        if FLAGS.skip_commit_partial_disk_list:
          log.ERROR("Skipping proto commit due to disk count mismatch.")
          return False

      # Initialize hades proto at the /appliance/physical/hades/config/<cvm_id>.
      ret = zk_session.create(FLAGS.hades_znode_dir, b"Nodata")
      if not ret and zk_session.error() != "node exists":
        log.ERROR("Failed to create zknode %s with %s" %
                  (FLAGS.hades_znode_dir, zk_session.error()))
        return False

      ret = zk_session.create(FLAGS.hades_config_znode_dir, b"Nodata")
      if not ret and zk_session.error() != "node exists":
        log.ERROR("Failed to create zknode %s with %s" %
                  (FLAGS.hades_config_znode_dir, zk_session.error()))
        return False

      ret = zk_session.create(hades_config_znode,
                              discovered_hades_config.SerializeToString())
      if not ret and zk_session.error() != "node exists":
        log.ERROR("Failed to create hades config CVM zk node %s with %s" %
                  (hades_config_znode, zk_session.error()))
        return False
      else:
        return True

    log.DEBUG("Using discovered_hades_config:\n%s" %
              str(discovered_hades_config))

    while True:
      # Sync discovered config with stored config.
      if discovered_hades_config is None:
        log.ERROR("Empty Hades config was discovered")
        return False

      discovered_slot_list = discovered_hades_config.slot_list[:]
      new_hades_config = HadesProto()
      self.__populate_misc_to_config(new_hades_config, discover_pmem=False,
                                     host=hypervisor_obj)
      recalibrate_nvme_slots(discovered_slot_list, self.__slot_count,
                             hades_config)
      sync_slots_from_old_config(discovered_slot_list,
                                 hades_config, new_hades_config)

      if FLAGS.sanitize_duplicate_location:
        new_hades_config = sanitize_hades_proto_for_location(new_hades_config)
        if FLAGS.abort_on_disk_slot_overlap and new_hades_config is None:
          log.ERROR("Skipping proto commit due to fault on a slot")
          return False

      if (FLAGS.configure_pmem_devices and
          not PmemDeviceUtil.sync_pmem_device_config(hades_config,
                                                     discovered_hades_config,
                                                     new_hades_config)):
        log.ERROR("Failed to synchronize PMEM device information in Hades "
                  "proto")

      if not check_disks_in_config(new_hades_config):
        log.WARNING("Disks discovered in Hades doesn't match count with the "
                    "enumerated disks, it will result in unsolicited behavior.")
        if FLAGS.skip_commit_partial_disk_list:
          log.ERROR("Skipping proto commit due to disk count mismatch.")
          return False

      ret = hades_utils.commit_hades_proto(new_hades_config, version,
                                           zk_session)
      if not ret:
        log.WARNING("Failed to set new hades config. Potential CAS error. "
                    "Retrying")
        hades_config, version = hades_utils.get_hades_proto(zk_session)

        if hades_config is None:
          log.ERROR("Unable to fetch the Hades config")
          return False

        discovered_hades_config = self.__discover_hades_config(
          host=hypervisor_obj)
        continue

      return True

  def __maybe_configure_and_set_sed_password(self, zk_session=None):
    """
    Method to configure and set SED password for eligible SED disks.

    Args:
      zk_session (ZookeeperSession): ZookeeperSession to use. If None, new
        session is created. Default: None.

    Returns:
      bool: True on Success.
    """
    node_disk_list = self.__get_node_disks_from_zeus(zk_session=zk_session)
    hades_config, _ = hades_utils.get_hades_proto(zk_session)
    for disk in self.usable_disks():
      # If disk is new we may have to set a password before mounting.
      disk_obj = Disk(disk)
      log.CHECK(disk_obj)
      disk_serial = disk_obj.serial_number()

      # Stargate usable is true if the disk has one empty data partition.
      stargate_usable = self.is_stargate_usable(disk)

      # Having an entry in zeus means that this disk may be being used.
      disk_id, disk_uuid = sed_utils.disk_has_entry_in_zeus(node_disk_list, disk_serial)
      in_zeus = disk_id is not None

      disk_mounted = self.disk_is_mounted_in_hades(disk_serial,
                                                   hades_config=hades_config)
      # Check that the disk has just an empty data partition and the disk is not
      # present in Zeus before doing a set bands since it is destructive.
      if (stargate_usable and not in_zeus):
        data_partition = disk_obj.get_data_partition()
        if sed_utils.band_configure_needed(disk, data_partition):
          # Band reset is a destructive, needing unmount, set band, reformat,
          # and mount, which is all done in clean_partition.
          partition_mounted = Partition(data_partition).initialize().mounted()
          if not self.__clean_partitions([data_partition],
                                         mount_disk=partition_mounted):
            log.ERROR("Unable to clean partition and reset band")
            continue

      if (not disk_mounted and not stargate_usable and not in_zeus):
        # If a disk does not pass at least one of these checks then it
        # is not in use by anyone and there is no reason to set a password.
        continue
      if not sed_utils.maybe_set_sed_password(disk,
                                              hades_config,
                                              node_disk_list,
                                              zk_session):
        log.ERROR("Could not detect if we had to set passwords on disk %s"
                  % disk_serial)

    log.INFO("Finished mounting and cleaning of SED device's mounted "
             "partition")
    return True

  @classmethod
  def sanitize_hades_proto_for_location(cls, hades_config):
    """
    With introduction of logical_slot_id within slot, it is made
    possible to have same "location" but uniquely different
    entries due to logical_slot_id. All other APIs that use Hades
    protobuf may not be aware of this change and hence depending
    upon their algorithm, it may hide/show information about correct disk.

    Now, it is not possible to have same physical slot holding two drives
    at any given time. Implies it is important to have ability to identify
    unique controller/slot combination in the Hades, but it is not
    necessary to have both entries.

    In order to avoid this ambiguity, `__sanitize_hades_proto_for_location`
    aims to implement following:
        a) Within the list of slot, should have only single slot with
           the same location field. To achieve that, following rules apply.
        b) If there are two slots with the same location, following combination
           exists:
                         Slot@i   Slot@j  Conclusion
               Prob# 1   Empty    Empty    Remove anyone of the two.
               Prob# 2   Present  Empty    Remove slot from index j
               Prob# 3   Empty    Present  Remove slot from index i
               Prob# 4   Present  Present  Error condition. Print msg,
                                           and no action.
    Now above explanation is for two slots. However, this algorithm applies
    to "n" slots with a little simpler implementation.
    1)  If there are more than one slot that is not empty for the
        same location, it is an error (Similar to Prob# 4).
    2)  If all slots with same location are empty, keep anyone and remove
        others.  (Similar to Prob# 1)
    3)  Keep Non-Empty and remove others (Similar to Prob# 2 and 3)

    Args:
        hades_config: Hades proto to be commited.
    Returns
        modified_hades_config: Hades proto that is modified and ready
                               to be committed.
    Note: This function shall work on reference. So input shall be modified.
    """
    # Step# 1: Create structure for hash[location] -> (index,disk_presence)
    location_map = dict()
    roll_back_stack = []
    ReducedSlotData = collections.namedtuple("ReducedSlotData",
                                             ["index", "disk_present"])
    log.INFO("Sanitize Hades Proto")
    log.DEBUG("Sanitize Hades Config : \n%s" % str(hades_config))
    for index, slot in enumerate(hades_config.slot_list):
      disk_present = safe_has_field(slot, "disk")
      if safe_has_field(slot, "disk_present"):
        disk_present = slot.disk_present
      # Create and use this tuple (0-(n-1),  True|False) tuples
      # as base structure.
      value_tuple = ReducedSlotData(index, disk_present)
      location_map.setdefault(slot.location, []).append(value_tuple)

    # Step# 2, check each hashed value of above stated rules are true.
    # Also, create list of index that can be removed.
    index_to_remove = []
    fault_at_any_location = False
    for location, slot_info in location_map.items():
      log.DEBUG("Checking for location %s (Claimed by %s)" % (location,
                                                              slot_info))
      non_empty_cnt = 0
      for item in slot_info:
        if item.disk_present:
          non_empty_cnt += 1

      log.INFO("For location-%s, number of occupied "
               "slots: %d" % (location, non_empty_cnt))
      # Error that one location claimed by more than one non empty slots.
      if non_empty_cnt > 1:
        log.ERROR("Location %s is claimed by more than one "
                  "non-empty slots." % location)
        log.INFO("%s" % slot_info)
        fault_at_any_location = True
        continue

      # All slots are empty, so we can keep one and remove others.
      # For simplicity, keeping the first occurrence.
      if non_empty_cnt == 0:
        index_to_remove.extend([info.index for info in slot_info[1:]])
        # Since all the stats that got computed are not relevant and decision
        # is made, process next key.
        continue

      # Only option left is single slot that is not empty. So remove all that
      # is empty. Implementation applies to those as well when only single
      # occupied slot present for a given location.
      for info in slot_info:
        if not info.disk_present:
          index_to_remove.append(info.index)

    if fault_at_any_location:
      log.INFO("Failed to sanitize Hades Config : \n%s" % str(hades_config))
      return hades_config
    # Remove items from the upper index.
    index_to_remove.sort(reverse=True)
    try:
      log.DEBUG("Indices to remove: %s" % index_to_remove)
      for idx in index_to_remove:
        rmvd_item = hades_config.slot_list.pop(idx)
        roll_back_stack.append((idx, rmvd_item))
      # All transfer is completed. Now roll back can be cleared.
      del roll_back_stack[:]
    except Exception as e:
      log.ERROR("Exception caught while sanitizing hades config. %s" % str(e))
      log.INFO("Half way Hades Config:\n%s" % str(hades_config))
      log.INFO("Attempted removal of indices: %s" % index_to_remove)
      log.INFO("Applying data from roll_back_stack")
      while len(roll_back_stack) > 0:
        data = roll_back_stack.pop()
        idx, slot = data
        log.INFO("@%d, placing %s" % (idx, str(slot)))
        hades_config.slot_list.insert(idx, slot)
      log.INFO("Recovered Hades Config:\n%s" % str(hades_config))

    log.DEBUG("Returning sanitized Hades Config:\n%s" % str(hades_config))
    return hades_config

  def __is_cluster_configured(self, zk_session=None):
    """
    Returns True if cluster is configured, else False.
    """
    config = Configuration().initialize(host_port_list=self.__host_port_list,
                                        zk_session=zk_session)
    if not config:
      log.DEBUG("Failed to initialize configuration object")
      return False

    config_proto = config.config_proto()
    if not config_proto:
      log.ERROR("Failed to get configuration proto")
      return False

    if hades_utils.zeus_node_entry_from_proto(config_proto):
      return True

    log.ERROR("Failed to get node entry from the zeus configuration")
    return False

  def __get_slot_from_config(self, hades_config, location):
    """
    Given a hades config proto and a location, this function returns the slot.
    """
    if not hades_config:
      return None
    for slot in hades_config.slot_list:
      if slot.location == location:
        return slot
    else:
      log.ERROR("Did not discover slot entry for location: %s" % location)
      return None

  def __get_slot_from_serial(self, hades_config, serial):
    """
    Given a hades config proto and a serial number, this function returns the
    slot.

    Args:
      hades_config(HadesConfigProto): The HadesConfigProto to iterate over.
      serial(str): The serial number for which the slot needs to be returned.
    Returns:
      None: If the location is not found.
      Slot proto object: The proto object corresponding to the serial number.
    """
    if hades_config is None:
      return None

    for slot in hades_config.slot_list:
      if slot.disk_present and slot.disk.serial == serial:
        return slot
    else:
      log.ERROR("Did not discover slot entry for serial: %s" % serial)
      return None

  def __unmount_disk(self, disk):
    """
    Unmount all the partitions in the disk.
    Retry few times with sleep intervals.
    Returns True if unmount was successful, False otherwise.
    """
    log.DEBUG("Unmount partitions in disk %s" % disk)

    unmount_disk = False
    for retryc in range(FLAGS.disk_unmount_retry_count):
      if not self.unmount_disk(disk):
        time.sleep(FLAGS.firmware_upgrade_default_wait)
        log.ERROR("Could not unmount disk %s, retry" % disk)
      else:
        log.DEBUG("Unmount disk %s done successfully" % disk)
        return True
    return False

  @rpchandler
  def get_disk_location_map(self):
    """
    Get the location map for disks.  The map consists of "/dev/sd*, loc"
    mapping. Returns disk location map if successful, else returns None.
    """
    is_hyperv_passthrough = (Hypervisor.get_hypervisor_type() ==
                 ConfigurationProto.ManagementServer.kHyperv)

    if disk_info_from_disk_location and FLAGS.slot_to_disk_location:
      # TODO: Remove getattr once slot_to_disk_location code is merged.
      location_map = getattr(Disk, "slot_to_disk_location")(self.__model,
                      is_hyperv=is_hyperv_passthrough).items()
    else:
      location_map = Disk.disk_location(self.__model,
                        is_hyperv=is_hyperv_passthrough).items()
    if not location_map:
      log.ERROR("Unable to find disk location map")
      return None
    if disk_info_from_disk_location:
      return {disk: loc for loc, disk in location_map.items()}
    else:
      return location_map

  @rpchandler
  def disk_serial_to_block_device(self, disk_serial):
    """
    Obtain block device name (e.g. /dev/sda) by matching disk_serial.
    Return block device name if successful, None otherwise.
    """
    if disk_serial is None:
      return None

    disks = Disk.disks()
    for disk in disks:
      disk_obj = Disk(disk)
      if disk_serial == disk_obj.serial_number():
        return disk
    return None

  def get_disk_serial_to_block_device_mapping(self):
    """
    Obtain a hashmap of serial_number to block device name mapping
    Return:
      A python dict key: serial_number -> value: block device name
    """
    serial_number_to_disk_obj_map = {}
    disks = Disk.disks()
    for disk in disks:
      disk_obj = Disk(disk)
      serial_number_to_disk_obj_map[disk_obj.serial_number()] = disk
    return serial_number_to_disk_obj_map


  def __get_slot_for_disk(self, hades_config, disk):
    """
    Find the hades proto slot entry for a given disk.
    If a slot with the disk is found, returns the slot, else returns None.
    """
    log.DEBUG("Get slot corresponding to a disk in hades proto")

    disk_obj = Disk(disk)
    disk_serial = disk_obj.serial_number()
    slot_list = hades_config.slot_list
    for slot in slot_list:
      # Check if this slot has any disk present.
      if not slot.disk_present:
        continue

      # Found slot with disk.
      if slot.disk.serial == disk_serial:
        # Found matching disk.
        return slot

    # Did not find slot with the disk information.
    return None

  def __get_slot_for_disk_serial(self, hades_config, disk_serial):
    """
    Find the hades proto slot entry for a given disk serial.

    Args:
      hade_config(proto): Hades config proto.
      disk_serial(str): The disk serial number.

    Returns:
      int: If a slot with the disk serial is found, returns the slot.
      None: If a slot is not found, it returns None.
    """
    log.DEBUG("Get slot corresponding to a disk serial %s in hades proto" %
              disk_serial)

    slot_list = hades_config.slot_list
    for slot in slot_list:
      # Check if this slot has any disk present.
      if not slot.disk_present:
        continue

      # Found slot with disk.
      if slot.disk.serial == disk_serial:
        # Found matching disk.
        return slot

    # Did not find slot with the disk information.
    return None

  def __set_hades_planned_outage(self, disk_serial):
    """
    This accessor function sets planned_outage flag to true in hades proto
    for the disk provided. Setting hades planned outage is not supported on
    cloud disks.

    Args:
      disk_serial(str): Serial number of the disk to be operated on.

    Returns:
      bool: True on successful configuration and False if the disk with given
      disk serial is a cloud disk or otherwise.
    """
    log.INFO("Set hades planned outage for disk %s" % disk_serial)

    # Verifying if the disk with the given disk serial is a cloud disk.
    if CloudHelperUtil.is_cloud_disk(disk_serial_id=disk_serial):
      log.ERROR("The disk with the given disk serial id is a cloud disk, "
                "setting hades planned outage is not supported on cloud "
                "disk")
      return False

    for retryc in range(FLAGS.hades_retry_count):
      # Get hades proto's slot information for disk.
      proto, version = hades_utils.get_hades_proto()
      if not proto:
        log.ERROR("Hades proto not found")
        return False
      slot = self.__get_slot_for_disk_serial(proto, disk_serial)
      if slot:
        # Set target firmware version in hades proto.
        slot.disk.planned_outage = True

        # Set hades proto zk node.
        ret = hades_utils.commit_hades_proto(proto, version)
        if ret:
          log.INFO("Hades proto set successfully for disk %s" % disk_serial)
          return True
        else:
          log.ERROR("Unable to set hades proto for disk %s, retrying" %
                    disk_serial)
          continue
      else:
        log.ERROR("Set hades proto failed, unable to find slot for disk %s" %
                  disk_serial)
        return False

    log.ERROR("Set hades proto failed after retrying %s times" %
              FLAGS.hades_retry_count)
    return False

  def __clear_hades_planned_outage(self, disk_serial):
    """
    This accessor function clears planned_outage flag in hades proto
    for the disk provided. Clearing hades planned outage is not supported on
    cloud disks.

    Args:
      disk_serial(str): Serial number of the disk to be operated on.

    Returns:
      bool: true on successful configuration and False if the disk with given
      disk serial is a cloud disk or otherwise.
    """
    log.INFO("Set hades planned outage for disk %s" % disk_serial)

    # Verifying if the disk with the given disk serial is a cloud disk.
    if CloudHelperUtil.is_cloud_disk(disk_serial_id=disk_serial):
      log.ERROR("The disk with the given disk serial id is a cloud disk, "
                "clearing hades planned outage is not supported on cloud "
                "disk")
      return False

    for retryc in range(FLAGS.hades_retry_count):
      # Get hades proto's slot information for disk.
      proto, version = hades_utils.get_hades_proto()
      if not proto:
        log.ERROR("Hades proto not found")
        return False
      slot = self.__get_slot_for_disk_serial(proto, disk_serial)
      if slot:
        # Set target firmware version in hades proto.
        slot.disk.planned_outage = False

        # Set hades proto zk node.
        ret = hades_utils.commit_hades_proto(proto, version)
        if ret:
          log.INFO("Hades proto set successfully for disk %s" % disk_serial)
          return True
        else:
          log.ERROR("Unable to set hades proto for disk %s, retrying" %
                    disk_serial)
          continue
      else:
        log.ERROR("Set hades proto failed, unable to find slot for disk %s" %
                  disk_serial)
        return False

    log.ERROR("Set hades proto failed after retrying %s times" %
              FLAGS.hades_retry_count)
    return False

  def disk_under_diagnosis(self, disk_serial, zk_session=None):
    """
    Returns True if disk with serial disk_serial is currently running
    diagnostic test, else returns False.
    Args:
      zk_session (ZookeeperSession): ZK session to use. If None, then a fresh
        one is created. Default None.
    """
    if not disk_serial:
      log.INFO("Invalid disk_serial given to diagnostics")
      return False

    hades_config, _ = hades_utils.get_hades_proto(zk_session)
    if not hades_config:
      log.ERROR("Failed to get hades proto")
      return False

    for slot in hades_config.slot_list:
      if slot.disk.serial == disk_serial:
        if slot.disk.HasField("under_diagnosis") and slot.disk.under_diagnosis:
          return True
        return False
    return False

  def __clear_disk_diagnostics(self, disk_serial):
    """
    Clear disk diagnostics field for the disk in hades proto.
    """
    if not disk_serial:
      log.INFO("Invalid disk_serial given to diagnostics")
      return False
    for retry in range(FLAGS.hades_retry_count):
      hades_config, version = hades_utils.get_hades_proto()
      if not hades_config:
        log.ERROR("Failed to get hades proto")
        return False

      disk = None
      if PmemDeviceUtil.is_pmem_device_serial(disk_serial):
        for device in hades_config.pmem_device_list:
          if device.serial == disk_serial:
            disk = device
            break
      else:
        for slot in hades_config.slot_list:
          if slot.disk.serial == disk_serial:
            disk = slot.disk
            break

      if not disk:
        log.ERROR("Could not locate disk %s in hades config" % disk_serial)
        return False

      if disk.HasField("under_diagnosis") and disk.under_diagnosis:
        log.INFO("Cleared diagnostics for disk %s" % disk_serial)
        disk.under_diagnosis = False
      else:
        # under_diagnosis is not set. Return True
        return True

        # Set hades proto zk node.
      ret = hades_utils.commit_hades_proto(hades_config, version)
      if ret:
        log.DEBUG("Hades proto set successfully for disk %s" % disk_serial)
        return True
      else:
        log.ERROR("Unable to set hades proto for disk %s, retrying" %
                  disk_serial)
        continue

    log.ERROR("Unable to clear diagnostics for disk %s" % disk_serial)
    return False

  def __get_disk_model_hades_proto(self, disk_serial):
    """
    Read the disk model of disk with given serial from hades proto.
    Args:
      disk_serial (str): Serial number of the disk.
    Returns:
      str: Disk model in case of success. None in case of any failure.
    """
    hades_config, version = hades_utils.get_hades_proto()
    if not hades_config:
      log.ERROR("Failed to get hades proto")
      return None
    for slot in hades_config.slot_list:
      if slot.disk.serial == disk_serial:
        return slot.disk.model
    return None

  def __set_hades_proto_bad_disk(self, disk_serial, defer_unmount=False):
    """
    Marks the disk with disk_serial as bad in hades proto.
    """
    for retry in range(FLAGS.hades_retry_count):
      hades_config, version = hades_utils.get_hades_proto()
      if not hades_config:
        log.ERROR("Failed to get hades proto")
        return False

      found = False
      for slot in hades_config.slot_list:
        if slot.disk_present and slot.disk.serial == disk_serial:
          found = True
          break

      if not found:
        log.ERROR("Could not locate disk %s in hades config" % disk_serial)
        return False

      slot.disk.is_bad = True
      slot.disk.is_mounted = defer_unmount

      # Set hades proto zk node.
      ret = hades_utils.commit_hades_proto(hades_config, version)
      if ret:
        log.DEBUG("Successfully marked is_bad=True in hades "
                  "proto for disk: %s" % disk_serial)
        return True
      else:
        log.ERROR("Unable to set is_bad=True in hades proto "
                  "for disk %s, retrying" % disk_serial)
        continue

    log.ERROR("Unable to set bad_disk for disk %s" % disk_serial)
    return False

  def __mark_disk_usable(self, disk):
    """
    Make the disk usable by stargate.  If successful return with
    recoverable error, otherwise return fatal error.
    """
    if not self.mark_disks_stargate_usable([disk]):
      log.ERROR("Failed to mark disk %s online, fatal failure" % disk)
      return False, FLAGS.firmware_upgrade_fatal_failure
    log.ERROR("Disk %s is back online, recoverable failure" % disk)
    return False, FLAGS.firmware_upgrade_recoverable_failure

  def __make_disk_online(self, disk):
    """
    Make the disk usable by mounting it and marking it stargate usable.
    Returns False and error code if failed, and True if succeeds.
    """
    if not self.mount_disk(disk):
      log.ERROR("Failed to mount disk %s after firmware upgrade" % disk)
      return False, FLAGS.firmware_upgrade_fatal_failure
    if not self.mark_disks_stargate_usable([disk]):
      log.ERROR("Post firmware upgrade disk online failed")
      return False, FLAGS.firmware_upgrade_fatal_failure
    return True, None

  @fatal_on_exception
  def __user_disk_repartition_add_zeus(self, disk, repartition=False,
                                       add_zeus=False, partition_type="ext4",
                                       reserved_block_pct=1, rma=False):
    """
    Repartition, mount and add disk to zeus depending upon input.
    Params:
      disk (string)     : disk block device name e.g. /dev/sda
      repartition (bool): If true then repartition else do not
      add_zeus (bool)   : If true then add disk to zeus else do not
      type(string)      : Type of partition
      rbp (integer)     : percentage of blocks to reserve for superuser
      rma(bool)         : If this repartition is for an RMA vs. a capacity
                          upgrade. Default: False.

    Returns True if successful, False otherwise.:
    """
    status = self.disk_repartition_add_zeus(disk, repartition,
                                            add_zeus, partition_type,
                                            reserved_block_pct, rma=rma)
    if not status:
      self.__clear_background_operation_disk(disk)
      return False

    if not self.__clear_background_operation_disk(disk):
      return False

    return True

  # helper functions.
  def disk_serial_to_disk_id(self, disk_serial, zk_session=None,
                             config_proto=None):
    """
    Get all disks that match serial from zeus config proto.
    If there is only one matching entry then return corresponding disk_id.
    But if there are multiple matches then return one with to_remove=False
    Code FATALs if there are more than 1 entries with matching disks serials
    and to_remove=False.

    Args:
      disk_serial(str): The serial number of the disk.
      zk_session(ZK Sesssion object): The zookeeper session object. If None is
        provided, it will be fetched. Default: None.
      config_proto (ConfigProto): The configuration proto object of the cluster.
        If None is provided, it will be fetched. Default: None.

    Returns:
      int: disk_id if successful, None otherwise.
    """
    if not disk_serial:
      return None

    if PmemDeviceUtil.is_pmem_device_serial(disk_serial):
      device_id = PmemDeviceUtil.device_serial_to_device_id(disk_serial)
      return device_id

    disk_list = self.__get_node_disks_from_zeus(
      zk_session=zk_session, config_proto=config_proto)
    if not disk_list:
      log.WARNING("No disk entry found for node")
      return None

    # Maximum one entry for disk with to_remove=False.
    disk_in_use = None
    # Multiple entries posible for disk with to_remove=True.
    disks_to_be_removed = []
    for disk in disk_list:
      if disk.disk_serial_id == disk_serial:
        if not disk.to_remove:
          if disk_in_use == None:
            disk_in_use = disk.disk_id
          else:
            # There should be only one disk which matches with serial number
            # and is not marked to_remove.
            log.FATAL("There is more than 1 entry with matching serial %s and"
                      " marked to_remove=False in config proto" % disk_serial)
        else:
          disks_to_be_removed.append(disk.disk_id)

    if disk_in_use:
      return disk_in_use
    elif len(disks_to_be_removed) == 1:
      return disks_to_be_removed[0]
    elif len(disks_to_be_removed) == 0:
      log.ERROR("Disk serial %s does not have a matching disk id entry in "
                "the config proto" % disk_serial)
      return None
    else:
      # If we reach here it means that all disks with disk_serial are
      # to_remove=True and there are atleast 2 such disks.
      # This is an extreme case so return None in this case.
      # Now there are 2 disks with matching disk_serial.
      log.ERROR("More than 1 disk entry present with disk serial %s which are "
                "marked to_remove=True in config proto" % disk_serial)
      return None

  def __is_boot_disk_only(self, disk_serial, hades_proto=None):
    """
    Check if disk with disk serial is a boot disk only in hades proto.
    Returns True if disk is a boot disk only, False otherwise.
    """
    if not hades_proto:
      hades_proto, _ = hades_utils.get_hades_proto()
      if not hades_proto:
        log.ERROR("Failed to get hades proto")
        return False

    for slot in hades_proto.slot_list:
      if slot.disk_present and slot.disk.serial == disk_serial:
        if slot.disk.boot_disk_only:
          return True
    return False

  def __is_disk_mounted_hades(self, disk_serial, hades_proto=None):
    """
    Check if disk with disk serial is marked mounted in hades proto.
    Returns True if disk is marked mounted, False otherwise.
    """
    if not hades_proto:
      hades_proto, _ = hades_utils.get_hades_proto()
      if not hades_proto:
        log.ERROR("Failed to get hades proto")
        return False

    if PmemDeviceUtil.is_pmem_device_serial(disk_serial):
      for pmem_device in hades_proto.pmem_device_list:
        if pmem_device.serial == disk_serial:
          return pmem_device.is_mounted
      log.ERROR("PMEM device with serial %s doesn't exist in Hades proto" %
                disk_serial)
      return False

    for slot in hades_proto.slot_list:
      if slot.disk_present and slot.disk.serial == disk_serial:
        if slot.disk.is_mounted:
          return True
    return False

  def __is_disk_bad_hades(self, disk_serial, hades_proto=None):
    """
    Check if disk with disk serial is marked bad in hades proto.

    Args:
      disk_serial(str): The serial number of the disk.
    Returns:
      None: If we fail to fetch the HadesProto or failed to
        discover the serial number in the HadesProto.
      bool: True if disk is marked bad, False otherwise.
    """
    if not hades_proto:
      hades_proto, _ = hades_utils.get_hades_proto()
      if not hades_proto:
        log.ERROR("Failed to get hades proto")
        return None

    if PmemDeviceUtil.is_pmem_device_serial(disk_serial):
      for device in hades_proto.pmem_device_list:
        if not device.HasField("is_bad"):
          log.INFO("Pmem device with serial %s does not have the is_bad field"
                   % disk_serial)
          return False
        if device.is_bad:
          log.ERROR("Pmem device with serial %s is marked bad" % disk_serial)
          return True
        else:
          log.INFO("Pmem device with serial %s is not marked bad" %
                   disk_serial)
          return False
      log.INFO("Could not find Pmem device with serial %s in the Hades proto" %
                disk_serial)
      return None

    for slot in hades_proto.slot_list:
      if slot.disk_present and slot.disk.serial == disk_serial:
        if slot.disk.HasField("is_bad"):
          if slot.disk.is_bad:
            log.ERROR("Disk with serial %s is marked bad" % disk_serial)
            return True
          else:
            log.INFO("Disk with serial %s is not marked bad" % disk_serial)
            return False
        else:
          log.INFO("Disk with serial %s does not have the is_bad field" %
                   disk_serial)
          return False
    log.INFO("Could not find disk with serial %s in the Hades proto" %
             disk_serial)
    return None

  def __get_node_disks_from_zeus(self, zk_session=None, config_proto=None,
                                 get_pmem=False):
    """
    Get a list of disks in zeus configuration for this node.
    Need to check both service_vm_id and last_service_vm_id in zeus.
    Args:
      zk_session (zk_session): Zk_session to reuse. Default: None.
      config_proto (proto): Config proto cached copy. Default: None.
      get_pmem (bool): Whether to return PMEM devices as well. Default: False.

    Returns:
      A list of disks if successful, empty list otherwise.
    """
    if not config_proto:
      config = Configuration().initialize(host_port_list=self.__host_port_list,
                                          zk_session=zk_session)
      if not config:
        log.ERROR("No configuration initialized")
        return None
      config_proto = config.config_proto()

    cvm_id = hades_utils.get_node_cvm_id(zk_session, config_proto)
    disk_list = []
    for disk in config_proto.disk_list:
      if ((disk.HasField("service_vm_id") and disk.service_vm_id == cvm_id) or
          (disk.HasField("last_service_vm_id") and
           disk.last_service_vm_id == cvm_id)):
        disk_list.append(disk)

    if not get_pmem:
      return disk_list

    pmem_device_list = []
    for device in config_proto.pmem_device_list:
      if ((device.HasField("service_vm_id") and
           device.service_vm_id == cvm_id) or
          (device.HasField("last_service_vm_id") and
           device.last_service_vm_id == cvm_id)):
        pmem_device_list.append(device)

    return disk_list + pmem_device_list

  def __are_all_disks_marked_to_remove(self, disk_serial, config_proto=None,
                                       zk_session=None):
    """
    Check if all disk entries are marked for removal.
    Return True if successful, False otherwise.
    """
    if not config_proto:
      config = Configuration().initialize(
          host_port_list=self.__host_port_list, zk_session=zk_session)
      if not config:
        log.ERROR("No configuration initialized")
        return False
      config_proto = config.config_proto()

    node_disks = self.__get_node_disks_from_zeus(config_proto=config_proto)

    for disk in node_disks:
      if disk.disk_serial_id == disk_serial and not disk.to_remove:
        return False

    return True

  def __get_disk_error(self, disk_serial_short):
    """
    Routine to determine disk errors and count parsed by disk error parser.

    Args:
      disk_serial_short (str): Disk serial number.
    Returns:
      dict: Dict of mapping disk errors and their count.
        Sample output: {
          "kMediumError": 2,
          ...
        }
    """
    # Get list of all disks errors from Hades proto.
    disk_errors_list = get_disk_errors_hades_proto()

    # Define default value for disk_errors, useful when disk_errors_list does
    # not contain given disk_serial_short or when DiskErrorParser is disabled.
    disk_errors = {"GenericDiskError": 1}

    if disk_errors_list is not None:
      disk_errors = disk_errors_list.get(disk_serial_short, disk_errors)

    return disk_errors

  def __get_node_cvm_id(self, zk_session=None, config_proto=None):
    """
    Routine fetches CVM id for the node.

    Args:
      zk_session(ZookeeperSession object): The session object. Default: None.
      config_proto(ConfigurationProto object): The configuration proto of the
        cluster. Default: None.
    Returns:
      int: The id of the node. If we are unable to find it, we return -1.
    """
    cvm_id = hades_utils.get_node_cvm_id(zk_session, config_proto)

    if not cvm_id:
      log.ERROR("Unable to find CVM id of the node")
      return -1

    return cvm_id

  def __get_node_cvm_uuid(self, zk_session=None, config_proto=None):
    node = hades_utils.zeus_node_entry(zk_session, config_proto)
    if node:
      if node.HasField("uuid"):
        return node.uuid
    log.ERROR("Unable to read node entry in zk")
    return None

  def __get_node_cvm_external_ip(self, zk_session=None, config_proto=None):
    node = hades_utils.zeus_node_entry(zk_session, config_proto)
    if node:
      return node.service_vm_external_ip

    log.ERROR("Unable to read node entry in zk")
    return "Unknown"

  def __configure_disk(self, disk, zk_session=None, config_proto=None,
                       rma_disk_list=[]):
    """
    Creates a disk_config.json if disk_config.json does not already exist or
    if 'formatted' is True.

    Args:
      disk(str): the disk under consideration.
      zk_session(session obj): The session object for ZK session.
      config_proto(ConfigProto): The config proto object of the cluster.
      rma_disk_list(list): List of disks to be RMA'd.
    Returns:
      dict: updated disk_config if successful, else returns None.
    """
    partition = self.get_data_partition(disk)
    if not partition:
      log.ERROR("Failed to get data partition for disk %s" % disk)
      return None

    log.INFO("Checking if we need to prepare partition %s" % partition)
    log.INFO("Preparing partition %s" % partition)
    part_obj = Partition(partition).initialize()
    if not part_obj:
      log.ERROR("Unable to create partition object for disk: %s" % disk)
      return None

    disk_block_store_managed = block_store_utils.is_block_store_enabled_disk(
      disk, config_proto)
    log.INFO("Disk %s managed by block store: %s" %
             (disk, disk_block_store_managed))

    # Get the cluster id and UUID.
    cluster_id = None
    if config_proto is not None and safe_has_field(config_proto, "cluster_id"):
      cluster_id = config_proto.cluster_id

    if cluster_id is None:
      cluster_id = self.__get_cluster_id(zk_session=zk_session)

    # Zk disk params should have disk_config for existing disks.
    disk_config = block_store_utils.get_disk_params_from_zk(
      disk, config_proto)
    log.DEBUG("Disk config for disk %s from ZK: %s" % (disk, disk_config))

    if disk_config is None:
      # Read disk_config.json if the mountpath exists.
      # We return None if disk_config_json exists, we fail to load and
      # validate the disk_config.
      # We continue to create a new disk_config if disk_config_json path does
      # not exist.
      mountpoint = part_obj.mount_path()
      disk_config_json = os.path.join(mountpoint, STARGATE_DISK_CONFIG)
      if os.path.exists(disk_config_json):
        log.INFO("%s already exists in %s" % (disk_config_json, mountpoint))
        try:
          disk_config = json.load(open(disk_config_json))

          # TODO: Add check for incarnation id.
          if disk_config["cluster_id"] != cluster_id:
            log.ERROR("Partition %s mounted at %s has cluster id %s "
                      "but the current cluster has the id %s" %
                      (partition, mountpoint,
                       disk_config["cluster_id"], cluster_id))
            return None

        except IOError as ex:
          log.ERROR("Failed to load disk config %s for disk %s, error %s" %
                    (disk_config_json, part_obj.get_partition_name(), str(ex)))
          return None
        return disk_config
    else:
      # Setting the "bstore_disk" value to False when the disk_config exists to
      # have Hades evaluate again for the block store eligibility during the
      # disk addition.
      disk_config["bstore_disk"] = False
      return disk_config

    mountpoint = part_obj.mount_path()
    if mountpoint == "":
      log.ERROR(
        "Unable to create partition object for partition %s" % partition)
      return None

    log.INFO("Configuring %s mounted at %s" %
             (part_obj.get_partition_name(), mountpoint))

    # This section indicates that we need to create and persist disk config.
    # Determine storage tier.
    if not PmemDevice.is_pmem_device(disk):
      tier = utils.find_storage_tier(part_obj.get_disk_name())
      if not tier:
        log.ERROR("Failed to find storage tier for %s" %
                  part_obj.get_partition_name())
        return None

      log.INFO("Placing %s in tier %s" % (part_obj.get_partition_name(), tier))

    # Statvfs size for the disk to be populated into disk_config.
    disk_size_total = 0
    # Find disk size.
    if PmemDevice.is_pmem_device(disk):
      disk_size = DiskSizeUtil.get_statvfs_size_bytes(mountpoint)
      disk_size_total = disk_size
    else:
      disk_size_total = DiskSizeUtil.get_statvfs_size_bytes(mountpoint)
      rma = disk in rma_disk_list
      disk_size, _ = DiskSizeUtil.get_disk_size(disk, disk_size_total, rma=rma)

    diskconfig = {}
    try:
      # Allocate component id before creating the disk_config.json. If
      # component id allocation fails, we will not end up with empty
      # disk_config.json file.
      disk_id = self.__allocate_component_ids(1, zk_session=zk_session)
      log.CHECK(disk_id is not None)

      # Create disk_config.json.
      fp = open(disk_config_json, "wb", 0)
      diskconfig["disk_id"] = disk_id
      diskconfig["disk_size"] = disk_size
      if not PmemDevice.is_pmem_device(disk):
        diskconfig["storage_tier"] = tier
      diskconfig["statfs_disk_size"] = disk_size_total
      diskconfig["cluster_id"] = cluster_id
      config_write = "%s\n" % json.dumps(diskconfig, sort_keys=True, indent=2)

      # Encode to UTF-8 prior to writing to the file.
      fp.write(config_write.encode("utf-8"))
      os.fsync(fp.fileno())
      os.chown(disk_config_json, self.__nutanix_uid, self.__nutanix_gid)
      fp.close()
    except (UnicodeEncodeError, IOError, OSError) as ex:
      log.FATAL("Failed to create new disk_config.json, error %s" % str(ex))

    return diskconfig

  def __get_cluster_id(self, zk_session=None):
    """
    Returns the unique id assigned to the cluster. Returns None if no cluster
    id is found.
    """
    config = Configuration().initialize(
        host_port_list=self.__host_port_list, zk_session=zk_session)
    if not config:
      log.ERROR("No configuration initialized")
      return None

    config_proto = config.config_proto()
    if not config_proto:
      log.ERROR("Cannot retrieve configuration proto, Zookeeper may not be up")
      return None
    if not config_proto.HasField("cluster_id"):
      log.ERROR("No 'cluster_id' present in the Zeus Configuration")
      return None
    return config_proto.cluster_id

  def __get_cluster_uuid(self, zk_session=None):
    """
    Returns the unique uuid assigned to the cluster. Returns None if no cluster
    id is found.
    """
    config = Configuration().initialize(
        host_port_list=self.__host_port_list, zk_session=zk_session)
    if not config:
      log.ERROR("No configuration initialized")
      return None

    config_proto = config.config_proto()
    if not config_proto:
      log.ERROR("Cannot retrieve configuration proto, Zookeeper may not be up")
      return None
    if not safe_has_field(config_proto, "cluster_uuid"):
      log.ERROR("No 'cluster_uuid' present in the Zeus Configuration")
      return None
    return config_proto.cluster_uuid

  def __allocate_component_ids(self, number_ids, zk_session=None):
    """
    """
    if not zk_session:
      zk_session = genesis_utils.get_zk_session(
          host_port_list=self.__host_port_list)
      if not zk_session:
        log.ERROR("Unable to obtain a zk session")
        return None

    return allocate_component_ids(zk_session, number_ids)

  def __get_device_path_from_serial_id(self, serial_id):
    """
    This routine fetches the device path (/dev/sdc) from a serial id.
    """
    log.INFO("Looking for serial id: %s" % serial_id)

    # Discover all the devices.
    devices = Disk.disks()

    # Create devices to Serial ID map.
    for device in devices:
      # Fetch the serial ID.
      disk_obj = Disk(device)
      if serial_id == disk_obj.serial_number():
        log.INFO("Discovered device %s that matches serial number %s" %
                 (device, serial_id))
        return device

    log.ERROR("Could not find device with serial id: %s" % serial_id)
    return None

  def __get_nvme_disks(self, disk_tier_map):
    """
    Returns a list of NVMe disks.

    Args:
      disk_tier_map(dict): A mapping of disks and tiers.
    Returns:
      list: List of the NVMe devices.
    """
    nvme_disks = []
    nvme_partition_list = NvmeDisk.nvme_partitions()

    for disk in disk_tier_map.get("SSD-PCIe", []):
      if disk in nvme_partition_list:
        nvme_disks.append(disk)
    return nvme_disks

  def __populate_disk_tier_map(self, hades_mounted_disks, config_proto,
                               zk_session=None):
    """
    Build disk tier map.

    Args:
      hades_mounted_disks (list): List of usable disks to choose from with disk
        config either from config proto or disk_config.json.
        Ex: ['/dev/sda', '/dev/sdb']
      config_proto (ConfigurationProto): The ConfigurationProto of the cluster.
      zk_session (ZookeeperSession): Zookeeper session object. Default: None.

    Returns
      dict: The tier map of the disks.
    """
    # Return parameters.
    disk_tier_map = {}

    oplog_disks = self.get_node_oplog_disks(config_proto)
    oplog_disks_serial = [str(disk.disk_serial_id) for disk in oplog_disks]

    # Fetch the latency optimized disks.
    low_latency_disks = []
    if FLAGS.only_select_low_latency_disks_for_oplog:
      low_latency_disks = Disk.get_latency_optimized_disks()

    for disk in hades_mounted_disks:
      tier = utils.find_storage_tier(disk)
      if not tier:
        log.WARNING("Could not fetch tier for disk: %s" % disk)
        continue

      # Check if the interface for the kernel managed device is SSD-PCIe.
      # In that case, we consider the device to be an NVMe. However, do so if
      # if discover_scsi_emulated_nvme is set to True.
      if FLAGS.discover_scsi_emulated_nvme:
        disk_obj = Disk(disk)

        if disk_obj.is_scsi_emulated_nvme():
          log.INFO("Disk %s is a SCSI emulated NVMe device" % disk)
          interface_tier = disk_obj.get_disk_interface_type()
          if interface_tier is not None:
            tier = interface_tier
            log.INFO("Disk %s is a SCSI Emulated NVMe device. "
                     "Placing it in the tier: %s" % (disk, tier))
          else:
            log.ERROR("Unable to fetch interface of disk: %s. Retaining its "
                      "original tier: %s" % (disk, tier))

      # Add the disk to the low_latency tier.
      if (FLAGS.only_select_low_latency_disks_for_oplog and
          disk in low_latency_disks):
        tier = "low_latency"

      serial_number = Disk(disk).serial_number()

      if tier not in disk_tier_map:
        disk_tier_map[tier] = [serial_number]
      else:
        # Ensure disks that have oplog-store on them are in the front of the
        # queue. This allows for the disks to be preferred.
        if serial_number in oplog_disks_serial:
          disk_tier_map[tier].insert(0, serial_number)
        else:
          disk_tier_map[tier].append(serial_number)

    # If SPDK is not enabled, we halt here.
    if not FLAGS.spdk_enabled:
      return disk_tier_map

    # Get the disks on this node.
    disks = self.__get_node_disks_from_zeus(config_proto=config_proto)

    # Filter disks not in the Hades proto.
    hades_config, _ = hades_utils.get_hades_proto(zk_session=zk_session,
                                                  config_proto=config_proto)

    mounted_disks_serial = [slot.disk.serial for slot in hades_config.slot_list
                            if slot.disk_present and slot.disk.is_mounted]

    # Account for SPDK managed disks.
    allowed_tier_list = ["SSD-PCIe", "SSD-MEM-NVMe"]
    if FLAGS.enable_low_endurance_oplog_store:
      allowed_tier_list.append("SSD-LowEndurance")
    for disk in disks:
      if str(disk.storage_tier) not in allowed_tier_list:
        continue

      tier = str(disk.storage_tier)
      serial_number = str(disk.disk_serial_id)

      if serial_number not in mounted_disks_serial:
        log.INFO("Skipping disk with serial %s for oplog-store selection" %
                 serial_number)
        continue

      if tier not in disk_tier_map:
        disk_tier_map[tier] = [serial_number]
      else:
        if serial_number not in disk_tier_map[tier]:
          if safe_has_field(disk, "oplog_disk_size"):
            disk_tier_map[tier].insert(0, serial_number)
          else:
            disk_tier_map[tier].append(serial_number)

    return disk_tier_map

  def get_node_oplog_disks(self, config_proto):
    """
    Routine to get a list of disks that have oplog-store on them.

    Args:
      config_proto(ConfigurationProto): ConfigurationProto of the cluster.

    Returns:
      list: List of disks that have oplog-store on it.
    """
    disks = self.__get_node_disks_from_zeus(config_proto=config_proto)

    oplog_disks = []

    for disk_iter in disks:
      if safe_has_field(disk_iter, "oplog_disk_size"):
        log.INFO("Oplog-store was found on disk: %s" % disk_iter.disk_serial_id)
        oplog_disks.append(disk_iter)

    return oplog_disks

  def select_oplog_disks(self, hades_mounted_disks, config_proto,
                         multi_disk_oplog_supported=True, zk_session=None):
    """
    Routine to select oplog disks.

    Args:
      hades_mounted_disks (list): List of usable disks to choose from with disk
        config either from config proto or disk_config.json.
        Ex: ['/dev/sda', '/dev/sdb']
      config_proto(ConfigurationProto): The ConfigurationProto of the cluster.
      multi_disk_oplog_supported(bool): If True, multiple oplog disks are
        chosen. Default: True.
      zk_session (ZookeeperSession): Zookeeper session object. Default: None.

    Returns:
      list: List of disks chosen to hold the oplog-store.
    """
    # Get the disk tier map.
    disk_tier_map = self.__populate_disk_tier_map(
      hades_mounted_disks, config_proto=config_proto, zk_session=zk_session)

    log.DEBUG("Disk tier map: %s" % disk_tier_map)

    # Enabling all SSDs for oplog is False by default, except when
    # max_ssds_for_oplog is -1.
    enable_all_ssds_for_oplog = False
    num_oplog_disks = 0
    chosen_disks = []

    if FLAGS.max_ssds_for_oplog == -1:
      enable_all_ssds_for_oplog = True

    if multi_disk_oplog_supported:
      # Fetch NVMe devices.
      nvme_disks = disk_tier_map.get("SSD-PCIe", [])
      nvme_disks.extend(disk_tier_map.get("SSD-MEM-NVMe", []))

      # Fetch low latency devices.
      low_latency_disks = []
      if FLAGS.only_select_low_latency_disks_for_oplog:
        low_latency_disks = disk_tier_map.get("low_latency", [])

      if low_latency_disks:
        log.INFO("Setting up oplog disk(s) from Low Latency devices")
        preferred_disks = low_latency_disks
      elif nvme_disks and FLAGS.only_select_nvme_disks_for_oplog:
        log.INFO("Setting up oplog disk(s) from NVMe disks")
        preferred_disks = nvme_disks
      else:
        preferred_tiers = [ "SSD-MEM-NVMe", "SSD-PCIe", "SSD-SATA" ]
        log.INFO("Setting up oplog disk(s) from the following tiers %s" %
                 preferred_tiers)
        if FLAGS.enable_low_endurance_oplog_store:
          preferred_tiers.append("SSD-LowEndurance")
        preferred_disks = []
        for tier in preferred_tiers:
          _ = [preferred_disks.append(disks) \
               for disks in disk_tier_map.get(tier, [])]

      for disk in preferred_disks:
        # Return early from the function if number of oplog disks set up
        # is greater than the max_ssds_for_oplog gflag.
        if (not enable_all_ssds_for_oplog and
            num_oplog_disks >= FLAGS.max_ssds_for_oplog):
          break

        log.INFO("Choosing %s for oplog" % disk)
        chosen_disks.append(disk)
        num_oplog_disks += 1

    log.INFO("Disks chosen for oplog: %s" % chosen_disks)
    return chosen_disks

  def __add_disk_to_config_proto_prechecks(
    self, serial_number, disk_name, config_proto, disk_config, zk_session,
    raise_alert):
    """
    Returns True if all pre-checks pass for adding a new disk to Config Proto.

    Args:
      serial_number (str): Disk serial number.
      disk_name (str): Disk name.
      config_proto (ConfigProto): Config proto.
      disk_config(dict): Disk config, either retreived from zeus_config or
        mountpath/disk_config.json. This would reflect state of existing disks
        that are part of the cluster.
      zk_session(ZookeeperSession): ZookeeperSession Obj.
      raise_alert(bool): If set to True, raise alert wherever suitable.
        Default: False.
    Returns:
      bool: True if all pre-checks pass for adding given new disk to Config
        Proto. Otherwise returns False.
    """
    # 1. Node removal precheck: Fail the precheck if node is being removed.
    if ZeusUtil.is_node_being_removed(config_proto, zk_session):
      log.ERROR("Node removal pre-check failed")
      return False

    # 2. Storage tier eligibility precheck: Fail the precheck if incompatible
    # tiers are detected on the cluster.
    if not StorageTierUtil(self).storage_tier_eligibility_check(
      config_proto, serial_number, disk_config, zk_session):
      log.ERROR("Disk: %s failed storage tier eligibility rules, will "
                "not be added to zeus_config" % serial_number)

      if raise_alert:
        alert_util = AlertUtil(disk_manager=self)
        disk_model = Disk(disk_name).get_disk_model()
        action = "Incompatible tiers found upon disk addition. Remove "\
                 "the disk"
        alert_util.raise_physical_disk_add_alert(
          disk_serial=serial_number, zk_session=zk_session,
          disk_model=disk_model, alert_level="CRITICAL",
          action=action)

      log.ERROR("Storage tier eligibility pre-check failed")
      return False

    log.INFO("Add disk pre-checks passed for the disk %s" % serial_number)
    return True

  def __update_stargate_disks_in_zeus(self, disks, disk_id_dev_node_map,
                                      zk_session=None,
                                      multi_disk_oplog_supported=True,
                                      rma_disk_list=[],
                                      raise_alert=False,
                                      hades_proto=None):
    """
    Scan the disk config files and update their information into the zeus
    configuration.

    Args:
      disks(list of string): List of disk names.
      disk_id_dev_node_map(dict): Dict with key: disk_id and val: disk_name.
      zk_session (ZookeeperSession): Zookeeper session object. Default: None.
      multi_disk_oplog_supported(bool): Multi disk oplog support.
        Default: True.
      rma_disk_list(list of string): List of disk names to be RMA'd.
        Default: Empty list.
      raise_alert(bool): If set to True, raise alert wherever suitable.
        Default: False.
      hades_proto (HadesProto): The Hades proto of the node.
        Default: None.

    Returns:
      bool: True on success and False otherwise.
    """
    # At this point all available disks have already been mounted at their
    # appropriate locations. Scan over them and populate their information into
    # zeus.

    # Map from a disk id to a tuple:
    #   (disk_config object, disk_config directory).
    log.INFO("Updating disks %s in configuration proto" % disks)

    zeus_config = Configuration().initialize(
        host_port_list=self.__host_port_list,
        zk_session=zk_session)

    if not zeus_config:
      log.ERROR("Unable to connect to zk, is cluster up?")
      return False

    disk_configs = []
    disk_id_disk_config_map = {}

    # Fetch the config proto.
    config_proto = self.__get_zk_config_proto(zk_session=zk_session)
    if config_proto is None:
      log.ERROR("Could not fetch config proto")
      return False

    if not hades_proto:
      log.ERROR("Failed to get the Hades config proto")
      return False

    # Check if Block Store is enabled on this node.
    block_store_constraint_met = \
      block_store_utils.is_block_store_node_constraint_met(config_proto,
                                                           hades_proto)
    log.INFO("Block store enabled on this node: %s" %
             block_store_constraint_met)

    usable_disks = []
    for disk in disks:
      partition = self.get_data_partition(disk)
      if not partition:
        log.INFO("Disk %s does not have data partition" % disk)
        continue

      part_obj = Partition(partition).initialize()
      if not part_obj:
        log.ERROR("Failed to create partition %s object for disk %s" %
                  (partition, disk))
        continue

      # TODO(Noufal): Either enhance block_store_utils.get_disk_params_from_zk
      # to read PMEM device from zk or write a separate method for PMEM and
      # call it from here for pmem devices.
      disk_config = block_store_utils.get_disk_params_from_zk(
        disk, config_proto)

      if disk_config:
        mount_path = disk_config["mount_path"]
        disk_id = int(disk_config["disk_id"])
        disk_serial_id = disk_config["disk_serial_id"]
        disk_proto = block_store_utils.get_disk_proto_from_zk_with_serial(
          config_proto, disk_serial_id)
        if disk_proto:
          disk_config["bstore_disk"] = \
            block_store_utils.is_disk_block_store_managed(disk_proto)
        else:
          log.ERROR("Failed to fetch disk_proto for disk: %s from "
                    "ConfigProto" % disk_serial_id)
        disk_id_disk_config_map[disk_id] = (disk_config, mount_path)
        usable_disks.append(disk)
        continue
      else:
        log.INFO("Disk %s is not in the ConfigurationProto yet, will instead "
                 "use the disk_config.json" % disk)

      # Fetch mount path for devices not in the ConfigurationProto.
      mount_path = part_obj.mount_path()
      if not mount_path:
        log.ERROR("Disk %s does not have a mountpoint, and is not managed as "
                  "a Block Store disk. Skipping disk" % disk)
        continue
      disk_configs.append(os.path.join(mount_path, "disk_config.json"))
      usable_disks.append(disk)

    log.INFO("Partitions and mountpath verified for disks")

    # Validating for presence of low_endurance_disks.
    is_low_endurance_disk_present = False

    for path in disk_configs:
      disk_config = None
      with open(path) as fd:
        try:
          disk_config = json.load(fd)
        except:
          log.ERROR("Failed to read disk config %s" % path)
          return False

      disk_id = int(disk_config["disk_id"])
      mount_path = os.path.dirname(path)
      # We will initially have bstore_disk field set to False for disks with
      # disk_config with key "bstore_disk" not present.
      if not "bstore_disk" in disk_config:
        disk_config["bstore_disk"] = False
      disk_config["disk_serial_id"] = os.path.basename(mount_path)
      disk_id_disk_config_map[int(disk_id)] = (disk_config, mount_path)
      # Validating if low_endurance_drive is present in kernel devices.
      if (FLAGS.ptlc_storage_tiering_enabled and
          disk_config["storage_tier"] == "SSD-LowEndurance"):
        is_low_endurance_disk_present = True

    # Choose disks for the Oplog-Store.
    oplog_disks = self.select_oplog_disks(
      usable_disks, config_proto, multi_disk_oplog_supported,
      zk_session=zk_session)

    # Validating if low_endurance_drive if present in spdk devices and mounted
    # in Hades proto.
    if (FLAGS.ptlc_storage_tiering_enabled and not
        is_low_endurance_disk_present):
      is_low_endurance_disk_present = DiskSizeUtil.tier_device_present(
        config_proto, hades_proto, "SSD-LowEndurance")

    for disk_id in disk_id_disk_config_map.keys():
      disk_config, mount_point = disk_id_disk_config_map[disk_id]
      serial_number = disk_config["disk_serial_id"]
      device_path = disk_id_dev_node_map[int(disk_config["disk_id"])]
      disk_config["bstore_disk"] = (
        block_store_utils.can_enable_block_store_on_disk(
          device_path, config_proto, block_store_constraint_met,
          is_low_endurance_disk_present))
      log.INFO("Block store to be enabled on disk %s: %s" %
              (serial_number, disk_config["bstore_disk"]))
      if serial_number in oplog_disks:
        if disk_config.get("oplog_disk_size", 0) == 0:
          log.INFO("Using disk %s for oplog-store" % device_path)
          disk_config["oplog_disk_size"] = -1
          disk_config["cluster_id"] = config_proto.cluster_id

          # Update disk_config.json for this chosen disk.
          path = os.path.join(mount_point, "disk_config.json")
          try:
            with open(path, "w") as fd:
              log.INFO("Persisting oplog_disk_size to path: %s" % path)
              obj = json.dumps(disk_config, indent=2)
              fd.write(obj)
          except (IOError, OSError) as ex:
            log.ERROR("Unable to persist disk_config.json with oplog_disk_"
                      "size to %s. Expected for block store managed devices" %
                      path)
            log.ERROR("Exception: %s" % str(ex))
        else:
          log.INFO("Disk %s has Oplog-Store on it" % device_path)
    log.DEBUG("Oplog and blockstore setup done for devices, "
              "disk_id_disk_config_map before validation for EXT4 ratio: %s" %
              json.dumps(disk_id_disk_config_map, sort_keys=True, indent=2))

    if FLAGS.validate_ext4_total_ratio:
      disk_id_disk_config_map = \
        DiskSizeUtil.validate_ratio_met_for_blockstore_enablement(
          disk_id_disk_config_map)
    log.INFO("Oplog and blockstore setup done for devices, "
             "disk_id_disk_config_map: %s" %
             json.dumps(disk_id_disk_config_map, sort_keys=True, indent=2))

    trimmable_disk_objs = \
      TrimUtil.get_disk_objs_qualified_for_trim()

    def update_disks(config_proto):
      changed = ProtoUpdate.kNoChangesToProto
      tombstoned_disks = set(config_proto.disk_tombstone_list[:])
      for disk_id in disk_id_disk_config_map.keys():
        disk_config, mount_point = disk_id_disk_config_map[disk_id]
        dev_node = disk_id_dev_node_map[int(disk_config["disk_id"])]
        dev_disk = Disk(dev_node)
        serial_number = disk_config["disk_serial_id"]

        # For SPDK disks we won't even be in this code. There isn't a risk
        # of inadvertantly marking a disk as trim_enabled=False just b/c it's
        # SPDK.
        disk_config["trim_enabled"] = \
          TrimUtil.is_disk_serial_trim_capable(serial_number, disk_config,
                                               trimmable_disk_objs)

        if disk_id in config_disk_id_set:
          # Check if the config_proto has changed.
          if self.__update_zeus_with_disk_config(
              config_proto, disk_config, mount_point, serial_number,
              disk_id_dev_node_map, hades_proto, zk_session):
            changed = ProtoUpdate.kChangesToProto
          log.INFO("Zeus config updates done")

        else:
          log.INFO("Running add disk pre-checks for disk %s" % serial_number)
          if not self.__add_disk_to_config_proto_prechecks(
            serial_number, dev_node, config_proto, disk_config, zk_session,
            raise_alert):
            # Add disks pre-checks failed. Abort the proto changes if reached
            # here, i.e., even the disks that passed the rules check but yet to
            # be committed would be disbanded.
            log.ERROR("Add disk pre-checks failed for disk %s. Aborting proto "
                      "change commits" % serial_number)
            return ProtoUpdate.kAbortProtoChanges

          if serial_number in tombstoned_disks:
            log.INFO("Removing disk %s with serial %s from tombstone list" %
                     (dev_node, serial_number))
            config_proto.disk_tombstone_list.remove(serial_number)

          changed = ProtoUpdate.kChangesToProto
          log.INFO("Adding new disk %s to zeus" % disk_config)

          rma = dev_node in rma_disk_list
          log.INFO("Disk %s is being RMA'd: %s" % (dev_node, rma))

          self.__add_disk_to_zeus(config_proto, disk_config, mount_point,
                                  serial_number, disk_id_dev_node_map,
                                  zk_session=zk_session, rma=rma)

          log.INFO("Added disks to zeus config")

          if PmemDeviceUtil.is_pmem_device_serial(serial_number):
            continue
          active_sp = [sp for sp in config_proto.storage_pool_list
                       if sp.to_remove == False]
          active_ctr = [ctr for ctr in config_proto.container_list
                       if ctr.to_remove == False]
          if len(active_sp) == 1:
            storage_pool = active_sp[0]
            log.INFO("Adding new disk %s to only storage pool present in "
                     "cluster" % disk_id)
            storage_pool.disk_id.append(disk_id)
            for disk_entry in config_proto.disk_list:
              if disk_entry.disk_id == disk_id:
                storage_pool.disk_uuid.append(disk_entry.disk_uuid)
            # Increase max capacity of all containers using the storage pool.
            for container in active_ctr:
              if storage_pool.storage_pool_id in container.storage_pool_id:
                container.params.max_capacity += int(disk_config["disk_size"])
          log.INFO("Storage pool updates done")
      return changed

    # Iterator to track the number of iterations to commit the modified proto.
    iteration_number = 1
    # Time delay introduced to commit the modified proto to avoid CAS errors.
    time_delay = 0
    while True:
      if FLAGS.enable_hades_disk_proto_update_random_time_delay:
        log.INFO("Trying to commit the modified proto on SVM: %s, "
                  "attempt: %d" % (self.__get_node_cvm_external_ip(),
                                   iteration_number))
        back_off_time = pow(2, iteration_number)
        time_delay = \
          float((min(random.randint(0, back_off_time),
                     FLAGS.hades_disks_proto_random_delay_ms)))/1000.0
        log.DEBUG("Time delay: %f secs for iteration: %d" % (time_delay,
                  iteration_number))
      config_proto = zeus_config.config_proto()
      config_disk_id_set = set()
      for disk in config_proto.disk_list:
        config_disk_id_set.add(disk.disk_id)
      for device in config_proto.pmem_device_list:
        config_disk_id_set.add(device.device_id)
      last_timestamp = config_proto.logical_timestamp

      # If the protobuf has not changed, then do not try to update.
      commit_to_zk = update_disks(config_proto)

      if commit_to_zk == ProtoUpdate.kAbortProtoChanges:
        log.ERROR("Found discrepancies in disk addition to cluster, aborting "
                  "zeus config updates")
        return False

      if commit_to_zk == ProtoUpdate.kNoChangesToProto:
        log.INFO("No updates to the ConfigProto")
        break

      if not zeus_config.commit(config_proto):
        if config_proto.logical_timestamp > last_timestamp:
          if FLAGS.enable_hades_disk_proto_update_random_time_delay:
            iteration_number += 1
            time.sleep(time_delay)
          continue
        log.ERROR("Failed to update the Zeus configuration with disk "
                  "configuration changes")
        return False
      log.INFO("Successfully updated the Zeus configuration with disk "
               "configuration changes")
      break

    # This is a hack until Hades is faster at processing "update_disk". We've
    # already determined which disks need trim by the above calls to
    # "update_disks", but trim fields aren't updated in ZK above. Only the
    # disk_id_disk_config_map is updated to indicate trim is to be
    # enabled/disabled. As a result, we'll quickly iterate over the Zk config
    # and only update the trim info to avoid CAS errors.
    # TODO: This abomination should be removed once "update_disks" is faster.
    while True:
      log.DEBUG("Attempting to set trim specific ZK configuration")
      changed = False
      config_proto = zeus_config.config_proto()
      last_timestamp = config_proto.logical_timestamp
      local_disk_ids = list(disk_id_disk_config_map.keys())
      for disk in config_proto.disk_list:
        # This disk is from another SVM.
        if int(disk.disk_id) not in local_disk_ids:
          continue

        trim_enabled_intent = \
          disk_id_disk_config_map[disk.disk_id][0]["trim_enabled"]

        # trim_enabled is either not set or the set value doesn't match our
        # intended value so we need to update ZK.
        if (not safe_has_field(disk, "trim_enabled") or
            disk.trim_enabled != trim_enabled_intent):
          disk.trim_enabled = trim_enabled_intent
          changed = True
          continue

      if changed and not zeus_config.commit(config_proto):
        # CAS error, let's retry.
        if config_proto.logical_timestamp > last_timestamp:
          continue
        log.ERROR("Failed to update the Zeus configuration with trim "
                  "specific disk configuration changes")
        return False

      if changed:
        log.INFO("Successfully updated the Zeus configuration with "
                 "trim specific disk configuration changes")
      else:
        log.DEBUG("No trim specific Zeus configuration updates required")

      return True

  def __add_disk_to_zeus(self, config_proto, disk_config, mount_path,
                         serial_number, disk_id_dev_node_map,
                         zk_session=None, rma=False):
    """
    Addes a disk to the Zeus configuration protobuf with the information in
    'disk_config'.

    config_proto: An instance of a Zeus configuration protobuf
    disk_config: An instance of a JSON object created from a disk_config.json
                 file
    mount_path: Where the stargate disk is mounted
    """
    # If we did not find the disk in the configuration protobuf, we need to add
    # it.
    log.INFO("Adding a new disk serial: %s to the Zeus Configuration, "
             "disk_id_dev_node_map: %s" %
             (serial_number, disk_id_dev_node_map))
    log.INFO("Block store to be enabled on disk: %s: %s" %
             (serial_number, disk_config["bstore_disk"]))

    if PmemDeviceUtil.is_pmem_device_serial(serial_number):
      device_name = disk_id_dev_node_map[int(disk_config["disk_id"])]
      PmemDeviceUtil.add_device_to_config_proto(config_proto, disk_config,
                                                mount_path, serial_number,
                                                device_name)
      return

    disk = config_proto.disk_list.add()
    disk.disk_id = int(disk_config["disk_id"])
    disk.disk_uuid = str(NutanixUuid.new())
    disk.storage_tier = disk_config["storage_tier"]
    disk.disk_size = int(disk_config["disk_size"])
    disk.service_vm_id = hades_utils.get_node_cvm_id(config_proto=config_proto)
    disk.trim_enabled = disk_config["trim_enabled"]
    disk_path = disk_id_dev_node_map[int(disk_config["disk_id"])]
    log.INFO("Mount path: %s; Disk path: %s" % (mount_path, disk_path))

    if disk_config["bstore_disk"]:
      blockstore_params = \
        block_store_utils.get_block_store_configs_for_zeus(
          device_path=disk_path, disk_serial=serial_number)
      if blockstore_params:
        # Sleep for specified duration before updating blockstore fields.
        time.sleep(FLAGS.\
          hades_block_store_experimental_sleep_secs_before_zeus_config_update)

        disk.block_store_device_info.format_needed = True
        disk.block_store_device_info.start_offset_bytes = \
          blockstore_params["start_offset_bytes"]
        disk.block_store_device_info.end_offset_bytes = \
          blockstore_params["end_offset_bytes"]

    # Fetch the Node UUID.
    node_uuid_str = self.__get_node_cvm_uuid(config_proto=config_proto)
    if node_uuid_str:
      disk.node_uuid = node_uuid_str

    # If the mount_path is empty, populate it with the appropriate path.
    if mount_path == "":
      mount_path = self.__get_mount_path(serial_number)
    disk.mount_path = mount_path
    disk.disk_serial_id = serial_number

    statfs_disk_size = DiskSizeUtil.get_statvfs_size_bytes(mount_path)

    # Set the statfs_disk_size.
    disk.statfs_disk_size = statfs_disk_size

    # Calculate disk_size.
    log.INFO("Calculate the disk_size for disk %s [RMA: %s]" %
             (disk_path, rma))
    disk_size, extra_reservation_bytes = \
      DiskSizeUtil.get_disk_size(disk_path, statfs_disk_size, rma=rma)

    disk.disk_size = disk_size

    if extra_reservation_bytes:
      extra_res_proto = disk.extra_disk_reservation.add()
      extra_res_proto.component = \
        ConfigurationProto.Disk.ExtraDiskReservation.kUnclaimed
      extra_res_proto.size_bytes = extra_reservation_bytes

    disk.data_dir_sublevels = STARGATE_DISK_DEFAULT_DATA_DIR_SUBLEVELS
    disk.data_dir_sublevel_dirs = STARGATE_DISK_DEFAULT_DATA_DIR_SUBLEVEL_DIRS

    # If disk is a self encrypting drive, create an empty self_encrypting_drive
    # field to indicate that corresponding disk is an SED.
    if sed_utils.is_a_self_encrypting_drive(disk_path):
      # Create SED proto object.
      zeus_sed = ConfigurationProto.Disk.SelfEncryptingDrive()

      # Copy HadesProto information into the ConfigProto.
      proto, version = hades_utils.get_hades_proto(zk_session=zk_session)
      log.CHECK(proto is not None)
      slot = self.__get_slot_for_disk(proto, disk_path)
      log.CHECK(slot is not None)

      # Copy over all the passwords.
      if slot.disk.HasField("self_encrypting_drive"):
        hades_sed = slot.disk.self_encrypting_drive
        for current_password in hades_sed.current_password_list:
          zeus_password = zeus_sed.current_password_list.add()
          zeus_password.secret_uid = current_password.secret_uid
          zeus_password.key_management_server_uuid = (
            current_password.key_management_server_uuid)
        for tentative_password in hades_sed.tentative_password_list:
          zeus_password = zeus_sed.tentative_password_list.add()
          zeus_password.secret_uid = tentative_password.secret_uid
          zeus_password.key_management_server_uuid = (
            tentative_password.key_management_server_uuid)

      # Copy the potentially populated proto into the disk.
      disk.self_encrypting_drive.CopyFrom(zeus_sed)

    # Check If the NVMe drive is managed by VMD device, populate the zeus entry
    # during add disk operation to indicate that NVMe is managed by VMD.
    # self_managed_nvme field is set to true if NVMe device is managed by VMD
    # set to false otherwise.
    disk_name = self.disk_serial_to_block_device(serial_number)
    is_nvme_device = NvmeDisk.is_nvme_device(disk_name)
    if is_nvme_device:
      log.DEBUG("Evaluating NVMe SW Serviceablity")
      sw_serviceable_nvme = is_feature_enabled(
          zk_session, PlatformSolutionCapabilities.kSWServiceableNVMe)
      log.INFO("Device {} managed by SW serviceability: {}".format(
          disk_name, sw_serviceable_nvme))

      # Caveat: sw_serviceable_nvme is node property. Today we don't have
      # a case where there is a possibility of a NVMe device which is not
      # serviceable being on a node which is sw serviceable.
      is_self_managed = (NvmeDisk.is_vmd_managed(disk_name) or
          sw_serviceable_nvme)
      if (not disk.HasField("self_managed_nvme") or
          (disk.self_managed_nvme != is_self_managed)):
        disk.self_managed_nvme = is_self_managed

    # Set the oplog disk size.
    if disk_config.get("oplog_disk_size", "0") != "0":
      oplog_size = int(disk_config["oplog_disk_size"])
      log.INFO("Setting oplog_disk_size to %s for disk %s" %
                (oplog_size, disk.disk_id))
      disk.oplog_disk_size = oplog_size

    # Store the location of the disk.
    disk_location = self.get_disk_location_from_hades(
        serial_number, zk_session=zk_session)
    if disk_location != -1:
      disk.disk_location = int(disk_location)

  def __update_zeus_with_disk_config(self, config_proto, disk_config,
                                     mount_path, serial_number,
                                     disk_id_dev_node_map,
                                     hades_proto, zk_session):
    """
    Updates the Zeus configuration protobuf with the information in
    'disk_config'. Returns True if the Zeus configuration protobuf changed.

    Args:
      config_proto (ConfigProto): An instance of the configuration protobuf.
      disk_config (dict): An instance of a JSON object created from a
        disk_config.json file or the configuration proto.
      mount_path(str): Where the stargate disk is mounted.
      serial_number(str): The serial number of the device.
      disk_id_dev_node_map (dict): The mapping of disk id to the disk's
        parameters.
      hades_proto (HadesProto): The Hades proto object.
      zk_session (ZookeperSession): The ZookeperSession object.

    Returns:
      bool: True if the Config Proto needs to be changed, False otherwise.
    """
    log.INFO("Updating zeus disk: %s" % disk_config)

    changed = False
    sw_serviceable_nvme = None

    # Try and fetch the device name. It will be None for SPDK managed devices.
    device_name = disk_id_dev_node_map.get(int(disk_config["disk_id"]), None)

    if PmemDeviceUtil.is_pmem_device_serial(serial_number):
      changed = PmemDeviceUtil.update_zeus_with_device_config(
        config_proto, disk_config, mount_path, serial_number, device_name)
      return changed

    for disk in config_proto.disk_list:
      if int(disk.disk_id) == int(disk_config["disk_id"]):
        # Check if we need to update any properties.
        reserve_oplog_space = False
        if disk_config.get("oplog_disk_size", "0") != "0":
          if not disk.HasField("oplog_disk_size"):
            oplog_size = int(disk_config["oplog_disk_size"])
            log.INFO("Setting oplog_disk_size to %s for disk %s" %
                      (oplog_size, disk.disk_id))
            disk.oplog_disk_size = oplog_size
            disk.disk_size = int(disk_config["disk_size"])
            if not disk.HasField("block_store_device_info"):
              disk.statfs_disk_size = \
                DiskSizeUtil.get_statvfs_size_bytes(mount_path)

            reserve_oplog_space = True
            changed = True
        elif disk.HasField("oplog_disk_size"):
          log.FATAL("Zeus config for disk %s thinks it contains oplog "
                    "while disk_config.json says otherwise?" % disk.disk_id)

        # Zeus is the authoritative source of the disk_size field once the disk
        # has been added to the configuration. Stargate dynamically updates
        # this field to adjust for metadata spillover, and it is possible that
        # the value in zeus may diverge from that in disk_config.json. The
        # json value will be brought in sync the next time stargate starts.
        # We'll just log a warning here if we see a temporary discrepancy.
        if disk.disk_size != int(disk_config["disk_size"]):
          # After initial upgrade to multi disk oplog version, space for oplog
          # will be reserved on any additional ssds.
          if reserve_oplog_space:
            disk.disk_size = int(disk_config["disk_size"])
            changed = True
          else:
            log.WARNING("Disk size in zeus: %s differs from that in the disk "
                        "config json: %s for disk %s" %
                        (disk.disk_size, disk_config["disk_size"],
                         disk.disk_id))

        if disk.mount_path != mount_path:
          if mount_path == "":
            log.INFO("Mount path is being set to empty. Skipping ...")
          else:
            log.INFO("Current: %s; New: %s" % (disk.mount_path, mount_path))
            disk.mount_path = mount_path
            changed = True

        # Ensure a disk has a disk serial entry. Should the disk serial id
        # be non-empty, we do not modify it.
        if (not disk.HasField("disk_serial_id") or
            (disk.HasField("disk_serial_id") and
             not disk.disk_serial_id)):
          disk.disk_serial_id = serial_number
          changed = True

        service_vm_id = hades_utils.get_node_cvm_id(config_proto=config_proto)
        if (not disk.HasField("last_service_vm_id") and
            disk.service_vm_id != service_vm_id):
          disk.service_vm_id = service_vm_id
          disk.node_uuid = self.__get_node_cvm_uuid(config_proto=config_proto)
          changed = True

        # Manage NVMe Devices backed by VMD
        # set self_managed_nvme as true if managed by VMD otherwsie false
        # Disks are enumerated based on serial number from disk config object
        # NVMe drives moved from vmd node to non vmd node & vice versa
        is_nvme_device = NvmeDisk.is_nvme_device(device_name)
        if is_nvme_device:
          if sw_serviceable_nvme is None:  # Set once in the loop.
            log.DEBUG("Evaluating NVMe SW Serviceability")
            sw_serviceable_nvme = is_feature_enabled(
                zk_session, PlatformSolutionCapabilities.kSWServiceableNVMe)
          log.INFO("Device {} managed by SW serviceability: {}".format(
              device_name, sw_serviceable_nvme))
          is_self_managed = (NvmeDisk.is_vmd_managed(device_name) or
              sw_serviceable_nvme)
          if (not disk.HasField("self_managed_nvme") or
             (disk.self_managed_nvme != is_self_managed)):
            disk.self_managed_nvme = is_self_managed
            changed = True

        # Ensure that the data dir levels and sublevels are configured. We will
        # update both to the default value if any of them are missing.
        if (not disk.HasField("data_dir_sublevels") or
            not disk.HasField("data_dir_sublevel_dirs")):
          disk.data_dir_sublevels = STARGATE_DISK_DEFAULT_DATA_DIR_SUBLEVELS
          disk.data_dir_sublevel_dirs = \
            STARGATE_DISK_DEFAULT_DATA_DIR_SUBLEVEL_DIRS
          changed = True
          log.WARNING("Setting data_dir_sublevel to %s and "
                      "data_dir_sublevel_dirs to %s for disk %s" %
                      (disk.data_dir_sublevels, disk.data_dir_sublevel_dirs,
                       disk.disk_id))

        # Generate disk UUID for zeus config.
        if not disk.HasField("disk_uuid"):
          disk.disk_uuid = str(NutanixUuid.new())
          changed = True

        disk_location = self.get_disk_location_from_hades(
          serial_number, hades_proto=hades_proto)
        if disk_location != -1:
          log.INFO("Ensuring disk %s has the disk location %s" %
                   (device_name, disk_location))
          if (not disk.HasField("disk_location") or
              disk.disk_location != int(disk_location)):
            disk.disk_location = int(disk_location)
            changed = True
        else:
          log.WARNING("Disk %s is not found in the disk locations "
                      "config file" % device_name)

        # If the disk has contains_metadata = true, ensure that it has
        # metadata_disk_reservation_bytes set.
        if ((disk.HasField("contains_metadata") and disk.contains_metadata) and
            (not disk.HasField("metadata_disk_reservation_bytes"))):
          # This disk was marked as a metadata disk by hades. Add explicit
          # metadata reservation.
          kGB = 1024 * 1024 * 1024
          disk.metadata_disk_reservation_bytes = (
              FLAGS.metadata_maxsize_GB * kGB)
          changed = True

        return changed

  def __get_zk_config_proto(self, zk_session=None):
    """
    Return the Zookeeper Config proto.

    Args:
      zk_session (ZookeeperSession): Zookeeper session obj.

    Returns:
      (proto, None): Returns proto object, if any errors, returns None.
    """
    # Establish a zookeeper session, if no arg passed.
    if not zk_session:
      zk_session = genesis_utils.get_zk_session(
          host_port_list=self.__host_port_list)
      if not zk_session:
        log.ERROR("Unable to obtain a zk session")
        return None

    # Fetch the proto in Zookeeper.
    config = Configuration().initialize(
        host_port_list=self.__host_port_list, zk_session=zk_session)
    if not config:
      log.ERROR("No configuration initialized")
      return None

    config_proto = config.config_proto()
    if not config_proto:
      log.ERROR("Cannot retrieve configuration proto, Zookeeper may not be up")
      return None

    return config_proto

  def __get_block_store_device_mount_path(self, disk, config_proto):
    """
    Routine returns the mount path for a given block store managed device.

    Returns:
      str: Mountpath as stored in ZK for the block store managed device.
      None: If mount path is not found.
    """
    # Get the serial number of the disk.
    serial_id = Disk(disk).serial_number()

    if not config_proto:
      log.ERROR("Cannot retrieve configuration proto, Zookeeper may not be up")
      return None

    for disk in config_proto.disk_list:
      if disk.disk_serial_id == serial_id:
        return disk.mount_path

    log.ERROR("Could not discover disk %s in ZK" % disk)
    return None

  def __get_mount_paths_from_disk_names(self, disks=None, config_proto=None):
    """
    Returns list of mount paths.
    """
    if not disks:
      return None

    if not config_proto:
      return None

    # List of mount paths.
    stargate_disks = []

    for disk in disks:
      log.INFO("Processing disk: %s" % disk)
      data_partition = self.get_data_partition(disk)
      log.INFO("Data partition: %s" % data_partition)
      if not data_partition:
        log.INFO("Disk %s does not have any data partition" % disk)
        continue
      if block_store_utils.is_block_store_enabled_disk(disk, config_proto):
        mount_path = \
          self.__get_block_store_device_mount_path(disk, config_proto)
      else:
        part_obj = Partition(data_partition).initialize()
        mount_path = part_obj.mount_path()
      stargate_disks.append(mount_path)
    return stargate_disks

  def get_mount_path(self, disk_name):
    """
    Returns the mount of path of the disk.
    """
    mount_path = self.__get_mount_paths_from_disk_names(disk_name)

    if mount_path:
      return mount_path[0]
    else:
      return None

  def get_slot_from_hades(self, disk_serial, hades_proto=None,
                          zk_session=None):
    """
    Returns the slot that has the disk with the serial. If disk is not present
    in the hades config, it returns None.
    """
    if hades_proto is None:
      hades_proto, version = hades_utils.get_hades_proto(
          zk_session=zk_session)

    if not hades_proto:
      return None

    for slot in hades_proto.slot_list:
      if slot.disk_present and slot.disk.serial == disk_serial:
        return slot
    return None

  def get_disk_slot_designation(self, disk_serial, hades_proto=None):
    """
    Given the disk_serial, returns slot designation of a disk in string.
    If disk is not present in the hades config, it returns "Unknown".

    An optional parameter hades_proto is passed in if the caller would like
    to use there own (cached or newly discovered) version of the config.
    """
    disk_location = self.get_disk_location_from_hades(disk_serial, hades_proto)
    if disk_location != -1:
      if self.__model == "USE_LAYOUT":
        hardware_layout = HardwareLayout.get_instance()
        return hardware_layout.get_slot_designation(disk_location-1)
      return str(disk_location)
    else:
      return "Unknown"

  def get_disk_location_from_hades(self, disk_serial, hades_proto=None,
                                   zk_session=None):
    """
    Given the disk_serial, returns human readable location of a disk.
    If disk is not present in the hades config, it returns None.

    An optional parameter hades_proto is passed in if the caller would like
    to use there own (cached or newly discovered) version of the config.
    """
    log.CHECK(self.__model is not None)
    slot = self.get_slot_from_hades(disk_serial, hades_proto=hades_proto,
                                    zk_session=zk_session)
    if slot is not None and slot.location:
      return slot.location
    return -1

  def is_disk_present_hades(self, disk_serial, zk_session=None,
                            hades_config=None):
    """
    Return True if disk is present is hades, False otherwise.
    Args:
      disk_serial (str): Disk serial.
      zk_session (ZookeeperSession): ZK session to use. If None, then a fresh
        one is created. Default None.
      hades_config (HadesProto): Hades proto. If None, then fetches fresh
        proto. Default None.
    """
    if not hades_config:
      hades_config, version = hades_utils.get_hades_proto(
        zk_session=zk_session)

    if not hades_config:
      log.ERROR("Failed to get Hades config while checking whether "
                "device {0} is present in Hades".format(disk_serial))
      return False

    if (FLAGS.configure_pmem_devices and
        PmemDeviceUtil.is_pmem_device_serial(disk_serial)):
      found = PmemDeviceUtil.is_pmem_device_present_hades(disk_serial,
                                                         hades_config)
      if found is None:
        log.ERROR("Could not find whether PMEM device %s is present in Hades "
                  "proto" % disk_serial)
        return False
      if not found:
        log.ERROR("PMEM device %s is not present in Hades proto" % disk_serial)
      return found

    slot = self.get_slot_from_hades(disk_serial, hades_proto=hades_config,
                                    zk_session=zk_session)
    if slot is not None:
      return True
    return False

  def disk_removed_from_node(self, disk_serial):
    """
    Check if the disk used to be part of the node. Verified by mountpath
    leftover fragments.
    Args:
      disk_serial (str): Disk serial.
    Returns:
      bool: True if disk's mountpath exists, else False.
    """
    mount_path = self.__get_mount_path(disk_serial)
    return os.path.isdir(mount_path)

  def __get_mount_path(self, serial):
    """
    Return the mount path for given disk serial.

    Args:
      serial(str): Disk serial.

    Returns:
      str: Mount path.
    """
    if serial is None:
      log.ERROR("Invalid serial was discovered")
      return None

    if PmemDeviceUtil.is_pmem_device_serial(serial):
      mount_path = PmemDeviceUtil.get_mount_path(serial)
    else:
      mount_path = os.path.join(self.__stargate_disk_directory, serial)

    return mount_path

  def kill_stargate(self):
    """
    Kill local stargate.
    Returns True if successful, False otherwise.
    """
    try:
      log.INFO("Killing the local stargate")
      urllib.request.urlopen(
        "http://localhost:2009/h/exit?abort=1&dumpcore=0&delaysecs=0",
        timeout=10)
      return True

    except Exception as ex:
      # This case will be hit when we fail to kill the remote stargate.
      # We continue with a warning since the attempt here is only to reduce
      # a chance of failure.
      log.WARNING("Failed to kill local stargate: %s" % str(ex))
      return False

  def __maybe_remove_cassandra_symlink(self, disk_serial_short):
    """
    Remove cassandra symlink if it matches with disk_serial_short.
    """
    path = os.path.join(FLAGS.nutanix_data_dir, "cassandra")
    if not os.path.lexists(path):
      log.INFO("Cassandra symlink does not exist")
      return

    if os.path.islink(path):
      full_path = os.readlink(path)
      if disk_serial_short and full_path.find(disk_serial_short) != -1:
        log.INFO("Disk with serial %s is a part of cassandra symlink, "
                 "deleting cassandra symlink" % disk_serial_short)
        os.unlink(path)
      else:
        log.INFO("Disk with serial %s is not part of cassandra symlink" %
                 disk_serial_short)
    else:
      log.INFO("%s is a directory and not symlink" % path)

    return

  def grab_shutdown_token_and_reboot(self, shutdown_cmd="reboot -f",
                                     retries=2):
    """
    Get a shutdown token and reboot.

    Args:
      shutdown_cmd (str): Shutdown command. Default: reboot -f.
      retries (int): Number of trials to ask for shutdown token. Default: 2.

    Returns:
      bool: True if shutdown token granted, else False.
    """
    import cluster.client.cluster_upgrade as cluster_upgrade

    if os.path.exists(FLAGS.skip_disk_remove_reboot_marker):
      log.INFO("Disable reboot on disk removal marker exists, skipping reboot")
      return True

    # Request for shutdown token is a blocking call. But the RPC itself is
    # susceptible to timeout (default: 60 secs). In such cases, ask for token
    # again. If not granted, return early.
    while (retries > 0):
      log.INFO("Request for shutdown token")
      ret = self.__cluster_manager.prepare_node_for_shutdown(
                reason="disk_remove")

      if isinstance(ret, RpcError):
        log.ERROR("Error doing RPC for shutdown token. Ret: %s" % ret)
      elif ret == False:
        log.ERROR("Unable to get shutdown token")
      else:
        log.INFO("Got shutdown token due to failed disk unmount. Rebooting in "
                 "30 secs")
        break

      retries -= 1
      # Don't wait for last iteration.
      if retries:
        log.INFO("Wait for 30 secs, retry for shutdown token. Trials "
                 "remaining: %s" % retries)
        time.sleep(30)
    else:
      log.ERROR("Shutdown token not granted. Skip node reboot")
      return False

    zk_session = ZookeeperSession(host_port_list=self.__host_port_list)
    if not zk_session.wait_for_connection(None):
      log.ERROR("Unable to obtain a zk session, err %s" % zk_session.error())

    if zk_session:
      genesis_utils.forward_storage_traffic_for_ip(zk_session)

    zk_session.close()

    if not cluster_upgrade.pre_shutdown_ops():
      log.ERROR("Unable to stop services on the node")

    if not cluster_upgrade.shutdown_service_vm(shutdown_cmd):
      # We should only hit this log statement if the SVM shutdown failed.
      log.ERROR("Unable to reboot the CVM after grabbing token")
      return False
    return True

  @rpchandler
  def disk_is_mounted_in_hades(self, disk_serial, hades_config=None):
    """
    Checks the hades configuration to see if a disk is mounted.

    Returns True if present and mounted, False otherwise.
    """
    if not hades_config:
      zk_session = ZookeeperSession(host_port_list=self.__host_port_list)
      if not zk_session.wait_for_connection(None):
        log.ERROR("Unable to obtain a zookeeper session")
        return False
      hades_config, _ = hades_utils.get_hades_proto(zk_session)

    if PmemDeviceUtil.is_pmem_device_serial(disk_serial):
      for pmem_device in hades_config.pmem_device_list:
        if pmem_device.serial == disk_serial:
          return pmem_device.is_mounted
      log.ERROR("PMEM device with serial %s doesn't exist in Hades proto" %
                disk_serial)
      return False

    for slot in hades_config.slot_list:
      if not slot.disk_present:
        continue
      if slot.disk.serial == disk_serial:
        log.INFO("Disk with serial %s is present in slot %s" %
                 (disk_serial, slot.location))
        return slot.disk.is_mounted
    return False

  @rpchandler
  def remove_stale_secrets_from_hades(self, kms_uuid, disk_serial=None):
    """
    If a KMS is removed from the Zeus Config then clear out the stale passwords
    from the hades proto.

    If a disk_serial is specified then it will only remove secrets in Hades
    for that disk.

    Returns True if it was successful, False on error.
    """
    return sed_utils.remove_stale_secrets_from_hades(
      kms_uuid, self.__host_port_list, disk_serial)

  @rpchandler
  def change_sed_disk_password(self, disk, remove_password=False):
    """
    Adds or removed a password for a set of disks.

    disk: disk location (/dev/sdf) to change the password of.
    remove_password: when True sets the password back to the manufacturer
                     default.

    returns (result, error_message)
    """
    #TODO: Will be more verbose after logic to bulk change passwords is changed
    # in genesis.
    return sed_commands.secure_password([disk],
                                        set_to_manufacturer_pin=remove_password)

  @rpchandler
  def secure_erase_disk(self, disk, crypto_erase_locked=False):
    """
    Securely erases the band covering a partition.

    disk: The disk to erase (/dev/sda).
    crypto_erase_locked: Whether to do this operation on a protected disk.

    Returns True on success, False on error.
    """
    partition = self.get_data_partition(disk)
    return sed_commands.secure_erase(disk, partition, crypto_erase_locked)

  @rpchandler
  def get_disks_for_xtrim(self):
    """
    Return the list of disks on which Xtrim needs to be run.

    Returns: list of dicts containing the disk information.
    """
    return TrimUtil.get_disks_for_xtrim()

  def add_disk_slot_in_disk_location(self, disk_serial):
    """
    Chooses a slot for virtual disk and add it to disk_config.json.
    This is required only for virtual disks (null clusters and PC).
    Returns True if successful, False otherwise.
    """
    if  self.__is_hyperv:
      return True

    if self.__model != "null":
      return True

    MAX_SLOTS = 25

    disk_location_map = {}
    try:
      with open(FLAGS.disk_location_json_path) as fd:
        disk_location_map = json.load(fd)
        log.DEBUG("Disk location map %s" % disk_location_map)
    except Exception as ex:
      log.ERROR("Failed to read %s with exception %s" %
                    (FLAGS.disk_location_json_path, ex))
      disk_location_map = {}

    slots = set(disk_location_map.values())
    max_slots = set(range(1, MAX_SLOTS + 1))

    available_slots = max_slots - slots

    if not available_slots:
      log.ERROR("All slots are occupied")
      return False
    available_slots = list(available_slots)
    slot_num = available_slots[0]

    if disk_serial in disk_location_map:
      log.INFO("Disk with serial %s is already present in disk location" %
               disk_serial)
      return True

    log.INFO("Adding disk %s to slot %s" %(disk_serial, slot_num))

    try:
      with open(FLAGS.disk_location_json_path, 'w') as fd:
        disk_location_map[disk_serial] = slot_num
        log.INFO(disk_location_map)
        json.dump(disk_location_map, fd)
    except Exception as ex:
      log.ERROR("Failed to write %s with exception %s" %
                (FLAGS.disk_location_json_path, ex))
      return False

    os.chown(FLAGS.disk_location_json_path, self.__nutanix_uid,
             self.__nutanix_gid)
    return True

  def clean_stale_virtual_disk_entries(self):
    """
    Remove any stale entries from disk_location.json
    This is required only for virtual disks (null clusters and PC).
    """
    if self.__is_hyperv:
      return True

    if self.__model != "null":
      return True

    valid_serials = []
    for disk in Disk.disks():
      disk_obj = Disk(disk)
      valid_serials.append(disk_obj.serial_number())

    disk_location_map = {}
    try:
      with open(FLAGS.disk_location_json_path, 'r') as fd:
        disk_location_map = json.load(fd)
    except Exception as ex:
      log.ERROR("Failed to read %s with exception %s" %
                (FLAGS.disk_location_json_path, ex))
      return False

    # Remove stale entries.
    disk_location_map = dict((serial, slot) for serial, slot in
                             disk_location_map.items()
                             if serial in valid_serials)

    try:
      with open(FLAGS.disk_location_json_path, 'w') as fd:
       json.dump(disk_location_map, fd)
    except Exception as ex:
      log.ERROR("Failed to write %s with exception %s" %
                (FLAGS.disk_location_json_path, ex))
      return False

    os.chown(FLAGS.disk_location_json_path, self.__nutanix_uid,
             self.__nutanix_gid)
    return True

  def qa_skip_unmount(self, disk_serial):
    """
    Workaround for ENG-30611: QA only flag to not unmount the disk
    by hades if disk has some data. Marker file lists all disks to
    be ignored for unmounting, all other workflows are untouched.
    Returns True if skip unmount is desired, False otherwise.
    """
    qa_ignore_disks_marker = "/home/nutanix/agave/ignore_disks.json"
    if not os.path.exists(qa_ignore_disks_marker):
      return False

    try:
      with open(qa_ignore_disks_marker) as jsonfile:
        ignore_disks = json.load(jsonfile)["ignore_disks"]
    except IOError:
      log.ERROR("Failed to load %s" % qa_ignore_disks_marker)
      return False

    if disk_serial in ignore_disks:
      log.INFO("Skipping unmounting of disk with serial %s" % disk_serial)
      return True

    return False

  @rpchandler
  def stop_all_bg_jobs(self):
    """Stop DiskHealthMonitor and DiskErrorParser threads if running."""
    if (FLAGS.enable_disk_error_parser and
        self.__disk_error_parser is not None and
        self.__disk_error_parser.is_alive()):
      log.INFO("Stopping DiskErrorParser")
      self.__disk_error_parser.stop()

    if (FLAGS.enable_disk_health_monitor and
        self.__disk_health_monitor is not None and
        self.__disk_health_monitor.is_alive()):
      log.INFO("Stopping DiskHealthMonitor")
      self.__disk_health_monitor.stop()

  @rpchandler
  def check_files_in_path(self, path):
    """
    This is a helper method which checks for files under given path.
    Args:
      path(str) : Path to check files under them.
    Returns:
      True if any files are found, False otherwise.
    """
    if path:
      files_in_path = glob.glob(path)
      if files_in_path:
        log.INFO("Found files in %s" % path)
        return True

    return False

  def get_max_sectors_kb(self, disk):
    """
    Reads the max sectors value to /sys/block/sdX/queue/max_sectors_kb for the
    given disk
    """
    log.INFO("Reading disk block_params: max_sectors_kb on disk %s" % disk)
    read_val = None
    max_sectors_path = hades_utils.max_sectors_path(disk)
    if not max_sectors_path:
      return False
    try:
      with open(max_sectors_path, "r") as f:
        read_val = f.read().rstrip()
    except:
      return False
    return read_val

  @staticmethod
  def get_ssd_count():
    """
    Returns the number of SSDs on the node.
    """
    count = 0
    disks = Disk.disks()
    for dev in disks:
      disk = Disk(dev)
      model = disk.get_disk_model()
      if hcl.is_ssd_disk(model):
        count = count + 1
    return count

  @staticmethod
  def is_high_perf_platform(ssd_threshold):
    """
    To enable certain features like Multiqueue on AHV, we have the
    following criteria (one of the below):
    a) Node should have NVME disks.
    b) Node should have RDMA capability.
    c) Node must have atleast 4 SSDs

    Input: ssd_threshold is the total number of ssds to check for.
    Returns: True if it satisfies of the conditions above or False
             otherwise.
    """
    num_ssds = DiskManager.get_ssd_count()
    num_nvme = NvmeDisk.nvme_block_devices()
    log.DEBUG("Number of SSDs %d . Number of NVMe %d" % (num_ssds, len(num_nvme)))
    return ((num_ssds >= ssd_threshold) or (len(num_nvme) > 0))

  def is_nvme_disk_remove_add_triggered_by_ns_resize(self, disk_serial):
    """
    Routine to check if the disk remove/add was triggered by NVMe namespace
    resize by checking if the intent file is present.
    Args:
      disk_serial (str): NVMe disk serial. Ex: "S3HDNX0M700022".
    Returns:
      bool: True, if remove/add udev events triggered by NVMe namespace
        resize. False, otherwise.
    """
    # Check for NVMe namespace resize intent file with disk_serial.
    if FLAGS.nvme_namespace_resize_enabled:
      intent_file_path = os.path.join(FLAGS.nvme_namespace_resize_intent_dir,
                                      disk_serial)
      if os.path.exists(intent_file_path):
        log.INFO("NVMe disk %s remove/add is triggered by NVMe namespace "
                 "resize" % disk_serial)
        return True
    return False
