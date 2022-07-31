=============
zoned-storage
=============

Zoned Block Devices (ZBDs) devide the LBA space to block regions called zones
that are larger than the LBA size. It can only allow sequential writes, which
reduces write amplification in SSD, leading to higher throughput and increased
capacity. More details about ZBDs can be found at:

https://zonedstorage.io/docs/introduction/zoned-storage

zone emulation
--------------
In its current status, the virtio-blk device is not aware of ZBDs but the guest
sees host-managed drives as regular drive that will runs correctly under the
most common write workloads.

The zoned device support aims to let guests (virtual machines) access zoned
storage devices on the host (hypervisor) through a virtio-blk device. This
involves extending QEMU's block layer and virtio-blk emulation code.

If the host supports zoned block devices, it can set VIRTIO_BLK_F_ZONED. Then
in the guest side, it appears following situations:
1) If the guest virtio-blk driver sees the VIRTIO_BLK_F_ZONED bit set, then it
will assume that the zoned characteristics fields of the config space are valid.
2) If the guest virtio-blk driver sees a zoned model that is NONE, then it is
known that is a regular block device.
3) If the guest virtio-blk driver sees a zoned model that is HM(or HA), then it
is known that is a zoned block device and probes the other zone fields.

On QEMU sides,
1) The DEFINE PROP BIT macro must be used to declare that the host supports
zones.
2) BlockDrivers can declare zoned device support once known the zoned model
for the block device is not NONE.

zoned storage APIs
------------------

Zone emulation part extends the block layer APIs and virtio-blk emulation section
with the minimum set of zoned commands that are necessary to support zoned
devices. The commands are - Report Zones, four zone operations and Zone Append
(developing).

testing
-------

It can be tested on a null_blk device using qemu-io, qemu-iotests or blkzone(8)
command in the guest os.

1. For example, the command line for zone report using qemu-io is:

$ path/to/qemu-io --image-opts driver=zoned_host_device,filename=/dev/nullb0 -c
"zrp offset nr_zones"

To enable zoned device in the guest os, the guest kernel must have the virtio-blk
driver with ZBDs support. The link to such patches for the kernel is:

https://github.com/dmitry-fomichev/virtblk-zbd

Then, add the following options to the QEMU command line:
-blockdev node-name=drive0,driver=zoned_host_device,filename=/dev/nullb0

After the guest os booting, use blkzone(8) to test zone operations:
blkzone report -o offset -c nr_zones /dev/vda

2. We can also use the qemu-iotests in ./tests/qemu-iotests/tests/zoned.sh.

