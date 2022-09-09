/*
 * Virtio Block Device
 *
 * Copyright IBM, Corp. 2007
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_VIRTIO_BLK_H
#define QEMU_VIRTIO_BLK_H

#include "standard-headers/linux/virtio_blk.h"
#include "hw/virtio/virtio.h"
#include "hw/block/block.h"
#include "sysemu/iothread.h"
#include "sysemu/block-backend.h"
#include "qom/object.h"

#define TYPE_VIRTIO_BLK "virtio-blk-device"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOBlock, VIRTIO_BLK)

/* This is the last element of the write scatter-gather list */
struct virtio_blk_inhdr
{
    unsigned char status;
};

struct virtio_blk_zone_append_inhdr {
    unsigned char status;
    uint8_t reserved[7];
    int64_t append_sector;
};

#define VIRTIO_BLK_AUTO_NUM_QUEUES UINT16_MAX

struct VirtIOBlkConf
{
    BlockConf conf;
    IOThread *iothread;
    char *serial;
    uint32_t request_merging;
    uint16_t num_queues;
    uint16_t queue_size;
    bool seg_max_adjust;
    bool report_discard_granularity;
    uint32_t max_discard_sectors;
    uint32_t max_write_zeroes_sectors;
    bool x_enable_wce_if_config_wce;
};

struct VirtIOBlockDataPlane;

struct VirtIOBlockReq;
struct VirtIOBlock {
    VirtIODevice parent_obj;
    BlockBackend *blk;
    void *rq;
    QEMUBH *bh;
    VirtIOBlkConf conf;
    unsigned short sector_mask;
    bool original_wce;
    VMChangeStateEntry *change;
    bool dataplane_disabled;
    bool dataplane_started;
    struct VirtIOBlockDataPlane *dataplane;
    uint64_t host_features;
    size_t config_size;
};

typedef struct VirtIOBlockReq {
    VirtQueueElement elem;
    int64_t sector_num;
    VirtIOBlock *dev;
    VirtQueue *vq;
    IOVDiscardUndo inhdr_undo;
    IOVDiscardUndo outhdr_undo;
    union {
        struct virtio_blk_inhdr *in_hdr;
        struct virtio_blk_zone_append_inhdr *zone_append_inhdr;
    } in;
    struct virtio_blk_outhdr out;
    QEMUIOVector qiov;
    size_t in_len;
    struct VirtIOBlockReq *next;
    struct VirtIOBlockReq *mr_next;
    BlockAcctCookie acct;
} VirtIOBlockReq;

#define VIRTIO_BLK_MAX_MERGE_REQS 32

typedef struct MultiReqBuffer {
    VirtIOBlockReq *reqs[VIRTIO_BLK_MAX_MERGE_REQS];
    unsigned int num_reqs;
    bool is_write;
} MultiReqBuffer;

void virtio_blk_handle_vq(VirtIOBlock *s, VirtQueue *vq);
void virtio_blk_process_queued_requests(VirtIOBlock *s, bool is_bh);

#endif
