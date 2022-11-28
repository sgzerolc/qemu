/*
 * Block driver for the zoned block device format. Inspired by Linux null_blk
 * driver.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "block/block_int.h"
#include "block/qdict.h"
#include "sysemu/block-backend.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/qapi-visit-block-core.h"
#include "qemu/bswap.h"
#include "qemu/bitmap.h"
#include "qemu/coroutine.h"
#include "qemu/memalign.h"
#include "migration/blocker.h"

#define HEADER_MAGIC "zone"
#define ZONED_ZT_IS_CONV(wp)    (wp & 1ULL << 59)

typedef struct ZonedHeader {
    char magic[4];
    uint32_t zone_size;
    uint32_t nr_zones;
    uint32_t zone_nr_seq;
    uint32_t zone_nr_conv;
    uint32_t max_active_zones;
    uint32_t max_open_zones;
    uint32_t max_append_sectors;
    uint64_t device_size;
    uint8_t zone_model;
    char reserved[471]; /* header size is aligned with 512-byte */
} QEMU_PACKED ZonedHeader;

typedef struct BDRVZonedState {
    ZonedHeader header;
    BlockZoneWps *wps;
    uint64_t header_size;
    uint64_t meta_size;
    uint32_t nr_zones_exp_open;
    uint32_t nr_zones_imp_open;
    uint32_t nr_zones_closed;
} BDRVZonedState;

static const char *const mutable_opts[] = { "offset", "size", NULL };

static QemuOptsList zoned_runtime_opts = {
        .name = "zoned",
        .head = QTAILQ_HEAD_INITIALIZER(zoned_runtime_opts.head),
        .desc = {
                {
                        .name = "offset",
                        .type = QEMU_OPT_SIZE,
                        .help = "offset in the disk where the image starts",
                },
                {
                        .name = "len",
                        .type = QEMU_OPT_SIZE,
                        .help = "length",
                },
                { /* end of list */ }
        },
};

static QemuOptsList zoned_create_opts = {
        .name = "zoned-create-opts",
        .head = QTAILQ_HEAD_INITIALIZER(zoned_create_opts.head),
        .desc = {
                {
                        .name = BLOCK_OPT_SIZE,
                        .type = QEMU_OPT_SIZE,
                        .help = "size of zoned device",
                },
                {
                        .name = BLOCK_OPT_Z_TYPE,
                        .type = QEMU_OPT_NUMBER,
                        .help = "zoned",
                },
                {
                        .name = BLOCK_OPT_Z_ZSIZE,
                        .type = QEMU_OPT_SIZE,
                        .help = "zone size",
                },
                {
                        .name = BLOCK_OPT_Z_NR_COV,
                        .type = QEMU_OPT_NUMBER,
                        .help = "numbers of conventional zones",
                },
                {
                        .name = BLOCK_OPT_Z_NR_SEQ,
                        .type = QEMU_OPT_NUMBER,
                        .help = "numbers of sequential zones",
                },
                {
                        .name = BLOCK_OPT_Z_MAS,
                        .type = QEMU_OPT_NUMBER,
                        .help = "max append sectors",
                },
                {
                        .name = BLOCK_OPT_Z_MAZ,
                        .type = QEMU_OPT_NUMBER,
                        .help = "max active zones",
                },
                {
                        .name = BLOCK_OPT_Z_MOZ,
                        .type = QEMU_OPT_NUMBER,
                        .help = "max open zones",
                },
                { /* end of list */ }
        }
};

static int zoned_probe(const uint8_t *buf, int buf_size,
                       const char *filename)
{
    const ZonedHeader *zh = (const void*)buf;

    if (buf_size >= sizeof(ZonedHeader) &&
        !memcmp(zh->magic, HEADER_MAGIC, 4)) {
        return 100;
    } else {
        return 0;
    }
}

static inline int zoned_get_wp(int index, uint64_t *wp)
{
    /* clear state and type information */
    return ((wp[index] << 5) >> 5);
}

static inline int zoned_get_zs(int index, uint64_t *wp)
{
    return (wp[index] >> 60);
}

static inline void zoned_set_wp(uint64_t *wp, BlockZoneState zs)
{
    uint64_t addr = *wp;
    addr |= ((uint64_t)zs << 60);
    *wp = addr;
}

static int zoned_check_active(BlockDriverState *bs)
{
    BDRVZonedState *s = bs->opaque;

    if (!s->header.max_active_zones) {
        return 0;
    }

    /* skip this issue for now: over max active zones limit */
    printf("eo: %d, io: %d, cz: %d, maz: %d\n", s->nr_zones_exp_open, s->nr_zones_imp_open,
           s->nr_zones_closed, s->header.max_active_zones);
    if (s->nr_zones_exp_open + s->nr_zones_imp_open + s->nr_zones_closed
        < s->header.max_active_zones) {
        return 0;
    }

    return -1;
}

static int zoned_check_open(BlockDriverState *bs)
{
    BDRVZonedState *s = bs->opaque;
    if (!s->header.max_open_zones) {
        return 0;
    }

    if (s->nr_zones_exp_open + s->nr_zones_imp_open
        < s->header.max_open_zones) {
        return 0;
    }

    if(s->nr_zones_imp_open) {
        if ((zoned_check_active(bs) == 0) &&
            (s->nr_zones_exp_open < s->header.max_open_zones)) {
            /* close one implicitly open zones to make it available */
            for (int i = s->header.zone_nr_conv; i < s->header.nr_zones; ++i) {
                if (zoned_get_zs(i, s->wps->wp) == BLK_ZS_IOPEN) {
                    uint64_t wp = zoned_get_wp(i, s->wps->wp);
                    zoned_set_wp(&wp, BLK_ZS_CLOSED);
                    s->wps->wp[i] = wp;
                    s->nr_zones_imp_open--;
                    s->nr_zones_closed++;
                    printf("after closing one imp_open zone:eo: %d, io: %d, cz: %d, maz: %d\n", s->nr_zones_exp_open, s->nr_zones_imp_open,
                           s->nr_zones_closed, s->header.max_active_zones);
                    break;
                }
            }

        }
    }

    return -1;
}

/*
 *
 */
static int zoned_check_zone_resources(BlockDriverState *bs,
                                      BlockZoneState zs)
{
    int ret;

    switch (zs) {
    case BLK_ZS_EMPTY:
        ret = zoned_check_active(bs);
        if (ret < 0) {
            error_report("No enough active zones");
            return ret;
        }
        return ret;
    case BLK_ZS_CLOSED:
        ret = zoned_check_open(bs);
        if (ret < 0) {
            error_report("No enough open zones");
            return ret;
        }
        return ret;
    default:
        return -EINVAL;
    }

}

static inline int zoned_refresh_metadata(BlockDriverState *bs)
{
    int ret;
    BDRVZonedState *s = bs->opaque;
    uint64_t *temp = g_malloc(s->meta_size);
    ret = bdrv_pread(bs->file, s->header.device_size - s->meta_size,
                     s->meta_size, temp, 0);
//    printf("refresh m: offset %ld\n", s->header.device_size - s->meta_size);
    if (ret < 0) {
        error_report("Can not read metadata\n");
        return ret;
    }

    memcpy(s->wps->wp, temp, s->meta_size);
    return 0;
}

/*
 * Open the emulated device.
 */
static int zoned_open(BlockDriverState *bs, QDict *options, int flags,
                      Error **errp)
{
    BDRVZonedState *s = bs->opaque;
    ZonedHeader zh;
    int ret;

    bs->file = bdrv_open_child(NULL, options, "file", bs, &child_of_bds,
                               BDRV_CHILD_IMAGE, false, errp);
    if (!bs->file) {
        return -EINVAL;
    }

    ret = bdrv_pread(bs->file, 0, sizeof(zh), &zh, 0);
    if (ret < 0) {
        goto fail;
    }

    if (memcmp(zh.magic, HEADER_MAGIC, 4) != 0) {
        error_setg(errp, "Image not in zoned format");
        goto fail;
    }

    s->header = zh;
    s->header_size = sizeof(zh);
    s->meta_size = le64_to_cpu(sizeof(uint64_t) * zh.nr_zones);
//    printf("open check zone size %d\n", s->header.zone_size);
//    printf("open check meta size %ld\n", s->meta_size);
    s->wps = g_malloc(sizeof(BlockZoneWps) + s->meta_size);
    ret = zoned_refresh_metadata(bs);
    if (ret < 0) {
        goto fail;
    }
//    for (int i = 0; i < 12; ++i) {
//        printf("[%d]: 0x%lx\n", i, s->wps->wp[i]);
//    }
    qemu_co_mutex_init(&s->wps->colock);
    return 0;
fail:
    return ret;
}

static void zoned_refresh_limits(BlockDriverState *bs, Error **errp)
{
    BDRVZonedState *s = bs->opaque;
    bs->bl.zoned = s->header.zone_model;
    bs->bl.zone_size = s->header.zone_size;
    bs->bl.nr_zones = s->header.nr_zones;
    bs->bl.max_append_sectors = s->header.max_append_sectors;
    bs->bl.max_active_zones = s->header.max_active_zones;
    bs->bl.max_open_zones = s->header.max_open_zones;
    bs->bl.write_granularity = BDRV_SECTOR_SIZE;
    bs->bl.wps = s->wps;
//    printf("rl: zoned 0x%x\n", bs->bl.zoned);
//    printf("refresh limits: zone size %d\n", bs->bl.zone_size);
    bs->total_sectors = bs->bl.nr_zones * bs->bl.zone_size >> BDRV_SECTOR_BITS;
//    printf("rl: new total sec %ld\n", bs->total_sectors);
}

static int zoned_probe_blocksizes(BlockDriverState *bs, BlockSizes *bsz)
{
    bsz->log = BDRV_SECTOR_SIZE;
    bsz->phys = BDRV_SECTOR_SIZE;
//    printf("probing zbs\n");
    return 0;
}

static inline int zoned_adjust_offset(BlockDriverState *bs, int64_t *offset,
                                      int64_t bytes, bool is_write) {
    BDRVZonedState *s = bs->opaque;

    if (*offset > s->header.device_size || bytes > (s->header.device_size - *offset - s->meta_size)) {
        return is_write ? -ENOSPC : -EINVAL;
    }

    *offset += s->header_size;
    return 0;
}
static coroutine_fn int zoned_co_preadv(BlockDriverState *bs, int64_t offset,
                                        int64_t bytes, QEMUIOVector *qiov,
                                        BdrvRequestFlags flags)
{
    int ret = zoned_adjust_offset(bs, &offset, bytes, false);
    if (ret < 0) {
        return ret;
    }

    return bdrv_co_preadv(bs->file, offset, bytes, qiov, flags);
}

static coroutine_fn int zoned_co_pwritev(BlockDriverState *bs, int64_t offset,
                                         int64_t bytes, QEMUIOVector *qiov,
                                         BdrvRequestFlags flags)
{
    BDRVZonedState *s = bs->opaque;
    BlockZoneState zs;
    uint64_t wp;
    int index;
    int ret;
//    printf("zoned format: write\n");

    ret = zoned_adjust_offset(bs, &offset, bytes, true);
    if (ret < 0) {
        return ret;
    }

    ret = bdrv_co_pwritev(bs->file, offset, bytes, qiov, flags);
    if (ret < 0) {
        return ret;
    }

    qemu_co_mutex_lock(&s->wps->colock);
    index = offset / s->header.zone_size;
    if (!ZONED_ZT_IS_CONV(s->wps->wp[index])) {
        /*
         * Implicitly open one closed zone to write if there are zone resources
         * left.
         */
        zs = zoned_get_zs(index, s->wps->wp);
        wp = zoned_get_wp(index, s->wps->wp);
        if (zs == BLK_ZS_CLOSED || zs == BLK_ZS_EMPTY) {
            ret = zoned_check_zone_resources(bs, zs);
            if (ret < 0) {
                goto unlock;
            }

            if (zs == BLK_ZS_CLOSED) {
                s->nr_zones_closed--;
                s->nr_zones_imp_open++;
            } else {
                s->nr_zones_imp_open++;
            }
        }
        printf("after writing one zone:eo: %d, io: %d, cz: %d, maz: %d\n", s->nr_zones_exp_open, s->nr_zones_imp_open,
               s->nr_zones_closed, s->header.max_active_zones);
        printf("zoned: wrote %ld at %ld\n", bytes, offset);
        printf("before writing: 0x%lx\n", wp);
        wp += bytes;
        zoned_set_wp(&wp, BLK_ZS_IOPEN);
        s->wps->wp[index] = wp;
        printf("after writing: 0x%lx\n", wp);
        ret = bdrv_pwrite(bs->file, s->header.device_size - s->meta_size
                                    + sizeof(uint64_t) * index, sizeof(uint64_t), &wp, 0);
        if (ret < 0) {
            goto exit;
        }
        ret = bdrv_co_flush(bs);
        if (ret < 0) {
            goto exit;
        }
    }
    goto unlock;

exit:
    error_report("Failed to sync metadata with file");
    return ret;
unlock:
    qemu_co_mutex_unlock(&s->wps->colock);
    return ret;
}

static int coroutine_fn zoned_co_zone_report(BlockDriverState *bs, int64_t offset,
                                             unsigned int *nr_zones,
                                             BlockZoneDescriptor *zones)
{
    BDRVZonedState *s = bs->opaque;
    uint64_t zs = s->header.zone_size;
    int si;
    if (zs > 0) {
        si = offset / zs;
//        printf("si %d\n", si);
        unsigned int nrz = *nr_zones;
        qemu_co_mutex_lock(&s->wps->colock);
        for (int i = 0; i < nrz; ++i) {
            zones[i].start = si * zs;
            zones[i].length = zs;
            zones[i].cap = zs;

            uint64_t wp = s->wps->wp[si];
//            printf("wp before: 0x%lx\n", wp);
            if (ZONED_ZT_IS_CONV(wp)) {
                zones[i].type = BLK_ZT_CONV;
                zones[i].state = BLK_ZS_NOT_WP;
                /* Clear the zone type bit */
                wp &= ~(1ULL << 59);
            } else {
                zones[i].type = BLK_ZT_SWR;
                zones[i].state = zoned_get_zs(i, s->wps->wp);
//                printf("zs %d, 0x%x\n", i, zones[i].state);
                /* Clear the zone state bits */
                wp = zoned_get_wp(i, s->wps->wp);
            }

            zones[i].wp = wp;
//            printf("%d: 0x%lx zone start\n", i, zones[i].start);
//            printf("%d: 0x%lx wp\n", i, wp);
            ++si;
        }
        qemu_co_mutex_unlock(&s->wps->colock);
    }
    return 0;
}

static int zoned_open_zone(BlockDriverState *bs, uint32_t index) {
    BDRVZonedState *s = bs->opaque;
    BlockZoneState zs = zoned_get_zs(index, s->wps->wp);
    uint64_t wp = zoned_get_wp(index, s->wps->wp);
    int ret;
//    printf("zoned format: open zones at %x state\n", zs);

    switch(zs) {
    case BLK_ZS_EMPTY:
        ret = zoned_check_zone_resources(bs, BLK_ZS_EMPTY);
        if (ret < 0) {
            return ret;
        }
        break;
    case BLK_ZS_IOPEN:
        s->nr_zones_imp_open--;
        break;
    case BLK_ZS_EOPEN:
        return 0;
    case BLK_ZS_CLOSED:
        ret = zoned_check_zone_resources(bs, BLK_ZS_CLOSED);
        if (ret < 0) {
            return ret;
        }
        s->nr_zones_closed--;
        break;
    case BLK_ZS_FULL:
        break;
    default:
        return -EINVAL;
    }
//    printf("before oz: %lx\n", wp);
    zoned_set_wp(&wp, BLK_ZS_EOPEN);
//    printf("after oz: %lx\n", wp);
    s->nr_zones_exp_open++;
    printf("after opening one zone:eo: %d, io: %d, cz: %d, maz: %d\n", s->nr_zones_exp_open, s->nr_zones_imp_open,
           s->nr_zones_closed, s->header.max_active_zones);
    s->wps->wp[index] = wp;
    ret = bdrv_pwrite(bs->file, s->header.device_size - s->meta_size
        + sizeof(uint64_t) * index, sizeof(uint64_t), &wp, 0);
    if (ret < 0) {
        goto exit;
    }
    ret = bdrv_co_flush(bs);
    if (ret < 0) {
        goto exit;
    }
    return 0;
exit:
    error_report("Failed to sync metadata with file");
    return ret;
}

static int zoned_close_zone(BlockDriverState *bs, uint32_t index) {
    BDRVZonedState *s = bs->opaque;
    BlockZoneState zs = zoned_get_zs(index, s->wps->wp);
    uint64_t wp = zoned_get_wp(index, s->wps->wp);
    int ret;

    switch(zs) {
    case BLK_ZS_EMPTY:
        break;
    case BLK_ZS_IOPEN:
        s->nr_zones_imp_open--;
        break;
    case BLK_ZS_EOPEN:
        s->nr_zones_exp_open--;
        break;
    case BLK_ZS_CLOSED:
        ret = zoned_check_zone_resources(bs, BLK_ZS_CLOSED);
        if (ret < 0) {
            return ret;
        }
        s->nr_zones_closed--;
        break;
    case BLK_ZS_FULL:
        break;
    default:
        return -EINVAL;
    }

    if (zs == BLK_ZS_EMPTY) {
        zoned_set_wp(&wp, BLK_ZS_EMPTY);
    } else {
        zoned_set_wp(&wp, BLK_ZS_CLOSED);
        s->nr_zones_closed++;
    }
    printf("after closing one zone:eo: %d, io: %d, cz: %d, maz: %d\n", s->nr_zones_exp_open, s->nr_zones_imp_open,
           s->nr_zones_closed, s->header.max_active_zones);
    s->wps->wp[index] = wp;
    ret = bdrv_pwrite(bs->file, s->header.device_size - s->meta_size
        + sizeof(uint64_t) * index, sizeof(uint64_t), &wp, 0);
    if (ret < 0) {
        goto exit;
    }
    ret = bdrv_co_flush(bs);
    if (ret < 0) {
        goto exit;
    }
    return 0;
exit:
    error_report("Failed to sync metadata with file");
    return ret;
}

static int zoned_finish_zone(BlockDriverState *bs, uint32_t index) {
    BDRVZonedState *s = bs->opaque;
    BlockZoneState zs = zoned_get_zs(index, s->wps->wp);
    uint64_t wp = zoned_get_wp(index, s->wps->wp);
    int ret;
//    printf("zoned format: close zones at %x state\n", zs);

    switch(zs) {
    case BLK_ZS_EMPTY:
        ret = zoned_check_zone_resources(bs, BLK_ZS_EMPTY);
        if (ret < 0) {
            return ret;
        }
        break;
    case BLK_ZS_IOPEN:
        s->nr_zones_imp_open--;
        break;
    case BLK_ZS_EOPEN:
        s->nr_zones_exp_open--;
        break;
    case BLK_ZS_CLOSED:
        ret = zoned_check_zone_resources(bs, BLK_ZS_CLOSED);
        if (ret < 0) {
            return ret;
        }
        s->nr_zones_closed--;
        break;
    case BLK_ZS_FULL:
        return 0;
    default:
        return -EINVAL;
    }
    printf("after finishing one zone:eo: %d, io: %d, cz: %d, maz: %d\n", s->nr_zones_exp_open, s->nr_zones_imp_open,
           s->nr_zones_closed, s->header.max_active_zones);
    wp = (index + 1) * s->header.zone_size;
    zoned_set_wp(&wp, BLK_ZS_FULL);
    s->wps->wp[index] = wp;
    ret = bdrv_pwrite(bs->file, s->header.device_size - s->meta_size
                                + sizeof(uint64_t) * index, sizeof(uint64_t), &wp, 0);
    if (ret < 0) {
        goto exit;
    }
    ret = bdrv_co_flush(bs);
    if (ret < 0) {
        goto exit;
    }
    return 0;
exit:
    error_report("Failed to sync metadata with file");
    return ret;
}

static int zoned_reset_zone(BlockDriverState *bs, uint32_t index) {
    BDRVZonedState *s = bs->opaque;
    BlockZoneState zs = zoned_get_zs(index, s->wps->wp);
    uint64_t wp = zoned_get_wp(index, s->wps->wp);
    int ret;
    printf("zoned format: reset zones[%d] from %x state\n", index, zs);

    switch(zs) {
    case BLK_ZS_EMPTY:
        return 0;
    case BLK_ZS_IOPEN:
        s->nr_zones_imp_open--;
        break;
    case BLK_ZS_EOPEN:
        s->nr_zones_exp_open--;
        break;
    case BLK_ZS_CLOSED:
        s->nr_zones_closed--;
        break;
    case BLK_ZS_FULL:
        break;
    default:
        return -EINVAL;
    }

    wp = index * s->header.zone_size;
    /* clear data */
    ret = bdrv_pwrite_zeroes(bs->file, s->header_size + wp,
                             s->header.zone_size, 0);
    if (ret < 0) {
        goto exit;
    }
    printf("after resetting one zone:eo: %d, io: %d, cz: %d, maz: %d\n", s->nr_zones_exp_open, s->nr_zones_imp_open,
           s->nr_zones_closed, s->header.max_active_zones);
    zoned_set_wp(&wp, BLK_ZS_EMPTY);
    s->wps->wp[index] = wp;
    ret = bdrv_pwrite(bs->file, s->header.device_size - s->meta_size
                                + sizeof(uint64_t) * index, sizeof(uint64_t), &wp, 0);
    if (ret < 0) {
        goto exit;
    }
    ret = bdrv_co_flush(bs);
    if (ret < 0) {
        goto exit;
    }
    return 0;
exit:
    error_report("Failed to reset zones");
    return ret;
}

static int coroutine_fn zoned_co_zone_mgmt(BlockDriverState *bs, BlockZoneOp op,
                                           int64_t offset, int64_t len)
{
    BDRVZonedState *s = bs->opaque;
    BlockZoneWps *wps = s->wps;
    int ret = 0;
    int64_t capacity = bs->total_sectors << BDRV_SECTOR_BITS;
    int64_t zone_size = s->header.zone_size;
    int64_t zone_size_mask = zone_size - 1;

    if (offset & zone_size_mask) {
        error_report("sector offset %" PRId64 " is not aligned to zone size "
                     "%" PRId64 "", offset / 512, zone_size / 512);
        return -EINVAL;
    }

    if (((offset + len) < capacity && len & zone_size_mask) ||
        offset + len > capacity) {
        error_report("number of sectors %" PRId64 " is not aligned to zone size"
                     " %" PRId64 "", len / 512, zone_size / 512);
        return -EINVAL;
    }

    qemu_co_mutex_lock(&s->wps->colock);
    uint32_t index = offset / zone_size;
    if (ZONED_ZT_IS_CONV(wps->wp[index]) && len != capacity) {
        error_report("zone mgmt operations are not allowed for conventional zones");
        ret = -EIO;
        goto unlock;
    }

    switch(op) {
    case BLK_ZO_OPEN:
        ret = zoned_open_zone(bs, index);
        break;
    case BLK_ZO_CLOSE:
        ret = zoned_close_zone(bs, index);
        break;
    case BLK_ZO_FINISH:
        ret = zoned_finish_zone(bs, index);
        break;
    case BLK_ZO_RESET:
        if (len == capacity) {
            for (int i = s->header.zone_nr_conv; i < s->header.nr_zones; ++i) {
                printf("reset all[%d]: offset 0x%lx\n", i, offset);
                ret = zoned_reset_zone(bs, i);
                if (ret < 0) {
                    goto unlock;
                }
            }
        } else {
            printf("reset zone with sector offset 0x%lx\n", offset);
            ret = zoned_reset_zone(bs, index);
        }
        break;
    default:
        error_report("Unsupported zone op: 0x%x", op);
        ret = -ENOTSUP;
        break;
    }

unlock:
    qemu_co_mutex_unlock(&s->wps->colock);
    return ret;
}

static int coroutine_fn zoned_co_zone_append(BlockDriverState *bs, int64_t *offset,
                                             QEMUIOVector *qiov,
                                             BdrvRequestFlags flags)
{
    assert(flags == 0);
    int ret;
    int64_t zone_size_mask = bs->bl.zone_size - 1;
    int64_t iov_len = 0;
    int64_t len = 0;
    BDRVZonedState *s = bs->opaque;
    int index = *offset / s->header.zone_size;

    if (*offset & zone_size_mask) {
        error_report("sector offset %" PRId64 " is not aligned to zone size "
                     "%" PRId32 "", *offset / 512, bs->bl.zone_size / 512);
        return -EINVAL;
    }

    int64_t wg = bs->bl.write_granularity;
    int64_t wg_mask = wg - 1;
    for (int i = 0; i < qiov->niov; i++) {
        iov_len = qiov->iov[i].iov_len;
        if (iov_len & wg_mask) {
            error_report("len of IOVector[%d] %" PRId64 " is not aligned to "
                         "block size %" PRId64 "", i, iov_len, wg);
            return -EINVAL;
        }
        len += iov_len;
    }

    ret = zoned_co_pwritev(bs, *offset, len, qiov, 0);
    if (ret == 0) {
        qemu_co_mutex_lock(&s->wps->colock);
        int wp = zoned_get_wp(index, s->wps->wp);
        *offset = wp;
        uint64_t wp_end = *offset + len;
        zoned_set_wp(&wp_end, BLK_ZS_IOPEN);
        s->wps->wp[index] = wp_end;
        qemu_co_mutex_unlock(&s->wps->colock);
    }

    return ret;
}

static void zoned_close(BlockDriverState *bs)
{
    BDRVZonedState *s = bs->opaque;
    if (s->wps) {
        g_free(s->wps);
    }
}

static int coroutine_fn zoned_co_create(BlockdevCreateOptions *opts,
                                        Error **errp)
{
    BlockdevCreateOptionsZoned *zoned_opts;
    BlockDriverState *bs;
    BlockBackend *blk;
    ZonedHeader zh;
    int64_t size, meta_size;
    uint8_t tmp[BDRV_SECTOR_SIZE];
    int ret, i;

    assert(opts->driver == BLOCKDEV_DRIVER_ZONED);
    zoned_opts = &opts->u.zoned;
    size = zoned_opts->size;
    meta_size = sizeof(uint64_t) * (zoned_opts->zone_nr_seq + zoned_opts->zone_nr_conv);
    uint64_t meta[meta_size];
    memset(meta, 0, meta_size);

    bs = bdrv_open_blockdev_ref(zoned_opts->file, errp);
    if (bs == NULL) {
        return -EIO;
    }

    blk = blk_new_with_bs(bs, BLK_PERM_WRITE | BLK_PERM_RESIZE, BLK_PERM_ALL,
                          errp);
    if (!blk) {
        ret = -EPERM;
        goto out;
    }
    blk_set_allow_write_beyond_eof(blk, true);

    zh.zone_model = cpu_to_le64(zoned_opts->zoned);
    zh.device_size = cpu_to_le64(size);
    zh.zone_nr_conv = cpu_to_le64(zoned_opts->zone_nr_conv);
    zh.zone_nr_seq = cpu_to_le64(zoned_opts->zone_nr_seq);
    zh.nr_zones = cpu_to_le64(zoned_opts->zone_nr_conv + zoned_opts->zone_nr_seq);
    zh.zone_size = cpu_to_le64(zoned_opts->zone_size << BDRV_SECTOR_BITS);
    zh.max_active_zones = cpu_to_le64(zoned_opts->max_active_zones);
    zh.max_open_zones = cpu_to_le64(zoned_opts->max_open_zones);
    zh.max_append_sectors = cpu_to_le64(zoned_opts->max_append_sectors);

    for (i = 0; i < zoned_opts->zone_nr_conv; ++i) {
        meta[i] = i * zh.zone_size;
        meta[i] += 1ULL << 59;
//        printf("0b%lb\n", meta[i]);
    }
    for (; i < zh.nr_zones; ++i) {
        meta[i] = i * zh.zone_size;
        /* For sequential zones, the first four most significant bit indicates zone states. */
        meta[i] += ((uint64_t)BLK_ZS_EMPTY << 60);
//        printf("0b%lb\n", meta[i]);
    }

    /* write zhs and metadata to the file */
    memcpy(zh.magic, HEADER_MAGIC, sizeof(zh.magic));
    memset(tmp, 0, sizeof(tmp));
    memcpy(tmp, &zh, sizeof(zh));

    ret = blk_pwrite(blk, 0, sizeof(zh), tmp, 0);
    if (ret < 0) {
        goto exit;
    }
    ret = blk_pwrite_zeroes(blk, BDRV_SECTOR_SIZE, size - sizeof(zh) - meta_size, 0);
    if (ret < 0) {
        goto exit;
    }
    ret = blk_pwrite(blk, size - meta_size, meta_size, meta, 0);
    printf("offset %ld meta size %ld\n", size-meta_size, meta_size);
    if (ret < 0) {
        goto exit;
    }
    ret = blk_flush(blk);
    if (ret < 0) {
        goto exit;
    }
    ret = 0;

out:
    blk_unref(blk);
    bdrv_unref(bs);
    return ret;
exit:
    error_setg_errno(errp, -ret, "Failed to create Zoned device file");
    goto out;
}

static int coroutine_fn zoned_co_create_opts(BlockDriver *drv,
                                             const char *filename,
                                             QemuOpts *opts, Error **errp)
{
    BlockdevCreateOptions *create_options = NULL;
    BlockDriverState *bs = NULL;
    QDict *qdict;
    Visitor *v;
    int ret;

    static const QDictRenames opt_renames[] = {
        { BLOCK_OPT_Z_NR_COV,     "zone-nr-conv"},
        { BLOCK_OPT_Z_NR_SEQ,     "zone-nr-seq"},
        { BLOCK_OPT_Z_MOZ,        "max-open-zones"},
        { BLOCK_OPT_Z_MAZ,        "max-active-zones"},
        { BLOCK_OPT_Z_MAS,        "max-append-sectors"},
        { BLOCK_OPT_Z_ZSIZE,      "zone-size"},
        { NULL, NULL },
    };

    /* Parse options and convert legacy syntax */
    qdict = qemu_opts_to_qdict_filtered(opts, NULL, &zoned_create_opts,
                                        true);
    if (!qdict_rename_keys(qdict, opt_renames, errp)) {
        ret = -EINVAL;
        goto done;
    }

    /* Create and open the file (protocol layer) */
    ret = bdrv_create_file(filename, opts, errp);
    if (ret < 0) {
        goto done;
    }

    bs = bdrv_open(filename, NULL, NULL,
                   BDRV_O_RDWR | BDRV_O_RESIZE | BDRV_O_PROTOCOL, errp);
    if (bs == NULL) {
        ret = -EIO;
        goto done;
    }

    /* Now get the QAPI type BlockdevCreateOptions */
    qdict_put_str(qdict, "driver", "zoned");
    qdict_put_str(qdict, "file", bs->node_name);

    v = qobject_input_visitor_new_flat_confused(qdict, errp);
    if (!v) {
        ret = -EINVAL;
        goto done;
    }

    visit_type_BlockdevCreateOptions(v, NULL, &create_options, errp);
    visit_free(v);
    if (!create_options) {
        ret = -EINVAL;
        goto done;
    }

    /* Create the zoned image (format layer) */
    ret = zoned_co_create(create_options, errp);
    if (ret < 0) {
        goto done;
    }
    ret = 0;

done:
    qobject_unref(qdict);
    bdrv_unref(bs);
    qapi_free_BlockdevCreateOptions(create_options);
    return ret;
}

static const char *const zoned_strong_runtime_opts[] = {
    "offset",
    "len",

    NULL
};

static BlockDriver bdrv_zoned = {
        .format_name	= "zoned",
        .instance_size	= sizeof(BDRVZonedState),
        .bdrv_probe		= zoned_probe,
        .bdrv_open		= zoned_open,
        .bdrv_close		= zoned_close,
        .bdrv_child_perm = bdrv_default_perms,
        .is_format              = true,
        .bdrv_refresh_limits    = zoned_refresh_limits,
        .bdrv_probe_blocksizes  = zoned_probe_blocksizes,
        // reopen: prepare, commit, abort

        // metadata cache flushing: invalidate_cache, migrate_add_blocker
        .bdrv_co_preadv         = zoned_co_preadv,
        .bdrv_co_pwritev        = zoned_co_pwritev,

        .bdrv_co_zone_report  = zoned_co_zone_report,
        .bdrv_co_zone_mgmt  = zoned_co_zone_mgmt,
        .bdrv_co_zone_append = zoned_co_zone_append,

        .bdrv_co_create         = zoned_co_create,
        .bdrv_co_create_opts    = zoned_co_create_opts,
        .create_opts            = &zoned_create_opts,
        .strong_runtime_opts    = zoned_strong_runtime_opts,
        .mutable_opts           = mutable_opts,
};

static void bdrv_zoned_init(void)
{
    bdrv_register(&bdrv_zoned);
}

block_init(bdrv_zoned_init);
