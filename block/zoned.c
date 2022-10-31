/*
 * Block driver for the zoned block device format
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
typedef struct ZonedHeader {
    char magic[4]; /* */
    uint32_t zone_nr_seq;
    uint64_t zone_size;
    uint64_t size;
} QEMU_PACKED ZonedHeader;

typedef struct BDRVZonedState {
    uint32_t zone_nr_seq;
    uint64_t size; /* device size in bytes */
    uint64_t meta_size;
    uint64_t zone_size;

    uint64_t offset;
    uint64_t len;
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

/*
 * Open the emulated device.
 */
static int zoned_open(BlockDriverState *bs, QDict *options, int flags,
                      Error **errp)
{
    BDRVZonedState *s = bs->opaque;
    ZonedHeader header;
    QemuOpts *opts = NULL;
    int ret;

    bs->file = bdrv_open_child(NULL, options, "file", bs, &child_of_bds,
                               BDRV_CHILD_IMAGE, false, errp);
    if (!bs->file) {
        return -EINVAL;
    }

    ret = bdrv_pread(bs->file, 0, sizeof(header), &header, 0);
    if (ret < 0) {
        goto fail;
    }

    if (memcmp(header.magic, HEADER_MAGIC, 4)) {
        error_setg(errp, "Image not in zoned format");
        goto fail;
    }

    opts = qemu_opts_create(&zoned_runtime_opts, NULL, 0, errp);
    if (!opts) {
        return -EINVAL;
    }

    if (!qemu_opts_absorb_qdict(opts, options, errp)) {
        return -EINVAL;
    }

    s->size = header.size;
    s->zone_nr_seq = header.zone_nr_seq;
    s->meta_size = sizeof(BlockZoneWps) + sizeof(uint64_t) * bs->bl.nr_zones;
    s->zone_size = header.zone_size;
    return 0;

fail:
    return ret;
}

static void zoned_refresh_limits(BlockDriverState *bs, Error **errp)
{
    bs->bl.request_alignment = BDRV_SECTOR_SIZE;
}


static coroutine_fn int zoned_co_preadv(BlockDriverState *bs, int64_t offset,
                                        int64_t bytes, QEMUIOVector *qiov,
                                        BdrvRequestFlags flags)
{
    return 0;
//    int ret;
//
//    ret = zoned_adjust_offset(bs, &offset, bytes, false);
//    if (ret) {
//        return ret;
//    }
//
//    BLKDBG_EVENT(bs->file, BLKDBG_READ_AIO);
//    return bdrv_co_preadv(bs->file, offset, bytes, qiov, flags);
}

static coroutine_fn int zoned_co_pwritev(BlockDriverState *bs, int64_t offset,
                                         int64_t bytes, QEMUIOVector *qiov,
                                         BdrvRequestFlags flags) {
    return 0;
}
//    void *buf = NULL;
//    BlockDriver *drv;
//    QEMUIOVector local_qiov;
//    int ret;
//
//    if (bs->probed && offset < BLOCK_PROBE_BUF_SIZE && bytes) {
//        /* Handling partial writes would be a pain - so we just
//         * require that guests have 512-byte request alignment if
//         * probing occurred */
//        QEMU_BUILD_BUG_ON(BLOCK_PROBE_BUF_SIZE != 512);
//        QEMU_BUILD_BUG_ON(BDRV_SECTOR_SIZE != 512);
//        assert(offset == 0 && bytes >= BLOCK_PROBE_BUF_SIZE);
//
//        buf = qemu_try_blockalign(bs->file->bs, 512);
//        if (!buf) {
//            ret = -ENOMEM;
//            goto fail;
//        }
//
//        ret = qemu_iovec_to_buf(qiov, 0, buf, 512);
//        if (ret != 512) {
//            ret = -EINVAL;
//            goto fail;
//        }
//
//        drv = bdrv_probe_all(buf, 512, NULL);
//        if (drv != bs->drv) {
//            ret = -EPERM;
//            goto fail;
//        }
//
//        /* Use the checked buffer, a malicious guest might be overwriting its
//         * original buffer in the background. */
//        qemu_iovec_init(&local_qiov, qiov->niov + 1);
//        qemu_iovec_add(&local_qiov, buf, 512);
//        qemu_iovec_concat(&local_qiov, qiov, 512, qiov->size - 512);
//        qiov = &local_qiov;
//    }
//
//    ret = zoned_adjust_offset(bs, &offset, bytes, true);
//    if (ret) {
//        goto fail;
//    }
//
//    BLKDBG_EVENT(bs->file, BLKDBG_WRITE_AIO);
//    ret = bdrv_co_pwritev(bs->file, offset, bytes, qiov, flags);
//
//    fail:
//    if (qiov == &local_qiov) {
//        qemu_iovec_destroy(&local_qiov);
//    }
//    qemu_vfree(buf);
//    return ret;
//}

static int coroutine_fn zoned_co_pwrite_zeroes(BlockDriverState *bs,
                                               int64_t offset, int64_t bytes,
                                               BdrvRequestFlags flags)
{
    return 0;
//    return bdrv_co_pwrite_zeroes(bs->file, offset, bytes, flags);
}

static int coroutine_fn zoned_co_zone_report(BlockDriverState *bs, int64_t offset,
                                             unsigned int *nr_zones,
                                             BlockZoneDescriptor *zones)
{
    BDRVZonedState *s = bs->opaque;
    int index = offset / s->zone_size;
    int ret;

    bs->bl.wps = g_malloc(s->meta_size);
    ret = bdrv_pread(bs->file, s->size - s->meta_size, s->meta_size, bs->bl.wps, 0);
    if (ret < 0) {
        error_report("Can not read metadata\n");
        return ret;
    }

    for (int i = 0; i < *nr_zones; ++i) {
        zones[i].start = i * s->zone_size;
        zones[i].length = s->zone_size;
        zones[i].cap = zones[i].length;

        if (!BDRV_ZT_IS_CONV(bs->bl.wps->wp[i])) {
            zones[i].type = BLK_ZT_SWR;
            zones[i].wp = bs->bl.wps->wp[i];
        } else {
            zones[i].type = BLK_ZT_CONV;
            zones[i].wp = zones[i].start;
        }

        zones[i].state = BDRV_ZONE_STATE(zones[i].wp) - 2;
        index += 1;
    }

    return 0;
}

static int coroutine_fn zoned_co_zone_mgmt(BlockDriverState *bs, BlockZoneOp op,
                                           int64_t offset, int64_t len)
{
    return 0;
}


static int coroutine_fn zoned_co_zone_append(BlockDriverState *bs, int64_t *offset,
                                             QEMUIOVector *qiov,
                                             BdrvRequestFlags flags)
{
    return bdrv_co_zone_append(bs->file->bs, offset, qiov, flags);
}

static void zoned_close(BlockDriverState *bs)
{
    return;
}

static int coroutine_fn zoned_co_create(BlockdevCreateOptions *opts,
                                        Error **errp)
{
    BlockdevCreateOptionsZoned *zoned_opts;
    BlockDriverState *bs;
    BlockBackend *blk;
    ZonedHeader header;
    int64_t size, meta_size;
    uint8_t tmp[BDRV_SECTOR_SIZE];
    int ret;

    assert(opts->driver == BLOCKDEV_DRIVER_ZONED);
    zoned_opts = &opts->u.zoned;
    size = zoned_opts->size;
    meta_size = sizeof(BlockZoneWps) + sizeof(uint64_t) *
            (zoned_opts->zone_nr_seq + zoned_opts->zone_nr_conv);
    uint8_t test[meta_size];


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

    bs->bl.zoned = cpu_to_le64(zoned_opts->zoned);
    bs->bl.nr_zones = cpu_to_le64(zoned_opts->zone_nr_conv + zoned_opts->zone_nr_seq);
    bs->bl.zone_size = cpu_to_le64(zoned_opts->zone_size << BDRV_SECTOR_BITS);
    bs->bl.max_active_zones = cpu_to_le64(zoned_opts->max_active_zones);
    bs->bl.max_open_zones = cpu_to_le64(zoned_opts->max_open_zones);
    bs->bl.max_append_sectors = cpu_to_le64(zoned_opts->max_append_sectors);

    bs->bl.wps = g_malloc(meta_size);
    qemu_co_mutex_init(&bs->bl.wps->colock);
    printf("writing wps\n");
    for (int i = 0; i < bs->bl.nr_zones; ++i) {
        /* The first most significant bit indicates zone type. */
        bs->bl.wps->wp[i] = i * bs->bl.zone_size;
        if (i < zoned_opts->zone_nr_conv) {
            bs->bl.wps->wp[i] += 1ULL << 63;
            printf("conv i %d wp %lb\n", i, bs->bl.wps->wp[i]);
        } else {
            bs->bl.wps->wp[i] += (unsigned long long)(BLK_ZS_EMPTY + 2) << 60;
            printf("seq i %d wp %lb\n", i, bs->bl.wps->wp[i]);
        }
        printf("i %d wp %lb\n", i, bs->bl.wps->wp[i]);
    }

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, HEADER_MAGIC, sizeof(header.magic));
    header.size = cpu_to_le64(size);
    header.zone_nr_seq = cpu_to_le64(zoned_opts->zone_nr_seq);
    header.zone_size = bs->bl.zone_size;

    /* write headers and metadata to the file */
    memset(tmp, 0, sizeof(tmp));
    memset(test, 0, meta_size);
    memcpy(tmp, &header, sizeof(header));
    memcpy(test, bs->bl.wps, meta_size);

    printf("start writing\n");
    ret = blk_pwrite(blk, 0, BDRV_SECTOR_SIZE, tmp, 0);
    if (ret < 0) {
        goto exit;
    }
    ret = blk_pwrite_zeroes(blk, BDRV_SECTOR_SIZE, size - BDRV_SECTOR_SIZE - meta_size, 0);
    if (ret < 0) {
        goto exit;
    }
    printf("create: meta size 0x%lx, meta data starts at 0x%lx\n", meta_size, size-meta_size);
    ret = blk_pwrite(blk, size - meta_size, meta_size, test, 0);
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

        // reopen: prepare, commit, abort

        // metadata cache flushing: invalidate_cache, migrate_add_blocker

        .bdrv_co_preadv         = zoned_co_preadv,
        .bdrv_co_pwritev        = zoned_co_pwritev,
        .bdrv_co_pwrite_zeroes = zoned_co_pwrite_zeroes,

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
