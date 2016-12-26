
/*
 *
 * SHARP fldr mode
 *     tewilove@gmail.com, All rights reserved
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rc4.h>
#include "fldr.h"
#include "encdec.h"
#include "utils.h"

#define NELEM(x) (sizeof(x)/sizeof(x[0]))

#define FLDR_IMEI_SIZE 16
#define FLDR_BLOCK_SIZE 512
#define FLDR_PAYLOAD_SIZE (240 * 1024)

#define LOGV(...) do { \
        fprintf(stdout, __VA_ARGS__); \
        fflush(stdout); \
    } while (0)

#define LOGE(...) do { \
        fprintf(stderr, __VA_ARGS__); \
        fflush(stderr); \
    } while (0)

struct fldr_payload {
    uint32_t magic;
    uint32_t partition;
    uint32_t offset;
    uint32_t count;
    char data[0];
} __attribute__((packed));

struct fldr_device_info {
    const char name[8];
    const char *key;
};

extern void *memmem(const void *, size_t, const void *, size_t);

const static char g_304sh_key[] = {
    0x64, 0x4E, 0x35, 0x35, 0x76, 0x69, 0x36, 0x76, 0x72, 0x4A, 0x6E, 0x31, 0x68, 0x54, 0x68, 0x6F,
    0x47, 0x4E, 0x54, 0x51, 0x36, 0x52, 0x2F, 0x49, 0x58, 0x46, 0x49, 0x76, 0x6B, 0x34, 0x59, 0x36
};

const static char g_303sh_key[] = {
    0x6D, 0x6E, 0x58, 0x71, 0x70, 0x70, 0x6C, 0x44, 0x47, 0x72, 0x79, 0x2B, 0x7A, 0x31, 0x56, 0x70,
    0x71, 0x71, 0x7A, 0x58, 0x41, 0x30, 0x53, 0x6F, 0x70, 0x4F, 0x4A, 0x76, 0x7A, 0x51, 0x4C, 0x2B
};

const static char g_302sh_key[] = {
    0x6D, 0x6E, 0x58, 0x71, 0x70, 0x70, 0x6C, 0x44, 0x47, 0x72, 0x79, 0x2B, 0x7A, 0x31, 0x56, 0x70,
    0x71, 0x71, 0x7A, 0x58, 0x41, 0x30, 0x53, 0x6F, 0x70, 0x4F, 0x4A, 0x76, 0x7A, 0x51, 0x4C, 0x2B
};

const static char g_sh04f_key[] = {
    0x59, 0x71, 0x47, 0x55, 0x42, 0x61, 0x54, 0x48, 0x6C, 0x4F, 0x31, 0x77, 0x59, 0x62, 0x38, 0x39,
    0x6B, 0x44, 0x7A, 0x4E, 0x61, 0x36, 0x77, 0x55, 0x4F, 0x56, 0x35, 0x5A, 0x4A, 0x30, 0x41, 0x2F
};

const static char g_shl23_key[] = {
    0x48, 0x34, 0x46, 0x77, 0x77, 0x62, 0x78, 0x2F, 0x37, 0x62, 0x34, 0x79, 0x56, 0x4B, 0x63, 0x57,
    0x72, 0x67, 0x48, 0x6A, 0x4c, 0x74, 0x7A, 0x50, 0x37, 0x4A, 0x34, 0x38, 0x6F, 0x51, 0x63, 0x6D
};

const static struct fldr_device_info g_fldr_devices[] = {
    { .name = {'P', 'A', '2', '1', 0, 0, 0, 0}, .key = g_302sh_key },
    { .name = {'P', 'A', '2', '3', 0, 0, 0, 0}, .key = g_303sh_key },
    { .name = {'P', 'A', '2', '4', 0, 0, 0, 0}, .key = g_304sh_key },
    { .name = {'D', 'L', '5', '0', 0, 0, 0, 0}, .key = g_sh04f_key },
    { .name = {'A', 'S', '9', '7', 0, 0, 0, 0}, .key = g_shl23_key },
};

static int fldr_flash(const char *pfile, int partition, const char *secrec) {
    int ret = -1, rc, fd = -1, i;
    struct stat fs;
    uint32_t status, size;
    struct libusb_device_handle *h;
    char fldr_name[FLDR_NAME_SIZE];
    char loader_path[PATH_MAX];
    size_t nbtr, offset, once;
    char *imei_loader_data = NULL;
    size_t imei_loader_size = 0;
    char imei[FLDR_IMEI_SIZE];
    char imei_text[16];
    RC4_KEY rc4_ctx;
    char magic[4];
    void *test;
    char *data_loader_data = NULL;
    size_t data_loader_size = 0;
    char ivec[16] = { 0 };
    char *generated_data = NULL;
    size_t generated_size = 0;
    struct fldr_device_info *device = NULL;
    struct fldr_payload *payload = NULL;

    if (partition < 0 || !pfile)
        return ret;
    rc = stat(pfile, &fs);
    if (rc < 0) {
        LOGE("Could not stat `%s\'", pfile);
        return ret;
    }
#ifdef __MINGW32__
    fd = open(pfile, O_RDONLY|O_BINARY);
#else
    fd = open(pfile, O_RDONLY);
#endif
    if (fd < 0) {
        LOGE("Could not open `%s\'", pfile);
        return ret;
    }
    rc = fldr_init();
    if (rc) {
        LOGE("USB init\n");
        goto fail_fldr_init;
    }
    h = fldr_open();
    if (!h) {
        LOGE("USB open\n");
        goto fail_fldr_open;
    }
    memset(fldr_name, 0, sizeof(fldr_name));
    rc = fldr_get_name(h, fldr_name);
    if (rc) {
        LOGE("FLDR test name\n");
        goto fail_fldr_get_name;
    }
    LOGV("Detected device: %s\n", fldr_name);
    for (i = 0; i < NELEM(g_fldr_devices); i++) {
        if (!strcmp(fldr_name, g_fldr_devices[i].name)) {
            device = (struct fldr_device_info *) &g_fldr_devices[i];
            break;
        }
    }
    if (device == NULL) {
        LOGE("FLDR device error\n");
        goto fail_fldr_device_error;
    }
    nbtr = fldr_write(h, secrec, 16);
    if (nbtr != 16)
        goto fail_fldr_write_secrec;
    memset(loader_path, 0, sizeof(loader_path));
    snprintf(loader_path, sizeof(loader_path), "%s.ldr", fldr_name);
    rc = file_read(loader_path, &imei_loader_data, &imei_loader_size);
    if (rc) {
        LOGE("Could not load `%s\'\n", loader_path);
        goto fail_file_read_imei_loader;
    }
    status = fldr_boot(h, (const char *) imei_loader_data, imei_loader_size, FLDR_FLAG_DUMP);
    if (status != 0xFC000201) {
        LOGE("FLDR imei boot\n");
        goto fail_fldr_boot_imei_loader;
    }
    nbtr = fldr_read(h, (char *) &size, sizeof(size));
    if (nbtr != sizeof(size)) {
        LOGE("FLDR imei read\n");
        goto fail_fldr_read_imei;
    }
    if (size != sizeof(imei)) {
        LOGE("FLDR imei read\n");
        goto fail_fldr_read_imei;
    }
    memset(imei, 0, sizeof(imei));
    nbtr = fldr_read(h, imei, sizeof(imei));
    if (nbtr != sizeof(imei)) {
        LOGE("FLDR imei read\n");
        goto fail_fldr_read_imei;
    }
    rc = fldr_close(h);
    h = NULL;
    if (rc) {
        LOGE("USB close\n");
        goto fail_fldr_close;
    }
    rc = imei_parse_qcom(imei, imei_text);
    if (rc) {
        LOGE("FLDR imei error\n");
        goto fail_fldr_imei_ng;
    }
    LOGV("Detected IMEI: %s\n", imei_text);
    memset(loader_path, 0, sizeof(loader_path));
    snprintf(loader_path, sizeof(loader_path), "%s.ldr", imei_text);
    rc = file_read(loader_path, &data_loader_data, &data_loader_size);
    if (rc) {
        LOGE("Could not load `%s\'\n", loader_path);
        goto fail_file_read_data_loader;
    }
    RC4_set_key(&rc4_ctx, 15, (const unsigned char *) imei_text);
    RC4(&rc4_ctx, data_loader_size, data_loader_data, data_loader_data);
    magic[0] = 'F'; magic[1] = 'L'; magic[2] = 'D'; magic[3] = 'R';
    test = memmem(data_loader_data, data_loader_size, magic, sizeof(magic));
    if (test == NULL ||
        (data_loader_size + data_loader_data - (char *) test < sizeof(struct fldr_payload) + FLDR_PAYLOAD_SIZE)) {
        LOGE("FLDR programmer error\n");
        goto fail_validate_data_loader;
    }
    payload = (struct fldr_payload *) test;
    for (offset = 0; offset < fs.st_size; offset += FLDR_PAYLOAD_SIZE) {
        float now, all;
        int per;

        payload->partition = partition;
        payload->offset = offset / FLDR_BLOCK_SIZE;
        once = fs.st_size - offset;
        if (once >= FLDR_PAYLOAD_SIZE)
            once = FLDR_PAYLOAD_SIZE;
        if (once & (FLDR_BLOCK_SIZE - 1))
            once = (once + FLDR_BLOCK_SIZE) & ~(FLDR_BLOCK_SIZE - 1);
        payload->count = once / FLDR_BLOCK_SIZE;
        memset(&payload->data[0], 0, FLDR_PAYLOAD_SIZE);
        rc = read(fd, &payload->data[0], once);
        if (rc != once) {
            LOGE("Could not read `%s\', %lx@%lx\n", pfile, (long) once, (long) offset);
            goto fail_file_read_data;
        }
        rc = fldr_encode(data_loader_data, data_loader_size, device->name, device->key, ivec,
                         &generated_data, &generated_size);
        if (rc) {
            LOGE("FLDR encode\n");
            goto fail_fldr_encode;
        }
retry:
        rc = fldr_boot_recv(generated_data, generated_size, secrec);
        if (rc) {
            goto retry;
        }
        now = (float)(unsigned)(offset + once);
        all = (float)(unsigned)(fs.st_size);
        per = 10000 * (now / all);
        LOGV("Written %08lx/%08lx %d.%02d%%\n", (long)(offset + once), (long) fs.st_size, per / 100, per % 100);
        free(generated_data);
        generated_data = NULL;
    }
    ret = 0;
fail_fldr_encode:
fail_file_read_data:
    if (generated_data)
        free(generated_data);
fail_validate_data_loader:
    if (data_loader_data)
        free(data_loader_data);
fail_file_read_data_loader:
fail_fldr_imei_ng:
fail_fldr_close:
fail_fldr_read_imei:
fail_fldr_boot_imei_loader:
    if (imei_loader_data)
        free(imei_loader_data);
fail_file_read_imei_loader:
fail_fldr_write_secrec:
fail_fldr_device_error:
fail_fldr_get_name:
    if (h)
        fldr_close(h);
fail_fldr_open:
fail_fldr_init:
    if (fd >= 0)
        close(fd);
    return ret;
}

static int fldr_run(const char *pfile, int flags, const char *secrec) {
    int ret = -1, rc;
    uint32_t status;
    struct libusb_device_handle *h;
    char fldr_name[FLDR_NAME_SIZE];
    char *loader_data = NULL;
    size_t loader_size = 0;
    char *extra_data = NULL;
    uint32_t extra_size = 0;
    size_t nbtr;

    if (pfile) {
        rc = file_read(pfile, &loader_data, &loader_size);
        if (rc) {
            LOGE("Could not load `%s\'\n", pfile);
            goto fail_file_read;
        }
    }
    rc = fldr_init();
    if (rc) {
        LOGE("USB init\n");
        goto fail_fldr_init;
    }
    h = fldr_open();
    if (!h) {
        LOGE("USB open\n");
        goto fail_fldr_open;
    }
    memset(fldr_name, 0, sizeof(fldr_name));
    rc = fldr_get_name(h, fldr_name);
    if (rc) {
        LOGE("FLDR test name\n");
        goto fail_fldr_get_name;
    }
    LOGV("Detected device: %s\n", fldr_name);
    if (flags & FLDR_FLAG_SEND_SEC) {
        nbtr = fldr_write(h, secrec, 16);
        if (nbtr != 16)
            goto fail_fldr_write_secrec;
    }
    if (loader_data && loader_size) {
        status = fldr_boot(h, (const char *) loader_data, loader_size, flags);
        ret = status == (uint32_t) 0xFC000201 ? 0 : -1;
        LOGV("Download result: %s(%08X)\n", ret ? "NGNG" : "OKOK", status);
        if (!ret && (flags & FLDR_FLAG_DUMP)) {
            size_t nb;

            nbtr = fldr_read(h, (char *) &extra_size, sizeof(extra_size));
            if (nbtr != sizeof(extra_size) || !nbtr) {
                LOGE("No extra data received.\n");
                goto fail_empty_data;
            }
            LOGV("Extra size: %08x\n", (int) extra_size);
            extra_data = malloc(extra_size);
            if (!extra_data)
                goto fail_malloc;
            nb = fldr_read(h, extra_data, extra_size);
            if (nb == (size_t) -1)
                nb = 0;
            dump("Extra data:", extra_data, nb);
            free(extra_data);
        }
    } else {
        ret = 0;
    }
fail_malloc:
fail_empty_data:
fail_fldr_write_secrec:
fail_fldr_get_name:
    fldr_close(h);
fail_fldr_open:
    fldr_free();
fail_fldr_init:
    if (loader_data && loader_size)
        free(loader_data);
fail_file_read:
    return ret;
}

int main(int argc, char *argv[]) {
    int ret = -1, rc, i, len;
    char ch;
    int flags = 0;
    // F9225D50E9D244601192A03B511F80C1
    char secrec[16] = {
        0xF9, 0x22, 0x5D, 0x50, 0xE9, 0xD2, 0x44, 0x60,
        0x11, 0x92, 0xA0, 0x3B, 0x51, 0x1F, 0x80, 0xC1,
    };
    char *rfile = NULL;
    char *pfile = NULL;
    int partition = 0;

    while ((ch = getopt(argc, argv, "hSs:r:H:dp:f:")) != -1) {
        switch (ch) {
            case 'S': {
                flags |= FLDR_FLAG_SEND_SEC;
                break;
            }
            case 's': {
                char digit;

                len = strlen(optarg);
                if (len != 32)
                    goto fail_usage;
                for (i = 0; i < len; i++) {
                    digit = optarg[i];
                    if (digit >= '0' && digit <= '9')
                        digit -= '0';
                    else if (digit >= 'A' && digit <= 'F')
                        digit -= ('A' - 10);
                    else if (digit >= 'a' && digit <= 'f')
                        digit -= ('a' - 10);
                    else
                        goto fail_usage;
                    secrec[i / 2] <<= 4;
                    secrec[i / 2] |= digit;
                }
                flags |= FLDR_FLAG_SEND_SEC;
                break;
            }
            case 'r':
                rfile = optarg;
                break;
            case 'H':
                flags |= FLDR_FLAG_HIGH_ADDR;
                break;
            case 'd':
                flags |= FLDR_FLAG_DUMP;
                break;
            case 'p':
                partition = strtol(optarg, NULL, 10);
                break;
            case 'f':
                pfile = optarg;
                break;
            case 'h':
            default:
fail_usage:
                fprintf(stderr, "Example:\n%s -S -r SHL23.ldr\n", argv[0]);
                return ret;
        }
    }
    if (partition && pfile)
        return fldr_flash(pfile, partition, secrec);
    return fldr_run(rfile, flags, secrec);
}

