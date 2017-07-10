
#include "fldr.h"
#include <unistd.h>
#include <string.h>
#include <libusb-1.0/libusb.h>

static libusb_context *g_ctx;

int fldr_init() {
    int rc;

    rc = libusb_init(&g_ctx);
    return rc;
}

void fldr_free() {
    libusb_exit(g_ctx);
}

// see lsusb -v -d 04dd:933a
void *fldr_open() {
    int rc;
    libusb_device_handle *h;

    for (;;) {
        h = libusb_open_device_with_vid_pid(g_ctx, USB_VID, USB_PID);
        if (h)
            break;
        usleep(10000);
    }
    rc = libusb_claim_interface(h, 1);
    if (rc) {
        // fprintf(stderr, "%04d:%s: %s(%d)\n", __LINE__, "libusb_claim_interface", libusb_error_name(rc), rc);
        goto fail;
    }
    rc = libusb_set_interface_alt_setting(h, 1, 1);
    if (rc) {
        // fprintf(stderr, "%04d:%s: %s(%d)\n", __LINE__, "libusb_set_interface_alt_setting", libusb_error_name(rc), rc);
        goto fail;
    }
    return h;
fail:
    libusb_close(h);
    return NULL;
}

int fldr_close(void *h) {
    int rc;

    rc = libusb_release_interface(h, 1);
    libusb_close(h);
    return rc;
}

size_t fldr_read(void *h, char *buff, size_t size) {
    int rc;
    size_t nbtr = 0;
    libusb_device *d;
    int ps;

    d = libusb_get_device((libusb_device_handle *) h);
    if (!d)
        return (size_t)(-1);
    ps = libusb_get_max_packet_size(d, 0x81);
    if (ps <= 0)
        ps = 512;
    while (nbtr < size) {
        int nb, ch;

        ch = size - nbtr;
        if (ch > ps)
            ch = ps;
        rc = libusb_bulk_transfer(
            (libusb_device_handle *) h,
            0x81,
            (unsigned char *) buff + nbtr,
            ch,
            &nb,
            10000);
        if (rc) {
            // fprintf(stderr, "%04d:%s: %s(%d)\n", __LINE__, __func__, libusb_error_name(rc), rc);
            break;
        }
        nbtr += nb;
    }
    // fprintf(stderr, "%s: %d\n", __func__, (int) nbtr);

    return nbtr;
}

size_t fldr_write(void *h, const char *buff, size_t size) {
    int rc;
    size_t nbtr = 0;
    libusb_device *d;
    int ps;

    d = libusb_get_device((libusb_device_handle *) h);
    if (!d)
        return (size_t)(-1);
    ps = libusb_get_max_packet_size(d, 0x01);
    if (ps <= 0)
        ps = 512;
    while (nbtr < size) {
        int nb, ch;

        ch = size - nbtr;
        if (ch > ps)
            ch = ps;
        rc = libusb_bulk_transfer(
            (libusb_device_handle *) h,
            0x01,
            (unsigned char *) buff + nbtr,
            ch,
            &nb,
            1000);
        if (rc) {
            // fprintf(stderr, "%04d:%s: %s(%d)\n", __LINE__, __func__, libusb_error_name(rc), rc);
            break;
        }
        nbtr += nb;
    }
    // fprintf(stderr, "%s: %d\n", __func__, (int) nbtr);

    return nbtr;
}

int fldr_get_name(void *h, char *out) {
    size_t nbtr;
    char data[16];

    data[0] = 0x30;
    data[1] = 0x01;
    data[2] = 0xce;
    nbtr = fldr_write(h, (const char *) data, 3);
    if (nbtr != 3)
        return -1;
    nbtr = fldr_read(h, data, 11);
    /*
     * 0x31 0x09 (8 byte) sum
     */
    if (nbtr != 11 || data[0] != 0x31 || data[1] != 0x09)
        return -1;
    if (out) {
        memset(out, 0, FLDR_NAME_SIZE);
        memcpy(out, data + 2, FLDR_NAME_SIZE);
    }
    return 0;
}

uint32_t fldr_boot(void *h, const char *data, size_t size, int flags) {
    uint32_t ret = (uint32_t) -1;
    size_t i, nbtr;
    unsigned char head[6];
    unsigned char sum;
    uint32_t status;

    if (size > 0x4000007)
        return ret;
    /*
     * op: 1 byte
     * size: 4 byte
     * addr: 1 byte
     * data: size byte(s)
     * sum: 1 byte
     */
    head[0] = 0;
    *((uint8_t *)(head + 1)) = ((size + 2) & 0xff000000) >> 24;
    *((uint8_t *)(head + 2)) = ((size + 2) & 0xff0000) >> 16;
    *((uint8_t *)(head + 3)) = ((size + 2) & 0xff00) >> 8;
    *((uint8_t *)(head + 4)) = (size + 2) & 0xff;
    if (flags & FLDR_FLAG_HIGH_ADDR)
        head[5] = 0xff;
    else
        head[5] = 0;
    nbtr = fldr_write(h, (const char *) head, sizeof(head));
    if (nbtr != sizeof(head))
        return ret;
    nbtr = fldr_write(h, data, size);
    if (nbtr != size)
        return ret;
    sum = 0;
    for (i = 0; i < 6; i++)
        sum += head[i];
    for (i = 0; i < size; i++)
        sum += (unsigned) data[i];
    sum = ~sum;
    nbtr = fldr_write(h, (const char *) &sum, sizeof(sum));
    if (nbtr != sizeof(sum))
        return ret;
    nbtr = fldr_read(h, (char *) &status, sizeof(status));
    if (nbtr != sizeof(status))
        return ret;
    ret = status;

    return ret;
}

uint32_t fldr_boot_recv(const char *data, size_t size, const char *secrec) {
    void *h;
    uint32_t result = (uint32_t) -1;
    size_t nbtr;
    uint32_t status;

    h = fldr_open();
    if (!h)
        return result;
    nbtr = fldr_write(h, secrec, 16);
    if (nbtr != 16) {
        fldr_close(h);
        return result;
    }
    status = fldr_boot(h, data, size, FLDR_FLAG_DUMP);
    fldr_close(h);
    if (status != 0xFC000201) {
        return result;
    }
    return 0;
}

