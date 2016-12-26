
#include "utils.h"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

void dump(const char *head, const void *data, size_t size) {
    size_t i;

    fprintf(stderr, "%s\n", head);
    fflush(stderr);
    for (i = 0; i < size; i++) {
        fprintf(stderr, "%02x ", *((char *) data + i) & 0xff);
        if ((i + 1) % 16 == 0)
            fprintf(stderr, "\n");
    }
    if (i % 16)
        fprintf(stderr, "\n");
    fflush(stderr);
}

int file_read(const char *path, char **data, size_t *size) {
    int rc, fd;
    struct stat fs;
    size_t nbrd;

    rc = stat(path, &fs);
    if (rc)
        return rc;
    if (fs.st_size <= 0)
        return -1;
    *size = fs.st_size;
    *data = malloc(fs.st_size);
    if (*data == NULL)
        return -1;
#ifdef __MINGW32__
    fd = open(path, O_RDONLY|O_BINARY);
#else
    fd = open(path, O_RDONLY);
#endif
    if (fd < 0) {
        free(*data);
        *data = NULL;
        return -1;
    }
    nbrd = 0;
    while (nbrd < fs.st_size) {
        int tmp;

        tmp = read(fd, *data + nbrd, fs.st_size - nbrd);
        if (tmp < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        nbrd += tmp;
    }
    close(fd);
    if (nbrd < fs.st_size) {
        free(*data);
        *data = NULL;
        return -1;
    }

    return 0;
}

int file_write(const char *path, const char *data, size_t size) {
    int rc, fd;
    size_t nbwr;

    fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd < 0)
        return -1;
    nbwr = 0;
    rc = ftruncate(fd, nbwr);
    if (rc)
        goto fail_truncate;
    while (nbwr < size) {
        int tmp;

        tmp = write(fd, data + nbwr, size - nbwr);
        if (tmp < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        nbwr += tmp;
    }
fail_truncate:
    close(fd);

    return nbwr == size ? 0 : -1;
}

int imei_parse_qcom(const char *data, char *imei) {
    if (data[0] != 0x00 || data[1] != 0x08 || (data[2] & 0xf) != 0x0a)
        return -1;
    imei[0] = ((data[2] & 0xf0) >> 4) + '0';
    imei[1] = (data[3] & 0xf) + '0';
    imei[2] = ((data[3] & 0xf0) >> 4) + '0';
    imei[3] = (data[4] & 0xf) + '0';
    imei[4] = ((data[4] & 0xf0) >> 4) + '0';
    imei[5] = (data[5] & 0xf) + '0';
    imei[6] = ((data[5] & 0xf0) >> 4) + '0';
    imei[7] = (data[6] & 0xf) + '0';
    imei[8] = ((data[6] & 0xf0) >> 4) + '0';
    imei[9] = (data[7] & 0xf) + '0';
    imei[10] = ((data[7] & 0xf0) >> 4) + '0';
    imei[11] = (data[8] & 0xf) + '0';
    imei[12] = ((data[8] & 0xf0) >> 4) + '0';
    imei[13] = (data[9] & 0xf) + '0';
    imei[14] = ((data[9] & 0xf0) >> 4) + '0';
    imei[15] = 0;
    return 0;
}

