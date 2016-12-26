
#include "encdec.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>

/*
int check_model(char *a) {
    return memcmp(a, "DL50", 4);
}

static int func1(int a, int b, int *c) {
    char data[12];
    char buff[4];
    int n;

    sprintf(data, "%04u", a);
    n = log40(a);
    if (n >= 4) {
        buff[0] = data[n - 4] ^ *((char *) &b + 0);
        buff[1] = data[n - 3] ^ *((char *) &b + 1);
        buff[2] = data[n - 2] ^ *((char *) &b + 2);
        buff[3] = data[n - 1] ^ *((char *) &b + 3);
    } else {
        buff[0] = data[0] ^ *((char *) &b + 0);
        buff[1] = data[1] ^ *((char *) &b + 1);
        buff[2] = data[2] ^ *((char *) &b + 2);
        buff[3] = data[3] ^ *((char *) &b + 3);
    }
    return memcmp(buff, c, 4);
}

static int func2(int a, int b, int *c) {
    char data[12];
    char *buff = (char *) c;
    int n;

    sprintf(data, "%04u", a);
    n = log40(a);
    if (n >= 4) {
        buff[0] = data[n - 4] ^ *((char *) &b + 0);
        buff[1] = data[n - 3] ^ *((char *) &b + 1);
        buff[2] = data[n - 2] ^ *((char *) &b + 2);
        buff[3] = data[n - 1] ^ *((char *) &b + 3);
    } else {
        buff[0] = data[0] ^ *((char *) &b + 0);
        buff[1] = data[1] ^ *((char *) &b + 1);
        buff[2] = data[2] ^ *((char *) &b + 2);
        buff[3] = data[3] ^ *((char *) &b + 3);
    }
}

// d1 = off + 544
// d2 = off + 512, 24
// nm = DL50\0\0\0\0\0\0
int check_info(int *d1, int *d2, int *nm) {
    int var1[15];
    int var2[15];
    int rc, i;

    for (i = 1; i < 16; i++) {
        rc = func1(d2[0] * d2[5] * i, d1[8 * i + 0], nm);
        if (rc)
            return 2;
        rc = func1(d2[2] * d2[5] * i, d1[8 * i + 1], nm + 1);
        if (rc)
            return 2;
        func2(d2[1] * d2[5] * i, d1[8 * i + 6], var1 + i - 1);
        func2(d2[3] * d2[5] * i, d1[8 * i + 7], var2 + i - 1);
    }
    for (i = 1; i < 15; i++) {
        if (memcmp(var1, var1 + i, 4))
            return 1;
        if (memcmp(var2, var2 + i, 4))
            return 1;
    }

    return 0;
}

// after 2k offset
// every 1kb data, data[0] = data[]

int check_nkb(char *d, int s) {
    int i;
    int n = s >> 10;

    for (i = 2; i < n; i++) {
        if (d[i *1024] != d[i * 1022])
            return 1;
    }

    return 0;
}

int fixup_nkb(char *data, int size) {
    int i, n, tail, nk, left;

    n = 0;
    tail = size - 4;
    memset(data + size - 4, 0xFF, 4);
    nk = tail / 1024;
    left = tail & 1023;
    for (i = nk; i >= 2; i--) {
        if (i == nb && left) {
            n = left - 1;
            memcpy(data + i * 1024, data + i * 1024 + 1, n);
            tail -= 1;
        } else {
            n += 1023;
            memcpy(data + i * 1024, data + i * 1024 + 1, n);
            tail -= 1;
        }
    }
    memcpy(data + 512, data + 1024, tail + 1024);
    return tail - 512;
}

 */

const static char g_sec_msk[] = {
    0x53, 0x55, 0x56, 0x6D, 0x4E, 0x31, 0x78, 0x79, 0x4C, 0x52, 0x44, 0x50, 0x71, 0x76, 0x2B, 0x6E
};

static uint32_t fldr_sum(void *data, size_t size) {
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i < size; i += 4)
        sum += *((uint32_t *)(data + i));

    return sum;
}

int fldr_encode(const char *data, size_t size,
        const char *name, const char *key, const char *iv,
        char **out_data, size_t *out_size) {
    int i, nkb;
    size_t actual_size;
    size_t nbtr;
    char *buff;
    uint32_t sum;
    struct aes_key_st aes_key;
    char aes_iv[16];

    /*
     * data:
     *   IV: 16 bytes
     *   AESed Data(
     *    data:
     *     data:
     *      info: offset 0x200,24
     *                   0x220,240
     *      name: offset 0x400,8(DL50, etc)
     *      ...
     *      code(with nkb): offset 0x800
     *     sum: 4
     *     padding: 16(=0xffffffff) if sum == -1
     *    sum: 4
     *   )
     */
    actual_size = size;
    nkb = 2 + actual_size / 1024;
    size += nkb; // nkb
    if (size & 0x0F) {
        size |= 0x0F;
        size += 1;
    }
    *out_size = 0x10 + 0x800 + size + 0x10;
    *out_data = calloc(1, *out_size);
    if (!*out_data)
        return -1;
    // IV
    buff = *out_data;
    memset(aes_iv, 0, 16);
    if (iv)
        memcpy(aes_iv, iv, 16);
    for (i = 0; i < 16; i++)
        buff[i] = aes_iv[i] ^ g_sec_msk[i];
    // AESed DATA
    buff = *out_data + 0x10;
    // head: jump
    // entry is +#0x50
    // fixup_nkb moved code@+#0x400 by -#0x200
    // XXX: adjust moved code by -#0x50
    //      Y 306SH
    //      N SH-04F
    *((uint32_t *)(buff + 0x50)) = 0xEA00016A; // B +#0x5B0
    *((uint32_t *)(buff + 0xA0)) = 0xEA000156; // B +#0x560
    // head: name
    memcpy(buff + 0x400, name, 8);
    // head: info
    memset(buff + 0x200, 0, 24);
    for (i = 0; i < 15; i++) {
        *((uint32_t *)(buff + 0x220 + i * 32)) = ((uint32_t) 0x30303030) ^ *((uint32_t *)(buff + 0x400));
        *((uint32_t *)(buff + 0x224 + i * 32)) = ((uint32_t) 0x30303030) ^ *((uint32_t *)(buff + 0x404));
        *((uint32_t *)(buff + 0x238 + i * 32)) = (uint32_t) 0x69776574;
        *((uint32_t *)(buff + 0x23C + i * 32)) = (uint32_t) 0x65766F6C;
    }
    // nkb
    nbtr = 0;
    for (i = 2; i <= nkb; i++) {
        if (i == nkb) {
            size_t n = actual_size - nbtr;

            if (n) {
                memcpy(buff + i * 1024 + 1, data + nbtr, n);
                nbtr += n;
            }
        } else {
            memcpy(buff + i * 1024 + 1, data + nbtr, 1023);
            nbtr += 1023;
        }
    }
    for (i = nkb; i >= 2; i--)
        buff[i * 1024] = buff[i * 1022];
    // head: sum1 & sum2
    sum = fldr_sum(buff, 0x800 + size + 8);
    if (sum == (uint32_t) 0xffffffff)
        *((uint32_t *)(buff + 0x800 + size + 4)) = (uint32_t) 0x12345679;
    *((uint32_t *)(buff + 0x800 + size + 8)) = fldr_sum(buff, 0x800 + size + 8);
    *((uint32_t *)(buff + 0x800 + size + 12)) = fldr_sum(buff, 0x800 + size + 12);
    // AES
    AES_set_encrypt_key((const unsigned char *) key, 256, &aes_key);
    AES_cbc_encrypt(
            (const unsigned char *) buff,
            (unsigned char *) buff,
            0x800 + size + 0x10,
            &aes_key,
            (unsigned char *) aes_iv, AES_ENCRYPT);
    //
    return 0;
}


