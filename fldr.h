
#ifndef _FLDR_H_
#define _FLDR_H_

#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define USB_VID 0x04dd
#define USB_PID 0x933a

#define FLDR_NAME_SIZE 8

#define FLDR_FLAG_SEND_SEC 0x00000001
#define FLDR_FLAG_HIGH_ADDR 0x00000002
#define FLDR_FLAG_DUMP 0x00000004

int fldr_init();
void fldr_free();
void *fldr_open();
int fldr_close(void *);
size_t fldr_read(void *h, char *buff, size_t size);
size_t fldr_write(void *h, const char *buff, size_t size);
int fldr_get_name(void *h, char *out);
uint32_t fldr_boot(void *h, const char *data, size_t size, int flags);
uint32_t fldr_boot_recv(const char *data, size_t size, const char *secrec);

#ifdef __cplusplus
}
#endif

#endif

