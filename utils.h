
#ifndef _UTILS_H_
#define _UTILS_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void dump(const char *head, const void *data, size_t size);
int file_read(const char *path, char **data, size_t *size);
int file_write(const char *path, const char *data, size_t size);
int imei_parse_qcom(const char *data, char *imei);

#ifdef __cplusplus
}
#endif

#endif

