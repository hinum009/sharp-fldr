
#ifndef _ENCDEC_H_
#define _ENCDEC_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int fldr_encode(const char *data, size_t size,
        const char *name, const char *key, const char *iv,
        char **out_data, size_t *out_size);

#ifdef __cplusplus
}
#endif

#endif

