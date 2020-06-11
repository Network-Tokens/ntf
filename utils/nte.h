#ifndef NTF_UTILS_NTE_H_
#define NTF_UTILS_NTE_H_

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <jose/b64.h>
#include <jose/jwe.h>
#ifdef __cplusplus
}
#endif
#include <string.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

json_t * nte_decrypt(const char * token_buf, const char * key_buf);

#ifdef __cplusplus
}
#endif

#endif // NTF_UTILS_NTE_H_
