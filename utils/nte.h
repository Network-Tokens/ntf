/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#ifndef NTF_UTILS_NTE_H_
#define NTF_UTILS_NTE_H_

#include <cjose/header.h>

#ifdef __cplusplus
extern "C" {
#endif

json_t * nte_decrypt(const char * token_buf, const char * key_buf);

#ifdef __cplusplus
}
#endif

#endif // NTF_UTILS_NTE_H_
