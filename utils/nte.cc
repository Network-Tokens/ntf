/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#include "nte.h"
#include <cjose/jwe.h>
#include <cjose/jwk.h>
#include <glog/logging.h>
#include <jansson.h>
#include <string.h>

extern "C" {

json_t * nte_decrypt(const char * token_buf, size_t token_buf_len,
                     const char * key_buf, size_t key_buf_len) {
  cjose_err error;
  cjose_jwe_t *jwe = cjose_jwe_import(token_buf, token_buf_len, &error);
  if(!jwe) {
    DLOG(WARNING) << "Failed to load JWE ( " << error.message << " )";
    return nullptr;
  }

  cjose_jwk_t *jwk = cjose_jwk_import(key_buf, key_buf_len, &error);
  if(!jwk) {
    DLOG(WARNING) << "Failed to load JWK ( " << error.message << " )";
    return nullptr;
  }

  size_t n_bytes = 0;
  uint8_t *output = cjose_jwe_decrypt(jwe, jwk, &n_bytes, &error);
  if (!output) {
    DLOG(WARNING) << "Failed to decrypt token ( " << error.message << " )";
    return nullptr;
  }

  json_error_t j_error;
  return json_incref(json_loadb((char*)output, n_bytes, 0, &j_error ));
}

} // extern "C"
