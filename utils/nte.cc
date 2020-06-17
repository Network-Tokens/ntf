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

json_t * nte_decrypt(const char * token_buf, const char * key_buf) {
  cjose_err error;
  size_t n_bytes;
  uint8_t * output;
  cjose_jwe_t * jwe;
  cjose_jwk_t * jwk;
  json_error_t j_error;

  jwe = cjose_jwe_import(token_buf, strlen(token_buf), &error);

  if(!jwe) {
    LOG(WARNING) << "Failed to load JWE ( " << error.message << " )";
    return nullptr;
  }

  jwk = cjose_jwk_import(key_buf, strlen(key_buf), &error);

  if(!jwk) {
    LOG(WARNING) << "Failed to load JWK ( " << error.message << " )";
    return nullptr;
  }

  output = cjose_jwe_decrypt(jwe, jwk, &n_bytes, &error);
  if (!output) {
    LOG(WARNING) << "Failed to decrypt token ( " << error.message << " )";
    return nullptr;
  }

  return json_incref(json_loadb((char*)output, n_bytes, 0, &j_error ));
}

} // extern "C"
