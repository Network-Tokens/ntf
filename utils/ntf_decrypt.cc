/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#include "ntf_api.h"
#include <cjose/cjose.h>
#include <cjose/jwe.h>
#include <cjose/jwk.h>
#include <glog/logging.h>
#include <jansson.h>

#undef DLOG
#define DLOG LOG


extern "C" json_t *
ntf_token_decrypt( const char *        token_buf,
                   size_t              token_buf_len,
                   const cjose_jwk_t * jwk )
{
    json_t *ret( nullptr );
    cjose_jwe_t *jwe( nullptr );

    do {
        cjose_err error;
        jwe = cjose_jwe_import(token_buf, token_buf_len, &error);
        if(!jwe) {
            DLOG(WARNING) << "Failed to load JWE ( " << error.message << " )";
            break;
        }

        size_t n_bytes = 0;
        uint8_t *output = cjose_jwe_decrypt(jwe, jwk, &n_bytes, &error);
        if (!output) {
            DLOG(WARNING) << "Failed to decrypt token ( " << error.message << " )";
            break;
        }

        json_error_t j_error;
        ret = json_loadb((char*)output, n_bytes, 0, &j_error );
        cjose_get_dealloc()( output );
    } while(0);

    if(jwe) {
        cjose_jwe_release(jwe);
    }

    return ret;
}
