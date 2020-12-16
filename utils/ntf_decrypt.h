#ifndef _NTF_DECRYPT_H_
#define _NTF_DECRYPT_H_

#include <cjose/header.h>
#include <cjose/jwk.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * Decrypts a raw token using a key.  If the provided key was used to generate
 * the token and the token is valid, the payload is returned as a JSON object.
 * If the key or token are invalid, nullptr is returned.
 * \param token_buf Pointer to raw token data
 * \param token_bu_len The length of the buffer at token_buf
 * \param key Pointer to the JWK used to create the token
 * \return JSON object containing decrypted payload, or nullptr if the key or
 * token are invalid.
 */
json_t *
ntf_token_decrypt( const char *        token_buf,
                   size_t              token_buf_len,
                   const cjose_jwk_t * key );

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _NTF_DECRYPT_H_
