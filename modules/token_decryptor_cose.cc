#include "token_decryptor.h"
#include "../utils/allocator_context.h"
#include <cose/cose.h>


bool
TokenDecryptor::DecryptToken_COSE( const uint8_t * token_data,
                                   size_t          token_length )
{
    ntf::cose::AllocatorContext ctx;

    // Decode the encoded CBOR object into a COSE Encrypt0 message
    cose_errback err;
    int type = 0;
    auto token = (HCOSE_ENCRYPT) COSE_Decode( token_data, token_length, &type,
            COSE_encrypt_object, &ctx, &err);
    if( !token ) {
        LOG(INFO) << "Failed to load token: " << (int) err.err;
        return false;
    }

    // Decrypt the Encrypt0 message using a pre-shared key
    if( !COSE_Encrypt_decrypt( token, (uint8_t*) shared_key.data(),
                shared_key.size(), &err )) {
        LOG(INFO) << "Failed to decrypt token: " << (int) err.err;
        return false;
    }

    // Extract the decrypted payload.
    size_t len;
    const uint8_t * data = COSE_Encrypt_GetContent( token, &len, &err );
    if( data && !len ) {
        // NOTE: There is a bug in cose-c in which it returns the correct data
        // but the length is 0.  It just so happens that the data is
        // null-terminated, so we can use strlen.  This is probably unsafe and
        // we should file a bug.
        len = strlen( (char*) data );
    }

    // Decode the decrypted payload
    cn_cbor_errback cn_err;
    cn_cbor * cbor = cn_cbor_decode( data, len, &ctx, &cn_err );
    if( !cbor ) {
        LOG(INFO) << "Failed to decode decrypted payload: " << (int) cn_err.err;
        return false;
    }

    // Get the handles to the fields
    auto bip = cn_cbor_mapget_string( cbor, "bip" );
    auto sid = cn_cbor_mapget_string( cbor, "sid" );
    auto exp = cn_cbor_mapget_string( cbor, "exp" );

    // Quick validation...
    if( 
        bip->type != CN_CBOR_TEXT
     || sid->type != CN_CBOR_UINT
     || exp->type != CN_CBOR_UINT
    ) {
        return false;
    }

    // Output payload content
    LOG(INFO) << "bip: " << std::string( bip->v.str, bip->length );
    LOG(INFO) << "sid: " << sid->v.uint;
    LOG(INFO) << "exp: " << exp->v.uint;
    return true;
}
