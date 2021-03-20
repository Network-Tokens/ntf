#include "allocator_context.h"
#include <cose/cose.h>
#include <cstring>


bool
DecryptToken_COSE( const uint8_t *     token_data,
                   size_t              token_length,
                   const std::string & shared_key )
{
    ntf::cose::AllocatorContext ctx;

    // Decode the encoded CBOR object into a COSE Encrypt0 message
    cose_errback err;
    int type = 0;
    auto token = (HCOSE_ENCRYPT) COSE_Decode( token_data, token_length, &type,
            COSE_encrypt_object, &ctx, &err);
    if( !token ) {
        return false;
    }

    // Decrypt the Encrypt0 message using a pre-shared key
    if( !COSE_Encrypt_decrypt( token, (uint8_t*) shared_key.data(),
                shared_key.size(), &err )) {
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
    return true;
}
