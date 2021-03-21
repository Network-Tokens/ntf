#include "allocator_context.h"
#include "utils/decrypt.h"
#include "utils/endian.h"

#include <arpa/inet.h>
#include <cose/cose.h>
#include <cstring>
#include <string>
#include <vector>


using bess::Packet;
using bess::utils::be32_t;
using namespace ntf::pb;
using namespace std;


namespace ntf::cose {

void *
DecodeToken( const uint8_t *     token_data,
             size_t              token_length,
             const string &      shared_key,
             AllocatorContext &  ctx )
{
    // Decode the encoded CBOR object into a COSE Encrypt0 message
    cose_errback err;
    int type = 0;
    auto token = (HCOSE_ENCRYPT) COSE_Decode( token_data, token_length, &type,
            COSE_encrypt_object, &ctx, &err);
    if( !token ) {
        return nullptr;
    }

    // Decrypt the Encrypt0 message using a pre-shared key
    if( !COSE_Encrypt_decrypt( token, (uint8_t*) shared_key.data(),
                shared_key.size(), &err )) {
        return nullptr;
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
    return cn_cbor_decode( data, len, &ctx, &cn_err );
}


bool
ExtractMetadata( void *                payload,
                 const vector<Field> & fields,
                 Packet *              pkt,
                 Module *              module )
{
    cn_cbor * cbor = reinterpret_cast<cn_cbor *>( payload );

    for( const auto & field : fields ) {
        auto item = cn_cbor_mapget_string( cbor, field.name.c_str() );
        if( !item ) {
            LOG(INFO) << "Failed to extract metadata: no field named " << field.name;
            return false;
        }

        switch( item->type ) {
        case CN_CBOR_TEXT:
            if( field.type == TokenField::IPV4 ) {
                string ip( item->v.str, item->length );
                struct in_addr addr;
                if( inet_aton( ip.c_str(), &addr ) ) {
                    // NOTE: This is stored in network byte order
                    set_attr<uint32_t>( module, field.attr_id, pkt, addr.s_addr );
                    continue;
                }
            }
            return false;
        case CN_CBOR_UINT:
            if( field.type == TokenField::INT ) {
                set_attr<uint64_t>( module, field.attr_id, pkt, item->v.uint );
                continue;
            }
            return false;
        default:
            LOG(INFO) << "Failed to extract metadata: unhandled type";
            return false;
        }
    }

    return true;
}

} // namespace ntf::cose
