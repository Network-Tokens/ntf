#ifndef _NTF_UTILS_DECRYPT_H_
#define _NTF_UTILS_DECRYPT_H_

#include "modules/token_decryptor.h"
#include "packet.h"
#include "module.h"


namespace ntf::cose {

void *
DecodeToken( const uint8_t *     token_data,
             size_t              token_length,
             const std::string&  shared_key,
             AllocatorContext &  ctx );

bool
ExtractMetadata( void *                     payload,
                 const std::vector<Field> & fields,
                 bess::Packet *             pkt,
                 Module *                   module );

}

#endif // _NTF_UTILS_DECRYPT_H_
