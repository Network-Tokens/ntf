#include "token_decryptor.h"

#include "utils/ether.h"
#include "utils/ip.h"

using bess::utils::be32_t;

CommandResponse
TokenDecryptor::Init( const ntf::pb::TokenDecryptorArg & )
{
  return CommandSuccess();
}

void
TokenDecryptor::ProcessBatch( Context *ctx, bess::PacketBatch *batch ) {
  RunNextModule(ctx, batch);
}

ADD_MODULE( TokenDecryptor, "token_decryptor",
            "Decrypts a token found by TokenDetector & extract metadata" )
