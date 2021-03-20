#ifndef BESS_MODULES_TOKEN_DECRYPTOR_H_
#define BESS_MODULES_TOKEN_DECRYPTOR_H_

#include "../module.h"
#include "../pb/token_decryptor_msg.pb.h"

class TokenDecryptor final : public Module {
public:
    static const gate_idx_t kNumOGates = 2;

    TokenDecryptor() : Module() {}

    CommandResponse Init( const ntf::pb::TokenDecryptorArg& );

    void ProcessBatch( Context* ctx, bess::PacketBatch* batch ) override;
};

#endif // BESS_MODULES_TOKEN_DECRYPTOR_H_
