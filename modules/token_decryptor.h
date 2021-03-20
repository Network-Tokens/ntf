#ifndef BESS_MODULES_TOKEN_DECRYPTOR_H_
#define BESS_MODULES_TOKEN_DECRYPTOR_H_

#include "../module.h"
#include "../pb/token_decryptor_msg.pb.h"
#include <string>


class TokenDecryptor final : public Module {
public:
    static const gate_idx_t kNumOGates = 2;

    TokenDecryptor() : Module() {}

    CommandResponse Init( const ntf::pb::TokenDecryptorArg& );

    void ProcessBatch( Context* ctx, bess::PacketBatch* batch ) override;

private:
    bool DecryptToken_COSE( const uint8_t * token_data,
                            size_t          token_length );

    int token_offset_attr = -1;
    int token_length_attr = -1;

    std::string shared_key;
};

#endif // BESS_MODULES_TOKEN_DECRYPTOR_H_
