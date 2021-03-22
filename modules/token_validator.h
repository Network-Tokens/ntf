#ifndef BESS_MODULES_TOKEN_VALIDATOR_H_
#define BESS_MODULES_TOKEN_VALIDATOR_H_

#include "../module.h"
#include "../pb/token_validator_msg.pb.h"


class TokenValidator final : public Module {
public:
    static const gate_idx_t kNumOGates = 3;

    TokenValidator() : Module() {}

    CommandResponse Init( const ntf::pb::TokenValidatorArg& );

    void ProcessBatch( Context* ctx, bess::PacketBatch* batch ) override;

private:
    int decap_offset_attr = -1;
    int bip_attr = -1;
    int exp_attr = -1;
};


#endif // BESS_MODULES_TOKEN_VALIDATOR_H_
