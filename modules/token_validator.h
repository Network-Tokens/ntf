/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#ifndef BESS_MODULES_TOKEN_VALIDATOR_H_
#define BESS_MODULES_TOKEN_VALIDATOR_H_

#include "../module.h"
#include "../pb/token_validator_msg.pb.h"


/**
 * Validates a decrypted network token applying policy.
 *
 * The token validator ensures that the token's bound IP address matches either
 * the source or destination of the packet starting at decap_offset, and
 * ensures the expiration time is still valid.
 *
 * Packets containing tokens that are not valid are emitted on out-gate 0.
 * If the token is valid, the packet is emitted on out-gate 1 if the token
 * granularity is set to `packet`.
 *
 * Additional attributes can be captured via the `fields` parameter when
 * initializing the module.  This allows for capturing other fields of
 * interest, like `sid`, which can be used by other modules to apply policy.
 *
 * TODO:  If the granularity is set to `flow`, the packets are emitted on
 * out-gate 2, facilitating flow-based tokens/allow-listing.
 *
 * This module depends on the following metadata attributes:
 *
 * - decap_offset: location of the inner packet (used to validate `bip`)
 * - bip:          the IP address the network token is bound to
 * - exp:          indicates absolute expiry time of the token
 */
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
