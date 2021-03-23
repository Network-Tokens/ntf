/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#ifndef BESS_MODULES_TOKEN_DETECTOR_H_
#define BESS_MODULES_TOKEN_DETECTOR_H_

#include "../module.h"
#include "../pb/token_detector_msg.pb.h"


/**
 * Detects a network token within a packet.
 *
 * The token detector can currently detect network tokens inside a Geneve
 * option, indicated by the appropriate Geneve option class & type.
 *
 * The metadata attributes used by this module are:
 *
 * - decap_offset: look for tokens in packets at this offset
 *
 * Currently the token detector is limited to Geneve options only.  This will
 * be extended to support STUN attributes and IPv6 extension headers.
 */
class TokenDetector final : public Module {
public:
    static const gate_idx_t kNumOGates = 2;

    TokenDetector() : Module() {}

    CommandResponse Init( const ntf::pb::TokenDetectorArg& );

    void ProcessBatch( Context* ctx, bess::PacketBatch* batch ) override;

private:
    int decap_offset_attr = -1;
    int token_offset_attr = -1;
    int token_length_attr = -1;

    ntf::pb::TokenDetectorArg::TokenInsert token_insert;

    uint16_t geneve_option_class;

    uint8_t geneve_option_type;
};

#endif // BESS_MODULES_TOKEN_DETECTOR_H_
