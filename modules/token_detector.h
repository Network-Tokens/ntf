#ifndef BESS_MODULES_TOKEN_DETECTOR_H_
#define BESS_MODULES_TOKEN_DETECTOR_H_

#include "../module.h"
#include "../pb/token_detector_msg.pb.h"


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
