#ifndef BESS_MODULES_GENEVE_DECAP_H_
#define BESS_MODULES_GENEVE_DECAP_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

class GeneveDecap final : public Module {
public:
    static const gate_idx_t kNumOGates = 2;

    GeneveDecap() : Module() {}

    CommandResponse Init( const bess::pb::EmptyArg& );

    void ProcessBatch( Context* ctx, bess::PacketBatch* batch ) override;

private:
    int decap_offset_attr = -1;
};

#endif // BESS_MODULES_GENEVE_DECAP_H_
