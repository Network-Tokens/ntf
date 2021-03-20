#ifndef BESS_MODULES_GENEVE_RETURN_H_
#define BESS_MODULES_GENEVE_RETURN_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

class GeneveReturn final : public Module {
public:
    GeneveReturn() : Module() {}

    CommandResponse Init( const bess::pb::EmptyArg& );

    void ProcessBatch( Context* ctx, bess::PacketBatch* batch ) override;
};

#endif // BESS_MODULES_GENEVE_RETURN_H_
