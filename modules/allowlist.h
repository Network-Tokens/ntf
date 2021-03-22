#ifndef BESS_MODULES_ALLOWLIST_H_
#define BESS_MODULES_ALLOWLIST_H_

#include "module.h"
#include "utils/ip.h"
#include "utils/flow.h"
#include "pb/allowlist_msg.pb.h"


class AllowList final : public Module {
public:
    static const gate_idx_t kNumIGates = 2;
    static const gate_idx_t kNumOGates = 2;

    AllowList() : Module() {}

    CommandResponse Init( const ntf::pb::AllowListArg& );

    void ProcessBatch( Context* ctx, bess::PacketBatch* batch ) override;

private:
    std::string GetDesc() const override;

    void AddAllowList( const bess::Packet * pkt,
                       const bess::utils::Ipv4 * );

    bool CheckAllowList( const bess::Packet * pkt,
                         const bess::utils::Ipv4 *,
                         uint64_t now );

    int decap_offset_attr = -1;
    int exp_attr = -1;

    uint32_t default_lifetime = 60;
    bool add_reverse_flow = false;

    FlowMap flows;
};


#endif // BESS_MODULES_ALLOWLIST_H_
