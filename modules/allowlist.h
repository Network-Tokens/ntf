/*
 * License : Apache-2.0
 * Copyright(c) 2021 Selfie Networks, Inc
 */

#ifndef BESS_MODULES_ALLOWLIST_H_
#define BESS_MODULES_ALLOWLIST_H_

#include "module.h"
#include "utils/ip.h"
#include "utils/flow.h"
#include "pb/allowlist_msg.pb.h"


/**
 * Generic Allow-list.  Currently supports TCP4 and UDP4 protocols.
 *
 * The module has two input gates and two output gates and operates as follows.
 *
 * - Packets received via in-gate 0 are by default emitted on out-gate 0
 * - Packets received via in-gate 0 with a corresponding flow on the allow-list
 *   are emitted on out-gate 1
 * - Packets received via in-gate 1 are always emitted on out-gate 1 and the
 *   corresponding flow is added to the allow list
 *
 * TODO: Packets added to the allow-list will have the configured metadata
 * attributes saved in the flow table.  This means packets that arrive on
 * in-gate 0 that belong to a flow on the allow-list will be emitted on
 * out-gate 1 with the same metadata attributes attached, whether they have a
 * token attached or not.
 *
 * This module depends on the following metadata attributes:
 *
 * - decap_offset: look for packets at this offset (used in conjunction with
 *                 decapsulation modules like GeneveDecap)
 * - exp:          indicates absolute expiry time of the entry in the
 *                 allow-list
 */
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
