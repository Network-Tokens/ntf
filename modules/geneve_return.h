/*
 * License : Apache-2.0
 * Copyright(c) 2021 Selfie Networks, Inc
 */

#ifndef BESS_MODULES_GENEVE_RETURN_H_
#define BESS_MODULES_GENEVE_RETURN_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

/**
 * Prepares a packet to be returned over the Geneve proxy.
 *
 * This module reverses the outer IP address, decreases the TTL, updates the
 * checksum and reverses MAC addresses on the original packet so that it can be
 * returned.
 */
class GeneveReturn final : public Module {
public:
    GeneveReturn() : Module() {}

    CommandResponse Init( const bess::pb::EmptyArg& );

    void ProcessBatch( Context* ctx, bess::PacketBatch* batch ) override;
};

#endif // BESS_MODULES_GENEVE_RETURN_H_
