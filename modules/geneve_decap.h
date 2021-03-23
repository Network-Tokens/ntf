/*
 * License : Apache-2.0
 * Copyright(c) 2021 Selfie Networks, Inc
 */

#ifndef BESS_MODULES_GENEVE_DECAP_H_
#define BESS_MODULES_GENEVE_DECAP_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

/**
 * Sets the `decap_offset` attribute to the offset in the packet immediately
 * after the geneve header & variable-length geneve options.
 *
 * Geneve proxes requires the exact original header to be placed back before
 * returning the packet, and there is too much data to store in metadata
 * attributes.  To work around this and to eliminate the complexity of
 * re-encapsulating the headers, this module marks the offset of the inner
 * packet rather than decapsulating, so the orignal data can be left in place.
 *
 * All modules that operate on packet data within NTF honor `decap_offset`.
 */
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
