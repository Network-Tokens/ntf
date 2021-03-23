/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#ifndef BESS_MODULES_REVERSEADDRESS_H_
#define BESS_MODULES_REVERSEADDRESS_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/endian.h"

#include "pb/revaddr_msg.pb.h"

static const size_t kMaxVariable = 16;

/**
 * Reverses the Ethernet & IP addresses of incoming packets, but not their
 * ports.
 *
 * The Geneve protocol wants packets destined to 6081.  Packets going the other
 * direction should use the original source & destination port.  The existing
 * BESS module IPSwap cannot be used for this because it also swaps the ports.
 */
class ReverseAddress final : public Module {
public:
  ReverseAddress() : Module() {}

  CommandResponse Init(const bess::pb::EmptyArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
};

#endif // BESS_MODULES_REVERSEADDRESS_H_
