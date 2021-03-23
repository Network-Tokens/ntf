/*
 * License : Apache-2.0
 * Copyright(c) 2021 Selfie Networks, Inc
 */

#ifndef BESS_MODULES_HEALTHCHECKRESPONDER_H_
#define BESS_MODULES_HEALTHCHECKRESPONDER_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/endian.h"

#include "pb/hcresponder_msg.pb.h"

static const size_t kMaxVariable = 16;

/**
 * A simple TCP healthcheck responder.
 *
 * If the incoming packet is a TCP SYN, the packet will be changed to a TCP
 * SYN-ACK addressed to the sender.  All other packets are dropped.  This
 * allows the pipeline to respond directly to a healthcheck mechanism from
 * within DPDK.
 */
class HealthcheckResponder final : public Module {
public:
  HealthcheckResponder() : Module() {}

  CommandResponse Init(const bess::pb::EmptyArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
};

#endif // BESS_MODULES_HEALTHCHECKRESPONDER_H_
