#ifndef BESS_MODULES_HEALTHCHECKRESPONDER_H_
#define BESS_MODULES_HEALTHCHECKRESPONDER_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/endian.h"

#include "pb/hcresponder_msg.pb.h"

static const size_t kMaxVariable = 16;

class HealthcheckResponder final : public Module {
public:
  HealthcheckResponder() : Module() {}

  CommandResponse Init(const bess::pb::EmptyArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
};

#endif // BESS_MODULES_HEALTHCHECKRESPONDER_H_