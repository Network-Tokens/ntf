#ifndef BESS_MODULES_REVERSEADDRESS_H_
#define BESS_MODULES_REVERSEADDRESS_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/endian.h"

#include "pb/revaddr_msg.pb.h"

static const size_t kMaxVariable = 16;

class ReverseAddress final : public Module {
public:
  ReverseAddress() : Module() {}

  CommandResponse Init(const bess::pb::EmptyArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
};

#endif // BESS_MODULES_REVERSEADDRESS_H_
