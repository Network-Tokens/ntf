// Copyright (c) 2014-2017, The Regents of the University of California.
// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef BESS_MODULES_NTF_H_
#define BESS_MODULES_NTF_H_

#include <map>

#include "module.h"
#include "pb/module_msg.pb.h"
//#include "pb/network_token_msg.pb.h"

#include "utils/cuckoo_map.h"
#include "utils/endian.h"

using bess::utils::be32_t;

/**
 * NTF detects network tokens in STUN messages,
 * and sets the appropriate DSCP marking. 
 */

struct NtfFlowEntry {
  uint64_t last_refresh; // in nanoseconds
};

struct NetworkToken {
  be32_t app_id;
  uint8_t * ciphertext;
};

struct FlowId {
  uint32_t src_addr;
  uint32_t dst_addr;

  uint8_t protocol;

  uint16_t src_tp;
  uint16_t dst_tp;
};

struct Flow {
  FlowId id;

  // hashes a FlowId
  struct Hash {
    // a similar method to boost's hash_combine in order to combine hashes
    inline void combine(std::size_t &hash, const unsigned int &val) const {
      std::hash<unsigned int> hasher;
      hash ^= hasher(val) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    }
    bess::utils::HashResult operator()(const FlowId &id) const {
      std::size_t hash = 0;
      combine(hash, id.src_addr);
      combine(hash, id.dst_addr);
      combine(hash, id.src_tp);
      combine(hash, id.dst_tp);
      combine(hash, (uint32_t)id.protocol);
      return hash;
    }
  };

  // to compare two FlowId for equality in a hash table
  struct EqualTo {
    bool operator()(const FlowId &id1, const FlowId &id2) const {
      bool ips = (id1.src_addr == id2.src_addr) && (id1.dst_addr == id2.dst_addr);
      bool ports =
          (id1.src_tp == id2.src_tp) && (id1.dst_tp == id2.dst_tp);
      return (ips && ports) && (id1.protocol == id2.protocol);
    }
  };
};   
  
class NTF final : public Module {
 public:
  enum Direction
  {
   kForward = 0,
   kReverse = 1,
  };
		  
  static const gate_idx_t kNumIGates = 2;
  static const gate_idx_t kNumOGates = 2;
  
  // static const Command cmds;
  
  CommandResponse Init(const bess::pb::EmptyArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  // NTF() : Module(), num_vars_(), vars_() {}


 private:
  // size_t num_vars_;
  // size_t vars_;
  using HashTable = bess::utils::CuckooMap<FlowId, uint64_t, Flow::Hash, Flow::EqualTo>;

  // 5 minutes for entry expiration
  static const uint64_t kTimeOutNs = 300ull * 1000 * 1000 * 1000;

  HashTable::Entry *CreateNewEntry(const Flow &flow, uint64_t now);

  template <Direction dir>
    void DoProcessBatch(Context *ctx, bess::PacketBatch *batch);

  NetworkToken * ExtractNetworkTokenFromPacket(bess::Packet *pkt);
  FlowId GetFlowId(bess::Packet *pkt);
  FlowId GetReverseFlowId(FlowId flow_id);
  void CheckPacketForNetworkToken(Context *ctx, bess::Packet *pkt);
  void ResetDscpMarking(bess::Packet *pkt);
  void SetDscpMarking(bess::Packet *pkt);


  HashTable map_;
  uint8_t kDSCP = 0;
  
};

#endif // BESS_MODULES_NTF_H_
