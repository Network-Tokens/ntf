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

#ifndef BESS_MODULES_PCAP_SOURCE_H_
#define BESS_MODULES_PCAP_SOURCE_H_

#include <map>

#include "module.h"
#include "pb/module_msg.pb.h"

#include "utils/cuckoo_map.h"
#include "utils/endian.h"
#include "pb/pcap_source.pb.h"
#include <pcap/pcap.h>

using bess::utils::be32_t;

class PcapSource final : public Module {
 public:
  static const Commands cmds;
  CommandResponse Init(const ntf::pb::PcapSourceArg &arg);
  CommandResponse CommandLoad(const ntf::pb::PcapSourceArg &arg);
  void ProcessBatch(Context*, bess::PacketBatch*) override;
  struct task_result RunTask(Context*, bess::PacketBatch*, void*);

 private:
  // Loads the next packet from the pcap file.  Populates next_packet_hdr.
  // Returns nullptr the end of the pcap has been reached.
  const u_char* LoadNextPacket();

  // Create a bess::Packet with the contents of the next outgoing packet
  bess::Packet* PrepareNextPacket();

  // Handle to pcap file
  pcap_t* pcap = nullptr;

  // Indicates who is the "client" in the pcap, used for determining which
  // direction to send packets.
  std::string src_ip;

  // If false, we will send packets FROM src_ip.  If true, we will send packets
  // TO src_ip.
  bool reverse = false;

  // Parsed address.  TODO: Support for IPv6.
  be32_t src_addr;

  // Pointer to raw data of next packet (from pcap file)
  const u_char* next_packet;

  // Information (such as timestamp) of the next packet
  pcap_pkthdr next_packet_hdr;

  // Time (relative to boot) when the pcap replay started in nanoseconds
  uint64_t start_ns;

  // Timestamp (POSIX) of the first packet in nanoseconds
  uint64_t first_packet_ns;
};

#endif // BESS_MODULES_PCAP_SOURCE_H_
