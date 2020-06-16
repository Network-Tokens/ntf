#ifndef BESS_MODULES_PCAP_SOURCE_H_
#define BESS_MODULES_PCAP_SOURCE_H_

#include "module.h"
#include <map>
#include <pcap/pcap.h>

#include "pb/pcap_source_msg.pb.h"
#include "utils/cuckoo_map.h"
#include "utils/endian.h"

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

  // Link type of pcap
  int link_type = DLT_RAW;

  // If false, we will send packets FROM src_ip.  If true, we will send packets
  // TO src_ip.
  bool reverse = false;

  // Address of the "client" in the pcap, used for determining which direciton
  // to send packets.
  std::string src_addr;

  // Same as src_addr but for IPv6
  std::string src_addr6;

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
