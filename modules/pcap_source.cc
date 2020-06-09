#include "pcap_source.h"
#include <glog/logging.h>
#include <math.h>
#include <algorithm>

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/stun.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;

static const std::string TEMP_PCAP = "/opt/ntf/JitsiMeetCall.pcap";

CommandResponse
PcapSource::Init(const bess::pb::EmptyArg &) {
  if (pcap) {
    return CommandFailure(EINVAL, "PcapSource already initialized");
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap = pcap_open_offline(TEMP_PCAP.c_str(), errbuf);
  if (!pcap) {
    return CommandFailure(errno, "Failed to open pcap: %s", errbuf);
  }

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "Task creation failed");
  }

  DLOG(INFO) << "PcapSource::Init(): Success";
  return CommandSuccess();
}

void PcapSource::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const int cnt = batch->cnt();
  DLOG(WARNING) << "ProcessBatch() Received batch with " << cnt << " packets";
  RunNextModule(ctx, batch);
};

struct task_result PcapSource::RunTask(Context *ctx, bess::PacketBatch *batch,
                                       void *) {
  const int cnt = batch->cnt();
  DLOG(WARNING) << "RunTask() Received batch with " << cnt << " packets";

  // Try reading the next packet from the PCAP file
  pcap_pkthdr header;
  const u_char* packet = pcap_next(pcap, &header);
  if (!packet) {
    // No way to tell if this is the end of the file or if an error occurred.
    // Assume we're at the end of the file.
    return {
      .block = true,
      .packets = 0,
      .bits = 0,
    };
  }

  // Allocate an empty packet from the packet pool
  bess::Packet* pkt = current_worker.packet_pool()->Alloc();
  if(!pkt) {
    DLOG(WARNING) << "Failed to allocate new packet from pool";
    return {
      .block = true,
      .packets = 0,
      .bits = 0,
    };
  }

  char *p = pkt->buffer<char *>() + SNBUF_HEADROOM;
  Ethernet *eth = reinterpret_cast<Ethernet *>(p);
  const int ethernet_head_room = sizeof(Ethernet);

  // Shouldn't matter if it's IPv6, the packet starts at the same offset.
  Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
  char *offset = reinterpret_cast<char*>(ip);

  int size = header.caplen;

  pkt->set_data_off(SNBUF_HEADROOM);
  pkt->set_total_len(size + ethernet_head_room);
  pkt->set_data_len(size + ethernet_head_room);
  bess::utils::Copy(offset, packet, size, true);

  int copy_len = std::min(size, static_cast<int>(pkt->tailroom()));
  size -= copy_len;

  if (size > 0) {
    DLOG(WARNING) << "TODO: Packet needs segmented";
  }

  batch->add(pkt);

  RunNextModule(ctx, batch);

  return {
      .block = false,
      .packets = 1,
      .bits = header.caplen * 8,
  };
};

ADD_MODULE(PcapSource, "pcap_source", "A source that can replay a PCAP file")
