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

  if (!OpenPcap(TEMP_PCAP)) {
    return CommandFailure(errno, "Failed to open pcap");
  }

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "Task creation failed");
  }

  LOG(INFO) << "PcapSource::Init(): Success";
  return CommandSuccess();
}

bool
PcapSource::OpenPcap(const std::string& filename) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap = pcap_open_offline(filename.c_str(), errbuf);
  return pcap != nullptr;
}

void PcapSource::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const int cnt = batch->cnt();
  LOG(WARNING) << "ProcessBatch() Received batch with " << cnt << " packets";
  RunNextModule(ctx, batch);
};

struct task_result PcapSource::RunTask(Context *ctx, bess::PacketBatch *batch,
                                       void *) {
  const int cnt = batch->cnt();
  batch->clear();
  LOG(WARNING) << "RunTask() Received batch with " << cnt << " packets";

  // Try reading the next packet from the PCAP file
  pcap_pkthdr header;
  const u_char* packet = pcap_next(pcap, &header);
  if (!packet) {
    // No way to tell if this is the end of the file or if an error occurred.
    // Assume we're at the end of the file.
    pcap_close(pcap);
    pcap = nullptr;

    if(!OpenPcap(TEMP_PCAP)) {
      return {
        .block = true,
        .packets = 0,
        .bits = 0,
      };
    }
    packet = pcap_next(pcap, &header);
  }

  // Allocate an empty packet from the packet pool
  bess::Packet* pkt = current_worker.packet_pool()->Alloc();
  if(!pkt) {
    LOG(WARNING) << "Failed to allocate new packet from pool";
    return {
      .block = true,
      .packets = 0,
      .bits = 0,
    };
  }

  char *ptr = pkt->buffer<char *>() + SNBUF_HEADROOM;
  int size = header.caplen;
  int copy_len = std::min(size, static_cast<int>(pkt->tailroom()));

  pkt->set_data_off(SNBUF_HEADROOM);
  pkt->set_total_len(copy_len);
  pkt->set_data_len(copy_len);
  bess::utils::CopyInlined(ptr, packet, copy_len, true);

  size -= copy_len;
  if (size > 0) {
    LOG(WARNING) << "TODO: Packet needs segmented";
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
