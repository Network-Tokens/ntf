#include "pcap_source.h"
#include <glog/logging.h>
#include <math.h>
#include <algorithm>

#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/stun.h"

static const std::string TEMP_PCAP = "/opt/ntf/JitsiMeetCall.pcap";

CommandResponse
PcapSource::Init(const bess::pb::EmptyArg &) {
  if (pcap) {
    return CommandResponse(EINVAL, "PcapSource already initialized");
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap = pcap_open_offline(TEMP_PCAP.c_str(), errbuf);
  if (!pcap) {
    return CommandFailure(errno, errbuf);
  }

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "Task creation failed");
  }

  return CommandSuccess();
}

void PcapSource::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  DLOG(WARNING) << "ProcessBatch() Received batch with " << cnt << " packets";
  RunNextModule(ctx, batch);
};

struct task_result PcapSource::RunTask(Context *ctx, bess::PacketBatch *batch,
                                       void *) {
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
    return CommandFailure(ENOMEM, "Failed to allocate packet");
  }

  // Copy the packet data from the PCAP into the new packet
  int caplen = header.caplen;
  int copy_len = std::min(caplen, static_cast<int>(pkt->tailroom()));
  bess::utils::CopyInlined(pkt->append(copy_len), packet, copy_len, true);

  int nb_segs = 1;
  packet += copy_len;
  caplen -= copy_len;
  bess::Packet* m = pkt;

  // If the PCAP packet is larger than the packet size we were allocated,
  // segment the rest of the packet & add this too
  while (caplen > 0) {
    m->set_next(current_worker.packet_pool()->Alloc());
    m = m->next();
    nb_segs++;

    copy_len = std::min(caplen, static_cast<int>(m->tailroom()));
    bess::utils::Copy(m->append(copy_len), packet, copy_len, true);

    packet += copy_len;
    caplen -= copy_len;
  }
  pkt->set_nb_segs(nb_segs);

  RunNextModule(ctx, batch);

  return {
      .block = true,
      .packets = 1,
      .bits = header.caplen * 8,
  };
};

ADD_MODULE(NTF, "pcap_source", "A source that can replay a PCAP file")
