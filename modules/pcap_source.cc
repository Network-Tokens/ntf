#include "pcap_source.h"
#include <algorithm>
#include <glog/logging.h>
#include <math.h>

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/stun.h"
#include "../utils/time.h"
#include "../utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using ntf::pb::PcapSourceArg;

static inline uint64_t Now() {
  return rdtsc() * 1e9 / tsc_hz;
}

const Commands PcapSource::cmds = {
  {"load", "PcapSourceArg", MODULE_CMD_FUNC(&PcapSource::CommandLoad), Command::THREAD_UNSAFE},
};

CommandResponse
PcapSource::Init(const PcapSourceArg &args) {
  return CommandLoad(args);
}

CommandResponse
PcapSource::CommandLoad(const PcapSourceArg &args) {
  if (pcap) {
    pcap_close(pcap);
    pcap = nullptr;
  }

  src_ip = args.src_ip();
  if (!ParseIpv4Address(src_ip, &src_addr)) {
    return CommandFailure(errno, "Invalid IP address: %s", src_ip.c_str());
  }

  reverse = args.reverse();

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap = pcap_open_offline(args.filename().c_str(), errbuf);
  if (!pcap) {
    return CommandFailure(errno, "Failed to open pcap: %s", errbuf);
  }

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    pcap_close(pcap);
    pcap = nullptr;
    return CommandFailure(ENOMEM, "Task creation failed");
  }
  start_ns = Now();
  first_packet_ns = 0;

  LOG(INFO) << "PcapSource::Init(): Success";
  return CommandSuccess();
}

void PcapSource::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const int cnt = batch->cnt();
  LOG(WARNING) << "ProcessBatch() Received batch with " << cnt << " packets";
  RunNextModule(ctx, batch);
};


const u_char *
PcapSource::LoadNextPacket() {
  // Try reading the next packet from the PCAP file
  while (pcap != nullptr) {
    const u_char* packet = pcap_next(pcap, &next_packet_hdr);
    if (!packet) {
      // No way to tell if this is the end of the file or if an error occurred.
      // Assume we're at the end of the file.
      pcap_close(pcap);
      pcap = nullptr;
      break;
    }

    if (!first_packet_ns) {
      first_packet_ns = next_packet_hdr.ts.tv_sec * 1e9 +
        next_packet_hdr.ts.tv_usec * 1000;
    }

    // const Ethernet *eth = reinterpret_cast<const Ethernet *>(packet);
    const Ipv4 *ip = reinterpret_cast<const Ipv4 *>(packet);
    if (!reverse) {
      if (ip->src == src_addr) {
        return packet;
      }
    } else {
      if (ip->dst == src_addr) {
        return packet;
      }
    }
  }
  return nullptr;
}

bess::Packet *
PcapSource::PrepareNextPacket() {
      // Allocate an empty packet from the packet pool
  bess::Packet *pkt = current_worker.packet_pool()->Alloc();
  if(!pkt) {
    LOG(WARNING) << "Failed to allocate new packet from pool";
    return nullptr;
  }

  char *ptr = pkt->buffer<char *>() + SNBUF_HEADROOM;
  int size = next_packet_hdr.caplen;
  int copy_len = std::min(size, static_cast<int>(pkt->tailroom()));

  pkt->set_data_off(SNBUF_HEADROOM);
  pkt->set_total_len(copy_len);
  pkt->set_data_len(copy_len);
  bess::utils::CopyInlined(ptr, next_packet, copy_len, true);

  size -= copy_len;
  if (size > 0) {
    LOG(WARNING) << "TODO: Packet needs segmented";
  }
  return pkt;
}

struct task_result PcapSource::RunTask(Context *ctx, bess::PacketBatch *batch,
                                       void *) {
  size_t total_bytes = 0;
  batch->clear();

  while(pcap != nullptr) {
    if (!next_packet) {
      next_packet = LoadNextPacket();
    }

    if (!next_packet) {
      // All done
      return { .block = true, .packets = 0, .bits = 0 };
    }

    const uint64_t now = Now();
    const uint64_t next_ts = (next_packet_hdr.ts.tv_sec * 1e9 + 
      next_packet_hdr.ts.tv_usec * 1000) - first_packet_ns + start_ns;

    if (next_ts < now) {
      bess::Packet* pkt = PrepareNextPacket();
      if(!pkt) {
        return { .block = true, .packets = 0, .bits = 0 };
      }

      batch->add(pkt);
      total_bytes += next_packet_hdr.caplen;
      next_packet = nullptr;
    } else {
      break;
    }
  }

  RunNextModule(ctx, batch);

  return {
      .block = (pcap == nullptr),
      .packets = (unsigned) batch->cnt(),
      .bits = total_bytes * 8,
  };
};

ADD_MODULE(PcapSource, "pcap_source", "A source that can replay a PCAP file")
