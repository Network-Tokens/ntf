#include "pcap_source.h"
#include <algorithm>
#include <arpa/inet.h>
#include <glog/logging.h>
#include <math.h>
#include <netinet/in.h>

#include "utils/ether.h"
#include "utils/ip.h"
#include "utils/stun.h"
#include "utils/time.h"
#include "utils/udp.h"

using namespace bess::utils;
using ntf::pb::PcapSourceArg;

const Commands PcapSource::cmds = {
  { "load", "PcapSourceArg",
     MODULE_CMD_FUNC(&PcapSource::CommandLoad), Command::THREAD_UNSAFE },
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

  // First try parsing as IPv4
  for(const auto& src_ip : args.src_ip()) {
    be32_t addr;
    if (ParseIpv4Address(src_ip, &addr)) {
      const char *data = reinterpret_cast<const char *>(&addr);
      src_addr = std::string(data, sizeof(addr));
    } else {
      // ... then IPv6
      struct in6_addr addr6;
      if (inet_pton(AF_INET6, src_ip.c_str(), &addr6) == 1) {
        const char *data = reinterpret_cast<const char*>(addr6.s6_addr);
        src_addr6 = std::string(data, sizeof(addr6.s6_addr));
      } else {
        return CommandFailure(errno, "Invalid IP address: %s", src_ip.c_str());
      }
    }
  }

  reverse = args.reverse();

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap = pcap_open_offline(args.filename().c_str(), errbuf);
  if (!pcap) {
    return CommandFailure(errno, "Failed to open pcap: %s", errbuf);
  }

  link_type = pcap_datalink(pcap);
  switch (link_type) {
  case DLT_EN10MB:
  case DLT_RAW:
    break;
  default:
    pcap_close(pcap);
    pcap = nullptr;
    return CommandFailure(EINVAL, "Invalid link type: %s",
        pcap_datalink_val_to_name(link_type));
  }

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    pcap_close(pcap);
    pcap = nullptr;
    return CommandFailure(ENOMEM, "Task creation failed");
  }

  start_ns = 0;
  first_packet_ns = 0;

  LOG(INFO) << "PcapSource::Load(): Loaded " << args.filename() << ", "
               "link_type: " << pcap_datalink_val_to_name(link_type);
  return CommandSuccess();
}

void PcapSource::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const int cnt = batch->cnt();
  DLOG(WARNING) << "ProcessBatch() Received batch with " << cnt << " packets";
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

    size_t ip_offset = 0;
    switch (link_type) {
    case DLT_RAW:
      break;
    case DLT_EN10MB:
      ip_offset = sizeof(Ethernet);
      break;
    }

    bool matches = false;
    const u_char* ip_start = packet + ip_offset;

    const Ipv4 *ip = reinterpret_cast<const Ipv4 *>(ip_start);
    if (ip->version == 4 && src_addr.size() == 4) {
      const u_char* addr = ip_start + (reverse ? 16 : 12);
      matches = (0 == memcmp(addr, src_addr.data(), src_addr.size()));
    } else if (ip->version == 6 && src_addr6.size() == 16) {
      const u_char* addr = ip_start + (reverse ? 24 : 8);
      matches = (0 == memcmp(addr, src_addr6.data(), src_addr6.size()));
    }

    if (matches) {
      return packet;
    }
  }
  return nullptr;
}

bess::Packet *
PcapSource::PrepareNextPacket() {
  // Allocate an empty packet from the packet pool
  bess::Packet *pkt = current_worker.packet_pool()->Alloc();
  if(!pkt) {
    DLOG(WARNING) << "Failed to allocate new packet from pool";
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
    DLOG(WARNING) << "TODO: sending packets too fast...";
  }
  return pkt;
}

struct task_result PcapSource::RunTask(Context *ctx, bess::PacketBatch *batch,
                                       void *) {
  size_t total_bytes = 0;
  batch->clear();

  if (unlikely(start_ns == 0)) {
    start_ns = ctx->current_ns;
  }

  while(pcap != nullptr) {
    // Load the next packet if it's not already loaded.  It might already be
    // loaded if we did it last cycle but it was not time to send yet.
    if (!next_packet) {
      next_packet = LoadNextPacket();
    }

    // If next_packet is null at this point, we have reached the end of the
    // trace.
    if (!next_packet) {
      return { .block = true, .packets = 0, .bits = 0 };
    }

    const uint64_t now = ctx->current_ns;
    const uint64_t next_ts = (next_packet_hdr.ts.tv_sec * 1e9 + 
      next_packet_hdr.ts.tv_usec * 1000) - first_packet_ns + start_ns;

    if (next_ts > now) {
      // We have caught up to where we should be.
      break;
    }

    bess::Packet* pkt = PrepareNextPacket();
    if(!pkt) {
      // Packet allocation failed - this shouldn't happen, so stop sending.
      return { .block = true, .packets = 0, .bits = 0 };
    }

    batch->add(pkt);
    total_bytes += next_packet_hdr.caplen;
    next_packet = nullptr;
  }

  // Pass any allocated packets to the next module.  It is possible that batch
  // may contain no packets.
  RunNextModule(ctx, batch);

  return {
      .block = (pcap == nullptr),
      .packets = (unsigned) batch->cnt(),
      .bits = total_bytes * 8,
  };
};

ADD_MODULE(PcapSource, "pcap_source", "A source that can replay a PCAP file")
