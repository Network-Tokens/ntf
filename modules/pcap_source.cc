/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#include "pcap_source.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cmath>
#include <glog/logging.h>
#include <netinet/in.h>

#include "utils/ether.h"
#include "utils/ip.h"
#include "utils/stun.h"
#include "utils/time.h"
#include "utils/udp.h"

using namespace bess::utils;
using ntf::pb::PcapSourceArg;

const Commands PcapSource::cmds = {
    { "load", "PcapSourceArg", MODULE_CMD_FUNC(&PcapSource::CommandLoad), Command::THREAD_UNSAFE },
};

CommandResponse
PcapSource::Init(const PcapSourceArg &args) {
    return CommandLoad(args);
}

static bool
TryParseAddress( const std::string& ip,
                 std::string& ip4_out,
                 std::string& ip6_out )
{
    // First try parsing as IPv4
    be32_t addr;
    if (ParseIpv4Address(ip, &addr)) {
        const char *data = reinterpret_cast<const char *>(&addr);
        ip4_out = std::string(data, sizeof(addr));
        return true;
    }

    // ... then IPv6
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
        const char *data = reinterpret_cast<const char*>(addr6.s6_addr);
        ip6_out = std::string(data, sizeof(addr6.s6_addr));
    }

    return false;
}

CommandResponse
PcapSource::CommandLoad(const PcapSourceArg &args) {
    if (pcap) {
        pcap_close(pcap);
        pcap = nullptr;
    }

    reverse = args.reverse();

    for(const auto& src_ip : args.src_ip()) {
        if( !TryParseAddress( src_ip, src_addr, src_addr6 ) ) {
            return CommandFailure(errno, "Invalid IP address: %s", src_ip.c_str());
        }
    }

    for(const auto& rewrite_src : args.rewrite_src()) {
        if( !TryParseAddress( rewrite_src, rewrite_src_addr, rewrite_src_addr6 ) ) {
            return CommandFailure(errno, "Invalid IP address: %s", rewrite_src.c_str());
        }
        rewrite_any = true;
    }

    for(const auto& rewrite_dst : args.rewrite_dst()) {
        if( !TryParseAddress( rewrite_dst, rewrite_dst_addr, rewrite_dst_addr6 ) ) {
            return CommandFailure(errno, "Invalid IP address: %s", rewrite_dst.c_str());
        }
        rewrite_any = true;
    }

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
            // No way to tell if this is the end of the file or if an error
            // occurred.  Assume we're at the end of the file.
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

    // Check to see if we should rewrite the source and/or destination address
    if (rewrite_any) {
        size_t offset = 0;
        Ethernet *eth = (Ethernet*)( ptr + offset );
        if (eth->ether_type.value() == Ethernet::Type::kIpv4) {
            offset += sizeof(Ethernet);
        }

        Ipv4 *ip = (Ipv4*)( ptr + offset );
        if (ip->version == 4) {
            const size_t SRC_OFFSET = 12;
            const size_t DST_OFFSET = 16;
            char* addr = ptr + offset + SRC_OFFSET;
            char* other_addr = ptr + offset + DST_OFFSET;
            if (reverse) {
                std::swap( addr, other_addr );
            }
            if (0 == memcmp(addr, src_addr.data(), src_addr.size())) {
                if (rewrite_src_addr.size()) {
                    memcpy(addr, rewrite_src_addr.data(), rewrite_src_addr.size());
                }
                if (rewrite_dst_addr.size()) {
                    memcpy(other_addr, rewrite_dst_addr.data(), rewrite_dst_addr.size());
                }
            }
        }
        else if (ip->version == 6) {
            const size_t SRC_OFFSET = 8;
            const size_t DST_OFFSET = 24;
            char* addr6 = ptr + offset + SRC_OFFSET;
            char* other_addr6 = ptr + offset + DST_OFFSET;
            if (reverse) {
                std::swap( addr6, other_addr6 );
            }
            if (0 == memcmp(addr6, src_addr6.data(), src_addr6.size())) {
                if (rewrite_src_addr6.size()) {
                    memcpy(addr6, rewrite_src_addr6.data(), rewrite_src_addr6.size());
                }
                if (rewrite_dst_addr6.size()) {
                    memcpy(other_addr6, rewrite_dst_addr6.data(), rewrite_dst_addr6.size());
                }
            }
        }
    }
    return pkt;
}

struct task_result PcapSource::RunTask(
        Context *ctx,
        bess::PacketBatch *batch,
        void *)
{
    size_t total_bytes = 0;
    batch->clear();

    if (unlikely(start_ns == 0)) {
        start_ns = ctx->current_ns;
    }

    while(pcap != nullptr) {
        // Load the next packet if it's not already loaded.  It might already
        // be loaded if we did it last cycle but it was not time to send yet.
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
            // Packet allocation failed - this shouldn't happen, so stop
            // sending.
            return { .block = true, .packets = 0, .bits = 0 };
        }

        batch->add(pkt);
        total_bytes += next_packet_hdr.caplen;
        next_packet = nullptr;
    }

    // Pass any allocated packets to the next module.  It is possible that
    // batch may contain no packets.
    RunNextModule(ctx, batch);

    return {
        .block = (pcap == nullptr),
        .packets = (unsigned) batch->cnt(),
        .bits = total_bytes * 8,
    };
};

ADD_MODULE(PcapSource, "pcap_source", "A source that can replay a PCAP file")
