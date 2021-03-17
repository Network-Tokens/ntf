#include "healthcheck_responder.h"

#include "utils/ether.h"
#include "utils/ip.h"
#include "utils/tcp.h"
#include "utils/checksum.h"

using bess::utils::be16_t;
using bess::utils::be32_t;


CommandResponse
HealthcheckResponder::Init( const bess::pb::EmptyArg & )
{
  return CommandSuccess();
}

void
HealthcheckResponder::ProcessBatch( Context *ctx, bess::PacketBatch *batch ) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Tcp;

  int cnt = batch->cnt();

  for( int i = 0; i < cnt; i++ ) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    if( ip->protocol != Ipv4::Proto::kTcp ) {
      // Skip packet - not TCP
      DropPacket( ctx, pkt );
    }

    size_t ip_bytes = (ip->header_length) << 2;
    Tcp * tcp = reinterpret_cast<Tcp *>(
          reinterpret_cast<uint8_t *>(ip) + ip_bytes);

    if( !(tcp->flags & Tcp::Flag::kSyn) ) {
      // Skip packet - we are only responding to SYN packets
      DropPacket( ctx, pkt );
    }

    // Set ACK & increase ack_num
    tcp->ack_num = be32_t( tcp->seq_num.value() + 1 );
    tcp->flags |= Tcp::Flag::kAck;

    // Switch source & destination
    Ethernet::Address tmp_ether;
    tmp_ether = eth->src_addr;
    eth->src_addr = eth->dst_addr;
    eth->dst_addr = tmp_ether;

    be32_t tmp_ip = ip->src;
    ip->src = ip->dst;
    ip->dst = tmp_ip;

    be16_t tmp_port = tcp->src_port;
    tcp->src_port = tcp->dst_port;
    tcp->dst_port = tmp_port;

    // Recalculate checksums
    tcp->checksum = CalculateIpv4TcpChecksum( *ip, *tcp );
    ip->checksum = CalculateIpv4Checksum( *ip );

    EmitPacket( ctx, batch->pkts()[i], 0 );
  }
}

ADD_MODULE( HealthcheckResponder, "hcresponder",
            "Responds to a TCP SYN for use with a health check" )
