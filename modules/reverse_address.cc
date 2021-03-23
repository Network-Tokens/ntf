/*
 * License : Apache-2.0
 * Copyright(c) 2021 Selfie Networks, Inc
 */

#include "reverse_address.h"

#include "utils/ether.h"
#include "utils/ip.h"

using bess::utils::be32_t;

CommandResponse
ReverseAddress::Init( const bess::pb::EmptyArg & )
{
  return CommandSuccess();
}

void
ReverseAddress::ProcessBatch( Context *ctx, bess::PacketBatch *batch ) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;

  int cnt = batch->cnt();

  for( int i = 0; i < cnt; i++ ) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    // std::swap cannot be used for packed fields
    bess::utils::be32_t tmp_ip = ip->src;
    ip->src = ip->dst;
    ip->dst = tmp_ip;
  }

  RunNextModule(ctx, batch);
}

ADD_MODULE( ReverseAddress, "revaddr",
            "Reverses the source and destination address of a packet" )
