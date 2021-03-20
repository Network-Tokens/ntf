#include "geneve_return.h"

#include "utils/ether.h"
#include "utils/ip.h"
#include "utils/udp.h"
#include "utils/checksum.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::be16_t;
using bess::utils::be32_t;


CommandResponse
GeneveReturn::Init( const bess::pb::EmptyArg & )
{
    return CommandSuccess();
}


void
GeneveReturn::ProcessBatch( Context * ctx, bess::PacketBatch * batch )
{
    int cnt = batch->cnt();

    for( int i = 0; i < cnt; i++ ) {
        bess::Packet *pkt = batch->pkts()[i];
        Ethernet *eth = pkt->head_data<Ethernet *>();
        uint16_t ether_type = eth->ether_type.value();
        if( ether_type != Ethernet::Type::kIpv4 ) {
            continue;
        }

        Ipv4 * ip = reinterpret_cast<Ipv4 *>( eth + 1 );
        if (ip->protocol != Ipv4::Proto::kUdp) {
            continue;
        }

        Ethernet::Address tmp_ether;
        tmp_ether = eth->src_addr;
        eth->src_addr = eth->dst_addr;
        eth->dst_addr = tmp_ether;

        be32_t tmp_ip = ip->src;
        ip->src = ip->dst;
        ip->dst = tmp_ip;
        ip->ttl -= 1;

        ip->checksum = CalculateIpv4Checksum( *ip );
    }

    RunNextModule( ctx, batch );
}

ADD_MODULE( GeneveReturn, "gnv_return", "Prepares a packet to be returned over the Geneve proxy" )
