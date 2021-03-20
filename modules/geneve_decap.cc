#include "geneve_decap.h"
#include "../utils/geneve.h"

#include "utils/ether.h"
#include "utils/ip.h"
#include "utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;
using ntf::utils::Geneve;

enum { FAIL_GATE = 0, FORWARD_GATE };

CommandResponse
GeneveDecap::Init( const bess::pb::EmptyArg & )
{
    using AccessMode = bess::metadata::Attribute::AccessMode;
    decap_offset_attr = AddMetadataAttr("decap_offset", sizeof(uint16_t), AccessMode::kWrite);
    return CommandSuccess();
}


void
GeneveDecap::ProcessBatch( Context * ctx, bess::PacketBatch * batch )
{
    int cnt = batch->cnt();

    for( int i = 0; i < cnt; i++ ) {
        bess::Packet *pkt = batch->pkts()[i];
        Ethernet *eth = pkt->head_data<Ethernet *>();
        uint16_t ether_type = eth->ether_type.value();
        if( ether_type != Ethernet::Type::kIpv4 ) {
            LOG(INFO) << "Can't decap - not IPv4";
            EmitPacket( ctx, pkt, FAIL_GATE );
            continue;
        }

        Ipv4 * ip = reinterpret_cast<Ipv4 *>( eth + 1 );
        if (ip->protocol != Ipv4::Proto::kUdp) {
            LOG(INFO) << "Can't decap - not UDP";
            EmitPacket( ctx, pkt, FAIL_GATE );
            continue;
        }

        size_t ip_bytes = (ip->header_length) << 2;
        Udp * udp = reinterpret_cast<Udp * >(
                reinterpret_cast<uint8_t *>(ip) + ip_bytes );

        if( udp->dst_port.value() != 6081 ) {
            LOG(INFO) << "Can't decap - not Geneve";
            EmitPacket( ctx, pkt, FAIL_GATE );
            continue;
        }

        Geneve * geneve = reinterpret_cast<Geneve *>(
                reinterpret_cast<uint8_t *>(udp) + sizeof(Udp) );

        uint16_t offset = sizeof(Ethernet) + ip_bytes + sizeof(Udp) +
            sizeof(Geneve) + geneve->opt_len * 4;

        LOG(INFO) << "Decap at offset " << offset;
        set_attr<uint16_t>( this, decap_offset_attr, pkt, offset );
        EmitPacket( ctx, pkt, FORWARD_GATE );
    }
}

ADD_MODULE( GeneveDecap, "gnv_decap", "Marks the end of a Geneve header" )
