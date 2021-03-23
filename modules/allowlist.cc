/*
 * License : Apache-2.0
 * Copyright(c) 2021 Selfie Networks, Inc
 */

#include "allowlist.h"
#include "utils/endian.h"
#include "utils/ether.h"
#include "utils/format.h"

using IpProto = bess::utils::Ipv4::Proto;
using bess::utils::be32_t;
using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;
using bess::utils::ToIpv4Address;

enum { FAIL_GATE = 0, FORWARD_GATE };


CommandResponse
AllowList::Init( const ntf::pb::AllowListArg & arg )
{
    using AccessMode = bess::metadata::Attribute::AccessMode;

    decap_offset_attr = AddMetadataAttr( "decap_offset", sizeof(uint16_t), AccessMode::kRead );
    exp_attr = AddMetadataAttr( "exp", sizeof(uint64_t), AccessMode::kRead );

    default_lifetime = arg.default_lifetime();
    add_reverse_flow = arg.add_reverse_flow();

    return CommandSuccess();
}


bool
AllowList::CheckAllowList( const bess::Packet *,
                           const bess::utils::Ipv4 * ip,
                           uint64_t                  now )
{
    FlowId flow_id( ip );
    DLOG(INFO) << "Check Allow list for: "
              << ToIpv4Address( be32_t(flow_id.src_addr) ) << ":" << flow_id.src_tp
              << "->"
              << ToIpv4Address( be32_t(flow_id.dst_addr) ) << ":" << flow_id.dst_tp;

    auto * hash_item = flows.Find( flow_id );
    if( !hash_item ) {
        // Not on allow list
        DLOG(INFO) << " - not allowed";
        return false;
    }

    FlowMap::Entry * hash_reverse_item = nullptr;

    if( add_reverse_flow ) {
        hash_reverse_item = flows.Find( flow_id.Reverse() );
        DCHECK( hash_reverse_item );
    }

    if( now > hash_item->second.exp * 1e9 ) {
        // Expired
        flows.Remove( hash_item->first );
        if( add_reverse_flow ) {
            flows.Remove( hash_reverse_item->first );
        }
        return false;
    }

    // TODO: Check bound fields

    DLOG(INFO) << " - okay";

    // TODO: Copy bound fields

    return true;
}


void
AllowList::AddAllowList( const bess::Packet *      pkt,
                         const bess::utils::Ipv4 * ip )
{
    auto exp = get_attr<uint64_t>( this, exp_attr, pkt );

    FlowEntry entry;
    entry.exp = exp;

    // TODO: Set configured field values from packet metadata

    FlowId flow_id( ip );
    flows.Insert( flow_id, entry );
    flows.Insert( flow_id.Reverse(), entry );

    DLOG(INFO) << "Add flow to allow list: "
              << ToIpv4Address( be32_t(flow_id.src_addr) ) << ":" << flow_id.src_tp
              << "->"
              << ToIpv4Address( be32_t(flow_id.dst_addr) ) << ":" << flow_id.dst_tp;
}


void
AllowList::ProcessBatch( Context *ctx, bess::PacketBatch *batch )
{
    int cnt = batch->cnt();

    // By default, go out the same gate we came in.  This means allowlisted
    // packets will go out 1 and packets not allowlisted will go out 0.
    for( auto i = 0; i < cnt; ++i ) {
        auto pkt = batch->pkts()[i];

        auto decap_offset = get_attr<uint16_t>( this, decap_offset_attr, pkt );

        auto eth = pkt->head_data<Ethernet *>( decap_offset );
        uint16_t ether_type = eth->ether_type.value();
        auto ip = reinterpret_cast<const Ipv4 *>( eth + 1 );
        if( ether_type != Ethernet::Type::kIpv4 ) {
            ip = reinterpret_cast<const Ipv4 *>( eth + 0 );
        }

        gate_idx_t out_gate = ctx->current_igate;
        if( ip->version != 4
         || !(ip->protocol == IpProto::kUdp || ip->protocol == IpProto::kTcp)
         ) {
            DLOG(INFO) << "Packet is not TCP4/UDP4";
            EmitPacket( ctx, pkt, out_gate );
            continue;
        }

        if( out_gate == 1 ) {
            AddAllowList( pkt, ip );
        } else if( CheckAllowList( pkt, ip, ctx->current_ns ) ) {
            out_gate = 1;
        }
        EmitPacket( ctx, pkt, out_gate );
    }
}

std::string
AllowList::GetDesc() const {
    return bess::utils::Format(
        "%zu flows", flows.Count()
    );
}

ADD_MODULE( AllowList, "allowlist", "Generic IPv4 allowlist" )
