#include "token_validator.h"
#include "utils/endian.h"
#include "utils/ether.h"
#include "utils/ip.h"

using bess::utils::be32_t;
using bess::utils::Ethernet;
using bess::utils::Ipv4;

enum { FAIL_GATE = 0, FORWARD_GATE };

CommandResponse
TokenValidator::Init( const ntf::pb::TokenValidatorArg & )
{
    using AccessMode = bess::metadata::Attribute::AccessMode;

    decap_offset_attr = AddMetadataAttr( "decap_offset", sizeof(uint16_t), AccessMode::kRead );
    bip_attr = AddMetadataAttr( "bip", sizeof(be32_t), AccessMode::kRead );
    exp_attr = AddMetadataAttr( "exp", sizeof(uint64_t), AccessMode::kRead );

    return CommandSuccess();
}


void
TokenValidator::ProcessBatch( Context *ctx, bess::PacketBatch *batch )
{
    int cnt = batch->cnt();

    for( int i = 0; i < cnt; ++i ) {
        auto pkt = batch->pkts()[i];

        auto decap_offset = get_attr<uint16_t>( this, decap_offset_attr, pkt );
        auto eth = pkt->head_data<Ethernet *>( decap_offset );

        uint16_t ether_type = eth->ether_type.value();
        auto ip = reinterpret_cast<const Ipv4 *>( eth + 1 );

        if( ether_type != Ethernet::Type::kIpv4 ) {
            // This might be an IP packet...
            ip = reinterpret_cast<const Ipv4 *>( eth + 0 );
        }

        gate_idx_t out_gate = FORWARD_GATE;
        if( ip->version == 4 ) {
            switch( ip->protocol ) {
                case Ipv4::Proto::kUdp:
                case Ipv4::Proto::kTcp: {
                    auto bip = get_attr<be32_t>( this, bip_attr, pkt );
                    if( ip->src != bip && ip->dst != bip ) {
                        out_gate = FAIL_GATE;
                    }
                    break;
                }
                default:
                    out_gate = FAIL_GATE;
                    break;
            }
        }

        if( out_gate == FORWARD_GATE ) {
            auto exp = get_attr<uint32_t>( this, exp_attr, pkt );
            uint64_t exp_ns = exp * 1e9;
            if( exp_ns < ctx->current_ns ) {
                out_gate = FAIL_GATE;
            }
        }

        EmitPacket( ctx, pkt, out_gate );
    }
}


ADD_MODULE( TokenValidator, "token_validator",
            "Ensure a decrypted token is valid given the bound IP & expiry" )
