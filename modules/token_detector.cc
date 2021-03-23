/*
 * License : Apache-2.0
 * Copyright(c) 2021 Selfie Networks, Inc
 */

#include "token_detector.h"
#include "../utils/geneve.h"

#include "utils/ether.h"
#include "utils/ip.h"
#include "utils/udp.h"


using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;
using bess::utils::be32_t;
using namespace ntf::pb;
using namespace ntf::utils;

enum { FAIL_GATE = 0, FORWARD_GATE };

CommandResponse
TokenDetector::Init( const TokenDetectorArg & arg )
{
    using AccessMode = bess::metadata::Attribute::AccessMode;

    decap_offset_attr = AddMetadataAttr("decap_offset", sizeof(uint16_t), AccessMode::kRead);
    token_offset_attr = AddMetadataAttr("token_offset", sizeof(uint16_t), AccessMode::kWrite);
    token_length_attr = AddMetadataAttr("token_length", sizeof(uint16_t), AccessMode::kWrite);

    token_insert = arg.token_insert();
    switch( token_insert ) {
    case TokenDetectorArg::GENEVE:
        geneve_option_class = arg.geneve_option_class();
        geneve_option_type = arg.geneve_option_type();
        break;
    default:
        return CommandFailure( -1, "Invalid token_insert value" );
    }
    return CommandSuccess();
}


bool
CheckTokenInsert_Geneve( const Ethernet * eth,
                         uint16_t         geneve_option_class,
                         uint8_t          geneve_option_type,
                         uint16_t &       token_offset,
                         uint16_t &       token_length )
{
    uint16_t ether_type = eth->ether_type.value();
    auto ip = reinterpret_cast<const Ipv4 *>( eth + 1 );

    if( ether_type != Ethernet::Type::kIpv4 ) {
        // This might be an IP packet...
        ip = reinterpret_cast<const Ipv4 *>( eth + 0 );
    }

    if( ip->version != 4 || ip->protocol != Ipv4::Proto::kUdp ) {
        return false;
    }

    size_t ip_bytes = (ip->header_length) << 2;
    auto udp = reinterpret_cast<const Udp * >(
            reinterpret_cast<const uint8_t *>(ip) + ip_bytes );

    if( udp->dst_port.value() != 6081 ) {
        return false;
    }

    const uint8_t * ptr = reinterpret_cast<const uint8_t *>(udp) + sizeof(Udp);
    const Geneve * geneve = reinterpret_cast<const Geneve *>( ptr );

    ptr += sizeof(Geneve);
    const uint8_t * end = ptr + geneve->opt_len * 4;

    while( ptr < end ) {
        auto opt = reinterpret_cast<const GeneveOption *>( ptr );
        ptr += sizeof(GeneveOption) + opt->length * 4;

        if( opt->option_class.value() == geneve_option_class
         && opt->type == geneve_option_type
        ) {
            auto token_ptr = reinterpret_cast<const uint8_t *>( opt ) + sizeof(GeneveOption);
            token_length = opt->length * 4;

            // Geneve options must be multiples of 4 bytes.  Padding for a
            // Network Token in a Geneve field goes at the start, so skip any
            // leading null-bytes.
            while( ! *token_ptr ) {
                token_ptr += 1;
                token_length -= 1;
            }

            token_offset = token_ptr - reinterpret_cast<const uint8_t* >( eth );
            return true;
        }
    }
    return false;
}


void
TokenDetector::ProcessBatch( Context *ctx, bess::PacketBatch *batch )
{
    int cnt = batch->cnt();
    for( int i = 0; i < cnt; ++i ) {
        bess::Packet *pkt = batch->pkts()[i];
        uint16_t decap_offset = get_attr<uint16_t>( this, decap_offset_attr, pkt );
        Ethernet *eth = pkt->head_data<Ethernet *>( decap_offset );

        bool token_found = false;
        uint16_t token_offset, token_length;

        switch( token_insert ) {
        case TokenDetectorArg::GENEVE:
            token_found = CheckTokenInsert_Geneve( eth, geneve_option_class,
                    geneve_option_type, token_offset, token_length );
            break;
        default:
            break;
        }

        if( token_found ) {
            token_offset += decap_offset;
            set_attr<uint16_t>( this, token_offset_attr, pkt, token_offset );
            set_attr<uint16_t>( this, token_length_attr, pkt, token_length );
        }

        EmitPacket( ctx, pkt, token_found ? FORWARD_GATE : FAIL_GATE );
    }
}


ADD_MODULE( TokenDetector, "token_detector",
            "Detects an NTF token within a packet" )
