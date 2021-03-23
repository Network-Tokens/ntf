/*
 * License : Apache-2.0
 * Copyright(c) 2021 Selfie Networks, Inc
 */

#include "packet.h"
#include "token_decryptor.h"
#include "utils/allocator_context.h"
#include "utils/decrypt.h"
#include "utils/endian.h"

using bess::utils::be32_t;
using namespace ntf::pb;

enum { FAIL_GATE = 0, FORWARD_GATE };


CommandResponse
TokenDecryptor::Init( const TokenDecryptorArg & arg )
{
    using AccessMode = bess::metadata::Attribute::AccessMode;

    token_offset_attr = AddMetadataAttr("token_offset", sizeof(uint16_t),
            AccessMode::kRead);
    token_length_attr = AddMetadataAttr("token_length", sizeof(uint16_t),
            AccessMode::kRead);

    shared_key = arg.shared_key();

    for( const auto& field : arg.fields() ) {
        int attr;
        switch( field.type() ) {
        case TokenField::INT:
            attr = AddMetadataAttr( field.name(), sizeof(uint64_t),
                    AccessMode::kWrite );
            break;
        case TokenField::IPV4:
            attr = AddMetadataAttr( field.name(), sizeof(be32_t),
                    AccessMode::kWrite );
            break;
        default:
            return CommandFailure( -1, "Invalid TokenField.type" );
        }
        fields.emplace_back( Field { field.name(), field.type(), attr } );
    }

    return CommandSuccess();
}


void
TokenDecryptor::ProcessBatch( Context *ctx, bess::PacketBatch *batch )
{
    int cnt = batch->cnt();

    for( int i = 0; i < cnt; ++i ) {
        bess::Packet * pkt = batch->pkts()[i];
        auto token_offset = get_attr<uint16_t>( this, token_offset_attr, pkt );
        auto token_length = get_attr<uint16_t>( this, token_length_attr, pkt );

        auto token_ptr = pkt->head_data<const uint8_t *>( token_offset );

        bool token_valid = false;

        // TODO: Detect type of token.  For now assume COSE.
        {
            ntf::cose::AllocatorContext ctx;
            void * cbor = ntf::cose::DecodeToken( token_ptr, token_length, shared_key, ctx );
            if( cbor ) {
                token_valid = ntf::cose::ExtractMetadata( cbor, fields, pkt, this );
            }
        }

        EmitPacket( ctx, pkt, token_valid ? FORWARD_GATE : FAIL_GATE );
    }
}

ADD_MODULE( TokenDecryptor, "token_decryptor",
            "Decrypts a token found by TokenDetector & extract metadata" )
