#include "token_decryptor.h"

enum { FAIL_GATE = 0, FORWARD_GATE };


CommandResponse
TokenDecryptor::Init( const ntf::pb::TokenDecryptorArg & arg )
{
    using AccessMode = bess::metadata::Attribute::AccessMode;

    token_offset_attr = AddMetadataAttr("token_offset", sizeof(uint16_t), AccessMode::kRead);
    token_length_attr = AddMetadataAttr("token_length", sizeof(uint16_t), AccessMode::kRead);

    shared_key = arg.shared_key();

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
        token_valid = DecryptToken_COSE( token_ptr, token_length );

        EmitPacket( ctx, pkt, token_valid ? FORWARD_GATE : FAIL_GATE );
    }
}


ADD_MODULE( TokenDecryptor, "token_decryptor",
            "Decrypts a token found by TokenDetector & extract metadata" )
