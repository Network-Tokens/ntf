#include "allowlist.h"
#include "utils/endian.h"

using bess::utils::be32_t;

enum { FAIL_GATE = 0, FORWARD_GATE };


CommandResponse
AllowList::Init( const ntf::pb::AllowListArg & )
{
    using AccessMode = bess::metadata::Attribute::AccessMode;

    decap_offset_attr = AddMetadataAttr( "decap_offset", sizeof(uint16_t), AccessMode::kRead );
    exp_attr = AddMetadataAttr( "exp", sizeof(uint64_t), AccessMode::kRead );

    return CommandSuccess();
}


bool
AllowList::CheckAllowList( bess::Packet * )
{
    return false;
}


void
AllowList::AddAllowList( bess::Packet * )
{
}


void
AllowList::ProcessBatch( Context *ctx, bess::PacketBatch *batch )
{
    int cnt = batch->cnt();

    // By default, go out the same gate we came in.  This means allowlisted
    // packets will go out 1 and packets not allowlisted will go out 0.
    for( auto i = 0; i < cnt; ++i ) {
        auto pkt = batch->pkts()[i];
        gate_idx_t out_gate = ctx->current_igate;
        if( out_gate == 1 ) {
            AddAllowList( pkt );
        } else if( CheckAllowList( pkt ) ) {
            out_gate = 1;
        }
        EmitPacket( ctx, pkt, out_gate );
    }

    RunNextModule( ctx, batch );
}


ADD_MODULE( AllowList, "allowlist", "Generic IPv4 allowlist" )
