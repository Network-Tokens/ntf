/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#include "ntf.h"
#include <algorithm>
#include <errno.h>
#include <cmath>
#include <glog/logging.h>
#include <jansson.h>

#include "utils/ether.h"
#include "utils/format.h"
#include "utils/ip.h"
#include "utils/stun.h"
#include "utils/udp.h"


using bess::utils::be16_t;
using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;
using IpProto = bess::utils::Ipv4::Proto;
using ntf::utils::AttributeTypes;
using ntf::utils::Stun;
using ntf::utils::StunAttribute;

#undef DLOG
#define DLOG LOG


// Value to use to indicate no application was detected
uint32_t APP_ID_NONE = 0x0;

const Commands NTF::cmds = {
    {"entry_create", "NTFEntryCreateArg", MODULE_CMD_FUNC(&NTF::CommandEntryCreate), Command::THREAD_UNSAFE},
    {"entry_modify", "NTFEntryModifyArg", MODULE_CMD_FUNC(&NTF::CommandEntryModify), Command::THREAD_UNSAFE},
    {"entry_delete", "NTFEntryDeleteArg", MODULE_CMD_FUNC(&NTF::CommandEntryDelete), Command::THREAD_UNSAFE},
};

CommandResponse
NTF::Init(const ntf::pb::NTFArg &arg) {
    using AccessMode = bess::metadata::Attribute::AccessMode;

    DLOG(WARNING) << __FUNCTION__;

    if (arg.dpid() == 0) {
        return CommandFailure(-1, "invalid DPID value");
    }
    dpid = arg.dpid();

    uint32_t max_token_entries = arg.max_entries();
    if( ntf_ctx ) {
        ntf_context_delete( ntf_ctx );
    }
    ntf_ctx = ntf_context_new( max_token_entries );

    rule_id_attr = AddMetadataAttr("rule_id", sizeof(uint32_t), AccessMode::kWrite);
    sid_field = ntf_context_get_field_id( ntf_ctx, "sid" );

    LOG(INFO) << "NTF initialized: dpid=" << dpid << " "
                 "max_token_entries=" << max_token_entries;
    return CommandSuccess();
};

CommandResponse
NTF::CommandEntryCreate(const ntf::pb::NTFEntryCreateArg &arg) {
    LOG(WARNING) << __FUNCTION__ << "(token_type=" << arg.token().token_type()
                 << ", encryption_key=" << arg.token().encryption_key()
                 << ", dscp=" << arg.dscp() << std::dec
                 << ", rule_id=" << arg.rule_id()
                 << ")";

    const uint32_t token_type( arg.token().token_type() );
    const uint8_t dscp( arg.dscp() );
    const std::string key( arg.token().encryption_key() );

    DLOG(INFO) << " - Creating entry for: " << token_type;
    int ret = ntf_context_token_type_add(
            ntf_ctx, token_type, key.data(), key.size(), dscp );
    if( ret == 0 ) {
        LOG(INFO) << "Creating entry for: " << token_type;
        return CommandSuccess();
    }

    switch( errno ) {
    case EEXIST:
        return CommandFailure(-1, "token with token_type already exists --- use entry_modify instead");
    case ENOMEM:
        return CommandFailure(-1, "token table is full");
    default:
        return CommandFailure(ret, "unknown error");
    }
}

CommandResponse
NTF::CommandEntryModify(const ntf::pb::NTFEntryModifyArg &arg) {
    LOG(WARNING) << __FUNCTION__ << "(token_type=" << arg.token().token_type()
                 << ", encryption_key=" << arg.token().encryption_key()
                 << ", dscp=" << arg.dscp() << std::dec
                 << ", rule_id=" << arg.rule_id()
                 << ")";

    const uint32_t token_type( arg.token().token_type() );
    const uint8_t dscp( arg.dscp() );
    const std::string key( arg.token().encryption_key() );

    LOG(INFO) << " - Updating entry for: " << token_type;
    int ret = ntf_context_token_type_modify(
            ntf_ctx, token_type, key.data(), key.size(), dscp );
    if( ret == 0 ) {
        return CommandSuccess();
    }

    switch( errno ) {
    case ENOENT:
        return CommandFailure(-1, "token with token_type does not exist --- use entry_create instead");
    default:
        return CommandFailure(ret, "unknown error");
    }
}

CommandResponse
NTF::CommandEntryDelete(const ntf::pb::NTFEntryDeleteArg &arg) {
    LOG(WARNING) << __FUNCTION__ << "(token_type=" << arg.token_type() << ")";

    const uint32_t token_type( arg.token_type() );

    LOG(INFO) << " - Removing entry for: " << token_type;
    int ret = ntf_context_token_type_remove( ntf_ctx, token_type );
    if( ret == 0 ) {
        return CommandSuccess();
    }

    switch( errno ) {
    case ENOENT:
        return CommandFailure(-1, "cannot find token with this token_type");
    default:
        return CommandFailure(ret, "unknown error");
    }
}

void NTF::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
    const int cnt = batch->cnt();
    uint64_t now = ctx->current_ns;

    for (int i = 0; i < cnt; i++ ) {
        bess::Packet *pkt = batch->pkts()[i];

        void * data( pkt->head_data<void*>() );
        size_t len( pkt->head_len() );

        void * sid_val;
        size_t sid_val_len;

        bool ret = ntf_process_packet( ntf_ctx, data, len, sid_field, now,
                &sid_val, &sid_val_len );
        if( ret ) {
            uint32_t sid32 = 0;
            switch( sid_val_len ) {
                case sizeof(uint32_t):
                    sid32 = *(uint32_t*) sid_val;
                    break;
                default:
                    // TODO: For now, ignore it if it's not 4 bytes.
                    break;
            }
            set_attr<uint32_t>(this, rule_id_attr, pkt, sid32);
        }
    }
    RunNextModule(ctx, batch);
}

std::string NTF::GetDesc() const {
    return bess::utils::Format(
        "%zu keys, %zu whitelisted flows",
        ntf_context_token_type_count( ntf_ctx ),
        ntf_context_whitelist_count( ntf_ctx )
    );
}

ADD_MODULE(NTF, "ntf", "interprets network tokens and enforces appropriate action")
