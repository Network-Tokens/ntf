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


// Value to use to indicate no application was detected
uint32_t APP_ID_NONE = 0x0;

const Commands NTF::cmds = {
    {"entry_create", "NtfEntryCreateArg", MODULE_CMD_FUNC(&NTF::CommandEntryCreate), Command::THREAD_UNSAFE},
    {"entry_modify", "NtfEntryModifyArg", MODULE_CMD_FUNC(&NTF::CommandEntryModify), Command::THREAD_UNSAFE},
    {"entry_delete", "NtfEntryDeleteArg", MODULE_CMD_FUNC(&NTF::CommandEntryDelete), Command::THREAD_UNSAFE},
};

CommandResponse
NTF::Init(const ntf::pb::NtfInitArg &arg) {
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
    sid_field = ntf_context_bind_field( ntf_ctx, "sid" );
    return CommandSuccess();
};

CommandResponse
NTF::CommandEntryCreate(const ntf::pb::NtfEntryCreateArg &arg) {
    LOG(WARNING) << __FUNCTION__ << "(dpid=" << arg.dpid() << std::hex
                 << ", app_id=" << arg.token().app_id()
                 << ", encryption_key=" << arg.token().encryption_key()
                 << ", dscp=" << arg.dscp() << std::dec
                 << ", rule_id=" << arg.rule_id()
                 << ")";

    if (dpid == 0 || arg.dpid() != dpid) {
        return CommandFailure(-1, "invalid DPID value");
    }

    const uint32_t token_app_id( arg.token().app_id() );
    const uint8_t dscp( arg.dscp() );
    const std::string key( arg.token().encryption_key() );

    LOG(INFO) << " - Creating entry for: " << token_app_id;
    int ret = ntf_context_app_add(
            ntf_ctx, token_app_id, key.data(), key.size(), dscp );
    if( ret == 0 ) {
        return CommandSuccess();
    }

    switch( errno ) {
    case EEXIST:
        return CommandFailure(-1, "token with app_id already exists --- use entry_modify instead");
    case ENOMEM:
        return CommandFailure(-1, "token table is full");
    default:
        return CommandFailure(ret, "unknown error");
    }
}

CommandResponse
NTF::CommandEntryModify(const ntf::pb::NtfEntryModifyArg &arg) {
    LOG(WARNING) << __FUNCTION__ << "(dpid=" << arg.dpid() << std::hex
                 << ", app_id=" << arg.token().app_id()
                 << ", encryption_key=" << arg.token().encryption_key()
                 << ", dscp=" << arg.dscp() << std::dec
                 << ", rule_id=" << arg.rule_id()
                 << ")";

    if (dpid == 0 || arg.dpid() != dpid) {
        return CommandFailure(-1, "invalid DPID value");
    }

    const uint32_t token_app_id( arg.token().app_id() );
    const uint8_t dscp( arg.dscp() );
    const std::string key( arg.token().encryption_key() );

    LOG(INFO) << " - Updating entry for: " << token_app_id;
    int ret = ntf_context_app_modify(
            ntf_ctx, token_app_id, key.data(), key.size(), dscp );
    if( ret == 0 ) {
        return CommandSuccess();
    }

    switch( errno ) {
    case ENOENT:
        return CommandFailure(-1, "token with app_id does not exist --- use entry_create instead");
    default:
        return CommandFailure(ret, "unknown error");
    }
}

CommandResponse
NTF::CommandEntryDelete(const ntf::pb::NtfEntryDeleteArg &arg) {
    LOG(WARNING) << __FUNCTION__ << "(dpid=" << arg.dpid() << ", app_id="
                 << arg.app_id() << ")";

    if (dpid == 0 || arg.dpid() != dpid) {
        return CommandFailure(-1, "invalid DPID value");
    }

    const uint32_t token_app_id( arg.app_id() );

    LOG(INFO) << " - Removing entry for: " << token_app_id;
    int ret = ntf_context_app_remove( ntf_ctx, token_app_id );
    if( ret == 0 ) {
        return CommandSuccess();
    }

    switch( errno ) {
    case ENOENT:
        return CommandFailure(-1, "cannot find token with this app_id");
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
        ntf_context_app_count( ntf_ctx ),
        ntf_context_whitelist_count( ntf_ctx )
    );
}

ADD_MODULE(NTF, "ntf", "interprets network tokens and enforces appropriate action")
