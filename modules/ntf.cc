/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#include "ntf.h"
#include <algorithm>
#include <cmath>
#include <glog/logging.h>
#include <jansson.h>

#include "utils/ether.h"
#include "utils/format.h"
#include "utils/ip.h"
#include "utils/stun.h"
#include "utils/udp.h"
#include "utils/nte.h"


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
    {"table_create", "NtfTableCreateArg", MODULE_CMD_FUNC(&NTF::CommandTableCreate), Command::THREAD_UNSAFE},
    {"table_delete", "NtfTableDeleteArg", MODULE_CMD_FUNC(&NTF::CommandTableDelete), Command::THREAD_UNSAFE},
    {"entry_create", "NtfEntryCreateArg", MODULE_CMD_FUNC(&NTF::CommandEntryCreate), Command::THREAD_UNSAFE},
    {"entry_modify", "NtfEntryModifyArg", MODULE_CMD_FUNC(&NTF::CommandEntryModify), Command::THREAD_UNSAFE},
    {"entry_delete", "NtfEntryDeleteArg", MODULE_CMD_FUNC(&NTF::CommandEntryDelete), Command::THREAD_UNSAFE},
};

CommandResponse
NTF::Init(const bess::pb::EmptyArg &) {
    using AccessMode = bess::metadata::Attribute::AccessMode;

    DLOG(WARNING) << __FUNCTION__;
    dpid = 0;
    max_token_entries = 0;
    tokenMap_.Clear();
    flowMap_.Clear();

    rule_id_attr = AddMetadataAttr("rule_id", sizeof(uint32_t), AccessMode::kWrite);

    return CommandSuccess();
};

CommandResponse
NTF::CommandTableCreate(const ntf::pb::NtfTableCreateArg &arg) {
    DLOG(WARNING) << __FUNCTION__ << "(dpid=" << arg.dpid() << ", max_entries="
                 << arg.max_entries() << ")" ;

    if (dpid) {
        DLOG(WARNING) << "Token table with DPID " << dpid <<
            " already exists, delete this first to proceed";
        return CommandFailure(-1, "token table already exists, delete this first to proceed");
    }

    if (arg.dpid() == 0) {
        return CommandFailure(-1, "invalid DPID value");
    }
    dpid = arg.dpid();
    max_token_entries = arg.max_entries();
    return CommandSuccess();
};

CommandResponse
NTF::CommandTableDelete(const ntf::pb::NtfTableDeleteArg &arg) {
    DLOG(WARNING) << __FUNCTION__ << "(dpid=" << arg.dpid() << ")";

    if (dpid != arg.dpid() || dpid == 0) {
        return CommandFailure(-1, "invalid DPID value");
    }

    dpid = 0;
    max_token_entries = 0;
    tokenMap_.Clear();
    return CommandSuccess();
};


template<class T> CommandResponse
NTF::EntrySet(const T &arg) {
    if (dpid == 0 || arg.dpid() != dpid) {
        return CommandFailure(-1, "invalid DPID value");
    }

    UserCentricNetworkTokenEntry entry;
    entry.app_id = arg.token().app_id();
    entry.encryption_key = arg.token().encryption_key();

    switch (arg.set_rule_id_case()) {
    case ntf::pb::NtfEntryCreateArg::SET_RULE_ID_NOT_SET:
        // Do nothing... 
        LOG(INFO) << "   - won't set rule ID";
        break;
    case T::kRuleId:
        entry.flags.set_rule_id = entry.rule_id > 0;
        entry.rule_id = arg.rule_id();
        LOG(INFO) << "   - will set rule_id on packet";
        break;
    }

    switch (arg.set_dscp_case()) {
    case T::SET_DSCP_NOT_SET:
        // Do nothing...
        LOG(INFO) << "   - no DSCP set";
        break;
    case ntf::pb::NtfEntryCreateArg::kDscp:
        entry.flags.set_dscp = 1;
        entry.dscp = arg.dscp();
        LOG(INFO) << "   - DSCP: 0x" << std::hex << (uint32_t) entry.dscp << std::dec;
        break;
    }

    for (int i = 0; i < arg.token().blacklist_size(); i++) {
        entry.blacklist.push_front(arg.token().blacklist(i));
    }
    if (!tokenMap_.Insert(entry.app_id, entry)) {
        LOG(WARNING) << "Failed to insert entry";
        return CommandFailure(-1, "failed to create new entry");
    }

    DLOG(WARNING) << "Entry inserted for 0x" << std::hex << entry.app_id << std::dec;

    UpdateAuthoritativeDscpMarkings();
    return CommandSuccess();
}


CommandResponse
NTF::CommandEntryCreate(const ntf::pb::NtfEntryCreateArg &arg) {
    LOG(WARNING) << __FUNCTION__ << "(dpid=" << arg.dpid() << std::hex
                 << ", app_id=" << arg.token().app_id()
                 << ", encryption_key=" << arg.token().encryption_key()
                 << ", dscp=" << arg.dscp() << std::dec
                 << ", rule_id=" << arg.rule_id()
                 << ")";

    uint32_t app_id = arg.token().app_id();
    if (tokenMap_.Find(app_id)) {
        return CommandFailure(-1, "token with app_id already exists --- use entry_modify instead");
    }

    if (tokenMap_.Count() == max_token_entries) {
        return CommandFailure(-1, "token table is full");
    }

    LOG(INFO) << " - Creating entry for: " << app_id;
    return EntrySet(arg);
};

CommandResponse
NTF::CommandEntryModify(const ntf::pb::NtfEntryModifyArg &arg) {
    LOG(WARNING) << __FUNCTION__ << "(dpid=" << arg.dpid() << std::hex
                 << ", app_id=" << arg.token().app_id()
                 << ", encryption_key=" << arg.token().encryption_key()
                 << ", dscp=" << arg.dscp() << std::dec
                 << ", rule_id=" << arg.rule_id()
                 << ")";

    uint32_t app_id = arg.token().app_id();
    if (!tokenMap_.Find(app_id)) {
        return CommandFailure(-1, "token with app_id doesn't exist --- use entry_create instead");
    }

    return EntrySet(arg);
};

CommandResponse
NTF::CommandEntryDelete(const ntf::pb::NtfEntryDeleteArg &arg) {
    LOG(WARNING) << __FUNCTION__ << "(dpid=" << arg.dpid() << ", app_id="
                 << arg.app_id() << ")";

    uint32_t app_id;

    if (dpid == 0 || arg.dpid() != dpid) {
        return CommandFailure(-1, "invalid DPID value");
    }

    app_id = arg.app_id();

    if (!tokenMap_.Find(app_id)) {
        return CommandFailure(-1, "cannot find token with this app_id");
    }

    tokenMap_.Remove(app_id);
    UpdateAuthoritativeDscpMarkings();
    return CommandSuccess();
}

FlowId NTF::GetFlowId(bess::Packet *pkt) {
    Ipv4 *ip = pkt->head_data<Ipv4 *>(sizeof(Ethernet));
    size_t ip_bytes = (ip->header_length) << 2;

    Udp *udp = pkt->head_data<Udp *>(sizeof(Ethernet) + ip_bytes);
    FlowId id = {
        ip->src.value(), ip->dst.value(),
        udp->src_port.value(), udp->dst_port.value(),
        ip->protocol
    };

    return id;
};

FlowId NTF::GetReverseFlowId(FlowId flow_id) {
    FlowId reverse_flow_id = flow_id;
    std::swap(reverse_flow_id.src_addr, reverse_flow_id.dst_addr);
    std::swap(reverse_flow_id.src_tp,reverse_flow_id.dst_tp);
    return reverse_flow_id;
};

/** Extracts a token from a packet.
 * It currently looks for tokens only at UDP STUN packets.
 */
std::optional<NetworkToken> NTF::ExtractNetworkTokenFromPacket(bess::Packet *pkt) {
    // The packet should be an Ethernet frame
    size_t offset = 0;
    Ethernet *eth = pkt->head_data<Ethernet *>();
    if (eth->ether_type.value() == Ethernet::Type::kIpv4) {
        offset += sizeof(Ethernet);
    } else {
        return {};
    }

    // Ensure this is a UDP packet.
    Ipv4 *ip = pkt->head_data<Ipv4 *>(offset);
    if (ip->protocol != IpProto::kUdp) {
        return {};
    }
    offset += (ip->header_length << 2);

    // Ensure UDP packet has payload.
    Udp *udp = pkt->head_data<Udp *>(offset);

    // For this to be a STUN message with an attribute, it needs to be > 28 bytes
    // 8 bytes for UDP header and 20 bytes for STUN message, and more for attribute.
    const size_t STUN_PACKET_MIN(sizeof(Udp) + sizeof(Stun));
    if (udp->length.value() <= STUN_PACKET_MIN) {
        return {};
    }

    offset += sizeof(Udp);

    // Try to interpret this as a STUN message. Is it a valid
    // STUN message length?
    // TODO(@yiannis): check that message type is also valid.
    Stun *stun = pkt->head_data<Stun *>(offset);
    if (stun->message_length.value() != udp->length.value() - STUN_PACKET_MIN) {
        return {};
    }

    size_t remaining_bytes = stun->message_length.value();

    uint8_t * next_attribute = reinterpret_cast<uint8_t*> (stun + 1);
    const size_t stun_msg_length = stun->message_length.value();
    const uint8_t * end = reinterpret_cast<uint8_t*>(stun) + stun_msg_length;

    while(next_attribute < end) {
        StunAttribute * attribute = reinterpret_cast<StunAttribute *>(next_attribute);
        if (attribute->type == be16_t(AttributeTypes::kNetworkToken)) {
            NetworkToken token;
            NetworkTokenHeader * token_header = reinterpret_cast<NetworkTokenHeader *>(attribute->payload_);

            token.app_id = token_header->header.value() & 0x0FFFFFFF;
            token.reflect_type = (token_header->header.value() & 0xF0000000) >> 28;
            token.payload = std::string(token_header->payload,attribute->length.value());
            return { token };
        }

        // STUN attributes are 32-bit aligned, but length reflects number of
        // bytes prior to padding. Round-up length appropriately to find the
        // next attribute.
        uint16_t padded_length = ceil(attribute->length.value()/(double)4)*4 + 4;
        // if attribute length is < 4 or larger than the remaining bytes for
        // this packet, the packet is not STUN, or it is malformed, or we
        // screwed parsing. Move on.  If remaining bytes == padded_length then
        // we finished parsing this packet.
        if (padded_length < 4 || padded_length >= remaining_bytes) {
            return {};
        }
        remaining_bytes -= padded_length; // type + length + padded payload
        next_attribute += padded_length;
    }
    return {};
};

void NTF::CheckPacketForNetworkToken(Context *ctx, bess::Packet *pkt) {
    std::optional<NetworkToken> token;
    FlowId flow_id;
    FlowId reverse_flow_id;

    token = ExtractNetworkTokenFromPacket(pkt);
    if(!token) {
        return;
    }

    DLOG(WARNING) << "Found a token with app-id 0x" << std::hex << token->app_id << std::dec;

    auto *hash_item = tokenMap_.Find(token->app_id);
    if(!hash_item) {
        DLOG(WARNING) << "No app with ID: 0x" << std::hex << token->app_id << std::dec;
        return;
    }

    NtfFlowEntry new_ntf_flow;
    json_t * _token = nte_decrypt(token->payload.data(),
                                  token->payload.size(),
                                  hash_item->second.encryption_key.data(),
                                  hash_item->second.encryption_key.size());
    if (!_token) {
        DLOG(WARNING) << "NTE Decrypt did not find a valid token";
        return;
    }

    uint64_t exp_ns = json_integer_value(json_object_get(_token, "exp"))*1e9;
    std::string bound_ip = json_string_value(json_object_get(_token,"bip"));
    be32_t bound_address;
    if (exp_ns < ctx->current_ns) {
        DLOG(WARNING) << "Detected token is expired --- ignoring...";
        return;
    }
    if (!ParseIpv4Address(bound_ip, &bound_address)) {
        DLOG(WARNING) << "Detected token does not have a valid bound IP address --- ignoring...";
        return;
    }

    // We have the expiration time and bound ip for this token. Now we need to
    // check if the bound ip matches ip source or destination.
    Ipv4 *ip = pkt->head_data<Ipv4 *>(sizeof(Ethernet));
    if ((bound_address != ip->src) && (bound_address != ip->dst)) {
        DLOG(WARNING) << "Detected token is bound to an IP other than source and destination (BIP:" <<
            ToIpv4Address(bound_address) << " SRCIP:" << ToIpv4Address(ip->src) << " DSTIP:" << ToIpv4Address(ip->dst);
        return;
    }

    // if we made it that far, this is a valid token and we should take action.
    new_ntf_flow.last_refresh = ctx->current_ns;
    new_ntf_flow.dscp = hash_item->second.dscp;
    new_ntf_flow.flags = hash_item->second.flags;
    flow_id = GetFlowId(pkt);
    reverse_flow_id = GetReverseFlowId(flow_id);
    flowMap_.Insert(flow_id, new_ntf_flow);
    flowMap_.Insert(reverse_flow_id, new_ntf_flow);

    DLOG(WARNING) << "Verified token with app-id 0x" << std::hex << token->app_id
                  << " --- marking packets with DSCP 0x"
                  << (uint16_t) new_ntf_flow.dscp << std::dec;
}

void NTF::ResetDscpMarking(bess::Packet *pkt) {
    DLOG(INFO) << __FUNCTION__;

    Ipv4 *ip = pkt->head_data<Ipv4 *>(sizeof(Ethernet));
    // Do nothing if TOS is 0.
    // This will be the most common, so check first to avoid set lookup.
    if (ip->type_of_service == 0) {
        return;
    }

    // If TOS is one of our authoritative DSCP markings, set it to 0,
    // otherwise leave as is.
    if (authoritative_dscp_markings.count(ip->type_of_service) > 0) {
        ip->type_of_service = 0;
    }
}

void NTF::SetDscpMarking(bess::Packet *pkt, uint8_t dscp) {
    Ipv4 *ip = pkt->head_data<Ipv4 *>(sizeof(Ethernet));
    ip->type_of_service = dscp;
}

void NTF::UpdateAuthoritativeDscpMarkings() {
    LOG(WARNING) << __FUNCTION__;

    // Go over all entries and add all dscp actions to the authoritative list.
    authoritative_dscp_markings.clear();
    for (TokenTable::iterator it=tokenMap_.begin(); it!=tokenMap_.end(); ++it) {
        LOG(WARNING) << std::hex << " - 0x" << it->first << ": 0x" << (int)it->second.dscp << std::dec;
        authoritative_dscp_markings.insert(it->second.dscp);
    }
}

void NTF::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
    int cnt = batch->cnt();

    FlowId flow_id;
    FlowId reverse_flow_id;

    uint64_t now = ctx->current_ns;

    for (int i = 0; i < cnt; i++ ) {
        bess::Packet *pkt = batch->pkts()[i];

        // First check if this packet has a network token
        // Flows that have a valid network token are inserted
        // in a FlowTable. We assume a bidirectional (non-reflecting) token
        // and proactively insert both directions.
        CheckPacketForNetworkToken(ctx, pkt);

        // If this flow is on the whitelist table, we need to set the DSCP
        // marking. We reset the DSCP marking for all other flows.
        flow_id = GetFlowId(pkt);
        reverse_flow_id = GetReverseFlowId(flow_id);
        auto *hash_item = flowMap_.Find(flow_id);
        auto *hash_reverse_item = flowMap_.Find(reverse_flow_id);

        (void) hash_item;
        (void) hash_reverse_item;

        if (hash_item == nullptr) {
            ResetDscpMarking(pkt);
        } else {
            // Forward and Reverse entries must have the same lifespan.
            DCHECK(hash_reverse_item != nullptr);

            // lazily remove expired flows
            // TODO(@yiannis): we should check expired flows when adding
            // new flows as well.
            if (now - hash_item->second.last_refresh> kTimeOutNs) {
                flowMap_.Remove(hash_item->first);
                flowMap_.Remove(hash_reverse_item->first);
                ResetDscpMarking(pkt);
            } else {
                ApplyFlowActionsToPacket(pkt, hash_item->second);
                hash_item->second.last_refresh = now;
                hash_reverse_item->second.last_refresh = now;
            }
        }
    }
    RunNextModule(ctx, batch);
}

void NTF::ApplyFlowActionsToPacket(bess::Packet* pkt, const NtfFlowEntry &entry) {
    DLOG(INFO) << __FUNCTION__;

    if (entry.flags.set_rule_id) {
        DLOG(INFO) << " - set rule_id";
        set_attr<uint32_t>(this, rule_id_attr, pkt, entry.rule_id);
    }

    if (entry.flags.set_dscp) {
        DLOG(INFO) << " - set dscp";
        SetDscpMarking(pkt, entry.dscp);
    }
}

std::string NTF::GetDesc() const {
    return bess::utils::Format("%zu services, %zu active tokens",
            tokenMap_.Count(), flowMap_.Count());
}

ADD_MODULE(NTF, "ntf", "interprets network tokens and enforces appropriate action")
