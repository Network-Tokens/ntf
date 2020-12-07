#include <cmath>
#include <errno.h>
#include <jansson.h>
#include "ntf_context.hpp"
#include "utils/stun.h"
#include "utils/nte.h"

// From BESS
#include "packet.h"
#include "utils/endian.h"
#include "utils/ether.h"
#include "utils/ip.h"
#include "utils/udp.h"


using IpProto = bess::utils::Ipv4::Proto;
using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;
using bess::utils::be32_t;
using ntf::utils::AttributeTypes;
using ntf::utils::Stun;
using ntf::utils::StunAttribute;


static const uint64_t kTimeOutNs = 300ull * 1000 * 1000 * 1000;


struct NetworkToken {
    uint8_t reflect_type;
    uint32_t app_id;
    std::string payload;
};


struct NetworkTokenHeader {
    be32_t header;
    char payload[];
};


FlowId
GetFlowId( const uint8_t* data, size_t length )
{
    DCHECK( length > sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Udp) );

    // TODO: This should support Layer-3 packets but right now requires a
    // packet with an Ethernet header to work properly.
    const Ipv4 *ip = (const Ipv4*)(const uint8_t*)( data + sizeof(Ethernet) );
    size_t ip_bytes = (ip->header_length) << 2;

    const Udp *udp = (const Udp*)(const uint8_t*)( data + sizeof(Ethernet) + ip_bytes );
    FlowId id = {
        ip->src.value(), ip->dst.value(),
        udp->src_port.value(), udp->dst_port.value(),
        ip->protocol
    };

    return id;
}


FlowId
GetReverseFlowId( FlowId flow_id )
{
    FlowId reverse_flow_id = flow_id;
    std::swap(reverse_flow_id.src_addr, reverse_flow_id.dst_addr);
    std::swap(reverse_flow_id.src_tp,reverse_flow_id.dst_tp);
    return reverse_flow_id;
}


int
NtfContext::AddApplication( token_app_id_t app_id,
                            const void *   key,
                            size_t         key_len,
                            dscp_t         dscp )
{
    if (tokenMap_.Find(app_id)) {
        errno = EEXIST;
        return -1;
    }

    if (tokenMap_.Count() == max_token_entries) {
        errno = ENOMEM;
        return -1;
    }

    UserCentricNetworkTokenEntry entry;
    entry.app_id = app_id;
    entry.encryption_key = std::string( (const char *) key, key_len );
    entry.dscp = dscp;
    // TODO: Something about entry.blacklist...

    if (!tokenMap_.Insert(entry.app_id, entry)) {
        errno = EAGAIN;
        LOG(WARNING) << "Failed to insert entry";
        return -1;
    }

    DLOG(WARNING) << "Entry inserted for 0x" << std::hex << entry.app_id << std::dec;

    UpdateAuthoritativeDscpMarkings();
    errno = 0;
    return 0;
}


void
NtfContext::UpdateAuthoritativeDscpMarkings()
{
    // Go over all entries and add all DSCP actions to the authoritative list.
    authoritative_dscp_markings.clear();
    for (TokenTable::iterator it = tokenMap_.begin(); it != tokenMap_.end(); ++it) {
        authoritative_dscp_markings.insert(it->second.dscp);
    }
}


token_app_id_t
NtfContext::ProcessPacket( void *   data,
                           size_t   length,
                           uint64_t now )
{
    CheckPacketForNetworkToken( data, length, now );

    // If this flow is on the whitelist table, we need to set the DSCP
    // marking. We reset the DSCP marking for all other flows.
    FlowId flow_id = GetFlowId( (const uint8_t*) data, length );
    FlowId reverse_flow_id = GetReverseFlowId( flow_id );
    auto *hash_item = flowMap_.Find( flow_id );
    auto *hash_reverse_item = flowMap_.Find( reverse_flow_id );

    if (hash_item == nullptr) {
        ResetDscpMarking( data, length );
        return 0;
    }
    // Forward and Reverse entries must have the same lifespan.
    DCHECK(hash_reverse_item != nullptr);

    // lazily remove expired flows
    // TODO(@yiannis): we should check expired flows when adding
    // new flows as well.
    if (now - hash_item->second.last_refresh> kTimeOutNs) {
        flowMap_.Remove(hash_item->first);
        flowMap_.Remove(hash_reverse_item->first);
        ResetDscpMarking( data, length );
        return 0;
    }

    SetDscpMarking( data, length, hash_item->second.dscp );
    hash_item->second.last_refresh = now;
    hash_reverse_item->second.last_refresh = now;
    return hash_item->second.app_id;
}


std::optional<NetworkToken>
ExtractNetworkTokenFromPacket( const uint8_t * data, size_t length )
{
    // The packet should be an Ethernet frame
    size_t offset = 0;
    const Ethernet *eth = (const Ethernet*)( data + offset );
    if (eth->ether_type.value() == Ethernet::Type::kIpv4) {
        offset += sizeof(Ethernet);
    } else {
        return {};
    }

    // Ensure this is a UDP packet.
    const Ipv4 *ip = (const Ipv4*)( data + offset );
    if (ip->protocol != IpProto::kUdp) {
        return {};
    }
    offset += (ip->header_length << 2);

    // Ensure UDP packet has payload.
    const Udp *udp = (const Udp*)( data + offset );

    // For this to be a STUN message with an attribute, it needs to be > 28
    // bytes 8 bytes for UDP header and 20 bytes for STUN message, and more for
    // attribute.
    const size_t STUN_PACKET_MIN(sizeof(Udp) + sizeof(Stun));
    if (udp->length.value() <= STUN_PACKET_MIN) {
        return {};
    }

    offset += sizeof(Udp);

    // Try to interpret this as a STUN message. Is it a valid STUN message
    // length?  TODO(@yiannis): check that message type is also valid.
    const Stun *stun = (const Stun*)( data + offset );
    if (stun->message_length.value() != udp->length.value() - STUN_PACKET_MIN) {
        return {};
    }

    size_t remaining_bytes = stun->message_length.value();

    const uint8_t * next_attribute = reinterpret_cast<const uint8_t*> (stun + 1);
    const uint8_t * end = data + length;

    while(next_attribute < end) {
        const StunAttribute * attribute = reinterpret_cast<const StunAttribute *>(next_attribute);
        if (attribute->type == be16_t(AttributeTypes::kNetworkToken)) {
            NetworkToken token;
            const NetworkTokenHeader * token_header = reinterpret_cast<const NetworkTokenHeader *>(attribute->payload_);

            token.app_id = token_header->header.value() & 0x0FFFFFFF;
            token.reflect_type = (token_header->header.value() & 0xF0000000) >> 28;
            token.payload = std::string(token_header->payload,attribute->length.value());
            return { token };
        }

        // STUN attributes are 32-bit aligned, but length reflects number of
        // bytes prior to padding. Round-up length appropriately to find the
        // next attribute.
        uint16_t padded_length = ::ceil(attribute->length.value()/(double)4)*4 + 4;
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
}


void
NtfContext::CheckPacketForNetworkToken( const void * data,
                                        size_t       length,
                                        uint64_t     current_ns )
{
    std::optional<NetworkToken> token;
    FlowId flow_id;
    FlowId reverse_flow_id;

    token = ExtractNetworkTokenFromPacket( (const uint8_t*) data, length );
    if(!token) {
        return;
    }

    DLOG(WARNING) << "Found a token with app-id 0x" << std::hex << token->app_id << std::dec;

    auto *hash_item = tokenMap_.Find(token->app_id);
    if(!hash_item) {
        DLOG(WARNING) << "No app with ID: 0x" << std::hex << token->app_id << std::dec;
        return;
    }

    json_t * _token = nte_decrypt(token->payload.data(),
                                  token->payload.size(),
                                  hash_item->second.encryption_key.data(),
                                  hash_item->second.encryption_key.size());
    if (!_token) {
        DLOG(WARNING) << "NTE Decrypt did not find a valid token";
        return;
    }

    do {
        uint64_t exp_ns = json_integer_value(json_object_get(_token, "exp"))*1e9;
        std::string bound_ip = json_string_value(json_object_get(_token,"bip"));
        be32_t bound_address;
        if (exp_ns < current_ns) {
            DLOG(WARNING) << "Detected token is expired --- ignoring...";
            break;
        }
        if (!ParseIpv4Address(bound_ip, &bound_address)) {
            DLOG(WARNING) << "Detected token does not have a valid bound IP address --- ignoring...";
            break;
        }

        // We have the expiration time and bound ip for this token. Now we need to
        // check if the bound ip matches ip source or destination.
        const Ipv4 *ip = (const Ipv4*)((const uint8_t*) data + sizeof(Ethernet));
        if ((bound_address != ip->src) && (bound_address != ip->dst)) {
            DLOG(WARNING) << "Detected token is bound to an IP other than source and destination (BIP:" <<
                ToIpv4Address(bound_address) << " SRCIP:" << ToIpv4Address(ip->src) << " DSTIP:" << ToIpv4Address(ip->dst);
            break;
        }

        // if we made it that far, this is a valid token and we should take action.
        NtfFlowEntry new_ntf_flow;
        new_ntf_flow.app_id = token->app_id;
        new_ntf_flow.last_refresh = current_ns;
        new_ntf_flow.dscp = hash_item->second.dscp;
        flow_id = GetFlowId( (const uint8_t*) data, length );
        reverse_flow_id = GetReverseFlowId(flow_id);
        flowMap_.Insert(flow_id, new_ntf_flow);
        flowMap_.Insert(reverse_flow_id, new_ntf_flow);

        DLOG(WARNING) << "Verified token with app-id 0x" << std::hex << token->app_id
                      << " --- marking packets with DSCP 0x"
                      << (uint16_t) new_ntf_flow.dscp << std::dec;
    } while(0);

    json_decref( _token );
}


void
NtfContext::ResetDscpMarking( void * data, size_t length )
{
    DLOG(INFO) << __FUNCTION__;
    DCHECK( length > sizeof(Ethernet) + sizeof(Ipv4) );

    Ipv4 *ip = (Ipv4*)( (uint8_t*) data + sizeof(Ethernet) );
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


void
NtfContext::SetDscpMarking( void * data, size_t length, uint8_t dscp )
{
    DCHECK( length > sizeof(Ethernet) + sizeof(Ipv4) );

    Ipv4 *ip = (Ipv4*)( (uint8_t*) data + sizeof(Ethernet) );
    ip->type_of_service = dscp;
}
