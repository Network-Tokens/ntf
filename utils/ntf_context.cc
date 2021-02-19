#include <cmath>
#include <errno.h>
#include <jansson.h>
#include "ntf_context.hpp"
#include "ntf_decrypt.h"
#include "utils/stun.h"

// From BESS
#include "packet.h"
#include "utils/endian.h"
#include "utils/ether.h"


#undef DLOG
#define DLOG LOG


using IpProto = bess::utils::Ipv4::Proto;
using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;
using bess::utils::be32_t;
using ntf::utils::AttributeTypes;
using ntf::utils::Stun;
using ntf::utils::StunAttribute;


static const size_t GTP_HEADER_SIZE = 8;


struct NetworkToken {
    uint8_t      reflect_type;
    uint32_t     token_type;
    const char * payload;
    size_t       payload_len;

    static const uint64_t kTimeOutNs = 300ull * 1000 * 1000 * 1000;
};


struct NetworkTokenHeader {
    be32_t header;
    char   payload[];
};


void
NtfFlowEntry::SetFieldData( field_id_t   id,
                            const void * data,
                            size_t       len )
{
    field_id = id;
    if( !id || !data ) {
        field_data.clear();
    } else {
        field_data = std::string( (const char*) data, len );
    }
}


int
NtfContext::AddEntry( token_type_t token_type,
                      const void * key,
                      size_t       key_len,
                      uint8_t      dscp )
{
    if (tokenMap_.Find(token_type)) {
        errno = EEXIST;
        return -1;
    }

    if (tokenMap_.Count() == max_token_entries) {
        errno = ENOMEM;
        return -1;
    }

    cjose_err error;
    cjose_jwk_t *jwk = cjose_jwk_import( (const char*) key, key_len, &error );
    if( !jwk ) {
        errno = EINVAL;
        return -1;
    }

    UserCentricNetworkTokenEntry entry;
    entry.token_type = token_type;
    entry.jwk = jwk;
    entry.dscp = dscp;
    // TODO: Something about entry.blacklist...

    if (!tokenMap_.Insert(entry.token_type, entry)) {
        errno = EAGAIN;
        LOG(WARNING) << "Failed to insert entry";
        return -1;
    }

    DLOG(WARNING) << "Entry inserted for 0x" << std::hex << entry.token_type
                  << ", dscp: 0x" << (int) dscp << std::dec;

    UpdateAuthoritativeDscpMarkings();
    errno = 0;
    return 0;
}


int
NtfContext::ModifyEntry( token_type_t token_type,
                         const void * key,
                         size_t       key_len,
                         uint8_t      dscp )
{
    if (!tokenMap_.Find(token_type)) {
        errno = ENOENT;
        return -1;
    }

    cjose_err error;
    cjose_jwk_t *jwk = cjose_jwk_import( (const char*) key, key_len, &error );
    if( !jwk ) {
        errno = EINVAL;
        return -1;
    }

    UserCentricNetworkTokenEntry entry;
    entry.token_type = token_type;
    entry.jwk = jwk;
    entry.dscp = dscp;
    // TODO: Something about entry.blacklist...

    if (!tokenMap_.Insert(entry.token_type, entry)) {
        errno = EAGAIN;
        LOG(WARNING) << "Failed to update entry";
        return -1;
    }

    DLOG(WARNING) << "Entry updated for 0x" << std::hex << entry.token_type << std::dec;

    UpdateAuthoritativeDscpMarkings();
    errno = 0;
    return 0;
}


int
NtfContext::DeleteEntry( token_type_t token_type )
{
    if (!tokenMap_.Find(token_type)) {
        errno = ENOENT;
        return -1;
    }

    tokenMap_.Remove( token_type );
    DLOG(WARNING) << "Entry removed for 0x" << std::hex << token_type << std::dec;
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


bool
CheckPacketForGTP( const uint8_t * data,
                   size_t          length )
{
    // For GTP check, we check the first byte - bit 5 is GTP rel 99, bit 4 is
    // protocol type GTP, and the second byte for 0xFF (message type = T-PDU)
    const uint8_t VERSION_REL_99 = 1 << 5;
    const uint8_t PROTO_TYPE_GTP = 1 << 4;

    const uint8_t FLAGS = (VERSION_REL_99 | PROTO_TYPE_GTP);
    const uint8_t MSG_TYPE_T_PDU = 0xFF;
    const size_t GTP_HEADER_LENGTH = 8;

    return length > GTP_HEADER_LENGTH &&
        (data[0] & FLAGS) == FLAGS &&
        data[1] == MSG_TYPE_T_PDU
    ;
}


bool
CheckForIpv4( uint8_t * data,
              size_t    length,
              Ipv4 *&   ipv4 )
{
    // First check for Ethernet
    size_t offset = 0;
    const Ethernet *eth = (const Ethernet*)( data + offset );
    if (
        length >= sizeof(Ethernet) &&
        eth->ether_type.value() == Ethernet::Type::kIpv4
    ) {
        offset += sizeof(Ethernet);
        length -= sizeof(Ethernet);
        DLOG(WARNING) << __FUNCTION__ << ": Found ethernet packet, offset is " << offset;
    }

    // Check for IP packet.  TODO: Checking for the protocol only might be
    // unreliable so maybe we should verify the checksum?
    Ipv4 *ip = (Ipv4*)( data + offset );
    if(length < sizeof(Ipv4)) {
        DLOG(WARNING) << __FUNCTION__ << ": not IPv4 (too short)";
        return false;
    }

    switch( ip->protocol ) {
    case IpProto::kUdp:
      // Okay
      break;
    case IpProto::kTcp:
      // Not okay, but worth logging for debugging
      DLOG(WARNING) << __FUNCTION__ << ": not UDP/IPv4 (TCP)";
      return false;
    default:
      DLOG(WARNING) << __FUNCTION__ << ": not UDP/IPv4 (unsupported protocol)";
      return false;
    }

    offset += (ip->header_length << 2) + sizeof(Udp);
    DLOG(WARNING) << __FUNCTION__ << ": Found UDP, offset is " << offset;

    // Is this packet GTP-encapsulated?
    if( CheckPacketForGTP( data + offset, length - offset ) ) {
        // Packet is GTP encapsulated.  Skip the header & parse the inner
        // packet.
        offset += GTP_HEADER_SIZE;
        ip = (Ipv4*)( data + offset );

        DLOG(WARNING) << __FUNCTION__ << ": GTP encapsulated, inner IPv4: " << offset;

        if(
            length > sizeof(Ipv4) &&
            ip->protocol != IpProto::kUdp
        ) {
            DLOG(WARNING) << __FUNCTION__ << ": GTP: not UDP/IPv4";
            return false;
        }
        DLOG(WARNING) << __FUNCTION__ << ": Found UDP (GTP), offset is " << offset + (ip->header_length << 2) + sizeof(Udp);
    }

    ipv4 = ip;
    return true;
}


bool
CheckPacketForNetworkToken( const uint8_t * data,
                            size_t          length,
                            const Ipv4 *    ipv4,
                            NetworkToken &  token )
{
    size_t offset = ((uint8_t*) ipv4) - data;
    const size_t STUN_PACKET_MIN(sizeof(Udp) + sizeof(Stun));
    size_t udp_length = 0;

    if( !ipv4 || ipv4->protocol != IpProto::kUdp ) {
        DLOG(WARNING) << __FUNCTION__ << ": not UDP/IPv4";
        return false;
    }

    offset += (ipv4->header_length << 2);

    // Ensure UDP packet has payload.
    const Udp *udp = (const Udp*)( data + offset );

    // For this to be a STUN message with an attribute, it needs to be > 28
    // bytes 8 bytes for UDP header and 20 bytes for STUN message, and more for
    // attribute. TODO(@aaron): I think the check below eliminates the need for
    // this one... recheck after GTP encapsulated packet support.
    if (udp->length.value() <= STUN_PACKET_MIN) {
        DLOG(WARNING) << __FUNCTION__ << ": packet too short";
        return false;
    }
    offset += sizeof(Udp);
    udp_length = udp->length.value();

    // Try to interpret this as a STUN message. Is it a valid STUN message
    // length?  TODO(@yiannis): check that message type is also valid.
    const Stun *stun = (const Stun*)( data + offset );
    if (stun->message_length.value() != udp_length - STUN_PACKET_MIN) {
        DLOG(WARNING) << __FUNCTION__ << ": truncated STUN message";
        DLOG(WARNING) << " - stun->message_length: " << stun->message_length.value() << ", udp->length: " << udp_length;
        return false;
    }

    size_t remaining_bytes = stun->message_length.value();

    const uint8_t * next_attribute = reinterpret_cast<const uint8_t*> (stun + 1);
    const uint8_t * end = data + length;

    while(next_attribute < end) {
        const StunAttribute * attribute = reinterpret_cast<const StunAttribute *>(next_attribute);
        if (attribute->type == be16_t(AttributeTypes::kNetworkToken)) {
            const NetworkTokenHeader * token_header = reinterpret_cast<const NetworkTokenHeader *>(attribute->payload_);

            token.token_type = token_header->header.value() & 0x0FFFFFFF;
            token.reflect_type = (token_header->header.value() & 0xF0000000) >> 28;
            token.payload = token_header->payload;
            token.payload_len = attribute->length.value() -
                sizeof(token_header->header);
            DLOG(WARNING) << __FUNCTION__ << ": found token with token_type: 0x" << std::hex
                          << token.token_type << std::dec;
            return true;
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
            DLOG(WARNING) << __FUNCTION__ << ": malformed STUN message";
            return false;
        }
        remaining_bytes -= padded_length; // type + length + padded payload
        next_attribute += padded_length;
    }
    DLOG(WARNING) << __FUNCTION__ << ": no network token";
    return false;
}


bool
CheckTokenAppId( const NetworkToken &            token,
                 TokenTable &                    token_table,
                 UserCentricNetworkTokenEntry *& entry )
{
    auto * hash_item = token_table.Find( token.token_type );
    if( !hash_item ) {
        DLOG(WARNING) << __FUNCTION__ << ": no token_type: 0x" << std::hex
                      << token.token_type << std::dec;
        DLOG(WARNING) << __FUNCTION__ << ": possible types are:";
        for( auto& it = token_table.begin(); it != token_table.end(); ++it ) {
            DLOG(WARNING) << __FUNCTION__ << " - 0x" << std::hex
                          << it->token_type << std::dec;
        }
        return false;
    }

    DLOG(WARNING) << __FUNCTION__ << "Found token type: 0x" << std::hex
        << token.token_type << ", dscp: 0x" << (unsigned short) hash_item->second.dscp << std::dec;
    entry = &hash_item->second;
    return true;
}


bool
CheckDecryptToken( const NetworkToken &           token,
                   UserCentricNetworkTokenEntry * token_entry,
                   json_t *&                      payload )
{
    payload = ntf_token_decrypt( token.payload, token.payload_len,
            token_entry->jwk );

    if( !payload ) {
        DLOG(WARNING) << __FUNCTION__ << ": token invalid";
        return false;
    }

    return true;
}


bool
CheckTokenExpiration( const json_t * payload,
                      uint64_t       now )
{
    auto val = json_object_get(payload, "exp");
    if( !val ) {
        // TODO: Should tokens without exp be invalid, or always valid?  For
        // now we assume they are invalid.
        DLOG(WARNING) << __FUNCTION__ << ": no expiry on token";
        return false;
    }

    uint64_t exp_ns = json_integer_value(val) * 1e9;
    if (exp_ns < now) {
        DLOG(WARNING) << __FUNCTION__ << ": token expired";
        return false;
    }
    return true;
}


bool
CheckBoundIp( const json_t * payload,
              const Ipv4 *   ipv4 )
{
    auto val = json_object_get( payload, "bip" );
    if( !val ) {
        // TODO: Should tokens without bip be invalid?  For now, assume yes.
        DLOG(WARNING) << __FUNCTION__ << ": no bound IP on token";
        return false;
    }

    std::string bound_ip = json_string_value( val );
    be32_t parsed_addr;
    if( !ParseIpv4Address(bound_ip, &parsed_addr) ) {
        DLOG(WARNING) << __FUNCTION__ << ": invalid bound IP on token";
        return false;
    }

    if( (parsed_addr != ipv4->src) && (parsed_addr != ipv4->dst) ) {
        DLOG(WARNING) << __FUNCTION__ << ": mismatched bound IP "
                      << "(BIP:" << ToIpv4Address( parsed_addr )
                      << " SRCIP:" << ToIpv4Address( ipv4->src )
                      << " DSTIP:" << ToIpv4Address( ipv4->dst ) << ")";
        return false;
    }

    return true;
}


bool
CheckField( const json_t *    payload,
            const FieldList & fields,
            field_id_t        field_id,
            NtfFlowEntry &    flow_entry )
{
    if( !field_id ) {
        DLOG(WARNING) << __FUNCTION__ << ": invalid field ID";
        return false;
    }

    size_t idx = field_id - 1;
    if( idx >= fields.size() ) {
        DLOG(WARNING) << __FUNCTION__ << ": field does not exist";
        return false;
    }

    auto val = json_object_get( payload, fields[idx].c_str() );
    if( !val ) {
        DLOG(WARNING) << __FUNCTION__ << ": token does not contain field";
        return false;
    }

    uint64_t     u;
    double       d;
    const void * s;
    size_t       len;

    switch( json_typeof( val ) ) {
        case JSON_STRING:
            len = json_string_length( val );
            s = json_string_value( val );
            break;
        case JSON_INTEGER:
            len = sizeof(uint64_t);
            u = json_integer_value( val );
            s = &u;
            break;
        case JSON_REAL:
            len = sizeof(double);
            d = json_real_value( val );
            s = &d;
            break;
        case JSON_TRUE:
        case JSON_FALSE:
            len = 1;
            u = json_boolean_value( val );
            s = &u;
            break;
        case JSON_OBJECT:
        case JSON_ARRAY:
        case JSON_NULL:
        default:
            DLOG(WARNING) << __FUNCTION__ << ": unsupported field type";
            return false;
    }

    flow_entry.SetFieldData( field_id, s, len );

    return true;
}


bool
NtfContext::ProcessPacket( void *     data,
                           size_t     length,
                           field_id_t field_id,
                           uint64_t   now,
                           void **    field_value,
                           size_t *   field_value_len )
{
    Ipv4 * ipv4 = nullptr;
    NetworkToken token;
    UserCentricNetworkTokenEntry * token_entry = nullptr;
    json_t * payload = nullptr;

    if(
        CheckForIpv4( (uint8_t*) data, length, ipv4 ) &&
        CheckPacketForNetworkToken( (uint8_t*) data, length, ipv4, token ) &&
        CheckTokenAppId( token, tokenMap_, token_entry ) &&
        CheckDecryptToken( token, token_entry, payload ) &&
        CheckTokenExpiration( payload, now ) &&
        CheckBoundIp( payload, ipv4 )
    ) {
        NtfFlowEntry new_flow;
        if(
            field_id == 0 ||
            CheckField( payload, fields, field_id, new_flow )
        ) {
            new_flow.token_type = token.token_type;
            new_flow.last_refresh = now;
            new_flow.dscp = token_entry->dscp;

            FlowId flow_id( ipv4 );
            flowMap_.Insert( flow_id, new_flow );
            flowMap_.Insert( flow_id.Reverse(), new_flow );

            DLOG(WARNING) << "Verified token with token type 0x"
                          << std::hex << token.token_type
                          << " --- marking packets with DSCP 0x"
                          << (uint16_t) new_flow.dscp << std::dec;
        }
    }

    if( payload ) {
        json_decref( payload );
    }

    if( !ipv4 ) {
        // We can do no good to this packet, so don't even try
        DLOG(WARNING) << __FUNCTION__ << ": unrecognized packet";
        return false;
    }

    // If this flow is on the allowlist table, we need to set the DSCP
    // marking. We reset the DSCP marking for all other flows.
    FlowId flow_id( ipv4 );
    auto * hash_item = flowMap_.Find( flow_id );
    auto * hash_reverse_item = flowMap_.Find( flow_id.Reverse() );

    if( !hash_item ) {
        DLOG(WARNING) << __FUNCTION__ << ": flow not allowlisted";
        ResetDscpMarking( ipv4 );
        return false;
    }

    // If we're looking for a different bound field, reject.
    if( field_id && field_id != hash_item->second.field_id ) {
        DLOG(WARNING) << __FUNCTION__ << ": field not bound on flow";
        ResetDscpMarking( ipv4 );
        return false;
    }

    // Forward and Reverse entries must have the same lifespan.
    DCHECK( hash_reverse_item );

    // lazily remove expired flows
    // TODO(@yiannis): we should check expired flows when adding
    // new flows as well.
    if( now - hash_item->second.last_refresh> NetworkToken::kTimeOutNs ) {
        DLOG(WARNING) << __FUNCTION__ << ": token expired";
        flowMap_.Remove( hash_item->first );
        flowMap_.Remove( hash_reverse_item->first );
        ResetDscpMarking( ipv4 );
        return false;
    }

    DLOG(WARNING) << __FUNCTION__ << ": setting dscp: 0x" << std::hex
                  << (unsigned short) hash_item->second.dscp << std::dec
                  << " on IP packet at offset: " << ((char*)ipv4 - (char*)data);
    SetDscpMarking( ipv4, hash_item->second.dscp );
    hash_item->second.last_refresh = now;
    hash_reverse_item->second.last_refresh = now;

    if( field_id ) {
        *field_value = hash_item->second.field_data.data();
        *field_value_len = hash_item->second.field_data.size();
    }
    return true;
}


void
NtfContext::ResetDscpMarking( Ipv4 * ip )
{
    DLOG(INFO) << __FUNCTION__;

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
NtfContext::SetDscpMarking( Ipv4 * ip, uint8_t dscp )
{
    ip->type_of_service = dscp;
}
