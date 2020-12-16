#ifndef _NTF_CONTEXT_HPP_
#define _NTF_CONTEXT_HPP_

#include <cjose/jwk.h>
#include <list>
#include <set>
#include "ntf_api.h"

// From BESS
#include "utils/cuckoo_map.h"
#include "utils/ip.h"
#include "utils/udp.h"


struct FlowId {
    uint32_t src_addr = 0;
    uint32_t dst_addr = 0;
    uint16_t src_tp = 0;
    uint16_t dst_tp = 0;
    uint8_t protocol = 0;

    using Ipv4 = bess::utils::Ipv4;
    using Udp = bess::utils::Udp;

    static size_t LengthFromIpv4( const Ipv4 * ipv4 ) {
        return ipv4->header_length << 2;
    }

    static const Udp * UdpFromIpv4( const Ipv4 * ipv4 ) {
        return (const Udp*)( ((uint8_t*) ipv4) + LengthFromIpv4( ipv4 ) );
    }

    FlowId() = default;
    FlowId( const FlowId& ) = default;

    FlowId( const Ipv4 * ipv4 )
        : src_addr( ipv4->src.value() ),
          dst_addr( ipv4->dst.value() ),
          src_tp( UdpFromIpv4( ipv4 )->src_port.value() ),
          dst_tp( UdpFromIpv4( ipv4 )->dst_port.value() ),
          protocol( ipv4->protocol ) {}

    FlowId Reverse() const {
        FlowId id = *this;
        std::swap( id.src_addr, id.dst_addr );
        std::swap( id.src_tp, id.dst_tp );
        return id;
    }
};

struct Flow {
    FlowId id;

    // hashes a FlowId
    struct Hash {
        // a similar method to boost's hash_combine in order to combine hashes
        inline void combine(std::size_t &hash, const unsigned int &val) const {
            std::hash<unsigned int> hasher;
            hash ^= hasher(val) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        }
        bess::utils::HashResult operator()(const FlowId &id) const {
            std::size_t hash = 0;
            combine(hash, id.src_addr);
            combine(hash, id.dst_addr);
            combine(hash, id.src_tp);
            combine(hash, id.dst_tp);
            combine(hash, (uint32_t)id.protocol);
            return hash;
        }
    };

    // to compare two FlowId for equality in a hash table
    struct EqualTo {
        bool operator()(const FlowId &id1, const FlowId &id2) const {
            bool ips =
               (id1.src_addr == id2.src_addr) && (id1.dst_addr == id2.dst_addr);
            bool ports =
               (id1.src_tp == id2.src_tp) && (id1.dst_tp == id2.dst_tp);
            return (ips && ports) && (id1.protocol == id2.protocol);
        }
    };
};

struct NtfFlowEntry {
    uint64_t    last_refresh;
    uint32_t    token_type;
    uint8_t     dscp;
    field_id_t  field_id;
    std::string field_data;

    void SetFieldData( field_id_t   id,
                       const void * data,
                       size_t       len );
};

struct UserCentricNetworkTokenEntry {
    uint32_t token_type = 0;
    cjose_jwk_t *jwk = nullptr;
    uint8_t dscp = 0;
    std::list<uint64_t> blacklist;

    UserCentricNetworkTokenEntry() {}

    UserCentricNetworkTokenEntry( const UserCentricNetworkTokenEntry& o ) {
        *this = o;
    }

    UserCentricNetworkTokenEntry &operator=( const UserCentricNetworkTokenEntry& o ) {
        if( this != &o ) {
            cjose_err error;
            jwk = cjose_jwk_retain( o.jwk, &error );
        }
        return *this;
    }

    ~UserCentricNetworkTokenEntry() {
        if( jwk ) {
            cjose_jwk_release( jwk );
        }
    }
};

using FlowTable = bess::utils::CuckooMap<
            FlowId, NtfFlowEntry, Flow::Hash, Flow::EqualTo>;

using TokenTable = bess::utils::CuckooMap<
        uint32_t, UserCentricNetworkTokenEntry>;

using FieldList = std::vector<std::string>;

class NtfContext {
public:
    NtfContext( size_t max_token_entries_ )
        : max_token_entries( max_token_entries_ ) {}

    virtual ~NtfContext() {}

    int AddTokenType( token_type_t token_type,
                      const void * key,
                      size_t       key_len,
                      dscp_t       dscp );

    field_id_t GetFieldId( const std::string& name )
        { fields.push_back( name ); return fields.size(); }

    bool ProcessPacket( void *     data,
                        size_t     length,
                        field_id_t field_id,
                        uint64_t   now,
                        void **    field_value,
                        size_t *   field_value_len );
 

    size_t TokenTypeCount() const { return tokenMap_.Count(); }
    size_t WhitelistCount() const { return flowMap_.Count(); }

private:
    void SetDscpMarking( void * data, size_t length, uint8_t dscp );
    void ResetDscpMarking( void * data, size_t length );

    // Recalculate authoritative_dscp_markings from the tokens in tokenMap_
    void UpdateAuthoritativeDscpMarkings();

    // Set of authoritative DSCP markings
    std::set<uint8_t> authoritative_dscp_markings;

    // Per-flow soft state for flows already whitelisted by a token.
    FlowTable flowMap_;

    // State for tokens.
    TokenTable tokenMap_;

    // List of fields that can be bound
    FieldList fields;

    size_t max_token_entries = 0;
};


#endif
