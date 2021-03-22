#ifndef BESS_UTILS_FLOW_H_
#define BESS_UTILS_FLOW_H_

#include <stdint.h>
#include "utils/endian.h"
#include "utils/ip.h"
#include "utils/udp.h"
#include "utils/cuckoo_map.h"


bess::utils::be16_t GENEVE_PORT( 6081 );


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

        // The reverse flow of a Geneve tunnel does not have its ports reversed
        if( id.dst_tp != GENEVE_PORT.value() ) {
            std::swap( id.src_tp, id.dst_tp );
        }
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


struct FlowEntry {
    uint64_t    exp;
};


using FlowMap = bess::utils::CuckooMap<
            FlowId, FlowEntry, Flow::Hash, Flow::EqualTo>;


#endif
