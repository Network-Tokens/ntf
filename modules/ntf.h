// Copyright (c) 2014-2017, The Regents of the University of California.
// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef BESS_MODULES_NTF_H_
#define BESS_MODULES_NTF_H_

#include <map>
#include <optional>

#include "module.h"
#include "pb/module_msg.pb.h"
#include "pb/ntf_msg.pb.h"

#include "utils/cuckoo_map.h"
#include "utils/endian.h"

using bess::utils::be32_t;

/**
 * NTF detects network tokens in STUN messages,
 * and sets the appropriate DSCP marking.
 *
 * Method of operation:
 *
 * NTF holds a number of network token entries in tokenTable. Each entry
 * describes a token, and is indexed through a unique app_id. app_id means a
 * network token application. For the purposes of this implementation an app_id
 * identifies a service offered by an operator. A network token entry includes
 * the key with which tokens are encrypted/decrypted, a blacklist, and the
 * actions to take when a token is detected.
 *
 * The only supported action right now is to mark the packet with a specific
 * DSCP codepoint.    To prevent abuse, NTF assumes authoritative actions with
 * regards to DSCP markings. If deemed responsible for a specific codepoint,
 * only packets/flows with valid tokens will have this marking. If such marking
 * is found in other flows, it will be reset to 0.
 *
 * Every packet that enters NTF is checked for network tokens (currently only
 * as STUN attributes).    When a valid token is detected, NTF enforces the
 * respective action and sets the DSCP marking.    NTF also (temporarily) stores
 * the 5-tuple of this flow into flow table, so that subsequent packets of this
 * flow are associated with this token.
 *
 * Packets with no tokens (or with invalid/unverified tokens) pass through the
 * NTF with no changes (apart from DSCP reseting as discussed earlier).
 */

struct NtfFlowActionFlags {
    unsigned set_dscp :1;
    unsigned set_app_id :1;
};

struct NtfFlowEntry {
    uint64_t last_refresh; // in nanoseconds
    uint32_t app_id;
    uint8_t dscp;
    struct NtfFlowActionFlags flags;
};

struct NetworkTokenHeader {
    be32_t header;
    char payload[];
};

struct NetworkToken {
    uint8_t reflect_type;
    uint32_t app_id;
    std::string payload;
};

struct FlowId {
    uint32_t src_addr;
    uint32_t dst_addr;

    uint8_t protocol;

    uint16_t src_tp;
    uint16_t dst_tp;
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

struct UserCentricNetworkTokenEntry {
    uint32_t app_id;
    std::string encryption_key;
    std::list<uint64_t> blacklist;
    uint32_t id;
    uint8_t dscp;
    struct NtfFlowActionFlags flags;
};

class NTF final : public Module {
 public:
    static const Commands cmds;

    uint32_t dpid;
    uint16_t max_token_entries;

    CommandResponse Init(const bess::pb::EmptyArg &arg);

    CommandResponse CommandTableCreate(const ntf::pb::NtfTableCreateArg &arg);
    CommandResponse CommandTableDelete(const ntf::pb::NtfTableDeleteArg &arg);
    CommandResponse CommandEntryCreate(const ntf::pb::NtfEntryCreateArg &arg);
    CommandResponse CommandEntryModify(const ntf::pb::NtfEntryModifyArg &arg);
    CommandResponse CommandEntryDelete(const ntf::pb::NtfEntryDeleteArg &arg);

    void ProcessBatch(Context*, bess::PacketBatch*) override;

    std::string GetDesc() const override;

 private:
    using FlowTable = bess::utils::CuckooMap<
        FlowId, NtfFlowEntry, Flow::Hash, Flow::EqualTo>;
    using TokenTable = bess::utils::CuckooMap<
        uint32_t, UserCentricNetworkTokenEntry>;

    // 5 minutes for entry expiration
    static const uint64_t kTimeOutNs = 300ull * 1000 * 1000 * 1000;
    std::set<uint8_t> authoritative_dscp_markings;

    FlowTable::Entry *CreateNewEntry(const Flow &flow, uint64_t now);

    /**
     * Checks whether a packet contains a network token.
     * Currently looks at tokens encoded as STUN attributes. This function
     * just detects tokens, but doesn't attempt to verify and/or evaluate them.
     *
     * Returns pointer to the network token, or nullptr if no token found.
     */
    std::optional<NetworkToken> ExtractNetworkTokenFromPacket(bess::Packet *pkt);

    // Get    a flow id (5-tuple) from a packet.
    FlowId GetFlowId(bess::Packet *pkt);

    // Get a reverse flow id by swapping ip address and transport ports.
    FlowId GetReverseFlowId(FlowId flow_id);

    /**
     * CheckPacketForNetworkToken performs all token-related functions for a
     * packet.    It uses ExtractNetworkTokenFromPacket to detect token for a
     * packet.    Verifies that this is a valid token and if so, evaluates it.    It
     * installs the necessary state to apply desired actions (e.g., DSCP marking)
     * for follow-up packets that belong to the same flow.
     */
    void CheckPacketForNetworkToken(Context *ctx, bess::Packet *pkt);

    /**
     * Marks a given packet according to the parameters specified within the
     * given NtfFlowEntry.
     */
    void MarkPacket(bess::Packet *pkt, const NtfFlowEntry &NtfFlowEntry);

    /**
     * Unmarks a given packet, removing any NTF metadata and resetting any
     * authoritative DSCP markings.
     */
    void UnmarkPacket(bess::Packet *pkt);

    /**
     * Resets the token-specific DSCP marking for flows that have not been
     * whitelisted through a token.
     */
    void ResetDscpMarking(bess::Packet *pkt);
    /**
     * Sets the token-specific DSCP marking for flows that have been whitelisted
     * through a token.
     */
    void SetDscpMarking(bess::Packet *pkt, uint8_t dscp);

    void UpdateAuthoritativeDscpMarkings();

    // Per-flow soft state for flows already whitelisted by a token.
    FlowTable flowMap_;

    // State for tokens.
    TokenTable tokenMap_;

    // Field for app_id attribute
    int app_id_attr = -1;
};

#endif // BESS_MODULES_NTF_H_
