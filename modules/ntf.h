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
#include "utils/ntf_api.h"

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
 * The supported actions right now are to mark the packet with a specific
 * DSCP codepoint, and to set the rule ID as metadata on packets.
 *
 * To prevent abuse, NTF assumes authoritative actions with regards to DSCP
 * markings. If deemed responsible for a specific codepoint, only packets/flows
 * with valid tokens will have this marking. If such marking is found in other
 * flows, it will be reset to 0.
 *
 * The rule_id metadata attribute can be set on packets from flows with a valid
 * network token.  The rule ID can be specified by an operator and can be used
 * to drive other decisions in the pipeline - for example, a UPF function might
 * contain a function that detects the rule_id attribute on new flows and
 * informs the PCRF of the flow description, so a dedicated bearer can be set
 * up dynamically.
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

class NTF final : public Module {
 public:
    static const Commands cmds;

    uint32_t dpid;

    CommandResponse Init(const bess::pb::EmptyArg &arg);

    CommandResponse CommandTableCreate(const ntf::pb::NtfTableCreateArg &arg);
    CommandResponse CommandTableDelete(const ntf::pb::NtfTableDeleteArg &arg);
    CommandResponse CommandEntryCreate(const ntf::pb::NtfEntryCreateArg &arg);
    CommandResponse CommandEntryModify(const ntf::pb::NtfEntryModifyArg &arg);
    CommandResponse CommandEntryDelete(const ntf::pb::NtfEntryDeleteArg &arg);

    void ProcessBatch(Context*, bess::PacketBatch*) override;

    std::string GetDesc() const override;

 private:
    // Field for rule ID attribute
    int rule_id_attr = -1;

    // NTF API context
    ntf_context_t * ntf_ctx;
};

#endif // BESS_MODULES_NTF_H_
