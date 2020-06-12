#include "ntf.h"
#include <glog/logging.h>
#include <math.h>
#include <algorithm>

#include "../utils/ip.h"
#include "../utils/ether.h"
#include "../utils/udp.h"
#include "../utils/stun.h"
#include "../utils/nte.h"

const Commands NTF::cmds = {
    {"table_create", "NtfTableCreateArg",MODULE_CMD_FUNC(&NTF::CommandTableCreate), Command::THREAD_UNSAFE},
    {"table_delete", "NtfTableDeleteArg",MODULE_CMD_FUNC(&NTF::CommandTableDelete), Command::THREAD_UNSAFE},
    {"entry_create", "NtfEntryCreateArg",MODULE_CMD_FUNC(&NTF::CommandEntryCreate), Command::THREAD_UNSAFE},
    {"entry_modify", "NtfEntryModifyArg",MODULE_CMD_FUNC(&NTF::CommandEntryModify), Command::THREAD_UNSAFE},
    {"entry_delete", "NtfEntryDeleteArg",MODULE_CMD_FUNC(&NTF::CommandEntryDelete), Command::THREAD_UNSAFE},
};

CommandResponse
NTF::Init(const bess::pb::EmptyArg &) {
  LOG(WARNING) << __FUNCTION__;
  dpid = 0;
  max_token_entries = 0;
  tokenMap_.Clear();
  flowMap_.Clear();
  
  return CommandSuccess();
};

CommandResponse
NTF::CommandTableCreate(const ntf::pb::NtfTableCreateArg &arg) {
  LOG(WARNING) << __FUNCTION__ << " " << arg.dpid() << arg.max_entries() ;
  
  if (dpid) {
    LOG(WARNING) << "Token table with DPID " << dpid << 
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
  LOG(WARNING) << __FUNCTION__ << " " << arg.dpid();
  
  if (dpid != arg.dpid() || dpid == 0) {
    return CommandFailure(-1, "invalid DPID value");
  }

  dpid = 0;
  max_token_entries = 0;
  tokenMap_.Clear();
  return CommandSuccess();
};

CommandResponse
NTF::CommandEntryCreate(const ntf::pb::NtfEntryCreateArg &arg) {
  LOG(WARNING) << __FUNCTION__;

  
  uint32_t app_id;
  
  if (dpid == 0 || arg.dpid() != dpid) {
    return CommandFailure(-1, "invalid DPID value");
  }

  app_id = arg.token().app_id();
  
  if (tokenMap_.Find(app_id)) {
    return CommandFailure(-1, "token with app_id already exists --- use entry_modify instead");
  }

  if (tokenMap_.Count() == max_token_entries) {
    return CommandFailure(-1, "token table is full");
  }            
  
  UserCentricNetworkTokenEntry entry;
  entry.app_id = app_id;
  entry.encryption_key = arg.token().encryption_key();
  entry.id = arg.entry_id();
  entry.dscp = arg.dscp();
  for (int i = 0; i < arg.token().blacklist_size(); i++) {
    entry.blacklist.push_front(arg.token().blacklist(i));
  }
  if (!tokenMap_.Insert(entry.app_id, entry)) {
    return CommandFailure(-1, "failed to create new entry");
  }

  UpdateAuthoritativeDscpMarkings();
  return CommandSuccess();
};

CommandResponse
NTF::CommandEntryModify(const ntf::pb::NtfEntryModifyArg &arg) {
  LOG(WARNING) << __FUNCTION__;  

  uint32_t app_id;
  
  if (dpid == 0 || arg.dpid() != dpid) {
    return CommandFailure(-1, "invalid DPID value");
  }

  app_id = arg.token().app_id();
  if (!tokenMap_.Find(app_id)) {
    return CommandFailure(-1, "token with app_id doesn't exist --- use entry_create instead");
  }
  
  UserCentricNetworkTokenEntry entry;
  entry.app_id = app_id;
  entry.encryption_key = arg.token().encryption_key();
  entry.id = arg.entry_id();
  entry.dscp = arg.dscp();
  for (int i = 0; i < arg.token().blacklist_size(); i++)
    entry.blacklist.push_front(arg.token().blacklist(i));

  if (!tokenMap_.Insert(entry.app_id, entry)) {
    return CommandFailure(-1, "failed to modify entry");
  }

  UpdateAuthoritativeDscpMarkings();
  return CommandSuccess();
};

CommandResponse
NTF::CommandEntryDelete(const ntf::pb::NtfEntryDeleteArg &arg) {
  LOG(WARNING) << __FUNCTION__;
  
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
  using bess::utils::Ipv4;
  using bess::utils::Udp; // UDP and TCP are the same for the purpose of taking a flow. 

  Ipv4 *ip = pkt->head_data<Ipv4 *>();
  size_t ip_bytes = (ip->header_length) << 2;
  Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

  FlowId id = {ip->src.value(), ip->dst.value(), ip->protocol,
	       udp->src_port.value(), udp->dst_port.value()};

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
  using bess::utils::Ipv4;
  using bess::utils::Udp;
  using ntf::utils::Stun;
  using ntf::utils::StunAttribute;
  using ntf::utils::AttributeTypes;
  using IpProto = bess::utils::Ipv4::Proto;

  // Ensure this is a UDP packet.
  Ipv4 *ip = pkt->head_data<Ipv4 *>();
  size_t ip_bytes = (ip->header_length) << 2;

  if (ip->protocol != IpProto::kUdp)
    return {};

  // Ensure UDP packet has payload.
  Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
  // For this to be a STUN message with an attribute, it needs to be > 28 bytes
  // 8 bytes for UDP header and 20 bytes for STUN message, and more for attribute.
  if (udp->length <= be16_t(sizeof(Udp) + sizeof(Stun))) 
    return {};

  // Try to interpret this as a STUN message. Is it a valid
  // STUN message length?
  // TODO(@yiannis): check that message type is also valid.
  Stun *stun = reinterpret_cast<Stun *>(udp + 1);
  if (stun->message_length != udp->length - be16_t(sizeof(Udp)+sizeof(Stun)))
    return {};

  size_t remaining_bytes = stun->message_length.value();

  uint8_t * next_attribute = reinterpret_cast<uint8_t*> (stun + 1);
  
  while(1) {
    StunAttribute * attribute = reinterpret_cast<StunAttribute *>(next_attribute);
    if (attribute->type == be16_t(AttributeTypes::kNetworkToken)) {
      NetworkToken token;
      NetworkTokenHeader * token_header = reinterpret_cast<NetworkTokenHeader *>(attribute->payload_);
      LOG(WARNING) << "STUN Attribute Length " << attribute->length.value();
      token.app_id = token_header->header.value() & 0x0FFFFFFF;
      token.reflect_type = (token_header->header.value() & 0xF0000000) >> 28;
      token.payload = std::string(token_header->payload,attribute->length.value());
      return { token };
    }

    // STUN attributes are 32-bit aligned, but length reflects number of bytes
    // prior to padding. Round-up length appropriately to find the next attribute.
    uint16_t padded_length = ceil(attribute->length.value()/(double)4)*4 + 4;
    // if attribute length is < 4 or larger than the remaining bytes for this packet, 
    // the packet is not STUN, or it is malformed, or we screwed parsing. Move on.
    // If remaining bytes == padded_length then we finished parsing this packet.
    if (padded_length < 4 || padded_length >= remaining_bytes) {
      return {};
    }
    remaining_bytes -= padded_length; // type + length + padded payload
    next_attribute += padded_length;
  }
};

void NTF::CheckPacketForNetworkToken(Context *ctx, bess::Packet *pkt) {
  std::optional<NetworkToken> token;
  FlowId flow_id;
  FlowId reverse_flow_id;

  token = ExtractNetworkTokenFromPacket(pkt);
  if(token) {
    LOG(WARNING) << "Found a token with app-id " << std::hex << token->app_id << std::dec;
    auto *hash_item = tokenMap_.Find(token->app_id);
    if(!hash_item)
      return;

    LOG(WARNING) << "Found entry";
    
    NtfFlowEntry new_ntf_flow;
    json_t * _token = nte_decrypt(token->payload.c_str(), hash_item->second.encryption_key.c_str());
    if (!_token) {
      LOG(WARNING) << "NTE Decrypt did not find a valid token";
      return;
    }
    LOG(WARNING) << "Decrypted Token" << (char*) json_dumps(_token, 0);
    // decrypt(ciphertext)
    // verify that alg == direct
    // verify src_ip == bip || dst_ip == bip
    // verify token is not expired
    // if everything is OK install state for both flows.
    new_ntf_flow.last_refresh = ctx->current_ns;
    new_ntf_flow.dscp = hash_item->second.dscp;
    flow_id = GetFlowId(pkt);
    reverse_flow_id = GetReverseFlowId(flow_id);
    flowMap_.Insert(flow_id, new_ntf_flow);
    flowMap_.Insert(reverse_flow_id, new_ntf_flow);
  }
};
  
void NTF::ResetDscpMarking(bess::Packet *pkt) {
  using bess::utils::Ipv4;

  Ipv4 *ip = pkt->head_data<Ipv4 *>();
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
  
  return;
}

void NTF::SetDscpMarking(bess::Packet *pkt, uint8_t dscp) {
  using bess::utils::Ipv4;

  Ipv4 *ip = pkt->head_data<Ipv4 *>();
  ip->type_of_service = dscp;
  return;
}

void NTF::UpdateAuthoritativeDscpMarkings() {
  using TokenTable = bess::utils::CuckooMap<uint32_t, UserCentricNetworkTokenEntry>;
  // go over all entries and add all dscp actions to the authoritative list.
  for (TokenTable::iterator it=tokenMap_.begin(); it!=tokenMap_.end(); ++it) {
    authoritative_dscp_markings.insert(it->second.dscp);
  }
}



template <NTF::Direction dir>
inline void NTF::DoProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  gate_idx_t ogate_idx = dir == kForward ? 1 : 0;
  int cnt = batch->cnt();

  FlowId flow_id;
  FlowId reverse_flow_id;
  
  uint64_t now = ctx->current_ns;

  for (int i = 0; i < cnt; i++ ) {
    bess::Packet *pkt = batch->pkts()[i];

    // First check if this packet has a network token
    // Flows that have a valid network token are inserted
    // in a FlowTable. We assume a bidirectional (non-reflecting) token
    // and proactivelyinsert both directions. 
    CheckPacketForNetworkToken(ctx, pkt);

    // If this flow is on the whitelist table, we need to set the DSCP
    // marking. We reset the DSCP marking for all other flows.
    flow_id = GetFlowId(pkt);
    reverse_flow_id = GetReverseFlowId(flow_id);
    auto *hash_item = flowMap_.Find(flow_id);
    auto *hash_reverse_item = flowMap_.Find(reverse_flow_id);

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
	SetDscpMarking(pkt, hash_item->second.dscp);
	hash_item->second.last_refresh = now;
	hash_reverse_item->second.last_refresh = now;
      }
    }
    EmitPacket(ctx, pkt, ogate_idx);
  }
};  

void NTF::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  gate_idx_t incoming_gate = ctx->current_igate;

  if (incoming_gate == 0) {
    DoProcessBatch<kForward>(ctx, batch);
  } else {
    DoProcessBatch<kReverse>(ctx, batch);
  }

  int cnt = batch->cnt();

  DLOG(WARNING) << "Received batch with " << cnt << " packets";
  
  RunNextModule(ctx, batch);
};

ADD_MODULE(NTF, "ntf", "interprets network tokens and enforces appropriate action")
