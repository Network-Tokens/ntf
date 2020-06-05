#include "ntf.h"
#include <glog/logging.h>
#include <math.h>
#include <algorithm>

#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/stun.h"

CommandResponse
NTF::Init(const bess::pb::EmptyArg &) {
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
NetworkToken * NTF::ExtractNetworkTokenFromPacket(bess::Packet *pkt) {
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
    return nullptr;

  // Ensure UDP packet has payload.
  Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
  // For this to be a STUN message with an attribute, it needs to be > 28 bytes
  // 8 bytes for UDP header and 20 bytes for STUN message, and more for attribute.
  // size_t udp_length = size_t(udp->length);
  if (udp->length <= be16_t(sizeof(Udp) + sizeof(Stun))) 
    return nullptr;

  // Try to interpret this as a STUN message. Is it a valid
  // STUN message length?
  // TODO(@yiannis): check that message type is also valid.
  Stun *stun = reinterpret_cast<Stun *>(udp + 1);
  if (stun->message_length != udp->length - be16_t(sizeof(Udp)))
    return nullptr;

  size_t remaining_bytes = stun->message_length.value() - sizeof(Stun);

  uint8_t * next_attribute = reinterpret_cast<uint8_t*> (stun + 1);
  
  while(1) {
    StunAttribute * attribute = reinterpret_cast<StunAttribute *>(next_attribute);
    if (attribute->type == be16_t(AttributeTypes::kNetworkToken)) {
      return reinterpret_cast<NetworkToken *>(attribute->payload); // attribute->length);
    }

    // STUN attributes are 32-bit aligned, but length reflects number of bytes
    // prior to padding. Round-up length appropriately to find the next attribute.
    uint16_t padded_length = ceil(attribute->length.value()/4)*4;
    remaining_bytes -= padded_length + 4; // type + length + padded payload

    if (remaining_bytes == 0) 
      return nullptr;

    next_attribute += padded_length;
  }
};
						  

void NTF::CheckPacketForNetworkToken(Context *ctx, bess::Packet *pkt) {
  NetworkToken * token;
  FlowId flow_id;
  FlowId reverse_flow_id;
  uint64_t now = ctx->current_ns;


  token = ExtractNetworkTokenFromPacket(pkt);
  // For now treat all tokens as valid. 
  if (token != nullptr) {
    now = ctx->current_ns;
    flow_id = GetFlowId(pkt);
    reverse_flow_id = GetReverseFlowId(flow_id);
    map_.Insert(flow_id, now);
    map_.Insert(reverse_flow_id, now);
  }
};
  
void NTF::ResetDscpMarking(bess::Packet *) {
  return;
}

void NTF::SetDscpMarking(bess::Packet *) {
  return;
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
    // in a HashTable. We assume a bidirectional (non-reflecting) token
    // and proactivelyinsert both directions. 
    CheckPacketForNetworkToken(ctx, pkt);

    // If this flow is on the whitelist table, we need to set the DSCP
    // marking. We reset the DSCP marking for all other flows.
    flow_id = GetFlowId(pkt);
    reverse_flow_id = GetReverseFlowId(flow_id);
    auto *hash_item = map_.Find(flow_id);
    auto *hash_reverse_item = map_.Find(reverse_flow_id);

    if (hash_item == nullptr) {
      ResetDscpMarking(pkt);
    } else {
      // Forward and Reverse entries must have the same lifespan.
      DCHECK(hash_reverse_item != nullptr);

      // lazily remove expired flows
      // TODO(@yiannis): we should check expired flows when adding
      // new flows as well. 
      if (now - hash_item->second > kTimeOutNs) {
	map_.Remove(hash_item->first);
	map_.Remove(hash_reverse_item->first);
	ResetDscpMarking(pkt);	
      } else {
	SetDscpMarking(pkt);
	hash_item->second = now;
	hash_reverse_item->second = now;
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
