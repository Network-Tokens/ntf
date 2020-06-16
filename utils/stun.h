/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#ifndef NTF_UTILS_STUN_H_
#define NTF_UTILS_STUN_H_

#include "endian.h"

using bess::utils::be16_t;  
using bess::utils::be32_t;  


namespace ntf {
  namespace utils {

    enum AttributeTypes: uint16_t {
      kNetworkToken = 0x8030,
    };

    // Basic STUN header definition
    struct[[gnu::packed]] Stun {

      be16_t message_type; // Message type.
      be16_t message_length; // Message length

      be32_t magic_cookie; // Magic Cookie
      uint8_t transaction_id[12]; // Transaction ID;
    };

    struct[[gnu::packed]] StunAttribute {
      be16_t type; // Attribute type
      be16_t length; // Attribute length
      char payload_[]; // Attribute payload
    };

    static_assert(sizeof(Stun) == 20, "struct Stun is incorrect");
  }
}

#endif // NTF_UTILS_STUN_H_
