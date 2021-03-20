/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#ifndef NTF_UTILS_GENEVE_H_
#define NTF_UTILS_GENEVE_H_

#include "utils/endian.h"

using bess::utils::be16_t;  
using bess::utils::be32_t;  


namespace ntf {
  namespace utils {

    // Basic GENEVE header definition
    struct[[gnu::packed]] Geneve {
#if __BYTE_ORDER__ == __LITTLE_ENDIAN
        uint8_t opt_len: 6;
        uint8_t ver: 2;

        uint8_t reserved: 6;
        uint8_t critical: 1;
        uint8_t oam: 1;

        be16_t protocol_type;

        unsigned vni: 24;
        unsigned reserved2: 8;
#elif __BYTE_ORDER__ == __BIG_ENDIAN
        uint8_t ver: 2;
        uint8_t opt_len: 6;

        uint8_t oam: 1;
        uint8_t critical: 1;
        uint8_t reserved: 6;

        be16_t protocol_type;

        unsigned vni: 24;
        unsigned reserved2: 8;
#endif
    };

    struct[[gnu::packed]] GeneveOption {
        be16_t option_class;
        uint8_t type;
#if __BYTE_ORDER__ == __LITTLE_ENDIAN
        uint8_t length: 5;
        uint8_t reserved: 3;
#elif __BYTE_ORDER__ == __BIG_ENDIAN
        uint8_t reserved: 3;
        uint8_t length: 5;
#endif
    };

    static_assert(sizeof(Geneve) == 8, "struct Geneve is incorrect");
    static_assert(sizeof(GeneveOption) == 4, "struct GeneveOption is incorrect");
  }
}

#endif // NTF_UTILS_GENEVE_H_
