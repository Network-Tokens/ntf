/*
 * License : Apache-2.0
 * Copyright(c) 2020 Selfie Networks, Inc
 */

#ifndef BESS_MODULES_TOKEN_DECRYPTOR_H_
#define BESS_MODULES_TOKEN_DECRYPTOR_H_

#include "../module.h"
#include "../pb/token_decryptor_msg.pb.h"
#include <string>
#include <vector>


/**
 * Contains a field that can be extracted from a token and the metadata
 * attribute ID to store the field from matched tokens in.
 */
struct Field {
    std::string name;
    ntf::pb::TokenField::FieldType type;
    int attr_id;
};


/**
 * Decrypts network tokens found in packets.
 *
 * Tokens should first be detected upstream using the TokenDetector module, to
 * set the appropriate metadata attributes.  Packets that contain tokens that
 * are successfully decrytped will be emitted on out-gate 1.  Tokens that fail
 * to decrypt will be emitted on out-gate 0.
 *
 * This module uses the following metadata attributes:
 *
 * token_offset: the ABSOLUTE offset of the token in the packet (ignoring
 *               decap_offset)
 *
 * token_length: the length of the token data
 *
 * Currently, the TokenDecryptor supports only a single COSE token, but will be
 * extended to support multiple types of different tokens.
 */
class TokenDecryptor final : public Module {
public:
    static const gate_idx_t kNumOGates = 2;

    TokenDecryptor() : Module() {}

    CommandResponse Init( const ntf::pb::TokenDecryptorArg& );

    void ProcessBatch( Context* ctx, bess::PacketBatch* batch ) override;

private:
    bool ProcessToken_COSE( const uint8_t * token_ptr, size_t token_length );

    int token_offset_attr = -1;
    int token_length_attr = -1;

    std::string shared_key;
    std::vector<Field> fields;
};

#endif // BESS_MODULES_TOKEN_DECRYPTOR_H_
