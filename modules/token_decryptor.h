#ifndef BESS_MODULES_TOKEN_DECRYPTOR_H_
#define BESS_MODULES_TOKEN_DECRYPTOR_H_

#include "../module.h"
#include "../pb/token_decryptor_msg.pb.h"
#include <string>
#include <vector>


struct Field {
    std::string name;
    ntf::pb::TokenField::FieldType type;
    int attr_id;
};


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
