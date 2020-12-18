#ifndef _NTF_API_H_
#define _NTF_API_H_

#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * NTF context - maintains information about flows, keys and other internal
 * state.
 */
typedef struct ntf_context_t ntf_context_t;


/**
 * Identifies the token type which will dictate how to decode a token.
 */
typedef uint32_t token_type_t;

/**
 * Type for a bound field in a network token
 */
typedef uint32_t field_id_t;

/**
 * Create a new NTF context.
 * \param max_token_entries Maximum number of app keys that can be added to
 * this context
 * \return a new NTF context.
 */
ntf_context_t *
ntf_context_new( size_t max_token_entries );


/**
 * Releases an NTF context
 * \param ctx NTF context to release
 */
void
ntf_context_delete( ntf_context_t * ctx );


/**
 * Adds a token type to an NTF context, so that the NTF context can detect
 * tokens for this application/service type.
 * \param ctx NTF context
 * \param token_type Token type identifier.  This ID is present in the header
 * of a network token and is used to determine which key is used to decrypt the
 * token.
 * \param key Pointer to encryption key (JWK)
 * \param key_len Length of encryption key
 * \param dscp If >0, indicate the DSCP value to set on packets of flows that
 * \return 0 on success, otherwise returns -1, with the reason in errno.
 * have presented valid network tokens.
 */
int
ntf_context_entry_add( ntf_context_t * ctx,
                       token_type_t    token_type,
                       const void *    key,
                       size_t          key_len,
                       uint8_t         dscp );


/**
 * Updates the key & DSCP setting for a token type already added to an NTF
 * context.
 * \param ctx NTF context
 * \param token_type Token type identifier
 * \param key Pointer to encryption key (JWT)
 * \param key_len Length of encryption key
 * \param dscp If >0, indicate the DSCP value to set on packets of flows that
 * \return 0 on success, otherwise returns -1, with the reason in errno.
 * have presented valid network tokens.
 */
int
ntf_context_entry_modify( ntf_context_t * ctx,
                          token_type_t    token_type,
                          const void *    key,
                          size_t          key_len,
                          uint8_t         dscp );


/**
 * Removes a token type from an NTF context.
 * \param ctx NTF context
 * \param token_type The token type to remove
 * \return 0 on success, otherwise returns -1, with the reason in errno.
 * have presented valid network tokens.
 */
int
ntf_context_entry_remove( ntf_context_t * ctx,
                          token_type_t    token_type );


/**
 * Returns the ID for a given field name.  The field name specifies a key
 * within the network token payload.  If the field is found within a network
 * token, it is stored with the flow information and can be retrieved
 * efficiently for any subsequent packets belonging to the same flow.
 * \param ctx NTF context
 * \param field_name Name of field in payload of which to retrieve its ID
 * \return An ID that can be used in ntf_process_packet() to retrieve the value
 * of the field in a payload.
 */
field_id_t
ntf_context_get_field_id( ntf_context_t * ctx,
                          const char *    field_name );




/**
 * Process a raw packet.  The raw packet will be inspected for a network token.
 * If one is found and is verified, state will be created for the flow and the
 * DSCP value will be set, if applicable.
 *
 * For packets not containing a network token:
 * - If state for a flow exists, the flow will be marked with the DSCP value,
 *   if applicable
 * - If no state for the flow exists and the flow contains a DSCP value that
 *   the NTF context is using, the DSCP value will be cleared.
 *
 * \param ctx NTF context
 * \param data Pointer to the beginning of the raw packet data (either an
 * Ethernet frame or an IP packet)
 * \param field_id The ID of the field to retrieve from the payload, or 0 if no
 * field is to be retrieved.
 * \param length The length of the packet pointed to by data
 * \param now The current timestamp in nanoseconds
 * \param field_value If the packet belongs to flow on the allowlist and the
 * field matching field_id was found in the network token payload, the value of
 * the field will be copied to the location specified by field_value.
 * \param field_value_len If the field value is returned via field_value, the
 * length of that value will be placed in field_value_len.
 * \return The token type for the flow, or 0 if there is no network token in
 * the packet and no state exists for this flow.  Also returns 0 for matching
 * tokens if field_id is not zero, and no matching field was found in the
 * network token for this flow.
 */
token_type_t
ntf_process_packet( ntf_context_t * ctx,
                    void *          data,
                    size_t          length,
                    field_id_t      field_id,
                    uint64_t        now,
                    void **         field_value,
                    size_t *        field_value_len );

/**
 * Returns the number of token types that have been registered with this NTF
 * context.
 * \param ctx NTF context
 * \return Number of application keys that have been registered with this NTF
 */
size_t
ntf_context_entry_count( const ntf_context_t * ctx );


/**
 * Returns the number of flows that have presented a valid network token and
 * are currently allow-listed.
 * \param ctx NTF context
 * \return Number of flows currently on the allow list
 */
size_t
ntf_context_allowlist_count( const ntf_context_t * ctx );


#ifdef __cplusplus
} // extern "C"
#endif


#endif // _NTF_API_H_
