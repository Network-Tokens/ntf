#ifndef _NTF_API_H_
#define _NTF_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * NTF context - maintains information about flows, keys and other internal
 * state.
 */
typedef struct ntf_context_t ntf_context_t;


/**
 * Identifies which application or service type within a token.
 */
typedef uint32_t token_app_id_t;


/**
 * Type to use for DSCP value
 */
typedef uint8_t dscp_t;


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
 * Adds an application to an NTF context, so that the NTF context can detect
 * tokens for this application/service type.
 * \param ctx NTF context
 * \param token_app_id The app ID that can be found within the network token
 * header
 * \param key Pointer to encryption key (JWT)
 * \param key_len Length of encryption key
 * \param dscp If >0, indicate the DSCP value to set on packets of flows that
 * \return 0 on success, otherwise returns -1, with the reason in errno.
 * have presented valid network tokens.
 */
int
ntf_context_app_add( ntf_context_t *  ctx,
                     token_app_id_t   token_app_id,
                     const void *     key,
                     size_t           key_len,
                     dscp_t           dscp );


/**
 * Updates an application already added to an NTF context.
 * \param ctx NTF context
 * \param token_app_id The app ID that can be found within the network token
 * header
 * \param key Pointer to encryption key (JWT)
 * \param key_len Length of encryption key
 * \param dscp If >0, indicate the DSCP value to set on packets of flows that
 * \return 0 on success, otherwise returns -1, with the reason in errno.
 * have presented valid network tokens.
 */
int
ntf_context_app_modify( ntf_context_t *  ctx,
                       token_app_id_t   token_app_id,
                       const void *     key,
                       size_t           key_len,
                       dscp_t           dscp );


/**
 * Removes an application from an NTF context.
 * \param ctx NTF context
 * \param token_app_id The app ID to remove
 * \return 0 on success, otherwise returns -1, with the reason in errno.
 * have presented valid network tokens.
 */
int
ntf_context_app_remove( ntf_context_t *  ctx,
                        token_app_id_t   token_app_id );


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
 * \param length The length of the packet pointed to by data
 * \param now The current timestamp in nanoseconds
 * \return The token app ID for the flow, or 0 if there is no network token in
 * the packet and no state exists for this flow.
 */
token_app_id_t
ntf_process_packet( const ntf_context_t *  ctx,
                    const void *           data,
                    size_t                 length,
                    uint64_t               now );

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _NTF_API_H_
