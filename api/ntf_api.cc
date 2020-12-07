#include <errno.h>
#include "ntf_api.h"
#include "ntf_context.hpp"


extern "C" {

typedef struct ntf_context_t {
    ntf_context_t( size_t max_token_entries )
        : ctx( max_token_entries ) {}

    NtfContext ctx;
} ntf_context_t;

/**
 * Create a new NTF context.
 */
ntf_context_t *
ntf_context_new( size_t max_token_entries )
{
    return new ntf_context_t( max_token_entries );
}


/**
 * Releases an NTF context
 */
void
ntf_context_delete( ntf_context_t * ptr )
{
    delete ptr;
}


/**
 * Adds an application to an NTF context, so that the NTF context can detect
 * tokens for this application/service type.
 */
int
ntf_context_app_add( ntf_context_t *  ptr,
                     token_app_id_t   token_app_id,
                     const void *     key,
                     size_t           key_len,
                     dscp_t           dscp )
{
    return ptr->ctx.AddApplication( token_app_id, key, key_len, dscp );
}


/**
 * Updates an application already added to an NTF context.
 */
int
ntf_context_app_modify( ntf_context_t *  ctx,
                        token_app_id_t   token_app_id,
                        const void *     key,
                        size_t           key_len,
                        dscp_t           dscp )
{
    errno = ENOTSUP;
    return -1;
}



/**
 * Removes an application from an NTF context.
 */
int
ntf_context_app_remove( ntf_context_t *  ctx,
                        token_app_id_t   token_app_id )
{
    errno = ENOTSUP;
    return -1;
}


/**
 * Process a raw packet.
 */
token_app_id_t
ntf_process_packet( const ntf_context_t *  ctx,
                    const void *           data,
                    size_t                 length,
                    uint64_t               now )
{
    return 0;
}


} // extern "C"
