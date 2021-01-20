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
ntf_context_entry_add( ntf_context_t * ptr,
                       token_type_t    token_type,
                       const void *    key,
                       size_t          key_len,
                       uint8_t         dscp )
{
    return ptr->ctx.AddEntry( token_type, key, key_len, dscp );
}


/**
 * Updates an application already added to an NTF context.
 */
int
ntf_context_entry_modify( ntf_context_t * ptr,
                          token_type_t    token_type,
                          const void *    key,
                          size_t          key_len,
                          uint8_t         dscp )
{
    return ptr->ctx.ModifyEntry( token_type, key, key_len, dscp );
}


/**
 * Removes an application from an NTF context.
 */
int
ntf_context_entry_remove( ntf_context_t * ptr,
                          token_type_t    token_type )
{
    return ptr->ctx.DeleteEntry( token_type );
    return -1;
}


/**
 * Process a raw packet.
 */
token_type_t
ntf_process_packet( ntf_context_t * ptr,
                    void *          data,
                    size_t          length,
                    field_id_t      field_id,
                    uint64_t        now,
                    void **         field_value,
                    size_t *        field_value_len )
{
    return ptr->ctx.ProcessPacket( data, length, field_id, now, field_value,
            field_value_len );
}


/**
 * Returns the number of token keys that have been registered with this NTF
 * context.
 */
size_t
ntf_context_entry_count( const ntf_context_t * ptr )
{
    return ptr->ctx.EntryCount();
}


/**
 * Returns the number of flows that have presented a valid network token and
 * are currently on the allow list.
 */
size_t
ntf_context_allowlist_count( const ntf_context_t * ptr )
{
    return ptr->ctx.AllowListCount();
}


/**
 * Bind a field name.
 */
field_id_t
ntf_context_get_field_id( ntf_context_t * ptr,
                          const char *    field_name )
{
    return ptr->ctx.GetFieldId( field_name );
}

} // extern "C"
