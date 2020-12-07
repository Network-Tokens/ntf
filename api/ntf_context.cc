#include <errno.h>
#include "ntf_context.hpp"


int
NtfContext::AddApplication( token_app_id_t app_id,
                            const void *   key,
                            size_t         key_len,
                            dscp_t         dscp )
{
    if (tokenMap_.Find(app_id)) {
        errno = EEXIST;
        return -1;
    }

    if (tokenMap_.Count() == max_token_entries) {
        errno = ENOMEM;
        return -1;
    }

    UserCentricNetworkTokenEntry entry;
    entry.app_id = app_id;
    entry.encryption_key = std::string( (const char *) key, key_len );
    entry.dscp = dscp;
    // TODO: Something about entry.blacklist...

    UpdateAuthoritativeDscpMarkings();
    errno = 0;
    return 0;
}


void
NtfContext::UpdateAuthoritativeDscpMarkings()
{
    // Go over all entries and add all DSCP actions to the authoritative list.
    authoritative_dscp_markings.clear();
    for (TokenTable::iterator it = tokenMap_.begin(); it != tokenMap_.end(); ++it) {
        authoritative_dscp_markings.insert(it->second.dscp);
    }
}
