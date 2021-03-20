#include "allocator_context.h"


namespace ntf::cose {

inline const size_t AllocatorContext::CHUNK_SIZE = 2048;


void *
AllocatorContext::allocate( size_t count, size_t size, void * ptr )
{
    AllocatorContext * ctx = (AllocatorContext*) ptr;

    const size_t required = count * size;
    if( required > ctx->remaining ) {
        ctx->remaining = std::max( CHUNK_SIZE, required );
        ctx->blocks.push_back( std::string( ctx->remaining, '\0' ) );
    }

    const size_t pos = ctx->blocks.back().size() - ctx->remaining;
    ctx->remaining -= required;
    return ctx->blocks.back().data() + pos;
}

} // namespace ntf::cose
