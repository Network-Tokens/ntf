#ifndef _NTF_ALLOCATORCONTEXT_H_
#define _NTF_ALLOCATORCONTEXT_H_


#define USE_CBOR_CONTEXT
#include <cn-cbor/cn-cbor.h>
#include <string>
#include <vector>


namespace ntf::cose {

struct AllocatorContext : cn_cbor_context {
    AllocatorContext() : cn_cbor_context { allocate, release, this } {}

private:
    static const size_t CHUNK_SIZE;

    size_t remaining = 0;
    std::vector<std::string> blocks;

    static void * allocate( size_t count, size_t size, void * ptr );
    static void release( void *, void * ) {}
};

} // namespace ntf::cose


#endif // _NTF_ALLOCATORCONTEXT_H_
