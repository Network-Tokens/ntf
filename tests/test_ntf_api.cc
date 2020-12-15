#include <UnitTest++/UnitTest++.h>
#include "utils/ntf_api.h"
#include "test_packets.h"


TEST(NtfContextUsage) {
    const std::string key( "{\"k\":\"_m-oZljsyhkMMv9JwFhZxKLmaWKl26dMhwBRZpZZYKI\",\"kty\":\"oct\"}" );

    ntf_context_t * ctx = ntf_context_new( 10 );
    CHECK( ctx );

    int ret = ntf_context_app_add( ctx, 0xB00F, key.data(), key.size(), 42 );
    CHECK_EQUAL( 0, ret );

    // We should have a single key with no flows in the whitelist
    CHECK_EQUAL( 1U, ntf_context_app_count( ctx ) );
    CHECK_EQUAL( 0U, ntf_context_whitelist_count( ctx ) );

    // We want to fetch the 'sid' field from the payload of valid tokens to
    // match against to determine which service ID/QoS policy to apply.
    int field_id = ntf_context_bind_field( ctx, "sid" );
    CHECK( field_id > 0 );

    const std::string stun_packet(
        ETHERNET_HEADER + IPV4_HEADER + UDP_HEADER + STUN_PACKET );

    void * field_value;
    size_t field_value_len;

    CHECK(
        ntf_process_packet( ctx,
            (char*) stun_packet.data(), stun_packet.size(),
            field_id, 0,
            &field_value, &field_value_len
        )
    );

    // We should have extracted the 'sid'.  It's an integer, so it should be 64
    // bits.
    CHECK_EQUAL( sizeof(uint64_t), field_value_len );

    // We should have detected the token app ID from the packet correctly
    // (TODO: this will become the service ID)
    uint64_t sid = * (uint64_t*) field_value;
    CHECK_EQUAL( 0xD00D, sid );

    // We should have a new entry in the whitelist for the packet, and another
    // entry for the reverse flow.
    CHECK_EQUAL( 2U, ntf_context_whitelist_count( ctx ) );

    // If the packet is processed again, the entry count in the flow whitelist
    // should not increase
    CHECK(
        ntf_process_packet( ctx,
            (char*) stun_packet.data(), stun_packet.size(),
            field_id, 0,
            &field_value, &field_value_len
        )
    );
    CHECK_EQUAL( 2U, ntf_context_whitelist_count( ctx ) );

    // Create another packet... This one we will blank out the token, so it
    // will be a very boring packet with no token data in it.
    const std::string BLANK_DATA( STUN_PACKET.size(), '\0' );
    const std::string very_boring_packet(
        ETHERNET_HEADER + IPV4_HEADER + UDP_HEADER + BLANK_DATA );

    // This packet is on the same flow.  Even though the token is no longer in
    // the packet, the field_id is saved on the flow information and can be
    // retrieved in subsequent packets.

    void * another_field_value;
    size_t another_field_value_len;

    CHECK(
        ntf_process_packet( ctx,
            (char*) very_boring_packet.data(), very_boring_packet.size(),
            field_id, 0,
            &another_field_value, &another_field_value_len
        )
    );

    uint64_t sid2 = * (uint64_t*) another_field_value;
    CHECK_EQUAL( 0xD00D, sid2 );

    ntf_context_delete( ctx );
}
