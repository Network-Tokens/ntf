#include <arpa/inet.h>
#include <cstring>
#include <UnitTest++/UnitTest++.h>
#include "utils/ntf_api.h"
#include "test_packets.h"


TEST(NtfContextUsage) {
    const std::string key( "{\"k\":\"_m-oZljsyhkMMv9JwFhZxKLmaWKl26dMhwBRZpZZYKI\",\"kty\":\"oct\"}" );

    ntf_context_t * ctx = ntf_context_new( 10 );
    CHECK( ctx );

    int ret = ntf_context_entry_add( ctx, 0xB00F, key.data(), key.size(), 42 );
    CHECK_EQUAL( 0, ret );

    // We should have a single key with no flows in the allowlist
    CHECK_EQUAL( 1U, ntf_context_entry_count( ctx ) );
    CHECK_EQUAL( 0U, ntf_context_allowlist_count( ctx ) );

    // We want to fetch the 'sid' field from the payload of valid tokens to
    // match against to determine which service ID/QoS policy to apply.
    int field_id = ntf_context_get_field_id( ctx, "sid" );
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
    uint64_t sid = * (uint64_t*) field_value;
    CHECK_EQUAL( 0xD00D, sid );

    // We should have a new entry in the allow list for the packet, and another
    // entry for the reverse flow.
    CHECK_EQUAL( 2U, ntf_context_allowlist_count( ctx ) );

    // If the packet is processed again, the entry count in the flow allowlist
    // should not increase
    CHECK(
        ntf_process_packet( ctx,
            (char*) stun_packet.data(), stun_packet.size(),
            field_id, 0,
            &field_value, &field_value_len
        )
    );
    CHECK_EQUAL( 2U, ntf_context_allowlist_count( ctx ) );

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


TEST(DetectsTokensInGtpEncapsulatedPackets)
{
    const std::string key( "{\"k\":\"_m-oZljsyhkMMv9JwFhZxKLmaWKl26dMhwBRZpZZYKI\",\"kty\":\"oct\"}" );

    ntf_context_t * ctx = ntf_context_new( 10 );
    CHECK( ctx );

    int ret = ntf_context_entry_add( ctx, 0xB00F, key.data(), key.size(), 42 );
    CHECK_EQUAL( 0, ret );

    // We should have a single key with no flows in the allowlist
    CHECK_EQUAL( 1U, ntf_context_entry_count( ctx ) );
    CHECK_EQUAL( 0U, ntf_context_allowlist_count( ctx ) );

    // We want to fetch the 'sid' field from the payload of valid tokens to
    // match against to determine which service ID/QoS policy to apply.
    int field_id = ntf_context_get_field_id( ctx, "sid" );
    CHECK( field_id > 0 );

    const std::string stun_packet( IPV4_HEADER + UDP_HEADER + STUN_PACKET );

    // GTP encapsulate the stun packet.  Note the GTP length is the inner
    // length, not the outer, so the GTP length should match the inner IP
    // length.
    std::string gtp_packet( GTP_HEADER + stun_packet );
    uint16_t gtp_length = htons( stun_packet.size() );
    memcpy( gtp_packet.data() + 2, &gtp_length, sizeof(gtp_length) );

    std::string udp_outer_packet( UDP_OUTER_HEADER + gtp_packet );
    uint16_t udp_length = htons( udp_outer_packet.size() );
    memcpy( udp_outer_packet.data() + 4, &udp_length, sizeof(udp_length) );

    std::string ipv4_outer_packet( IPV4_OUTER_HEADER + udp_outer_packet );
    uint16_t ipv4_length = htons( ipv4_outer_packet.size() );
    memcpy( ipv4_outer_packet.data() + 2, &ipv4_length, sizeof(ipv4_length) );

    std::string ether_packet( ETHERNET_HEADER + ipv4_outer_packet );

    void * field_value;
    size_t field_value_len;

    CHECK(
        ntf_process_packet( ctx,
            (char*) ether_packet.data(), ether_packet.size(),
            field_id, 0,
            &field_value, &field_value_len
        )
    );

    // We should have extracted the 'sid'.  It's an integer, so it should be 64
    // bits.
    CHECK_EQUAL( sizeof(uint64_t), field_value_len );
    uint64_t sid = * (uint64_t*) field_value;
    CHECK_EQUAL( 0xD00D, sid );

    // We should have a new entry in the allow list for the packet, and another
    // entry for the reverse flow.
    CHECK_EQUAL( 2U, ntf_context_allowlist_count( ctx ) );

    ntf_context_delete( ctx );
}
