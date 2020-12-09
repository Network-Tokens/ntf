#include <UnitTest++/UnitTest++.h>
#include "ntf_api.h"
#include "test_packets.h"


TEST(NtfContextUsage) {
    const std::string key( "{\"alg\":\"A128CBC-HS256\",\"k\":\"Qr_XwDGctna3SlR88rEJYt6Zm100SASYeJWSJihDnsA\",\"kty\":\"oct\"}" );
    const std::string token( "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..tO-hxpVQjViPNpuELFqrPw.wLwLl0PuMS6oMmAHPvlZqtdNY0xkbOnIi0OCz0iOvJoLbviO-WBgYbVRWkqumvS3camvfEfSTmTrkyMZWOi8xjJD0KSvULCO3XTtCJSml-E.t9-RpE4j1xLDV-a4oHjmtg" );

    ntf_context_t * ctx = ntf_context_new( 10 );
    CHECK( ctx );

    int ret = ntf_context_app_add( ctx, 0xB00F, key.data(), key.size(), 42 );
    CHECK_EQUAL( 0, ret );

    // We should have a single key with no flows in the whitelist
    CHECK_EQUAL( 1U, ntf_context_app_count( ctx ) );
    CHECK_EQUAL( 0U, ntf_context_whitelist_count( ctx ) );

    const std::string stun_packet(
        ETHERNET_HEADER + IPV4_HEADER + UDP_HEADER + STUN_PACKET );

    token_app_id_t app_id = ntf_process_packet(
            ctx, (char*) stun_packet.data(), stun_packet.size(), 0 );

    // We should have detected the token app ID from the packet correctly
    // (TODO: this will become the service ID)
    CHECK_EQUAL( 0xB00F, app_id );

    // We should have a new entry in the whitelist for the packet, and another
    // entry for the reverse flow.
    CHECK_EQUAL( 2U, ntf_context_whitelist_count( ctx ) );

    // If the packet is processed again, the entry count in the flow whitelist
    // should not increase
    ntf_process_packet(
            ctx, (char*) stun_packet.data(), stun_packet.size(), 0 );
    CHECK_EQUAL( 2U, ntf_context_whitelist_count( ctx ) );

    ntf_context_delete( ctx );
}
