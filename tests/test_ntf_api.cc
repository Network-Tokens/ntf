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

    const std::string stun_packet(
        ETHERNET_HEADER + IPV4_HEADER + UDP_HEADER + STUN_PACKET );

    token_app_id_t app_id = ntf_process_packet(
            ctx, (char*) stun_packet.data(), stun_packet.size(), 0 );

    CHECK_EQUAL( 0xB00F, app_id );

    ntf_context_delete( ctx );
}
