#include <UnitTest++/UnitTest++.h>
#include <jansson.h>
#include <string>
#include "utils/nte.h"


TEST(DecryptValidToken) {
    const std::string key( "{\"alg\":\"A128CBC-HS256\",\"k\":\"Qr_XwDGctna3SlR88rEJYt6Zm100SASYeJWSJihDnsA\",\"kty\":\"oct\"}" );
    const std::string token( "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..tO-hxpVQjViPNpuELFqrPw.wLwLl0PuMS6oMmAHPvlZqtdNY0xkbOnIi0OCz0iOvJoLbviO-WBgYbVRWkqumvS3camvfEfSTmTrkyMZWOi8xjJD0KSvULCO3XTtCJSml-E.t9-RpE4j1xLDV-a4oHjmtg" );

    json_t * decrypted_token = nte_decrypt(
            token.data(), token.size(),
            key.data(), key.size()
    );
    CHECK( decrypted_token );

    json_decref( decrypted_token );
}


TEST(BadToken) {
    const std::string key( "{\"alg\":\"A128CBC-HS256\",\"k\":\"Qr_XwDGctna3SlR88rEJYt6Zm100SASYeJWSJihDnsA\",\"kty\":\"oct\"}" );
    const std::string token( "bad token" );

    json_t * decrypted_token = nte_decrypt(
            token.data(), token.size(),
            key.data(), key.size()
    );
    CHECK( !decrypted_token );
}


TEST(BadKey) {
    const std::string key( "bad key" );
    const std::string token( "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..tO-hxpVQjViPNpuELFqrPw.wLwLl0PuMS6oMmAHPvlZqtdNY0xkbOnIi0OCz0iOvJoLbviO-WBgYbVRWkqumvS3camvfEfSTmTrkyMZWOi8xjJD0KSvULCO3XTtCJSml-E.t9-RpE4j1xLDV-a4oHjmtg" );

    json_t * decrypted_token = nte_decrypt(
            token.data(), token.size(),
            key.data(), key.size()
    );
    CHECK( !decrypted_token );
}
