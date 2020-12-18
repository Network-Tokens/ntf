#include <UnitTest++/UnitTest++.h>
#include <jansson.h>
#include <string>
#include "utils/ntf_decrypt.h"


struct JwkWrapper {
    cjose_jwk_t * jwk;

    JwkWrapper( const std::string &key ) {
        cjose_err error;
        jwk = cjose_jwk_import( key.data(), key.size(), &error );
        CHECK( jwk );
    }

    JwkWrapper( JwkWrapper& other ) = delete;
    JwkWrapper& operator=( JwkWrapper& other ) = delete;

    ~JwkWrapper() { cjose_jwk_release( jwk ); }
};


TEST(DecryptValidToken) {
    JwkWrapper jwk( "{\"alg\":\"A128CBC-HS256\",\"k\":\"Qr_XwDGctna3SlR88rEJYt6Zm100SASYeJWSJihDnsA\",\"kty\":\"oct\"}" );
    const std::string token( "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..tO-hxpVQjViPNpuELFqrPw.wLwLl0PuMS6oMmAHPvlZqtdNY0xkbOnIi0OCz0iOvJoLbviO-WBgYbVRWkqumvS3camvfEfSTmTrkyMZWOi8xjJD0KSvULCO3XTtCJSml-E.t9-RpE4j1xLDV-a4oHjmtg" );

    json_t * decrypted_token = ntf_token_decrypt(
            token.data(), token.size(),
            jwk.jwk
    );
    CHECK( decrypted_token );

    json_decref( decrypted_token );
}


TEST(BadToken) {
    JwkWrapper jwk( "{\"alg\":\"A128CBC-HS256\",\"k\":\"Qr_XwDGctna3SlR88rEJYt6Zm100SASYeJWSJihDnsA\",\"kty\":\"oct\"}" );
    const std::string token( "bad token" );

    json_t * decrypted_token = ntf_token_decrypt(
            token.data(), token.size(),
            jwk.jwk
    );
    CHECK( !decrypted_token );
}
