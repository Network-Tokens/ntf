#include "nte.h"
#include <glog/logging.h>

#ifdef __cplusplus
extern "C" {
#endif


#define MAXBUFLEN 1000000

char compact_jwe[] = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..1K9eul7zPanY1uUzuymV-w.9r6WvC38pm7l0LbqFd4JZv3lhHzkWEKYlmabHCAVt-QYCu_g0LK8XZ0EQPCseaXOP3HkHUdD2oYgZ5UHBAeBIw.CKV7vctjDHfPQlKV9tnyQA";
char key[] = "{\"alg\":\"A128CBC-HS256\",\"k\":\"Qr_XwDGctna3SlR88rEJYt6Zm100SASYeJWSJihDnsA\",\"key_ops\":[\"encrypt\",\"decrypt\"],\"kty\":\"oct\"}";
  
typedef struct {
  const char * name;
} jwe_field_t;

static jwe_field_t jwe_fields [] = {
		   { .name = "protected" },
		   { .name = "encryption_key"},
		   { .name = "iv"},
		   { .name = "ciphertext"},
		   { .name = "tag"}
};			   

static bool
valid_b64(const char *b64, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (b64[i] != 0 && !strchr(JOSE_B64_MAP, b64[i]))
            return false;
    }

    return true;
}

static json_t *
parse_compact(const char *arg) {
  json_auto_t *tmp = json_object();
  size_t i = 0;
  
  for (size_t j = 0; jwe_fields[j].name; j++) {
    const char *enc = strchr(&arg[i], '.');
    size_t len = strlen(&arg[i]);
    
    if (enc)
      len = enc - &arg[i];
    else if (jwe_fields[j + 1].name)
      return NULL;
    
    if (!valid_b64(&arg[i], len))
      return NULL;
    
    if (json_object_set_new(tmp, jwe_fields[j].name,
			    json_stringn(&arg[i], len)) < 0)
      return NULL;

    i += len + 1;
  }
  
  return json_incref(tmp);
}

json_t * nte_decrypt(const char * token_buf, const char * key_buf) {
  json_error_t j_error;

  json_t * jwe;
  json_t * jwk;

  LOG(WARNING) << __FUNCTION__;
  LOG(WARNING) << "KEY:" <<  key_buf;
  LOG(WARNING) << "TOKEN:" << token_buf;
  
  jwk = json_loads(key, 0, &j_error);
  
  if(!jwk) {
    LOG(WARNING) << "Failed to load JWK " << j_error.text;
    return NULL;
  }
  
  jwe = parse_compact(compact_jwe);

  if(!jwe) {
    LOG(WARNING) << "Failed to load JWE " << j_error.text;
    return NULL;
  }

  LOG(WARNING) << "Key:" << json_dumps(jwk,0);
  LOG(WARNING) << "JWE:" << json_dumps(jwe,0); 
  LOG(WARNING) << "Key:" << json_string_value(json_object_get(jwk, "k")) << "len:" << strlen(json_string_value(json_object_get(jwk,"k")));
  LOG(WARNING) << "CipherText:" << json_string_value(json_object_get(jwe, "ciphertext")) << "len:" << strlen(json_string_value(json_object_get(jwe,"ciphertext")));
  
  size_t out_size;
  char * output = (char*) jose_jwe_dec(NULL, jwe, NULL, jwk, &out_size);
  if(!output) {
    LOG(WARNING) << "Cannot decode JWE";
    return NULL;
  }
  LOG(WARNING) << "Output:" << output;
  return json_loads(output, 0, &j_error);
}

#ifdef __cplusplus
}
#endif
