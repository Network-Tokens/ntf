// Depends: jose and jansson
// Build: gcc -o hello_jwe hello_jwe.c  -ljose -ljansson
// Use: ./hello_jwe

#include <stdio.h>
#include <jose/b64.h>
#include <jose/jwe.h>
#include <string.h>
#include <errno.h>

#define MAXBUFLEN 1000000



//char compact_jwe[] = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..Qik6JKV-S6AhdIGn.NlASAlW4WjPhoDUCOXYV.sPLq8EGbSgnwY-w6urfqfg";

// char compact_jwe[] = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..LSqqwhy-nHKrLr93KEpAwA.-V1w4RrGpI_brvHaFCXvqsuen9XCzVdm9HMzf4DuVhyxL2ZcpRPxFtT8hUZUtIrNqu17Iig3nK-jDtBHFodDxw.ictpX3SL77GSDHEWaa_fog";

char compact_jwe[] = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..1K9eul7zPanY1uUzuymV-w.9r6WvC38pm7l0LbqFd4JZv3lhHzkWEKYlmabHCAVt-QYCu_g0LK8XZ0EQPCseaXOP3HkHUdD2oYgZ5UHBAeBIw.CKV7vctjDHfPQlKV9tnyQA";

char full_jwe[] = "{\"ciphertext\":\"-V1w4RrGpI_brvHaFCXvqsuen9XCzVdm9HMzf4DuVhyxL2ZcpRPxFtT8hUZUtIrNqu17Iig3nK-jDtBHFodDxw\",\"iv\":\"LSqqwhy-nHKrLr93KEpAwA\",\"protected\":\"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"tag\":\"ictpX3SL77GSDHEWaa_fog\"}";


char key[] = "{\"alg\":\"A128CBC-HS256\",\"k\":\"Qr_XwDGctna3SlR88rEJYt6Zm100SASYeJWSJihDnsA\",\"key_ops\":[\"encrypt\",\"decrypt\"],\"kty\":\"oct\"}";

typedef struct {
  char * name;
  char * mult;
} jwe_field_t;

jwe_field_t jwe_fields [] = {
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

json_t *
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

int main() {
  char source[MAXBUFLEN + 1];
  char destination[MAXBUFLEN+1];

  json_error_t j_error;
  json_t * jwe;


  json_t * jwk;

  jwk = json_loads(key, 0, &j_error);
  
  if(!jwk) {
    printf("Failed to load JWK (%s)\n", j_error.text);
    return 0;
  }


  jwe = parse_compact(compact_jwe);
  
  if(!jwe) {
    printf("Failed to load JWE (%s)\n", j_error.text);
    return 0;
  }

  printf("Key:%s\n", json_dumps(jwk,0));
  printf("JWE:%s\n", json_dumps(jwe,0)); 
  printf("Key:%s (len:%ld)\n", json_string_value(json_object_get(jwk, "k")), strlen(json_string_value(json_object_get(jwk,"k"))));
  printf("Ciphertext:%s (len:%ld)\n", json_string_value(json_object_get(jwe, "ciphertext")), strlen(json_string_value(json_object_get(jwe,"ciphertext"))));
	 
  
  size_t out_size;
  char * output = jose_jwe_dec(NULL, jwe, NULL, jwk, &out_size);
  if(!output) {
    printf("Cannot decode JWE\n");
    return 0;
  }
  
  printf("output size:%ld\n",out_size);
  printf("Output:%s\n", output);

  
  // printf("Destination:%s\n", destination);
  // printf("bytes read:%ld\n",bytes_read);
  // printf("JSON TYPE:%d\n", json_typeof(jwe));
  // char * json_str = json_dumps(jwe,0);
  // if (json_str) {
  //   printf("%s\n", json_dumps(jwe, 0));
  // }
  // else {
  //   printf("JSON conversion failed:%d (%s)", errno, strerror(errno));
  // }
}
