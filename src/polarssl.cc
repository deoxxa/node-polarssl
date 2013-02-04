#include <polarssl/config.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/bignum.h>
#include <polarssl/x509write.h>
#include <polarssl/rsa.h>

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

using namespace v8;
using namespace node;

Handle<Value> rsa_gen(const Arguments& args) {
  HandleScope scope;

  int key_len = 1024;

  /** check arguments */

  if (args.Length() > 0) {
    if (!args[0]->IsNumber()) {
      return scope.Close(Null());
    }

    key_len = args[0]->NumberValue();
  }

  /** arguments sane (hopefully) */

  /** start rsa stuff */

  int ret;

  rsa_context rsa;
  entropy_context entropy;
  ctr_drbg_context ctr_drbg;
  char pers[] = "rsa_genkey";

  entropy_init(&entropy);
  if ((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned char *) pers, strlen(pers))) != 0) {
    return scope.Close(Null());
  }

  rsa_init(&rsa, RSA_PKCS_V15, 0);

  if ((ret = rsa_gen_key(&rsa, ctr_drbg_random, &ctr_drbg, key_len, 65537)) != 0) {
    return scope.Close(Null());
  }

  /** rsa stuff done */

  /** create object representation */

  char data[16384]; // hope this is enough to store all keys :/
  memset(data, 0, 16384);
  size_t data_len = 16384;
  int r;

  Local< Object > object = Object::New();

  r = x509_write_key_der((unsigned char*)data, data_len, &rsa);
  Buffer* buffer_private = Buffer::New(r);
  memcpy(Buffer::Data(buffer_private), data + 16384 - r, r);
  object->Set(String::NewSymbol("private"), buffer_private->handle_);

  r = x509_write_pubkey_der((unsigned char*)data, data_len, &rsa);
  Buffer* buffer_public = Buffer::New(r);
  memcpy(Buffer::Data(buffer_public), data + 16384 - r, r);
  object->Set(String::NewSymbol("public"), buffer_public->handle_);

  /** object representation done */

  return scope.Close(object);
}

void init(Handle<Object> target) {
  target->Set(String::NewSymbol("rsa_gen"), FunctionTemplate::New(rsa_gen)->GetFunction());
}
NODE_MODULE(polarssl, init)
