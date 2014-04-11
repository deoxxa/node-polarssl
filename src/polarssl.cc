#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/rsa.h>
#include <polarssl/pk.h>

#include <node.h>
#include <nan.h>

#include <string>

using namespace v8;
using namespace node;

class polarssl_rsa_gen_key_worker : public NanAsyncWorker {
public:
  polarssl_rsa_gen_key_worker(NanCallback* callback, int bits) : NanAsyncWorker(callback),keySize(bits),privateKeyLength(16384),publicKeyLength(16384) {}
  ~polarssl_rsa_gen_key_worker() {}

  void Execute();

protected:
  void HandleOKCallback();

  int keySize;
  size_t privateKeyLength;
  size_t publicKeyLength;
  unsigned char privateKeyData[16384];
  unsigned char publicKeyData[16384];
};

void polarssl_rsa_gen_key_worker::Execute() {
  int rc;

  pk_context key;
  entropy_context entropy;
  ctr_drbg_context ctr_drbg;
  char pers[] = "rsa_genkey";

  entropy_init(&entropy);

  if ((rc = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned char *) pers, strlen(pers))) != 0) {
    errmsg = strdup("couldn't initialise random number generator");
    return;
  }

  pk_init(&key);

  if ((rc = pk_init_ctx(&key, pk_info_from_type(POLARSSL_PK_RSA))) != 0) {
    printf("err: %d\n", rc);
    errmsg = strdup("couldn't initialise key pair context");
    return;
  }

  rsa_init(pk_rsa(key), RSA_PKCS_V15, 0);
  if ((rc = rsa_gen_key(pk_rsa(key), ctr_drbg_random, &ctr_drbg, keySize, 65537)) != 0) {
    errmsg = strdup("couldn't generate key");
    return;
  }

  memset(privateKeyData, 0, 16384);
  memset(publicKeyData,  0, 16384);

  if ((rc = pk_write_key_pem(&key, privateKeyData, privateKeyLength)) < 0) {
    errmsg = strdup("couldn't serialise private key");
    return;
  }
  privateKeyLength = strlen(reinterpret_cast<const char*>(privateKeyData));

  if ((rc = pk_write_pubkey_pem(&key, publicKeyData, publicKeyLength)) < 0) {
    errmsg = strdup("couldn't serialise public key");
    return;
  }
  publicKeyLength = strlen(reinterpret_cast<const char*>(publicKeyData));

  pk_free(&key);
  entropy_free(&entropy);
}

void polarssl_rsa_gen_key_worker::HandleOKCallback() {
  NanScope();

  Local< Object > object = Object::New();

  char* privateKeyDataCopy = new char[privateKeyLength];
  char* publicKeyDataCopy  = new char[publicKeyLength];

  memcpy(privateKeyDataCopy, privateKeyData, privateKeyLength);
  memcpy(publicKeyDataCopy,  publicKeyData,  publicKeyLength);

  object->Set(String::NewSymbol("private"), String::New(privateKeyDataCopy, privateKeyLength));
  object->Set(String::NewSymbol("public"),  String::New(publicKeyDataCopy,  publicKeyLength));

  Local< Value > argv[] = {
    Local< Value >::New(Null()),
    object,
  };

  callback->Call(2, argv);
}

NAN_METHOD(polarssl_rsa_gen_key) {
  NanScope();

  int keySize = args[0]->Uint32Value();
  NanCallback *callback = new NanCallback(args[1].As<Function>());

  NanAsyncQueueWorker(new polarssl_rsa_gen_key_worker(callback, keySize));

  NanReturnUndefined();
}

void InitAll(Handle< Object > exports) {
  exports->Set(NanSymbol("rsa_gen_key"), FunctionTemplate::New(polarssl_rsa_gen_key)->GetFunction());
}

NODE_MODULE(polarssl, InitAll)
