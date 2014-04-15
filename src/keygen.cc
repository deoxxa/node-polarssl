#include <polarssl/error.h>

#include "key-rsa.h"

#include "keygen.h"

int PolarSSL::Keygen::Initialise() {
  int rc;

  entropy_init(&entropy);

  rc = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, NULL, 0);

  if (rc != 0) {
    return rc;
  }

  return 0;
}

void PolarSSL::Keygen::Init(v8::Handle<v8::Object> target) {
  v8::Local<v8::FunctionTemplate> constructorTemplate = v8::FunctionTemplate::New(New);

  constructorTemplate->SetClassName(v8::String::NewSymbol("Keygen"));

  constructorTemplate->InstanceTemplate()->SetInternalFieldCount(1);

  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("generateKey"), v8::FunctionTemplate::New(GenerateKey)->GetFunction());

  v8::Persistent<v8::Function> constructor = v8::Persistent<v8::Function>::New(constructorTemplate->GetFunction());

  target->Set(v8::String::NewSymbol("Keygen"), constructor);
}

NAN_METHOD(PolarSSL::Keygen::New) {
  NanScope();

  Keygen* keygen = new PolarSSL::Keygen();

  char err[1024];

  int rc = keygen->Initialise();

  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  keygen->Wrap(args.This());

  NanReturnValue(args.This());
}

NAN_METHOD(PolarSSL::Keygen::GenerateKey) {
  NanScope();

  char err[1024];

  int rc;

  Keygen* keygen = node::ObjectWrap::Unwrap<Keygen>(args.This());

  v8::Handle<v8::Object> keyObject = KeyRSA::NewInstance();

  KeyRSA* key = node::ObjectWrap::Unwrap<KeyRSA>(keyObject);

  const pk_info_t* pk_info = pk_info_from_type(POLARSSL_PK_RSA);
  if (pk_info == NULL) {
    NanThrowError("couldn't get pk_info for some reason");
    NanReturnUndefined();
  }

  rc = rsa_gen_key(&(key->ctx), ctr_drbg_random, &(keygen->ctr_drbg), 1024, 65537);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  NanReturnValue(keyObject);
}
