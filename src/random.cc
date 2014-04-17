#include <polarssl/error.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#include "random.h"

void PolarSSL::Random::Init(v8::Handle<v8::Object> target) {
  target->Set(v8::String::NewSymbol("randomBytes"), v8::FunctionTemplate::New(RandomBytes)->GetFunction());
}

NAN_METHOD(PolarSSL::Random::RandomBytes) {
  NanScope();

  char err[1024];
  int rc;

  ctr_drbg_context ctr_drbg;
  entropy_context entropy;

  entropy_init(&entropy);

  rc = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char *)"RANDOM_GEN", 10);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }
  ctr_drbg_set_prediction_resistance(&ctr_drbg, CTR_DRBG_PR_OFF);

  int bytes = args[0]->Uint32Value();

  unsigned char* data = new unsigned char[bytes];

  rc = ctr_drbg_random(&ctr_drbg, data, bytes);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  NanReturnValue(NanNewBufferHandle(reinterpret_cast<char*>(data), bytes));
}
