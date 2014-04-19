#include <node.h>

#include "hash.h"
#include "hmac.h"
#include "keygen.h"
#include "key-rsa.h"
#include "random.h"

void InitAll(v8::Handle<v8::Object> exports) {
  PolarSSL::Hash::Init(exports);
  PolarSSL::HMAC::Init(exports);
  PolarSSL::Keygen::Init(exports);
  PolarSSL::KeyRSA::Init(exports);
  PolarSSL::Random::Init(exports);
}

NODE_MODULE(polarssl, InitAll)
