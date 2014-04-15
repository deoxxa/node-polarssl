#include <node.h>

#include "hash.h"
#include "keygen.h"
#include "key-rsa.h"

void InitAll(v8::Handle<v8::Object> exports) {
  PolarSSL::Hash::Init(exports);
  PolarSSL::Keygen::Init(exports);
  PolarSSL::KeyRSA::Init(exports);
}

NODE_MODULE(polarssl, InitAll)
