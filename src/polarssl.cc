#include <node.h>

#include "hash.h"

void InitAll(v8::Handle<v8::Object> exports) {
  PolarSSL::Hash::Init(exports);
}

NODE_MODULE(polarssl, InitAll)
