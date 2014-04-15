#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/pk.h>

#include <node.h>
#include <nan.h>

#ifndef NODE_POLARSSL_KEYGEN_H
#define NODE_POLARSSL_KEYGEN_H

namespace PolarSSL {
  class Keygen : public node::ObjectWrap {
  public:
    static void Init(v8::Handle<v8::Object> target);

  private:
    Keygen() : errstr(NULL) {}
    ~Keygen() {}

    int Initialise();

    static NAN_METHOD(New);
    static NAN_METHOD(GenerateKey);

    const char* errstr;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
  };
};

#endif
