#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/rsa.h>

#include <node.h>
#include <nan.h>

#ifndef NODE_POLARSSL_KEYRSA_H
#define NODE_POLARSSL_KEYRSA_H

namespace PolarSSL {
  class KeyRSA : public node::ObjectWrap {
  public:
    static void Init(v8::Handle<v8::Object> target);
    static v8::Handle<v8::Object> NewInstance();

    rsa_context ctx;

  private:
    KeyRSA() {}
    ~KeyRSA() {}

    int Initialise();

    static NAN_METHOD(New);
    static NAN_GETTER(GetN);
    static NAN_SETTER(SetN);
    static NAN_GETTER(GetE);
    static NAN_SETTER(SetE);
    static NAN_GETTER(GetD);
    static NAN_SETTER(SetD);
    static NAN_GETTER(GetP);
    static NAN_SETTER(SetP);
    static NAN_GETTER(GetQ);
    static NAN_SETTER(SetQ);
    static NAN_GETTER(GetDP);
    static NAN_SETTER(SetDP);
    static NAN_GETTER(GetDQ);
    static NAN_SETTER(SetDQ);
    static NAN_GETTER(GetQP);
    static NAN_SETTER(SetQP);

    static v8::Persistent<v8::Function> constructor;
  };
};

#endif
