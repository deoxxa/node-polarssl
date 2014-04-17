#include <node.h>
#include <nan.h>

#ifndef NODE_POLARSSL_RANDOM_H
#define NODE_POLARSSL_RANDOM_H

namespace PolarSSL {
  class Random : public node::ObjectWrap {
  public:
    static void Init(v8::Handle<v8::Object> target);

  private:
    Random() {}
    ~Random() {}

    static NAN_METHOD(RandomBytes);
  };
};

#endif
