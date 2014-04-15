#include <polarssl/md.h>

#include <node.h>
#include <nan.h>

#ifndef NODE_POLARSSL_HASH_H
#define NODE_POLARSSL_HASH_H

namespace PolarSSL {
  class Hash : public node::ObjectWrap {
  public:
    static void Init(v8::Handle<v8::Object> target);

  private:
    Hash() : errstr(NULL) {}
    ~Hash() {}

    int Initialise(const char* md_name);

    static NAN_METHOD(New);
    static NAN_METHOD(Update);
    static NAN_METHOD(Digest);

    const char* errstr;
    const md_info_t* md_info;
    md_context_t md_ctx;
    unsigned char sum[POLARSSL_MD_MAX_SIZE];
  };
};

#endif
