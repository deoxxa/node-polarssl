#include <polarssl/md.h>

#include <node.h>
#include <nan.h>

#ifndef NODE_POLARSSL_HMAC_H
#define NODE_POLARSSL_HMAC_H

namespace PolarSSL {
  class HMAC : public node::ObjectWrap {
  public:
    static void Init(v8::Handle<v8::Object> target);

    const md_info_t* md_info;
    md_context_t md_ctx;

  private:
    HMAC() : errstr(NULL) {}
    ~HMAC() {}

    int Initialise(const char* name, const unsigned char* key, size_t key_length);

    static NAN_METHOD(New);
    static NAN_METHOD(Update);
    static NAN_METHOD(UpdateAsync);
    static NAN_METHOD(Digest);
    static NAN_METHOD(DigestAsync);

    const char* errstr;
  };

  class HMACUpdateWorker : public NanAsyncWorker {
  public:
    HMACUpdateWorker(NanCallback* callback, HMAC* hmac, const char* data, size_t data_length) : NanAsyncWorker(callback),hmac(hmac),data(data),data_length(data_length) {}
    ~HMACUpdateWorker() {}
    void Execute();
  private:
    HMAC* hmac;
    const char* data;
    size_t data_length;
  };

  class HMACDigestWorker : public NanAsyncWorker {
  public:
    HMACDigestWorker(NanCallback* callback, HMAC* hmac) : NanAsyncWorker(callback),hmac(hmac) {}
    ~HMACDigestWorker() {}
    void Execute();
    void HandleOKCallback();
  private:
    HMAC* hmac;
    unsigned char sum[POLARSSL_MD_MAX_SIZE];
  };
};

#endif
