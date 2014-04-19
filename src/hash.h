#include <polarssl/md.h>

#include <node.h>
#include <nan.h>

#ifndef NODE_POLARSSL_HASH_H
#define NODE_POLARSSL_HASH_H

namespace PolarSSL {
  class Hash : public node::ObjectWrap {
  public:
    static void Init(v8::Handle<v8::Object> target);

    const md_info_t* md_info;
    md_context_t md_ctx;

  private:
    Hash() : errstr(NULL) {}
    ~Hash() {}

    int Initialise(const char* name);

    static NAN_METHOD(New);
    static NAN_METHOD(Update);
    static NAN_METHOD(UpdateAsync);
    static NAN_METHOD(Digest);
    static NAN_METHOD(DigestAsync);
    static NAN_METHOD(GetHashes);

    const char* errstr;
  };

  class HashUpdateWorker : public NanAsyncWorker {
  public:
    HashUpdateWorker(NanCallback* callback, Hash* hash, const char* data, size_t data_length) : NanAsyncWorker(callback),hash(hash),data(data),data_length(data_length) {}
    ~HashUpdateWorker() {}
    void Execute();
  private:
    Hash* hash;
    const char* data;
    size_t data_length;
  };

  class HashDigestWorker : public NanAsyncWorker {
  public:
    HashDigestWorker(NanCallback* callback, Hash* hash) : NanAsyncWorker(callback),hash(hash) {}
    ~HashDigestWorker() {}
    void Execute();
    void HandleOKCallback();
  private:
    Hash* hash;
    unsigned char sum[POLARSSL_MD_MAX_SIZE];
  };
};

#endif
