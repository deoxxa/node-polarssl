#include <polarssl/cipher.h>

#include <node.h>
#include <nan.h>

#ifndef NODE_POLARSSL_CIPHER_H
#define NODE_POLARSSL_CIPHER_H

namespace PolarSSL {
  class Cipher : public node::ObjectWrap {
  public:
    static void Init(v8::Handle<v8::Object> target);

    const cipher_info_t* cipher_info;
    cipher_context_t cipher_ctx;

  private:
    Cipher() : errstr(NULL) {}
    ~Cipher() {}

    int Initialise(const char* name, const unsigned char* key, size_t key_len, const unsigned char* iv, size_t iv_len, operation_t operation);

    static NAN_METHOD(New);
    static NAN_METHOD(Update);
    static NAN_METHOD(UpdateAsync);
    static NAN_METHOD(Final);
    static NAN_METHOD(FinalAsync);
    static NAN_METHOD(GetCiphers);
    static NAN_GETTER(GetName);
    static NAN_GETTER(GetKeySize);
    static NAN_GETTER(GetIVSize);
    static NAN_GETTER(GetBlockSize);

    const char* errstr;
  };

  class CipherUpdateWorker : public NanAsyncWorker {
  public:
    CipherUpdateWorker(NanCallback* callback, Cipher* cipher, char* input, size_t input_length, char* output, size_t output_length) : NanAsyncWorker(callback),cipher(cipher),input(input),input_length(input_length),output(output),output_length(output_length) {}
    ~CipherUpdateWorker() {}
    void Execute();
    void HandleOKCallback();
  private:
    Cipher* cipher;
    int rc;
    char* input;
    size_t input_length;
    char* output;
    size_t output_length;
  };

  class CipherFinalWorker : public NanAsyncWorker {
  public:
    CipherFinalWorker(NanCallback* callback, Cipher* cipher, char* output, size_t output_length) : NanAsyncWorker(callback),cipher(cipher),output(output),output_length(output_length) {}
    ~CipherFinalWorker() {}
    void Execute();
    void HandleOKCallback();
  private:
    Cipher* cipher;
    int rc;
    char* output;
    size_t output_length;
  };
};

#endif
