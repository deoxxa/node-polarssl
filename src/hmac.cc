#include <polarssl/error.h>

#include "hmac.h"

int PolarSSL::HMAC::Initialise(const char* name, const unsigned char* key, size_t key_length) {
  int rc;

  memset(&md_ctx, 0, sizeof(md_context_t));

  md_info = md_info_from_string(name);
  if (md_info == NULL) {
    errstr = "no such hmac type found";
    return 1;
  }

  rc = md_init_ctx(&md_ctx, md_info);
  if (rc != 0) {
    return rc;
  }

  rc = md_hmac_starts(&md_ctx, key, key_length);
  if (rc != 0) {
    return rc;
  }

  return 0;
}

void PolarSSL::HMAC::Init(v8::Handle<v8::Object> target) {
  v8::Local<v8::FunctionTemplate> constructorTemplate = v8::FunctionTemplate::New(New);

  constructorTemplate->SetClassName(v8::String::NewSymbol("HMAC"));

  constructorTemplate->InstanceTemplate()->SetInternalFieldCount(1);

  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("update"), v8::FunctionTemplate::New(Update)->GetFunction());
  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("updateAsync"), v8::FunctionTemplate::New(UpdateAsync)->GetFunction());
  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("digest"), v8::FunctionTemplate::New(Digest)->GetFunction());
  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("digestAsync"), v8::FunctionTemplate::New(DigestAsync)->GetFunction());

  v8::Persistent<v8::Function> constructor = v8::Persistent<v8::Function>::New(constructorTemplate->GetFunction());

  target->Set(v8::String::NewSymbol("HMAC"), constructor);
}

NAN_METHOD(PolarSSL::HMAC::New) {
  NanScope();

  HMAC* hmac = new PolarSSL::HMAC();

  size_t name_length;
  char* name = NanCString(args[0]->ToString(), &name_length);

  v8::Local<v8::Value> buffer = args[1]->ToObject();
  if (!node::Buffer::HasInstance(buffer)) {
    NanThrowError("key must be a buffer");
    NanReturnUndefined();
  }

  int rc = hmac->Initialise(name, reinterpret_cast<unsigned char*>(node::Buffer::Data(buffer)), node::Buffer::Length(buffer));

  delete[] name;

  char err[1024];

  if (rc != 0) {
    if (hmac->errstr) {
      NanThrowError(hmac->errstr);
    } else {
      polarssl_strerror(rc, err, sizeof(err));
      NanThrowError(err);
    }
    NanReturnUndefined();
  }

  hmac->Wrap(args.This());

  NanReturnValue(args.This());
}

NAN_METHOD(PolarSSL::HMAC::Update) {
  NanScope();

  HMAC* hmac = node::ObjectWrap::Unwrap<HMAC>(args.This());

  char err[1024];

  v8::Local<v8::Value> buffer = args[0]->ToObject();

  if (!node::Buffer::HasInstance(buffer)) {
    NanThrowError("first argument must be a buffer");
    NanReturnUndefined();
  }

  int rc = md_hmac_update(&(hmac->md_ctx), reinterpret_cast<const unsigned char*>(node::Buffer::Data(buffer)), node::Buffer::Length(buffer));

  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  NanReturnValue(args.This());
}

NAN_METHOD(PolarSSL::HMAC::UpdateAsync) {
  NanScope();

  HMAC* hmac = node::ObjectWrap::Unwrap<HMAC>(args.This());

  v8::Local<v8::Value> buffer = args[0]->ToObject();

  if (!node::Buffer::HasInstance(buffer)) {
    NanThrowError("first argument must be a buffer");
    NanReturnUndefined();
  }

  NanCallback* callback = new NanCallback(args[1].As<v8::Function>());

  size_t data_length;
  char* data;

  data = static_cast<char*>(NanRawString(buffer, Nan::BINARY, &data_length, NULL, 0, 0));

  NanAsyncQueueWorker(new HMACUpdateWorker(callback, hmac, data, data_length));
  NanReturnUndefined();
}

void PolarSSL::HMACUpdateWorker::Execute() {
  // char err[1024];

  int rc = md_hmac_update(&(hmac->md_ctx), reinterpret_cast<const unsigned char*>(data), data_length);

  if (rc != 0) {
    // polarssl_strerror(rc, err, sizeof(err));
    errmsg = "error updating hmac context with data";
  }

  delete[] data;
}

NAN_METHOD(PolarSSL::HMAC::Digest) {
  NanScope();

  HMAC* hmac = node::ObjectWrap::Unwrap<HMAC>(args.This());

  char err[1024];

  unsigned char sum[POLARSSL_MD_MAX_SIZE];

  int rc = md_hmac_finish(&(hmac->md_ctx), sum);

  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  NanReturnValue(NanNewBufferHandle(reinterpret_cast<char*>(sum), hmac->md_info->size));
}

NAN_METHOD(PolarSSL::HMAC::DigestAsync) {
  NanScope();

  HMAC* hmac = node::ObjectWrap::Unwrap<HMAC>(args.This());

  NanCallback* callback = new NanCallback(args[0].As<v8::Function>());

  NanAsyncQueueWorker(new HMACDigestWorker(callback, hmac));
  NanReturnUndefined();
}

void PolarSSL::HMACDigestWorker::Execute() {
  // char err[1024];

  int rc = md_hmac_finish(&(hmac->md_ctx), sum);

  if (rc != 0) {
    // polarssl_strerror(rc, err, sizeof(err));
    errmsg = "error getting final digest";
  }
}

void PolarSSL::HMACDigestWorker::HandleOKCallback() {
  NanScope();

  v8::Local<v8::Value> argv[] = {
    v8::Local<v8::Value>::New(v8::Null()),
    NanNewBufferHandle(reinterpret_cast<char*>(sum), hmac->md_info->size),
  };

  callback->Call(2, argv);
}
