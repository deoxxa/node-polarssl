#include <polarssl/error.h>

#include "hash.h"

int PolarSSL::Hash::Initialise(const char* name) {
  int rc;

  memset(&md_ctx, 0, sizeof(md_context_t));

  md_info = md_info_from_string(name);
  if (md_info == NULL) {
    errstr = "no such hash type found";
    return 1;
  }

  rc = md_init_ctx(&md_ctx, md_info);
  if (rc != 0) {
    return rc;
  }

  rc = md_starts(&md_ctx);
  if (rc != 0) {
    return rc;
  }

  return 0;
}

void PolarSSL::Hash::Init(v8::Handle<v8::Object> target) {
  v8::Local<v8::FunctionTemplate> constructorTemplate = v8::FunctionTemplate::New(New);

  constructorTemplate->SetClassName(v8::String::NewSymbol("Hash"));

  constructorTemplate->InstanceTemplate()->SetInternalFieldCount(1);

  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("update"), v8::FunctionTemplate::New(Update)->GetFunction());
  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("updateAsync"), v8::FunctionTemplate::New(UpdateAsync)->GetFunction());
  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("digest"), v8::FunctionTemplate::New(Digest)->GetFunction());
  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("digestAsync"), v8::FunctionTemplate::New(DigestAsync)->GetFunction());

  v8::Persistent<v8::Function> constructor = v8::Persistent<v8::Function>::New(constructorTemplate->GetFunction());

  target->Set(v8::String::NewSymbol("Hash"), constructor);

  target->Set(v8::String::NewSymbol("getHashes"), v8::FunctionTemplate::New(GetHashes)->GetFunction());
}

NAN_METHOD(PolarSSL::Hash::New) {
  NanScope();

  Hash* hash = new PolarSSL::Hash();

  char* md_name = NanFromV8String(args[0]->ToString());
  int rc = hash->Initialise(md_name);
  delete[] md_name;

  char err[1024];

  if (rc != 0) {
    if (hash->errstr) {
      NanThrowError(hash->errstr);
    } else {
      polarssl_strerror(rc, err, sizeof(err));
      NanThrowError(err);
    }
    NanReturnUndefined();
  }

  hash->Wrap(args.This());

  NanReturnValue(args.This());
}

NAN_METHOD(PolarSSL::Hash::Update) {
  NanScope();

  Hash* hash = node::ObjectWrap::Unwrap<Hash>(args.This());

  char err[1024];

  v8::Local<v8::Value> buffer = args[0]->ToObject();

  if (!node::Buffer::HasInstance(buffer)) {
    NanThrowError("first argument must be a buffer");
    NanReturnUndefined();
  }

  int rc = md_update(&(hash->md_ctx), reinterpret_cast<const unsigned char*>(node::Buffer::Data(buffer)), node::Buffer::Length(buffer));

  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  NanReturnValue(args.This());
}

NAN_METHOD(PolarSSL::Hash::UpdateAsync) {
  NanScope();

  Hash* hash = node::ObjectWrap::Unwrap<Hash>(args.This());

  v8::Local<v8::Value> buffer = args[0]->ToObject();

  if (!node::Buffer::HasInstance(buffer)) {
    NanThrowError("first argument must be a buffer");
    NanReturnUndefined();
  }

  NanCallback* callback = new NanCallback(args[1].As<v8::Function>());

  size_t data_length;
  char* data;

  data = static_cast<char*>(NanRawString(buffer, Nan::BINARY, &data_length, NULL, 0, 0));

  NanAsyncQueueWorker(new HashUpdateWorker(callback, hash, data, data_length));
  NanReturnUndefined();
}

void PolarSSL::HashUpdateWorker::Execute() {
  // char err[1024];

  int rc = md_update(&(hash->md_ctx), reinterpret_cast<const unsigned char*>(data), data_length);

  if (rc != 0) {
    // polarssl_strerror(rc, err, sizeof(err));
    errmsg = "error updating hash context with data";
  }

  delete[] data;
}

NAN_METHOD(PolarSSL::Hash::Digest) {
  NanScope();

  Hash* hash = node::ObjectWrap::Unwrap<Hash>(args.This());

  char err[1024];

  unsigned char sum[POLARSSL_MD_MAX_SIZE];

  int rc = md_finish(&(hash->md_ctx), sum);

  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  NanReturnValue(NanNewBufferHandle(reinterpret_cast<char*>(sum), hash->md_info->size));
}

NAN_METHOD(PolarSSL::Hash::DigestAsync) {
  NanScope();

  Hash* hash = node::ObjectWrap::Unwrap<Hash>(args.This());

  NanCallback* callback = new NanCallback(args[0].As<v8::Function>());

  NanAsyncQueueWorker(new HashDigestWorker(callback, hash));
  NanReturnUndefined();
}

void PolarSSL::HashDigestWorker::Execute() {
  // char err[1024];

  int rc = md_finish(&(hash->md_ctx), sum);

  if (rc != 0) {
    // polarssl_strerror(rc, err, sizeof(err));
    errmsg = "error getting final digest";
  }
}

void PolarSSL::HashDigestWorker::HandleOKCallback() {
  NanScope();

  v8::Local<v8::Value> argv[] = {
    v8::Local<v8::Value>::New(v8::Null()),
    NanNewBufferHandle(reinterpret_cast<char*>(sum), hash->md_info->size),
  };

  callback->Call(2, argv);
}

NAN_METHOD(PolarSSL::Hash::GetHashes) {
  NanScope();

  const int* digestTypes = md_list();
  int i;

  for (i=0;digestTypes[i]!=0;++i) {}

  v8::Handle<v8::Array> array = v8::Array::New(i);

  const md_info_t* info;
  const char* name;

  for (i=0;digestTypes[i]!=0;++i) {
    info = md_info_from_type(static_cast<md_type_t>(digestTypes[i]));
    if (info == NULL) {
      NanThrowError("error getting type info");
      NanReturnUndefined();
    }

    name = md_get_name(info);
    if (name == NULL) {
      NanThrowError("error getting name from type");
      NanReturnUndefined();
    }

    array->Set(i, v8::String::New(name));
  }

  NanReturnValue(array);
}
