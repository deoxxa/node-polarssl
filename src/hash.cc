#include "hash.h"

int PolarSSL::Hash::Initialise(const char* md_name) {
  int rc;

  memset(&md_ctx, 0, sizeof(md_context_t));

  md_info = md_info_from_string(md_name);
  if (md_info == NULL) {
    err = "no such hash found";
    return 1;
  }

  rc = md_init_ctx(&md_ctx, md_info);
  if (rc != 0) {
    err = "error initiaising hash context";
    return 1;
  }

  rc = md_starts(&md_ctx);
  if (rc != 0) {
    err = "error starting hash context";
    return 1;
  }

  return 0;
}

void PolarSSL::Hash::Init(v8::Handle<v8::Object> target) {
  v8::Local<v8::FunctionTemplate> constructorTemplate = v8::FunctionTemplate::New(New);

  constructorTemplate->SetClassName(v8::String::NewSymbol("Hash"));

  constructorTemplate->InstanceTemplate()->SetInternalFieldCount(1);

  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("update"), v8::FunctionTemplate::New(Update)->GetFunction());
  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("digest"), v8::FunctionTemplate::New(Digest)->GetFunction());

  v8::Persistent<v8::Function> constructor = v8::Persistent<v8::Function>::New(constructorTemplate->GetFunction());

  target->Set(v8::String::NewSymbol("Hash"), constructor);
}

NAN_METHOD(PolarSSL::Hash::New) {
  NanScope();

  Hash* hash = new PolarSSL::Hash();

  char* md_name = NanFromV8String(args[0]->ToString());
  int rc = hash->Initialise(md_name);
  delete[] md_name;

  if (rc != 0) {
    NanThrowError(hash->err);
    NanReturnUndefined();
  }

  hash->Wrap(args.This());

  NanReturnValue(args.This());
}

NAN_METHOD(PolarSSL::Hash::Update) {
  NanScope();

  Hash* hash = node::ObjectWrap::Unwrap<Hash>(args.This());

  v8::Local<v8::Value> buffer = args[0]->ToObject();

  if (!node::Buffer::HasInstance(buffer)) {
    NanThrowError("first argument must be a buffer");
    NanReturnUndefined();
  }

  int rc = md_update(&(hash->md_ctx), reinterpret_cast<unsigned char*>(node::Buffer::Data(buffer)), node::Buffer::Length(buffer));

  if (rc != 0) {
    NanThrowError("error processing data to be hashed");
    NanReturnUndefined();
  }

  NanReturnValue(args.This());
}

NAN_METHOD(PolarSSL::Hash::Digest) {
  NanScope();

  Hash* hash = node::ObjectWrap::Unwrap<Hash>(args.This());

  int rc = md_finish(&(hash->md_ctx), hash->sum);

  if (rc != 0) {
    NanThrowError("error calculating final digest");
    NanReturnUndefined();
  }

  NanReturnValue(NanNewBufferHandle(reinterpret_cast<char*>(hash->sum), hash->md_info->size));
}
