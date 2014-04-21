#include <polarssl/error.h>

#include "cipher.h"

int PolarSSL::Cipher::Initialise(const char* name, const unsigned char* key, size_t key_len, const unsigned char* iv, size_t iv_len, operation_t operation) {
  int rc;

  memset(&cipher_ctx, 0, sizeof(cipher_context_t));

  cipher_info = cipher_info_from_string(name);
  if (cipher_info == NULL) {
    errstr = "no such cipher found";
    return 1;
  }

  rc = cipher_init_ctx(&cipher_ctx, cipher_info);
  if (rc != 0) {
    return rc;
  }

  rc = cipher_setkey(&cipher_ctx, key, key_len, operation);
  if (rc != 0) {
    return rc;
  }

  rc = cipher_set_iv(&cipher_ctx, iv, iv_len);
  if (rc != 0) {
    return rc;
  }

  rc = cipher_reset(&cipher_ctx);
  if (rc != 0) {
    return rc;
  }

  return 0;
}

void PolarSSL::Cipher::Init(v8::Handle<v8::Object> target) {
  v8::Local<v8::FunctionTemplate> constructorTemplate = v8::FunctionTemplate::New(New);

  constructorTemplate->SetClassName(v8::String::NewSymbol("Cipher"));

  constructorTemplate->InstanceTemplate()->SetInternalFieldCount(1);

  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("update"), v8::FunctionTemplate::New(Update)->GetFunction());
  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("updateAsync"), v8::FunctionTemplate::New(UpdateAsync)->GetFunction());
  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("final"), v8::FunctionTemplate::New(Final)->GetFunction());
  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("finalAsync"), v8::FunctionTemplate::New(FinalAsync)->GetFunction());

  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("name"), GetName);
  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("keySize"), GetKeySize);
  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("ivSize"), GetIVSize);
  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("blockSize"), GetBlockSize);

  v8::Persistent<v8::Function> constructor = v8::Persistent<v8::Function>::New(constructorTemplate->GetFunction());

  target->Set(v8::String::NewSymbol("Cipher"), constructor);

  target->Set(v8::String::NewSymbol("getCiphers"), v8::FunctionTemplate::New(GetCiphers)->GetFunction());
}

NAN_METHOD(PolarSSL::Cipher::New) {
  NanScope();

  Cipher* cipher = new PolarSSL::Cipher();

  size_t name_length;
  char* name = static_cast<char*>(NanRawString(args[0]->ToString(), Nan::BINARY, &name_length, NULL, 0, 0));

  int rc = cipher->Initialise(name, reinterpret_cast<unsigned char*>(node::Buffer::Data(args[1]->ToObject())), node::Buffer::Length(args[1]->ToObject()), reinterpret_cast<unsigned char*>(node::Buffer::Data(args[2]->ToObject())), node::Buffer::Length(args[2]->ToObject()), static_cast<operation_t>(args[3]->Int32Value()));

  delete[] name;

  char err[1024];

  if (rc != 0) {
    if (cipher->errstr) {
      NanThrowError(cipher->errstr);
    } else {
      polarssl_strerror(rc, err, sizeof(err));
      NanThrowError(err);
    }
    NanReturnUndefined();
  }

  cipher->Wrap(args.This());

  NanReturnValue(args.This());
}

NAN_METHOD(PolarSSL::Cipher::Update) {
  NanScope();

  Cipher* cipher = node::ObjectWrap::Unwrap<Cipher>(args.This());

  char err[1024];

  v8::Local<v8::Value> buffer = args[0]->ToObject();

  if (!node::Buffer::HasInstance(buffer)) {
    NanThrowError("first argument must be a buffer");
    NanReturnUndefined();
  }

  size_t output_length = node::Buffer::Length(buffer);
  char* output = new char[output_length];

  int rc = cipher_update(&(cipher->cipher_ctx), reinterpret_cast<const unsigned char*>(node::Buffer::Data(buffer)), node::Buffer::Length(buffer), reinterpret_cast<unsigned char*>(output), &output_length);

  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  NanReturnValue(NanNewBufferHandle(output, output_length));
}

NAN_METHOD(PolarSSL::Cipher::UpdateAsync) {
  NanScope();

  Cipher* cipher = node::ObjectWrap::Unwrap<Cipher>(args.This());

  v8::Local<v8::Value> buffer = args[0]->ToObject();

  if (!node::Buffer::HasInstance(buffer)) {
    NanThrowError("first argument must be a buffer");
    NanReturnUndefined();
  }

  NanCallback* callback = new NanCallback(args[1].As<v8::Function>());

  size_t input_length, output_length;
  char *input, *output;

  input = static_cast<char*>(NanRawString(buffer, Nan::BINARY, &input_length, NULL, 0, 0));

  output_length = input_length;
  output = new char[output_length];

  NanAsyncQueueWorker(new CipherUpdateWorker(callback, cipher, input, input_length, output, output_length));
  NanReturnUndefined();
}

void PolarSSL::CipherUpdateWorker::Execute() {
  rc = cipher_update(&(cipher->cipher_ctx), reinterpret_cast<const unsigned char*>(input), input_length, reinterpret_cast<unsigned char*>(output), &output_length);

  if (rc != 0) {
    errmsg = "error updating cipher context with data";
  }

  delete[] input;
}

void PolarSSL::CipherUpdateWorker::HandleOKCallback() {
  NanScope();

  v8::Local<v8::Value> argv[] = {
    v8::Local<v8::Value>::New(v8::Null()),
    NanNewBufferHandle(reinterpret_cast<char*>(output), output_length),
  };

  delete[] output;

  callback->Call(2, argv);
}

void PolarSSL::CipherUpdateWorker::HandleErrorCallback() {
  NanScope();

  char err[1024];

  polarssl_strerror(rc, err, sizeof(err));
  NanThrowError(err);

  v8::Local<v8::Value> argv[] = {
    v8::Local<v8::Value>::New(NanError(err)),
  };

  delete[] output;

  callback->Call(1, argv);
}

NAN_METHOD(PolarSSL::Cipher::Final) {
  NanScope();

  Cipher* cipher = node::ObjectWrap::Unwrap<Cipher>(args.This());

  char err[1024];

  size_t output_length = cipher_get_block_size(&(cipher->cipher_ctx));
  char* output = new char[output_length];

  int rc = cipher_finish(&(cipher->cipher_ctx), reinterpret_cast<unsigned char*>(output), &output_length);

  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  NanReturnValue(NanNewBufferHandle(output, output_length));
}

NAN_METHOD(PolarSSL::Cipher::FinalAsync) {
  NanScope();

  Cipher* cipher = node::ObjectWrap::Unwrap<Cipher>(args.This());

  NanCallback* callback = new NanCallback(args[0].As<v8::Function>());

  size_t output_length;
  char* output;

  output_length = cipher_get_block_size(&(cipher->cipher_ctx));
  output = new char[output_length];

  NanAsyncQueueWorker(new CipherFinalWorker(callback, cipher, output, output_length));
  NanReturnUndefined();
}

void PolarSSL::CipherFinalWorker::Execute() {
  rc = cipher_finish(&(cipher->cipher_ctx), reinterpret_cast<unsigned char*>(output), &output_length);

  if (rc != 0) {
    errmsg = "error updating cipher context with data";
  }
}

void PolarSSL::CipherFinalWorker::HandleOKCallback() {
  NanScope();

  v8::Local<v8::Value> argv[] = {
    v8::Local<v8::Value>::New(v8::Null()),
    NanNewBufferHandle(reinterpret_cast<char*>(output), output_length),
  };

  delete[] output;

  callback->Call(2, argv);
}

void PolarSSL::CipherFinalWorker::HandleErrorCallback() {
  NanScope();

  char err[1024];

  polarssl_strerror(rc, err, sizeof(err));
  NanThrowError(err);

  v8::Local<v8::Value> argv[] = {
    v8::Local<v8::Value>::New(NanError(err)),
  };

  delete[] output;

  callback->Call(1, argv);
}

NAN_GETTER(PolarSSL::Cipher::GetName) {
  NanScope();

  PolarSSL::Cipher* cipher = node::ObjectWrap::Unwrap<PolarSSL::Cipher>(args.This());

  const char* name = cipher_get_name(&(cipher->cipher_ctx));

  if (name == NULL) {
    NanReturnUndefined();
  }

  NanReturnValue(v8::String::New(name));
}

NAN_GETTER(PolarSSL::Cipher::GetKeySize) {
  NanScope();

  PolarSSL::Cipher* cipher = node::ObjectWrap::Unwrap<PolarSSL::Cipher>(args.This());

  int size = cipher_get_key_size(&(cipher->cipher_ctx));

  if (size == POLARSSL_KEY_LENGTH_NONE) {
    NanReturnUndefined();
  }

  NanReturnValue(v8::Number::New(size / 8));
}

NAN_GETTER(PolarSSL::Cipher::GetIVSize) {
  NanScope();

  PolarSSL::Cipher* cipher = node::ObjectWrap::Unwrap<PolarSSL::Cipher>(args.This());

  int size = cipher_get_iv_size(&(cipher->cipher_ctx));

  NanReturnValue(v8::Number::New(size));
}

NAN_GETTER(PolarSSL::Cipher::GetBlockSize) {
  NanScope();

  PolarSSL::Cipher* cipher = node::ObjectWrap::Unwrap<PolarSSL::Cipher>(args.This());

  unsigned int size = cipher_get_block_size(&(cipher->cipher_ctx));

  NanReturnValue(v8::Number::New(size));
}

NAN_METHOD(PolarSSL::Cipher::GetCiphers) {
  NanScope();

  const int* cipherTypes = cipher_list();
  int i;

  for (i=0;cipherTypes[i]!=0;++i) {}

  v8::Handle<v8::Array> array = v8::Array::New(i);

  const cipher_info_t* info;

  for (i=0;cipherTypes[i]!=0;++i) {
    info = cipher_info_from_type(static_cast<cipher_type_t>(cipherTypes[i]));
    if (info == NULL) {
      NanThrowError("error getting type info");
      NanReturnUndefined();
    }

    if (info->name == NULL) {
      NanThrowError("cipher didn't have a name");
      NanReturnUndefined();
    }

    array->Set(i, v8::String::New(info->name));
  }

  NanReturnValue(array);
}
