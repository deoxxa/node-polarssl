#include <polarssl/pk.h>
#include <polarssl/error.h>

#include "key-rsa.h"

v8::Persistent<v8::Function> PolarSSL::KeyRSA::constructor;

int PolarSSL::KeyRSA::Initialise() {
  memset(&ctx, 0, sizeof(ctx));

  rsa_init(&ctx, RSA_PKCS_V15, 0);

  return 0;
}

void PolarSSL::KeyRSA::Init(v8::Handle<v8::Object> target) {
  v8::Local<v8::FunctionTemplate> constructorTemplate = v8::FunctionTemplate::New(New);

  constructorTemplate->SetClassName(v8::String::NewSymbol("KeyRSA"));

  constructorTemplate->InstanceTemplate()->SetInternalFieldCount(1);

  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("format"), v8::FunctionTemplate::New(Format)->GetFunction());

  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("n"), PolarSSL::KeyRSA::GetN, PolarSSL::KeyRSA::SetN);
  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("e"), PolarSSL::KeyRSA::GetE, PolarSSL::KeyRSA::SetE);
  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("d"), PolarSSL::KeyRSA::GetD, PolarSSL::KeyRSA::SetD);
  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("p"), PolarSSL::KeyRSA::GetP, PolarSSL::KeyRSA::SetP);
  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("q"), PolarSSL::KeyRSA::GetQ, PolarSSL::KeyRSA::SetQ);
  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("dp"), PolarSSL::KeyRSA::GetDP, PolarSSL::KeyRSA::SetDP);
  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("dq"), PolarSSL::KeyRSA::GetDQ, PolarSSL::KeyRSA::SetDQ);
  constructorTemplate->PrototypeTemplate()->SetAccessor(NanSymbol("qp"), PolarSSL::KeyRSA::GetQP, PolarSSL::KeyRSA::SetQP);

  constructor = v8::Persistent<v8::Function>::New(constructorTemplate->GetFunction());

  target->Set(v8::String::NewSymbol("KeyRSA"), constructor);
}

NAN_METHOD(PolarSSL::KeyRSA::New) {
  NanScope();

  KeyRSA* key = new PolarSSL::KeyRSA();

  char err[1024];

  int rc = key->Initialise();

  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  key->Wrap(args.This());

  NanReturnValue(args.This());
}

v8::Handle<v8::Object> PolarSSL::KeyRSA::NewInstance() {
  NanScope();

  NanReturnValue(constructor->NewInstance(0, NULL));
}

NAN_METHOD(PolarSSL::KeyRSA::Format) {
  NanScope();

  char err[1024];

  int rc;

  KeyRSA* key = node::ObjectWrap::Unwrap<KeyRSA>(args.This());

  const pk_info_t* pk_info = pk_info_from_type(POLARSSL_PK_RSA);
  if (pk_info == NULL) {
    NanThrowError("couldn't get pk_info for some reason");
    NanReturnUndefined();
  }

  pk_context ctx;

  ctx.pk_info = pk_info;
  ctx.pk_ctx = &(key->ctx);

  unsigned char buf[65536];
  memset(buf, 0, 65536);

  int keyPart = 0;

  if (args.Length() >= 1) {
    size_t keyPartStringLength = 0;
    char* keyPartString = NanCString(args[0]->ToString(), &keyPartStringLength);

    if (strcmp(keyPartString, "public") == 0) {
      keyPart = 1;
    } else if (strcmp(keyPartString, "private") == 0) {
      keyPart = 2;
    } else {
      delete[] keyPartString;

      NanThrowError("first argument must be `public' or `private'");
      NanReturnUndefined();
    }

    delete[] keyPartString;
  } else {
    keyPart = 1;
  }

  if (keyPart == 1) {
    rc = pk_write_pubkey_pem(&ctx, buf, sizeof(buf));
  } else {
    rc = pk_write_key_pem(&ctx, buf, sizeof(buf));
  }

  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  v8::Local<v8::String> str = v8::String::New(reinterpret_cast<char*>(buf));

  NanReturnValue(str);
}

NAN_GETTER(PolarSSL::KeyRSA::GetN) {
  NanScope();

  char err[1024];

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  int rc;
  size_t slen;
  char* buf;

  slen = 0;

  rc = mpi_write_string(&(key->ctx.N), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf = new char[slen];

  rc = mpi_write_string(&(key->ctx.N), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf[slen] = 0;

  v8::Local<v8::String> str = v8::String::New(buf);

  delete[] buf;

  NanReturnValue(str);
}

NAN_SETTER(PolarSSL::KeyRSA::SetN) {
  NanScope();

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  size_t contentLength = 0;
  char* content = NanCString(value, &contentLength);
  mpi_read_string(&(key->ctx.N), 10, content);
  delete[] content;
}

NAN_GETTER(PolarSSL::KeyRSA::GetE) {
  NanScope();

  char err[1024];

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  int rc;
  size_t slen;
  char* buf;

  slen = 0;

  rc = mpi_write_string(&(key->ctx.E), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf = new char[slen];

  rc = mpi_write_string(&(key->ctx.E), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf[slen] = 0;

  v8::Local<v8::String> str = v8::String::New(buf);

  delete[] buf;

  NanReturnValue(str);
}

NAN_SETTER(PolarSSL::KeyRSA::SetE) {
  NanScope();

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  size_t contentLength = 0;
  char* content = NanCString(value, &contentLength);
  mpi_read_string(&(key->ctx.E), 10, content);
  delete[] content;
}

NAN_GETTER(PolarSSL::KeyRSA::GetD) {
  NanScope();

  char err[1024];

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  int rc;
  size_t slen;
  char* buf;

  slen = 0;

  rc = mpi_write_string(&(key->ctx.D), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf = new char[slen];

  rc = mpi_write_string(&(key->ctx.D), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf[slen] = 0;

  v8::Local<v8::String> str = v8::String::New(buf);

  delete[] buf;

  NanReturnValue(str);
}

NAN_SETTER(PolarSSL::KeyRSA::SetD) {
  NanScope();

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  size_t contentLength = 0;
  char* content = NanCString(value, &contentLength);
  mpi_read_string(&(key->ctx.D), 10, content);
  delete[] content;
}

NAN_GETTER(PolarSSL::KeyRSA::GetP) {
  NanScope();

  char err[1024];

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  int rc;
  size_t slen;
  char* buf;

  slen = 0;

  rc = mpi_write_string(&(key->ctx.P), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf = new char[slen];

  rc = mpi_write_string(&(key->ctx.P), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf[slen] = 0;

  v8::Local<v8::String> str = v8::String::New(buf);

  delete[] buf;

  NanReturnValue(str);
}

NAN_SETTER(PolarSSL::KeyRSA::SetP) {
  NanScope();

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  size_t contentLength = 0;
  char* content = NanCString(value, &contentLength);
  mpi_read_string(&(key->ctx.P), 10, content);
  delete[] content;
}

NAN_GETTER(PolarSSL::KeyRSA::GetQ) {
  NanScope();

  char err[1024];

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  int rc;
  size_t slen;
  char* buf;

  slen = 0;

  rc = mpi_write_string(&(key->ctx.Q), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf = new char[slen];

  rc = mpi_write_string(&(key->ctx.Q), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf[slen] = 0;

  v8::Local<v8::String> str = v8::String::New(buf);

  delete[] buf;

  NanReturnValue(str);
}

NAN_SETTER(PolarSSL::KeyRSA::SetQ) {
  NanScope();

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  size_t contentLength = 0;
  char* content = NanCString(value, &contentLength);
  mpi_read_string(&(key->ctx.Q), 10, content);
  delete[] content;
}

NAN_GETTER(PolarSSL::KeyRSA::GetDP) {
  NanScope();

  char err[1024];

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  int rc;
  size_t slen;
  char* buf;

  slen = 0;

  rc = mpi_write_string(&(key->ctx.DP), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf = new char[slen];

  rc = mpi_write_string(&(key->ctx.DP), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf[slen] = 0;

  v8::Local<v8::String> str = v8::String::New(buf);

  delete[] buf;

  NanReturnValue(str);
}

NAN_SETTER(PolarSSL::KeyRSA::SetDP) {
  NanScope();

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  size_t contentLength = 0;
  char* content = NanCString(value, &contentLength);
  mpi_read_string(&(key->ctx.DP), 10, content);
  delete[] content;
}

NAN_GETTER(PolarSSL::KeyRSA::GetDQ) {
  NanScope();

  char err[1024];

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  int rc;
  size_t slen;
  char* buf;

  slen = 0;

  rc = mpi_write_string(&(key->ctx.DQ), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf = new char[slen];

  rc = mpi_write_string(&(key->ctx.DQ), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf[slen] = 0;

  v8::Local<v8::String> str = v8::String::New(buf);

  delete[] buf;

  NanReturnValue(str);
}

NAN_SETTER(PolarSSL::KeyRSA::SetDQ) {
  NanScope();

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  size_t contentLength = 0;
  char* content = NanCString(value, &contentLength);
  mpi_read_string(&(key->ctx.DQ), 10, content);
  delete[] content;
}

NAN_GETTER(PolarSSL::KeyRSA::GetQP) {
  NanScope();

  char err[1024];

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  int rc;
  size_t slen;
  char* buf;

  slen = 0;

  rc = mpi_write_string(&(key->ctx.QP), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf = new char[slen];

  rc = mpi_write_string(&(key->ctx.QP), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  buf[slen] = 0;

  v8::Local<v8::String> str = v8::String::New(buf);

  delete[] buf;

  NanReturnValue(str);
}

NAN_SETTER(PolarSSL::KeyRSA::SetQP) {
  NanScope();

  PolarSSL::KeyRSA* key = node::ObjectWrap::Unwrap<PolarSSL::KeyRSA>(args.This());

  size_t contentLength = 0;
  char* content = NanCString(value, &contentLength);
  mpi_read_string(&(key->ctx.QP), 10, content);
  delete[] content;
}
