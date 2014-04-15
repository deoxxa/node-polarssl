#include <polarssl/error.h>

#include "keygen.h"

int PolarSSL::Keygen::Initialise() {
  int rc;

  entropy_init(&entropy);

  rc = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, NULL, 0);

  if (rc != 0) {
    return rc;
  }

  return 0;
}

void PolarSSL::Keygen::Init(v8::Handle<v8::Object> target) {
  v8::Local<v8::FunctionTemplate> constructorTemplate = v8::FunctionTemplate::New(New);

  constructorTemplate->SetClassName(v8::String::NewSymbol("Keygen"));

  constructorTemplate->InstanceTemplate()->SetInternalFieldCount(1);

  constructorTemplate->PrototypeTemplate()->Set(v8::String::NewSymbol("generateKey"), v8::FunctionTemplate::New(GenerateKey)->GetFunction());

  v8::Persistent<v8::Function> constructor = v8::Persistent<v8::Function>::New(constructorTemplate->GetFunction());

  target->Set(v8::String::NewSymbol("Keygen"), constructor);
}

NAN_METHOD(PolarSSL::Keygen::New) {
  NanScope();

  Keygen* keygen = new PolarSSL::Keygen();

  char err[1024];

  int rc = keygen->Initialise();

  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  keygen->Wrap(args.This());

  NanReturnValue(args.This());
}

NAN_METHOD(PolarSSL::Keygen::GenerateKey) {
  NanScope();

  char err[1024];

  int rc;

  Keygen* keygen = node::ObjectWrap::Unwrap<Keygen>(args.This());

  pk_context* pk_ctx = new pk_context;
  memset(pk_ctx, 0, sizeof(pk_context));

  const pk_info_t* pk_info = pk_info_from_type(POLARSSL_PK_RSA);
  if (pk_info == NULL) {
    NanThrowError("couldn't get pk_info for some reason");
    NanReturnUndefined();
  }

  rc = pk_init_ctx(pk_ctx, pk_info);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  rc = rsa_gen_key(pk_rsa(*pk_ctx), ctr_drbg_random, &(keygen->ctr_drbg), 1024, 65537);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }

  rsa_context *rsa = pk_rsa(*pk_ctx);

  v8::Local<v8::Object> obj = v8::Object::New();

  size_t slen;
  char* buf = NULL;

  slen = 0;
  rc = mpi_write_string(&(rsa->N), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }
  buf = new char[slen];
  rc = mpi_write_string(&(rsa->N), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }
  buf[slen] = 0;
  obj->Set(v8::String::NewSymbol("n"), v8::String::New(buf));

  slen = 0;
  rc = mpi_write_string(&(rsa->E), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }
  buf = new char[slen];
  rc = mpi_write_string(&(rsa->E), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }
  buf[slen] = 0;
  obj->Set(v8::String::NewSymbol("e"), v8::String::New(buf));

  slen = 0;
  rc = mpi_write_string(&(rsa->D), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }
  buf = new char[slen];
  rc = mpi_write_string(&(rsa->D), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }
  buf[slen] = 0;
  obj->Set(v8::String::NewSymbol("d"), v8::String::New(buf));

  slen = 0;
  rc = mpi_write_string(&(rsa->P), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }
  buf = new char[slen];
  rc = mpi_write_string(&(rsa->P), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }
  buf[slen] = 0;
  obj->Set(v8::String::NewSymbol("p"), v8::String::New(buf));

  slen = 0;
  rc = mpi_write_string(&(rsa->Q), 10, NULL, &slen);
  if (rc != 0 && rc != POLARSSL_ERR_MPI_BUFFER_TOO_SMALL) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }
  buf = new char[slen];
  rc = mpi_write_string(&(rsa->Q), 10, buf, &slen);
  if (rc != 0) {
    polarssl_strerror(rc, err, sizeof(err));
    NanThrowError(err);
    NanReturnUndefined();
  }
  buf[slen] = 0;
  obj->Set(v8::String::NewSymbol("q"), v8::String::New(buf));

  NanReturnValue(obj);
}
