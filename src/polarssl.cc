#include <polarssl/config.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/bignum.h>
#include <polarssl/x509write.h>
#include <polarssl/rsa.h>

#include <node.h>
#include <node_buffer.h>
#include <uv.h>
#include <v8.h>

#include <string>

using namespace v8;
using namespace node;

struct rsa_gen_Baton {
  rsa_gen_Baton() : error_code(0),key_public_len(16384),key_private_len(16384) {}

  uv_work_t request;
  Persistent< Function > callback;
  int error_code;
  std::string error_message;

  int key_length;
  unsigned char key_public_data[16384];
  size_t key_public_len;
  unsigned char key_private_data[16384];
  size_t key_private_len;
};

void rsa_gen_AsyncWork(uv_work_t* req) {
  rsa_gen_Baton* rsa_gen_baton = static_cast< rsa_gen_Baton* >(req->data);

  int ret;

  rsa_context rsa;
  entropy_context entropy;
  ctr_drbg_context ctr_drbg;
  char pers[] = "rsa_genkey";

  entropy_init(&entropy);
  if ((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned char *) pers, strlen(pers))) != 0) {
    rsa_gen_baton->error_code = 1;
    rsa_gen_baton->error_message = "couldn't initialise random number generator";
    return;
  }

  rsa_init(&rsa, RSA_PKCS_V15, 0);
  if ((ret = rsa_gen_key(&rsa, ctr_drbg_random, &ctr_drbg, rsa_gen_baton->key_length, 65537)) != 0) {
    rsa_gen_baton->error_code = 2;
    rsa_gen_baton->error_message = "couldn't generate key";
    return;
  }

  memset(rsa_gen_baton->key_private_data, 0, 16384);
  memset(rsa_gen_baton->key_public_data,  0, 16384);

  int r;

  r = x509_write_key_der(rsa_gen_baton->key_private_data,   rsa_gen_baton->key_private_len, &rsa);
  if (r < 0) {
    rsa_gen_baton->error_code = 3;
    rsa_gen_baton->error_message = "couldn't serialise private key";
    return;
  }
  rsa_gen_baton->key_private_len = r;

  r = x509_write_pubkey_der(rsa_gen_baton->key_public_data, rsa_gen_baton->key_public_len,  &rsa);
  if (r < 0) {
    rsa_gen_baton->error_code = 4;
    rsa_gen_baton->error_message = "couldn't serialise public key";
    return;
  }
  rsa_gen_baton->key_public_len = r;

  return;
}

void rsa_gen_AsyncAfter(uv_work_t* req) {
  HandleScope scope;

  rsa_gen_Baton* rsa_gen_baton = static_cast< rsa_gen_Baton* >(req->data);

  if (rsa_gen_baton->error_code) {
    const unsigned argc = 1;
    Local< Value > argv[argc] = { Local< Value >::New(Exception::Error(String::New(rsa_gen_baton->error_message.c_str()))) };
    rsa_gen_baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
  } else {
    Local< Object > object = Object::New();

    Buffer* buffer_private = Buffer::New(rsa_gen_baton->key_private_len);
    memcpy(Buffer::Data(buffer_private), rsa_gen_baton->key_private_data + 16384 - rsa_gen_baton->key_private_len, rsa_gen_baton->key_private_len);
    object->Set(String::NewSymbol("private"), buffer_private->handle_);

    Buffer* buffer_public = Buffer::New(rsa_gen_baton->key_public_len);
    memcpy(Buffer::Data(buffer_public), rsa_gen_baton->key_public_data + 16384 - rsa_gen_baton->key_public_len, rsa_gen_baton->key_public_len);
    object->Set(String::NewSymbol("public"), buffer_public->handle_);

    const unsigned argc = 2;
    Local< Value > argv[argc] = { Local< Value >::New(Null()), Local< Value >::New(object) };
    rsa_gen_baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
  }

  rsa_gen_baton->callback.Dispose();
  delete rsa_gen_baton;
}

Handle<Value> rsa_gen(const Arguments& args) {
  HandleScope scope;

  int key_length = 1024;

  /** check arguments */

  if (args.Length() < 1) {
    ThrowException(Exception::TypeError(String::New("wrong number of arguments (should be >= 1)")));

    return scope.Close(Undefined());
  }

  if (!args[args.Length() - 1]->IsFunction()) {
    ThrowException(Exception::TypeError(String::New("last argument should be a function")));

    return scope.Close(Undefined());
  }

  Local< Function > callback = Local< Function >::Cast(args[args.Length() - 1]);

  if (args.Length() == 2) {
    if (!args[0]->IsNumber()) {
      const unsigned argc = 1;
      Local< Value > argv[argc] = { Local< Value >::New(Exception::TypeError(String::New("first argument should be an integer"))) };
      callback->Call(Context::GetCurrent()->Global(), argc, argv);
      return scope.Close(Undefined());
    }

    key_length = args[0]->NumberValue();
  }

  /** arguments sane (hopefully) */

  /** start async work */

  rsa_gen_Baton* rsa_gen_baton = new rsa_gen_Baton();
  rsa_gen_baton->request.data = rsa_gen_baton;
  rsa_gen_baton->callback = Persistent< Function >::New(callback);
  rsa_gen_baton->key_length = key_length;

  uv_queue_work(uv_default_loop(), &rsa_gen_baton->request, rsa_gen_AsyncWork, rsa_gen_AsyncAfter);

  /** we're done for now */

  return Undefined();
}

void init(Handle<Object> target) {
  target->Set(String::NewSymbol("rsa_gen"), FunctionTemplate::New(rsa_gen)->GetFunction());
}
NODE_MODULE(polarssl, init)
