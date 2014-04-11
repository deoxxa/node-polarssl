#!/usr/bin/env node

var polarssl = require("./polarssl");

console.log("before generation call");

polarssl.rsa_gen_key(1024, function(err, key) {
  console.log("in callback");

  if (err) {
    return console.log(err);
  }

  console.log(key);

  console.log(key.private.toString());
  console.log(key.public.toString());
});

console.log("after generation call");
