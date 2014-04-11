#!/usr/bin/env node

var polarssl = require("./polarssl");

console.log("before generation call");

polarssl.rsa_gen_key(1024, function(err, key) {
  console.log("in callback");

  if (err) {
    return console.log(err);
  }

  console.log(key.private);
  console.log(key.public);
});

console.log("after generation call");
