#!/usr/bin/env node

var polarssl = require("./polarssl");

console.log("before generation call");

polarssl.rsa_gen(2048, function(err, key) {
  if (err) {
    return console.log(err);
  }

  console.log(key.public.toString("base64"));
  console.log(key.private.toString("base64"));
});

console.log("after generation call");
