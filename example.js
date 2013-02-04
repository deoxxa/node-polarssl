#!/usr/bin/env node

var polarssl = require("./polarssl");

var key = polarssl.rsa_gen(1024);

console.log(key.public.toString("base64"));
console.log(key.private.toString("base64"));
