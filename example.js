#!/usr/bin/env node

var polarssl = require("./polarssl");

var keygen = polarssl.createKeygen();

var key = keygen.generateKey();

console.log(JSON.stringify([
  key.n,
  key.e,
  key.d,
  key.p,
  key.q,
  key.dp,
  key.dq,
  key.qp,
], null, 2));

console.log(key.format("public"));
console.log(key.format("private"));
