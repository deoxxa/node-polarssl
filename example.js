#!/usr/bin/env node

var polarssl = require("./polarssl");

var hash = polarssl.createHash("sha1");

hash.update(Buffer("password"));

var digest = hash.digest();

console.log(digest.toString("hex"));
