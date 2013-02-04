node-polarssl
=============

Node.JS bindings for [PolarSSL](https://polarssl.org/), a clean, lightweight
crypto library.

Overview
--------

I want to make certs and stuff. PolarSSL is cool.

Features
--------

RSA Key Generation
------------------

```js
var key = polarssl.rsa_gen(1024);

console.log(key.private.toString("base64"));
console.log(key.public.toString("base64"));
```

License
-------

All original code is licensed under a 3-clause BSD license. A copy is included
with the source.

PolarSSL is licensed under the GPLv2.

Contact
-------

* GitHub ([http://github.com/deoxxa](deoxxa))
* Twitter ([http://twitter.com/deoxxa](@deoxxa))
* Email ([mailto:deoxxa@fknsrs.biz](deoxxa@fknsrs.biz))
