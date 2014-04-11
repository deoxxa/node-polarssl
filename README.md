node-polarssl
=============

Node.JS bindings for [PolarSSL](https://polarssl.org/), a clean, lightweight
crypto library.

Overview
--------

I want to make certs and stuff. PolarSSL is cool.

Functionality
-------------

### rsa_gen

```js
polarssl.rsa_gen(1024, function(err, key) {
  if (err) {
    return console.log(err);
  }

  console.log(key.private);
  console.log(key.public);
});
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
