node-polarssl
=============

Node.JS bindings for [PolarSSL](https://polarssl.org/), a clean, lightweight
crypto library.

RIDE THE POWER
--------------

![](https://i.imgur.com/YyicrOW.jpg)

Overview
--------

PolarSSL is a lot easier to reason about than OpenSSL, and has a nicer API that
can be exposed in node with less abstraction. Hopefully this module will be able
to form the base of an alternative for the built-in `crypto` and `tls` modules.

Warning
-------

Right now everything here is very very fluid. API's might change with a moment's
notice, and the version of this module on npm will likely be out of date. Please
clone directly from git://github.com/deoxxa/node-polarssl.git if you want to see
how things are doing.

Functionality
-------------

Most of this stuff mirrors the core [crypto api](http://nodejs.org/docs/latest/api/crypto.html),
so take a look at the official docs for more details. If an implemented method
in this module doesn't behave as specified in the official docs, it's a bug.
There are some additional methods as well, so read through this list for the
whole story.

### polarssl.createCipher

```js
var hash = polarssl.createCipher("ARC4-128", key=Buffer("..."), iv=Buffer("..."), mode=0);
```

### polarssl.Cipher

This is a duplex stream - write cleartext in, get ciphertext out.

```js
var cipher = new polarssl.Cipher("md5");
```

### polarssl.Cipher.update

```js
cipher.update(Buffer("this is some data"));
```

### polarssl.Cipher.updateAsync

```js
cipher.updateAsync(Buffer("this is some data"), function(err) {
  if (err) {
    return console.warn(err);
  }
});
```

### polarssl.Cipher.final

```js
var data = cipher.final();
```

### polarssl.Cipher.finalAsync

```js
cipher.finalAsync(function(err, data) {
  if (err) {
    return console.warn(err);
  }

  console.log(data);
});
```

### polarssl.createHash

```js
var hash = polarssl.createHash("md5");
```

### polarssl.Hash

This is a duplex stream - write data in, get digest out on `end()`.

```js
var hash = new polarssl.Hash("md5");
```

### polarssl.Hash.update

```js
hash.update(Buffer("this is some data"));
```

### polarssl.Hash.updateAsync

```js
hash.updateAsync(Buffer("this is some data"), function(err) {
  if (err) {
    return console.warn(err);
  }
});
```

### polarssl.Hash.digest

```js
var digest = hash.digest();
```

### polarssl.Hash.digestAsync

```js
hash.digestAsync(function(err, digest) {
  if (err) {
    return console.warn(err);
  }

  console.log(digest);
});
```

### polarssl.createHMAC

```js
var hmac = polarssl.createHMAC("md5", "whatever");
```

### polarssl.HMAC

This is a duplex stream - write data in, get digest out on `end()`.

```js
var hmac = new polarssl.HMAC("md5", "whatever");
```

### polarssl.HMAC.update

```js
hmac.update(Buffer("this is some data"));
```

### polarssl.HMAC.updateAsync

```js
hmac.updateAsync(Buffer("this is some data"), function(err) {
  if (err) {
    return console.warn(err);
  }
});
```

### polarssl.HMAC.digest

```js
var digest = hmac.digest();
```

### polarssl.HMAC.digestAsync

```js
hmac.digestAsync(function(err, digest) {
  if (err) {
    return console.warn(err);
  }

  console.log(digest);
});
```

### polarssl.createKeygen

```js
var keygen = polarssl.createKeygen();
```

### polarssl.Keygen

```js
var keygen = new polarssl.Keygen();
```

### polarssl.Keygen.generateKey

```js
var key = keygen.generateKey();
```

### polarssl.KeyRSA

```js
var key = new polarssl.KeyRSA();
```

### polarssl.KeyRSA.format

```js
var pem = key.format();
```

### polarssl.randomBytes

```js
var data = polarssl.randomBytes(100);
```

License
-------

All original code is licensed under a 3-clause BSD license. A copy is included
with the source.

PolarSSL is licensed under GPLv2.

Contact
-------

* GitHub ([deoxxa](http://github.com/deoxxa))
* Twitter ([@deoxxa](http://twitter.com/deoxxa))
* Email ([deoxxa@fknsrs.biz](mailto:deoxxa@fknsrs.biz))
