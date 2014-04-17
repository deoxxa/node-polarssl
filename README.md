node-polarssl
=============

Node.JS bindings for [PolarSSL](https://polarssl.org/), a clean, lightweight
crypto library.

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

### polarssl.createHash

### polarssl.Hash

### polarssl.Hash.update

### polarssl.Hash.digest

### polarssl.createKeygen

### polarssl.Keygen

### polarssl.Keygen.generateKey

### polarssl.KeyRSA

### polarssl.KeyRSA.format

### polarssl.randomBytes

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
