var _polarssl = require("./build/Release/polarssl");

var polarssl = module.exports = {
  Cipher: require("./lib/cipher"),
  Decipher: require("./lib/decipher"),
  getCiphers: _polarssl.getCiphers,
  Hash: require("./lib/hash"),
  HMAC: require("./lib/hmac"),
  getHashes: _polarssl.getHashes,
  Keygen: _polarssl.Keygen,
  KeyRSA: _polarssl.KeyRSA,
  Random: _polarssl.Random,
};

polarssl.createCipher = function createCipher(name, key, iv) {
  return new polarssl.Cipher(name, key, iv);
};

polarssl.createDecipher = function createDecipher(name, key, iv) {
  return new polarssl.Decipher(name, key, iv);
};

polarssl.createHash = function createHash(name) {
  return new polarssl.Hash(name);
};

polarssl.createHmac = function createHmac(name, key) {
  return new polarssl.HMAC(name, key);
};

polarssl.createKeygen = function createKeygen() {
  return new polarssl.Keygen();
};
