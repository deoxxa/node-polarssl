var _polarssl = require("./build/Release/polarssl");

var polarssl = module.exports = {
  Hash: require("./lib/hash"),
  Keygen: _polarssl.Keygen,
  KeyRSA: _polarssl.KeyRSA,
  Random: _polarssl.Random,
};

polarssl.createHash = function createHash(name) {
  return new polarssl.Hash(name);
};

polarssl.createKeygen = function createKeygen() {
  return new polarssl.Keygen();
};
