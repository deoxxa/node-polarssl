var polarssl = module.exports = require("./build/Release/polarssl");

polarssl.createHash = function createHash(name) {
  return new polarssl.Hash(name);
};
