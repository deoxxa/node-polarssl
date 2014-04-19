var _polarssl = require("../build/Release/polarssl"),
    stream = require("readable-stream");

var HMAC = module.exports = function HMAC(name, key) {
  stream.Transform.call(this);

  if (typeof key === "string") {
    key = Buffer(key);
  }

  this._hmac = new _polarssl.HMAC(name, key);
};
HMAC.prototype = Object.create(stream.Transform.prototype, {constructor: {value: HMAC}});

HMAC.prototype.update = function update(input, encoding) {
  if (typeof input === "string") {
    input = Buffer(input, encoding);
  }

  this._hmac.update(input);

  return this;
};

HMAC.prototype.digest = function digest() {
  return this._hmac.digest();
};

HMAC.prototype.updateAsync = function updateAsync(input, encoding, done) {
  if (typeof encoding === "function") {
    done = encoding;
    encoding = null;
  }

  if (typeof input === "string") {
    input = Buffer(input, encoding);
  }

  this._hmac.updateAsync(input, done);

  return this;
};

HMAC.prototype.digestAsync = function digestAsync(cb) {
  this._hmac.digestAsync(cb);

  return this;
};

HMAC.prototype._transform = function _transform(input, encoding, done) {
  if (typeof input === "string") {
    input = Buffer(input, encoding);
  }

  return this._hmac.updateAsync(input, done);
};

HMAC.prototype._flush = function _flush(done) {
  var self = this;

  this._hmac.digestAsync(function(err, digest) {
    if (err) {
      return done(err);
    }

    self.push(digest);

    return done();
  });
};
