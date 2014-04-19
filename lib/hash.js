var _polarssl = require("../build/Release/polarssl"),
    stream = require("readable-stream");

var Hash = module.exports = function Hash(name) {
  stream.Transform.call(this);

  this._hash = new _polarssl.Hash(name);
};
Hash.prototype = Object.create(stream.Transform.prototype, {constructor: {value: Hash}});

Hash.prototype.update = function update(input, encoding) {
  if (typeof input === "string") {
    input = Buffer(input, encoding);
  }

  this._hash.update(input);

  return this;
};

Hash.prototype.digest = function digest() {
  return this._hash.digest();
};

Hash.prototype.updateAsync = function updateAsync(input, encoding, done) {
  if (typeof encoding === "function") {
    done = encoding;
    encoding = null;
  }

  if (typeof input === "string") {
    input = Buffer(input, encoding);
  }

  this._hash.updateAsync(input, done);

  return this;
};

Hash.prototype.digestAsync = function digestAsync(cb) {
  this._hash.digestAsync(cb);

  return this;
};

Hash.prototype._transform = function _transform(input, encoding, done) {
  if (typeof input === "string") {
    input = Buffer(input, encoding);
  }

  return this._hash.updateAsync(input, done);
};

Hash.prototype._flush = function _flush(done) {
  var self = this;

  this._hash.digestAsync(function(err, digest) {
    if (err) {
      return done(err);
    }

    self.push(digest);

    return done();
  });
};
