var _polarssl = require("../build/Release/polarssl"),
    stream = require("readable-stream");

var Cipher = module.exports = function Cipher(name, key, iv, operation) {
  stream.Transform.call(this);

  if (typeof key === "string") {
    key = Buffer(key);
  }

  if (typeof iv === "string") {
    iv = Buffer(iv);
  }

  this._cipher = new _polarssl.Cipher(name, key, iv, operation);
};
Cipher.prototype = Object.create(stream.Transform.prototype, {constructor: {value: Cipher}});

Cipher.prototype.update = function update(input, encoding) {
  if (typeof input === "string") {
    input = Buffer(input, encoding);
  }

  return this._cipher.update(input);
};

Cipher.prototype.final = function final() {
  return this._cipher.final();
};

Cipher.prototype.updateAsync = function updateAsync(input, encoding, done) {
  if (typeof encoding === "function") {
    done = encoding;
    encoding = null;
  }

  if (typeof input === "string") {
    input = Buffer(input, encoding);
  }

  this._cipher.updateAsync(input, done);

  return this;
};

Cipher.prototype.finalAsync = function finalAsync(cb) {
  return this._cipher.finalAsync(cb);

  return this;
};

Cipher.prototype._transform = function _transform(input, encoding, done) {
  if (typeof input === "string") {
    input = Buffer(input, encoding);
  }

  var self = this;

  return this._cipher.updateAsync(input, function(err, data) {
    if (err) {
      return done(err);
    }

    self.push(data);

    return done();
  });
};

Cipher.prototype._flush = function _flush(done) {
  var self = this;

  return this._cipher.finalAsync(function(err, data) {
    if (err) {
      return done(err);
    }

    self.push(data);

    return done();
  });
};
