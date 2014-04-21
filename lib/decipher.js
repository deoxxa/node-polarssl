var _polarssl = require("../build/Release/polarssl"),
    stream = require("readable-stream");

var Decipher = module.exports = function Decipher(name, key, iv) {
  stream.Transform.call(this);

  if (typeof key === "string") {
    key = Buffer(key);
  }

  if (typeof iv === "string") {
    iv = Buffer(iv);
  }

  this._cipher = new _polarssl.Cipher(name, key, iv, 0);
};
Decipher.prototype = Object.create(stream.Transform.prototype, {constructor: {value: Decipher}});

Object.defineProperty(Decipher.prototype, "name", {
  get: function() { return this._cipher.name; },
});

Object.defineProperty(Decipher.prototype, "keySize", {
  get: function() { return this._cipher.keySize; },
});

Object.defineProperty(Decipher.prototype, "ivSize", {
  get: function() { return this._cipher.ivSize; },
});

Object.defineProperty(Decipher.prototype, "blockSize", {
  get: function() { return this._cipher.blockSize; },
});

Decipher.prototype.update = function update(input, encoding) {
  if (typeof input === "string") {
    input = Buffer(input, encoding);
  }

  return this._cipher.update(input);
};

Decipher.prototype.final = function final() {
  return this._cipher.final();
};

Decipher.prototype.updateAsync = function updateAsync(input, encoding, done) {
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

Decipher.prototype.finalAsync = function finalAsync(cb) {
  return this._cipher.finalAsync(cb);

  return this;
};

Decipher.prototype._transform = function _transform(input, encoding, done) {
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

Decipher.prototype._flush = function _flush(done) {
  var self = this;

  return this._cipher.finalAsync(function(err, data) {
    if (err) {
      return done(err);
    }

    self.push(data);

    return done();
  });
};
