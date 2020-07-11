"use strict";
var Buffer = require("safe-buffer").Buffer;
var BN = require("bn.js");
var EC = require("../elliptic/lib/elliptic").ec;

var ec = new EC("secp256k1");
var ecparams = ec.curve;

exports.privateKeyVerify = function (privateKey) {
  var bn = new BN(privateKey);
  return bn.cmp(ecparams.n) < 0 && !bn.isZero();
};

exports.publicKeyCreate = function (privateKey, compressed) {
  var d = new BN(privateKey);
  if (d.cmp(ecparams.n) >= 0 || d.isZero())
    throw new Error("messages.EC_PUBLIC_KEY_CREATE_FAIL");

  return Buffer.from(ec.keyFromPrivate(privateKey).getPublic(compressed, true));
};

exports.publicKeyVerify = function (publicKey) {
  return loadPublicKey(publicKey) !== null;
};

exports.publicKeyConvert = function (publicKey, compressed) {
  var pair = loadPublicKey(publicKey);
  if (pair === null) throw new Error("messages.EC_PUBLIC_KEY_PARSE_FAIL");

  return Buffer.from(pair.getPublic(compressed, true));
};

function loadPublicKey(publicKey) {
  var first = publicKey[0];
  switch (first) {
    case 0x02:
    case 0x03:
      if (publicKey.length !== 33) return null;
      return loadCompressedPublicKey(first, publicKey.slice(1, 33));
    case 0x04:
    case 0x06:
    case 0x07:
      if (publicKey.length !== 65) return null;
      return loadUncompressedPublicKey(
        first,
        publicKey.slice(1, 33),
        publicKey.slice(33, 65)
      );
    default:
      return null;
  }
}

function loadCompressedPublicKey(first, xBuffer) {
  var x = new BN(xBuffer);

  // overflow
  if (x.cmp(ecparams.p) >= 0) return null;
  x = x.toRed(ecparams.red);

  // compute corresponding Y
  var y = x.redSqr().redIMul(x).redIAdd(ecparams.b).redSqrt();
  if ((first === 0x03) !== y.isOdd()) y = y.redNeg();

  return ec.keyPair({ pub: { x: x, y: y } });
}

function loadUncompressedPublicKey(first, xBuffer, yBuffer) {
  var x = new BN(xBuffer);
  var y = new BN(yBuffer);

  // overflow
  if (x.cmp(ecparams.p) >= 0 || y.cmp(ecparams.p) >= 0) return null;

  x = x.toRed(ecparams.red);
  y = y.toRed(ecparams.red);

  // is odd flag
  if ((first === 0x06 || first === 0x07) && y.isOdd() !== (first === 0x07))
    return null;

  // x*x*x + b = y*y
  var x3 = x.redSqr().redIMul(x);
  if (!y.redSqr().redISub(x3.redIAdd(ecparams.b)).isZero()) return null;

  return ec.keyPair({ pub: { x: x, y: y } });
}

exports.privateKeyTweakAdd = function (privateKey, tweak) {
  var bn = new BN(tweak);
  if (bn.cmp(ecparams.n) >= 0)
    throw new Error("messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL");

  bn.iadd(new BN(privateKey));
  if (bn.cmp(ecparams.n) >= 0) bn.isub(ecparams.n);
  if (bn.isZero()) throw new Error("messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL");

  return bn.toArrayLike(Buffer, "be", 32);
};

exports.publicKeyTweakAdd = function (publicKey, tweak, compressed) {
  var pair = loadPublicKey(publicKey);
  if (pair === null) throw new Error("messages.EC_PUBLIC_KEY_PARSE_FAIL");

  tweak = new BN(tweak);
  if (tweak.cmp(ecparams.n) >= 0)
    throw new Error("messages.EC_PUBLIC_KEY_TWEAK_ADD_FAIL");

  var point = ecparams.g.mul(tweak).add(pair.pub);
  if (point.isInfinity())
    throw new Error("messages.EC_PUBLIC_KEY_TWEAK_ADD_FAIL");

  return Buffer.from(point.encode(true, compressed));
};

exports.sign = function (message, privateKey, noncefn, data) {
  if (typeof noncefn === "function") {
    var getNonce = noncefn;
    noncefn = function (counter) {
      var nonce = getNonce(message, privateKey, null, data, counter);
      if (!Buffer.isBuffer(nonce) || nonce.length !== 32)
        throw new Error("messages.ECDSA_SIGN_FAIL");

      return new BN(nonce);
    };
  }

  var d = new BN(privateKey);
  if (d.cmp(ecparams.n) >= 0 || d.isZero())
    throw new Error("messages.ECDSA_SIGN_FAIL");

  var result = ec.sign(message, privateKey, {
    canonical: true,
    k: noncefn,
    pers: data,
  });
  return {
    signature: Buffer.concat([
      result.r.toArrayLike(Buffer, "be", 32),
      result.s.toArrayLike(Buffer, "be", 32),
    ]),
    recovery: result.recoveryParam,
  };
};

exports.verify = function (message, signature, publicKey) {
  var sigObj = { r: signature.slice(0, 32), s: signature.slice(32, 64) };

  var sigr = new BN(sigObj.r);
  var sigs = new BN(sigObj.s);
  if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0)
    throw new Error("messages.ECDSA_SIGNATURE_PARSE_FAIL");
  if (sigs.cmp(ec.nh) === 1 || sigr.isZero() || sigs.isZero()) return false;

  var pair = loadPublicKey(publicKey);
  if (pair === null) throw new Error("messages.EC_PUBLIC_KEY_PARSE_FAIL");

  return ec.verify(message, sigObj, { x: pair.pub.x, y: pair.pub.y });
};
