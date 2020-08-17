"use strict";
var Buffer = require("safe-buffer").Buffer;

var bs58checkBase = require("./base");
var sha256 = require("crypto-js/sha256");
var CryptoJs = require("crypto-js");

function toWordArray(buf) {
  return CryptoJs.lib.WordArray.create(buf);
}

function toBuffer(wa) {
  return Buffer.from(wa.toString(CryptoJs.enc.Hex), "hex");
}

// SHA256(SHA256(buffer))
function sha256x2(buffer) {
  var wa = toWordArray(buffer);
  var tmp = sha256(wa);
  return toBuffer(sha256(tmp));
  // var tmp = createHash('sha256').update(buffer).digest()
  // return createHash('sha256').update(tmp).digest()
}

module.exports = bs58checkBase(sha256x2);
