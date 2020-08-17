var CryptoJs = require("crypto-js");
var Buffer = require("safe-buffer").Buffer;

function toWordArray(buf) {
  return CryptoJs.lib.WordArray.create(buf);
}

function toBuffer(wa) {
  return Buffer.from(wa.toString(CryptoJs.enc.Hex), "hex");
}

function rand(len) {
  return toBuffer(CryptoJs.lib.WordArray.random(len));
}

module.exports = {
  rand,
};
