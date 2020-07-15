var Buffer = require("safe-buffer").Buffer;
var CryptoJs = require("crypto-js");
var encUtf8 = require("crypto-js/enc-utf8");
var encHex = require("crypto-js/enc-hex");
var SHA256 = require("crypto-js/sha256");
var RIPEMD160 = require("crypto-js/ripemd160");
// import { WordArray, lib, enc } from "crypto-js";
var lib = require("crypto-js").lib;
var bs58 = require("../bs58check");
var bech32 = require("bech32");
var HDKey = require("../hdkey/hdkey");

var xpubConvertor = require("./xpubConvertor");

function toWordArray(buf) {
  return CryptoJs.lib.WordArray.create(buf);
}

function toBuffer(wa) {
  return Buffer.from(wa.toString(CryptoJs.enc.Hex), "hex");
}

function utf8ToHex(hexStr) {
  return encHex.stringify(encUtf8.parse(hexStr));
}

function hexToUtf8(hexStr) {
  return encUtf8.stringify(encHex.parse(hexStr));
}

function hexToBase64(hex) {
  return enc.Base64.stringify(encHex.parse(hex));
}

function hexToBase58(hex) {
  return bs58.encode(Buffer.from(hex, "hex"));
}

function base64ToHex(base64) {
  return encHex.stringify(enc.Base64.parse(base64));
}

function arrayBufferToHex(ab) {
  return encHex.stringify(lib.WordArray.create(ab));
}

function ripemd160(hex) {
  return RIPEMD160(encHex.parse(hex)).toString();
}
exports.ripemd160 = ripemd160;

function hash160(buf) {
  var sha = toBuffer(SHA256(toWordArray(buf)));
  // crypto.createHash('sha256').update(buf).digest()
  console.log(sha.toString("hex"));
  var hash = toBuffer(ripemd160(toWordArray(sha)));
  return hash;
  // return crypto.createHash('ripemd160').update(sha).digest()
}
exports.hash160 = hash160;

function sha256sync(hexData) {
  const dataWa = encHex.parse(hexData);
  const hash = SHA256(dataWa);
  return hash.toString(encHex);
}
exports.sha256sync = sha256sync;

const sha256ripemd160 = (hex) => {
  if (hex.length % 2 !== 0)
    throw new Error(`invalid hex string length: ${hex}`);
  const ProgramSha256 = sha256sync(hex);
  return ripemd160(ProgramSha256);
};
exports.sha256ripemd160 = sha256ripemd160;

function hexToArrayBuffer(hex) {
  // @ts-ignore
  hex = hex.toString(16);

  hex = hex.replace(/^0x/i, "");

  let bytes = [];
  for (let c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
  // @ts-ignore
  return new Uint8Array(bytes);
}

function normalArray(buffer) {
  const normal = [];
  for (let i = 0; i < buffer.length; ++i) normal[i] = buffer[i];
  return normal;
}

function toByteArray(normalArray) {
  const rv = new Uint8Array(normalArray.length);
  for (let i = 0; i < normalArray.length; ++i) rv[i] = normalArray[i];
  return rv;
}

function p2pkhAddress(pubKey, testnet) {
  const hash160 = sha256ripemd160(pubKey);
  // console.log("H160: " + hash160);
  const version = testnet ? "6f" : "00";
  const hashAndBytes = normalArray(hexToArrayBuffer(hash160));
  // console.log("HB: " + hashAndBytes);
  hashAndBytes.unshift(version);
  const hexed = arrayBufferToHex(toByteArray(hashAndBytes));
  // console.log("HEXED: " + hashAndBytes);
  // redundant bs58check encode scheme (uses bs58.encode instead)
  //   const doubleSHA = sha256sync(sha256sync(hexed));
  //   console.log("SHA256: " + doubleSHA);
  //   const addressChecksum = doubleSHA.substr(0, 8);
  //   const unencodedAddress = (testnet ? "6f" : "00") + hash160 + addressChecksum;
  //   console.log("UEAD: " + unencodedAddress);
  //   // This is the broken part - *** TODO *** FIX hexToBase58
  //   let uedBuffer = hexToArrayBuffer(unencodedAddress);
  //   console.log("UEAD BUFFER: " + uedBuffer);
  return bs58.encode(toBuffer(hexed));
}
exports.p2pkhAddress = p2pkhAddress;

// accept public key and encode as bech32 address with checksum
function p2wpkhAddress(pubKey, testnet) {
  // perform sha-256 followed by RIPEMD-160
  const hash160 = sha256ripemd160(pubKey);
  // console.log("H160: " + hash160);
  let bech32words = bech32.toWords(hexToArrayBuffer(hash160));
  //console.log("BECH32 words: " + bech32words);
  let hexhash = arrayBufferToHex(bech32words).replace(/000000/g, "");
  //console.log("HEX: " + hexhash);

  // set witness version (current is 0 - 00 in hex)
  let witnessVersion = "00";
  // append witness version to hexhash
  hexhash = witnessVersion + hexhash;
  let bech32wordsWV = hexToArrayBuffer(hexhash);

  //console.log("HEX + WV: " + hexhash);

  let humanReadable = testnet ? "tb" : "bc";
  let bech32encoded = bech32.encode(humanReadable, bech32wordsWV);
  //console.log("BECH32 encoded: " + bech32encoded);

  return bech32encoded;
}
exports.p2wpkhAddress = p2wpkhAddress;

function retrieveAddresses(
  extendedKey,
  path,
  addressType,
  indexstart,
  indexend,
  network
) {
  // TODO: change so when ypub is provided, generate p2sh '3' addresses
  if (
    extendedKey.substring(0, 4) === "ypub" ||
    extendedKey.substring(0, 4) === "zpub"
  ) {
    extendedKey = xpubConvertor.changeVersionBytes(extendedKey, "xpub");
  } else if (extendedKey.substring(0, 4) !== "xpub") {
    throw new Error(`Unsupported xpub version ${extendedKey}`);
  }

  // path e.g. m/44/0/
  let testnet = network === "mainnet" ? false : true;
  var myWallet = HDKey.fromExtendedKey(extendedKey);

  let addresses = {};
  for (let i = indexstart; i < indexend; i++) {
    const node = myWallet.derive(path + i);
    const pubKey = node.publicExtendedKey;

    let bs58decoded = bs58.decode(pubKey);
    let base58hex = bs58decoded.toString("hex");

    // console.log("BASE58-HEX: " + base58hex);
    let compressedPubkey = base58hex.substring(base58hex.length - 66);
    // console.log("COMPRESSED PUBKEY: " + compressedPubkey);

    //let sha256hashedpubkey = sha256sync(compressedPubkey);
    // console.log("SHA256: " + sha256hashedpubkey);
    // let hash160pubkey = ripemd160(sha256hashedpubkey);
    // console.log("RIPEMD: " + hash160pubkey);
    // // segwit address
    let address =
      addressType === "segwit"
        ? p2wpkhAddress(compressedPubkey, testnet)
        : addressType === "legacy"
        ? p2pkhAddress(compressedPubkey, testnet)
        : null;
    // console.log("ADDRESS: " + address);
    addresses[`m/0/${i}`] = address;
  }
  return addresses;
}
exports.retrieveAddresses = retrieveAddresses;
