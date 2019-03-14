"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _cipher = _interopRequireDefault(require("./cipher"));

var _hash = _interopRequireDefault(require("./hash"));

var _cfb = _interopRequireDefault(require("./cfb"));

var _gcm = _interopRequireDefault(require("./gcm"));

var _eax = _interopRequireDefault(require("./eax"));

var _ocb = _interopRequireDefault(require("./ocb"));

var _public_key = _interopRequireDefault(require("./public_key"));

var _signature = _interopRequireDefault(require("./signature"));

var _random = _interopRequireDefault(require("./random"));

var _pkcs = _interopRequireDefault(require("./pkcs1"));

var _pkcs2 = _interopRequireDefault(require("./pkcs5"));

var _crypto = _interopRequireDefault(require("./crypto"));

var _aes_kw = _interopRequireDefault(require("./aes_kw"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @fileoverview Provides access to all cryptographic primitives used in OpenPGP.js
 * @see module:crypto/crypto
 * @see module:crypto/signature
 * @see module:crypto/public_key
 * @see module:crypto/cipher
 * @see module:crypto/random
 * @see module:crypto/hash
 * @module crypto
 */
// TODO move cfb and gcm to cipher
const mod = {
  /** @see module:crypto/cipher */
  cipher: _cipher.default,

  /** @see module:crypto/hash */
  hash: _hash.default,

  /** @see module:crypto/cfb */
  cfb: _cfb.default,

  /** @see module:crypto/gcm */
  gcm: _gcm.default,
  experimental_gcm: _gcm.default,

  /** @see module:crypto/eax */
  eax: _eax.default,

  /** @see module:crypto/ocb */
  ocb: _ocb.default,

  /** @see module:crypto/public_key */
  publicKey: _public_key.default,

  /** @see module:crypto/signature */
  signature: _signature.default,

  /** @see module:crypto/random */
  random: _random.default,

  /** @see module:crypto/pkcs1 */
  pkcs1: _pkcs.default,

  /** @see module:crypto/pkcs5 */
  pkcs5: _pkcs2.default,

  /** @see module:crypto/aes_kw */
  aes_kw: _aes_kw.default
};
Object.assign(mod, _crypto.default);
var _default = mod;
exports.default = _default;