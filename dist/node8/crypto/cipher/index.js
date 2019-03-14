"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _aes = _interopRequireDefault(require("./aes"));

var _des = _interopRequireDefault(require("./des.js"));

var _cast = _interopRequireDefault(require("./cast5"));

var _twofish = _interopRequireDefault(require("./twofish"));

var _blowfish = _interopRequireDefault(require("./blowfish"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @fileoverview Symmetric cryptography functions
 * @requires crypto/cipher/aes
 * @requires crypto/cipher/des
 * @requires crypto/cipher/cast5
 * @requires crypto/cipher/twofish
 * @requires crypto/cipher/blowfish
 * @module crypto/cipher
 */
var _default = {
  /**
   * AES-128 encryption and decryption (ID 7)
   * @function
   * @param {String} key 128-bit key
   * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
   * @see {@link https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf|NIST FIPS-197}
   * @returns {Object}
   * @requires asmcrypto.js
   */
  aes128: (0, _aes.default)(128),

  /**
   * AES-128 Block Cipher (ID 8)
   * @function
   * @param {String} key 192-bit key
   * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
   * @see {@link https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf|NIST FIPS-197}
   * @returns {Object}
   * @requires asmcrypto.js
   */
  aes192: (0, _aes.default)(192),

  /**
   * AES-128 Block Cipher (ID 9)
   * @function
   * @param {String} key 256-bit key
   * @see {@link https://github.com/asmcrypto/asmcrypto.js|asmCrypto}
   * @see {@link https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf|NIST FIPS-197}
   * @returns {Object}
   * @requires asmcrypto.js
   */
  aes256: (0, _aes.default)(256),
  // Not in OpenPGP specifications
  des: _des.default.DES,

  /**
   * Triple DES Block Cipher (ID 2)
   * @function
   * @param {String} key 192-bit key
   * @see {@link https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf|NIST SP 800-67}
   * @returns {Object}
   */
  tripledes: _des.default.TripleDES,

  /**
   * CAST-128 Block Cipher (ID 3)
   * @function
   * @param {String} key 128-bit key
   * @see {@link https://tools.ietf.org/html/rfc2144|The CAST-128 Encryption Algorithm}
   * @returns {Object}
   */
  cast5: _cast.default,

  /**
   * Twofish Block Cipher (ID 10)
   * @function
   * @param {String} key 256-bit key
   * @see {@link https://tools.ietf.org/html/rfc4880#ref-TWOFISH|TWOFISH}
   * @returns {Object}
   */
  twofish: _twofish.default,

  /**
   * Blowfish Block Cipher (ID 4)
   * @function
   * @param {String} key 128-bit key
   * @see {@link https://tools.ietf.org/html/rfc4880#ref-BLOWFISH|BLOWFISH}
   * @returns {Object}
   */
  blowfish: _blowfish.default,

  /**
   * Not implemented
   * @function
   * @throws {Error}
   */
  idea: function () {
    throw new Error('IDEA symmetric-key algorithm not implemented');
  }
};
exports.default = _default;