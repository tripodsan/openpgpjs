"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _ecb = require("asmcrypto.js/dist_compat/aes/ecb");

/**
 * @requires asmcrypto.js
 */
// TODO use webCrypto or nodeCrypto when possible.
function aes(length) {
  const C = function (key) {
    const aes_ecb = new _ecb.AES_ECB(key);

    this.encrypt = function (block) {
      return aes_ecb.encrypt(block);
    };

    this.decrypt = function (block) {
      return aes_ecb.decrypt(block);
    };
  };

  C.blockSize = C.prototype.blockSize = 16;
  C.keySize = C.prototype.keySize = length / 8;
  return C;
}

var _default = aes;
exports.default = _default;