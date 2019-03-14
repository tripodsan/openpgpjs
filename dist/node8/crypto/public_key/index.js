"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _rsa = _interopRequireDefault(require("./rsa"));

var _elgamal = _interopRequireDefault(require("./elgamal"));

var _elliptic = _interopRequireDefault(require("./elliptic"));

var _dsa = _interopRequireDefault(require("./dsa"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @fileoverview Asymmetric cryptography functions
 * @requires crypto/public_key/dsa
 * @requires crypto/public_key/elgamal
 * @requires crypto/public_key/elliptic
 * @requires crypto/public_key/rsa
 * @module crypto/public_key
 */
var _default = {
  /** @see module:crypto/public_key/rsa */
  rsa: _rsa.default,

  /** @see module:crypto/public_key/elgamal */
  elgamal: _elgamal.default,

  /** @see module:crypto/public_key/elliptic */
  elliptic: _elliptic.default,

  /** @see module:crypto/public_key/dsa */
  dsa: _dsa.default
};
exports.default = _default;