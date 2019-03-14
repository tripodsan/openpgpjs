"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _keyring = _interopRequireDefault(require("./keyring.js"));

var _localstore = _interopRequireDefault(require("./localstore.js"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @fileoverview Functions dealing with storage of the keyring.
 * @see module:keyring/keyring
 * @see module:keyring/localstore
 * @module keyring
 */
_keyring.default.localstore = _localstore.default;
var _default = _keyring.default;
exports.default = _default;