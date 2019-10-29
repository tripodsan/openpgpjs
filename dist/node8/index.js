"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
Object.defineProperty(exports, "encrypt", {
  enumerable: true,
  get: function () {
    return openpgp.encrypt;
  }
});
Object.defineProperty(exports, "decrypt", {
  enumerable: true,
  get: function () {
    return openpgp.decrypt;
  }
});
Object.defineProperty(exports, "sign", {
  enumerable: true,
  get: function () {
    return openpgp.sign;
  }
});
Object.defineProperty(exports, "verify", {
  enumerable: true,
  get: function () {
    return openpgp.verify;
  }
});
Object.defineProperty(exports, "generateKey", {
  enumerable: true,
  get: function () {
    return openpgp.generateKey;
  }
});
Object.defineProperty(exports, "reformatKey", {
  enumerable: true,
  get: function () {
    return openpgp.reformatKey;
  }
});
Object.defineProperty(exports, "revokeKey", {
  enumerable: true,
  get: function () {
    return openpgp.revokeKey;
  }
});
Object.defineProperty(exports, "decryptKey", {
  enumerable: true,
  get: function () {
    return openpgp.decryptKey;
  }
});
Object.defineProperty(exports, "encryptSessionKey", {
  enumerable: true,
  get: function () {
    return openpgp.encryptSessionKey;
  }
});
Object.defineProperty(exports, "decryptSessionKeys", {
  enumerable: true,
  get: function () {
    return openpgp.decryptSessionKeys;
  }
});
Object.defineProperty(exports, "initWorker", {
  enumerable: true,
  get: function () {
    return openpgp.initWorker;
  }
});
Object.defineProperty(exports, "getWorker", {
  enumerable: true,
  get: function () {
    return openpgp.getWorker;
  }
});
Object.defineProperty(exports, "destroyWorker", {
  enumerable: true,
  get: function () {
    return openpgp.destroyWorker;
  }
});
Object.defineProperty(exports, "util", {
  enumerable: true,
  get: function () {
    return _util.default;
  }
});
Object.defineProperty(exports, "packet", {
  enumerable: true,
  get: function () {
    return _packet.default;
  }
});
Object.defineProperty(exports, "MPI", {
  enumerable: true,
  get: function () {
    return _mpi.default;
  }
});
Object.defineProperty(exports, "S2K", {
  enumerable: true,
  get: function () {
    return _s2k.default;
  }
});
Object.defineProperty(exports, "Keyid", {
  enumerable: true,
  get: function () {
    return _keyid.default;
  }
});
Object.defineProperty(exports, "ECDHSymmetricKey", {
  enumerable: true,
  get: function () {
    return _ecdh_symkey.default;
  }
});
Object.defineProperty(exports, "KDFParams", {
  enumerable: true,
  get: function () {
    return _kdf_params.default;
  }
});
Object.defineProperty(exports, "OID", {
  enumerable: true,
  get: function () {
    return _oid.default;
  }
});
Object.defineProperty(exports, "stream", {
  enumerable: true,
  get: function () {
    return _webStreamTools.default;
  }
});
Object.defineProperty(exports, "armor", {
  enumerable: true,
  get: function () {
    return _armor.default;
  }
});
Object.defineProperty(exports, "enums", {
  enumerable: true,
  get: function () {
    return _enums.default;
  }
});
Object.defineProperty(exports, "config", {
  enumerable: true,
  get: function () {
    return _config.default;
  }
});
Object.defineProperty(exports, "crypto", {
  enumerable: true,
  get: function () {
    return _crypto.default;
  }
});
Object.defineProperty(exports, "Keyring", {
  enumerable: true,
  get: function () {
    return _keyring.default;
  }
});
Object.defineProperty(exports, "AsyncProxy", {
  enumerable: true,
  get: function () {
    return _async_proxy.default;
  }
});
Object.defineProperty(exports, "HKP", {
  enumerable: true,
  get: function () {
    return _hkp.default;
  }
});
Object.defineProperty(exports, "WKD", {
  enumerable: true,
  get: function () {
    return _wkd.default;
  }
});
exports.cleartext = exports.message = exports.signature = exports.key = exports.default = void 0;

var openpgp = _interopRequireWildcard(require("./openpgp"));

var keyMod = _interopRequireWildcard(require("./key"));

var signatureMod = _interopRequireWildcard(require("./signature"));

var messageMod = _interopRequireWildcard(require("./message"));

var cleartextMod = _interopRequireWildcard(require("./cleartext"));

var _util = _interopRequireDefault(require("./util"));

var _packet = _interopRequireDefault(require("./packet"));

var _mpi = _interopRequireDefault(require("./type/mpi"));

var _s2k = _interopRequireDefault(require("./type/s2k"));

var _keyid = _interopRequireDefault(require("./type/keyid"));

var _ecdh_symkey = _interopRequireDefault(require("./type/ecdh_symkey"));

var _kdf_params = _interopRequireDefault(require("./type/kdf_params"));

var _oid = _interopRequireDefault(require("./type/oid"));

var _webStreamTools = _interopRequireDefault(require("@tripod/web-stream-tools"));

var _armor = _interopRequireDefault(require("./encoding/armor"));

var _enums = _interopRequireDefault(require("./enums"));

var _config = _interopRequireDefault(require("./config/config"));

var _crypto = _interopRequireDefault(require("./crypto"));

var _keyring = _interopRequireDefault(require("./keyring"));

var _async_proxy = _interopRequireDefault(require("./worker/async_proxy"));

var _hkp = _interopRequireDefault(require("./hkp"));

var _wkd = _interopRequireDefault(require("./wkd"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = Object.defineProperty && Object.getOwnPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : {}; if (desc.get || desc.set) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } } newObj.default = obj; return newObj; } }

/* eslint-disable import/newline-after-import, import/first */

/**
 * Export high level api as default.
 * Usage:
 *
 *   import openpgp from 'openpgp.js'
 *   openpgp.encryptMessage(keys, text)
 */
var _default = openpgp;
/**
 * Export each high level api function separately.
 * Usage:
 *
 *   import { encryptMessage } from 'openpgp.js'
 *   encryptMessage(keys, text)
 */

exports.default = _default;
const key = keyMod;
/**
 * @see module:signature
 * @name module:openpgp.signature
 */

exports.key = key;
const signature = signatureMod;
/**
 * @see module:message
 * @name module:openpgp.message
 */

exports.signature = signature;
const message = messageMod;
/**
 * @see module:cleartext
 * @name module:openpgp.cleartext
 */

exports.message = message;
const cleartext = cleartextMod;
/**
 * @see module:util
 * @name module:openpgp.util
 */

exports.cleartext = cleartext;