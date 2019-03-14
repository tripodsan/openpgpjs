"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.newPacketFromTag = newPacketFromTag;
exports.fromStructuredClone = fromStructuredClone;
Object.defineProperty(exports, "Compressed", {
  enumerable: true,
  get: function () {
    return _compressed.default;
  }
});
Object.defineProperty(exports, "SymEncryptedIntegrityProtected", {
  enumerable: true,
  get: function () {
    return _sym_encrypted_integrity_protected.default;
  }
});
Object.defineProperty(exports, "SymEncryptedAEADProtected", {
  enumerable: true,
  get: function () {
    return _sym_encrypted_aead_protected.default;
  }
});
Object.defineProperty(exports, "PublicKeyEncryptedSessionKey", {
  enumerable: true,
  get: function () {
    return _public_key_encrypted_session_key.default;
  }
});
Object.defineProperty(exports, "SymEncryptedSessionKey", {
  enumerable: true,
  get: function () {
    return _sym_encrypted_session_key.default;
  }
});
Object.defineProperty(exports, "Literal", {
  enumerable: true,
  get: function () {
    return _literal.default;
  }
});
Object.defineProperty(exports, "PublicKey", {
  enumerable: true,
  get: function () {
    return _public_key.default;
  }
});
Object.defineProperty(exports, "SymmetricallyEncrypted", {
  enumerable: true,
  get: function () {
    return _symmetrically_encrypted.default;
  }
});
Object.defineProperty(exports, "Marker", {
  enumerable: true,
  get: function () {
    return _marker.default;
  }
});
Object.defineProperty(exports, "PublicSubkey", {
  enumerable: true,
  get: function () {
    return _public_subkey.default;
  }
});
Object.defineProperty(exports, "UserAttribute", {
  enumerable: true,
  get: function () {
    return _user_attribute.default;
  }
});
Object.defineProperty(exports, "OnePassSignature", {
  enumerable: true,
  get: function () {
    return _one_pass_signature.default;
  }
});
Object.defineProperty(exports, "SecretKey", {
  enumerable: true,
  get: function () {
    return _secret_key.default;
  }
});
Object.defineProperty(exports, "Userid", {
  enumerable: true,
  get: function () {
    return _userid.default;
  }
});
Object.defineProperty(exports, "SecretSubkey", {
  enumerable: true,
  get: function () {
    return _secret_subkey.default;
  }
});
Object.defineProperty(exports, "Signature", {
  enumerable: true,
  get: function () {
    return _signature.default;
  }
});
Object.defineProperty(exports, "Trust", {
  enumerable: true,
  get: function () {
    return _trust.default;
  }
});

var _enums = _interopRequireDefault(require("../enums.js"));

var packets = _interopRequireWildcard(require("./all_packets.js"));

var _compressed = _interopRequireDefault(require("./compressed.js"));

var _sym_encrypted_integrity_protected = _interopRequireDefault(require("./sym_encrypted_integrity_protected.js"));

var _sym_encrypted_aead_protected = _interopRequireDefault(require("./sym_encrypted_aead_protected.js"));

var _public_key_encrypted_session_key = _interopRequireDefault(require("./public_key_encrypted_session_key.js"));

var _sym_encrypted_session_key = _interopRequireDefault(require("./sym_encrypted_session_key.js"));

var _literal = _interopRequireDefault(require("./literal.js"));

var _public_key = _interopRequireDefault(require("./public_key.js"));

var _symmetrically_encrypted = _interopRequireDefault(require("./symmetrically_encrypted.js"));

var _marker = _interopRequireDefault(require("./marker.js"));

var _public_subkey = _interopRequireDefault(require("./public_subkey.js"));

var _user_attribute = _interopRequireDefault(require("./user_attribute.js"));

var _one_pass_signature = _interopRequireDefault(require("./one_pass_signature.js"));

var _secret_key = _interopRequireDefault(require("./secret_key.js"));

var _userid = _interopRequireDefault(require("./userid.js"));

var _secret_subkey = _interopRequireDefault(require("./secret_subkey.js"));

var _signature = _interopRequireDefault(require("./signature.js"));

var _trust = _interopRequireDefault(require("./trust.js"));

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = Object.defineProperty && Object.getOwnPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : {}; if (desc.get || desc.set) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @fileoverview Exports all OpenPGP packet types
 * @requires enums
 * @module packet/all_packets
 */
// re-import module to parse packets from tag

/**
 * Allocate a new packet
 * @function newPacketFromTag
 * @memberof module:packet
 * @param {String} tag property name from {@link module:enums.packet}
 * @returns {Object} new packet object with type based on tag
 */
function newPacketFromTag(tag) {
  return new packets[packetClassFromTagName(tag)]();
}
/**
 * Allocate a new packet from structured packet clone
 * @see {@link https://w3c.github.io/html/infrastructure.html#safe-passing-of-structured-data}
 * @function fromStructuredClone
 * @memberof module:packet
 * @param {Object} packetClone packet clone
 * @returns {Object} new packet object with data from packet clone
 */


function fromStructuredClone(packetClone) {
  const tagName = _enums.default.read(_enums.default.packet, packetClone.tag);

  const packet = newPacketFromTag(tagName);
  Object.assign(packet, packetClone);

  if (packet.postCloneTypeFix) {
    packet.postCloneTypeFix();
  }

  return packet;
}
/**
 * Convert tag name to class name
 * @param {String} tag property name from {@link module:enums.packet}
 * @returns {String}
 * @private
 */


function packetClassFromTagName(tag) {
  return tag.substr(0, 1).toUpperCase() + tag.substr(1);
}