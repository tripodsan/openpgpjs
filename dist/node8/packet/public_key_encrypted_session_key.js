"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _keyid = _interopRequireDefault(require("../type/keyid"));

var _mpi = _interopRequireDefault(require("../type/mpi"));

var _crypto = _interopRequireDefault(require("../crypto"));

var _enums = _interopRequireDefault(require("../enums"));

var _util = _interopRequireDefault(require("../util"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @requires type/keyid
 * @requires type/mpi
 * @requires crypto
 * @requires enums
 * @requires util
 */

/**
 * Public-Key Encrypted Session Key Packets (Tag 1)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.1|RFC4880 5.1}:
 * A Public-Key Encrypted Session Key packet holds the session key
 * used to encrypt a message. Zero or more Public-Key Encrypted Session Key
 * packets and/or Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data Packet, which holds an encrypted message. The
 * message is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s). The
 * Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
 * Session Key packet for each OpenPGP key to which the message is encrypted.
 * The recipient of the message finds a session key that is encrypted to their
 * public key, decrypts the session key, and then uses the session key to
 * decrypt the message.
 * @memberof module:packet
 * @constructor
 */
function PublicKeyEncryptedSessionKey() {
  this.tag = _enums.default.packet.publicKeyEncryptedSessionKey;
  this.version = 3;
  this.publicKeyId = new _keyid.default();
  this.sessionKey = null;
  /** @type {Array<module:type/mpi>} */

  this.encrypted = [];
}
/**
 * Parsing function for a publickey encrypted session key packet (tag 1).
 *
 * @param {Uint8Array} input Payload of a tag 1 packet
 * @param {Integer} position Position to start reading from the input string
 * @param {Integer} len Length of the packet or the remaining length of
 *            input at position
 * @returns {module:packet.PublicKeyEncryptedSessionKey} Object representation
 */


PublicKeyEncryptedSessionKey.prototype.read = function (bytes) {
  this.version = bytes[0];
  this.publicKeyId.read(bytes.subarray(1, bytes.length));
  this.publicKeyAlgorithm = _enums.default.read(_enums.default.publicKey, bytes[9]);
  let i = 10;

  const algo = _enums.default.write(_enums.default.publicKey, this.publicKeyAlgorithm);

  const types = _crypto.default.getEncSessionKeyParamTypes(algo);

  this.encrypted = _crypto.default.constructParams(types);

  for (let j = 0; j < types.length; j++) {
    i += this.encrypted[j].read(bytes.subarray(i, bytes.length));
  }
};
/**
 * Create a string representation of a tag 1 packet
 *
 * @returns {Uint8Array} The Uint8Array representation
 */


PublicKeyEncryptedSessionKey.prototype.write = function () {
  const arr = [new Uint8Array([this.version]), this.publicKeyId.write(), new Uint8Array([_enums.default.write(_enums.default.publicKey, this.publicKeyAlgorithm)])];

  for (let i = 0; i < this.encrypted.length; i++) {
    arr.push(this.encrypted[i].write());
  }

  return _util.default.concatUint8Array(arr);
};
/**
 * Encrypt session key packet
 * @param {module:packet.PublicKey} key Public key
 * @returns {Promise<Boolean>}
 * @async
 */


PublicKeyEncryptedSessionKey.prototype.encrypt = async function (key) {
  let data = String.fromCharCode(_enums.default.write(_enums.default.symmetric, this.sessionKeyAlgorithm));
  data += _util.default.Uint8Array_to_str(this.sessionKey);

  const checksum = _util.default.calc_checksum(this.sessionKey);

  data += _util.default.Uint8Array_to_str(_util.default.writeNumber(checksum, 2));
  let toEncrypt;

  const algo = _enums.default.write(_enums.default.publicKey, this.publicKeyAlgorithm);

  if (algo === _enums.default.publicKey.ecdh) {
    toEncrypt = new _mpi.default(_crypto.default.pkcs5.encode(data));
  } else {
    toEncrypt = new _mpi.default((await _crypto.default.pkcs1.eme.encode(data, key.params[0].byteLength())));
  }

  this.encrypted = await _crypto.default.publicKeyEncrypt(algo, key.params, toEncrypt, key.getFingerprintBytes());
  return true;
};
/**
 * Decrypts the session key (only for public key encrypted session key
 * packets (tag 1)
 *
 * @param {module:packet.SecretKey} key
 *            Private key with secret params unlocked
 * @returns {Promise<Boolean>}
 * @async
 */


PublicKeyEncryptedSessionKey.prototype.decrypt = async function (key) {
  const algo = _enums.default.write(_enums.default.publicKey, this.publicKeyAlgorithm);

  const result = await _crypto.default.publicKeyDecrypt(algo, key.params, this.encrypted, key.getFingerprintBytes());
  let checksum;
  let decoded;

  if (algo === _enums.default.publicKey.ecdh) {
    decoded = _crypto.default.pkcs5.decode(result.toString());
    checksum = _util.default.readNumber(_util.default.str_to_Uint8Array(decoded.substr(decoded.length - 2)));
  } else {
    decoded = _crypto.default.pkcs1.eme.decode(result.toString());
    checksum = _util.default.readNumber(result.toUint8Array().slice(result.byteLength() - 2));
  }

  key = _util.default.str_to_Uint8Array(decoded.substring(1, decoded.length - 2));

  if (checksum !== _util.default.calc_checksum(key)) {
    throw new Error('Checksum mismatch');
  } else {
    this.sessionKey = key;
    this.sessionKeyAlgorithm = _enums.default.read(_enums.default.symmetric, decoded.charCodeAt(0));
  }

  return true;
};
/**
 * Fix custom types after cloning
 */


PublicKeyEncryptedSessionKey.prototype.postCloneTypeFix = function () {
  this.publicKeyId = _keyid.default.fromClone(this.publicKeyId);

  const algo = _enums.default.write(_enums.default.publicKey, this.publicKeyAlgorithm);

  const types = _crypto.default.getEncSessionKeyParamTypes(algo);

  for (let i = 0; i < this.encrypted.length; i++) {
    this.encrypted[i] = types[i].fromClone(this.encrypted[i]);
  }
};

var _default = PublicKeyEncryptedSessionKey;
exports.default = _default;