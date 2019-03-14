"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _cfb = require("asmcrypto.js/dist_compat/aes/cfb");

var _webStreamTools = _interopRequireDefault(require("web-stream-tools"));

var _config = _interopRequireDefault(require("../config"));

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
 * @requires asmcrypto.js
 * @requires web-stream-tools
 * @requires config
 * @requires crypto
 * @requires enums
 * @requires util
 */
const nodeCrypto = _util.default.getNodeCrypto();

const Buffer = _util.default.getNodeBuffer();

const VERSION = 1; // A one-octet version number of the data packet.

/**
 * Implementation of the Sym. Encrypted Integrity Protected Data Packet (Tag 18)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.13|RFC4880 5.13}:
 * The Symmetrically Encrypted Integrity Protected Data packet is
 * a variant of the Symmetrically Encrypted Data packet. It is a new feature
 * created for OpenPGP that addresses the problem of detecting a modification to
 * encrypted data. It is used in combination with a Modification Detection Code
 * packet.
 * @memberof module:packet
 * @constructor
 */

function SymEncryptedIntegrityProtected() {
  this.tag = _enums.default.packet.symEncryptedIntegrityProtected;
  this.version = VERSION;
  /** The encrypted payload. */

  this.encrypted = null; // string

  /**
   * If after decrypting the packet this is set to true,
   * a modification has been detected and thus the contents
   * should be discarded.
   * @type {Boolean}
   */

  this.modification = false;
  this.packets = null;
}

SymEncryptedIntegrityProtected.prototype.read = async function (bytes) {
  await _webStreamTools.default.parse(bytes, async reader => {
    // - A one-octet version number. The only currently defined value is 1.
    if ((await reader.readByte()) !== VERSION) {
      throw new Error('Invalid packet version.');
    } // - Encrypted data, the output of the selected symmetric-key cipher
    //   operating in Cipher Feedback mode with shift amount equal to the
    //   block size of the cipher (CFB-n where n is the block size).


    this.encrypted = reader.remainder();
  });
};

SymEncryptedIntegrityProtected.prototype.write = function () {
  return _util.default.concat([new Uint8Array([VERSION]), this.encrypted]);
};
/**
 * Encrypt the payload in the packet.
 * @param  {String} sessionKeyAlgorithm   The selected symmetric encryption algorithm to be used e.g. 'aes128'
 * @param  {Uint8Array} key               The key of cipher blocksize length to be used
 * @param  {Boolean} streaming            Whether to set this.encrypted to a stream
 * @returns {Promise<Boolean>}
 * @async
 */


SymEncryptedIntegrityProtected.prototype.encrypt = async function (sessionKeyAlgorithm, key, streaming) {
  let bytes = this.packets.write();
  if (!streaming) bytes = await _webStreamTools.default.readToEnd(bytes);
  const prefixrandom = await _crypto.default.getPrefixRandom(sessionKeyAlgorithm);
  const repeat = new Uint8Array([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);

  const prefix = _util.default.concat([prefixrandom, repeat]);

  const mdc = new Uint8Array([0xD3, 0x14]); // modification detection code packet

  let tohash = _util.default.concat([bytes, mdc]);

  const hash = _crypto.default.hash.sha1(_util.default.concat([prefix, _webStreamTools.default.passiveClone(tohash)]));

  tohash = _util.default.concat([tohash, hash]);

  if (sessionKeyAlgorithm.substr(0, 3) === 'aes') {
    // AES optimizations. Native code for node, asmCrypto for browser.
    this.encrypted = aesEncrypt(sessionKeyAlgorithm, _util.default.concat([prefix, tohash]), key);
  } else {
    tohash = await _webStreamTools.default.readToEnd(tohash);
    this.encrypted = _crypto.default.cfb.encrypt(prefixrandom, sessionKeyAlgorithm, tohash, key, false);
    this.encrypted = _webStreamTools.default.slice(this.encrypted, 0, prefix.length + tohash.length);
  }

  return true;
};
/**
 * Decrypts the encrypted data contained in the packet.
 * @param  {String} sessionKeyAlgorithm   The selected symmetric encryption algorithm to be used e.g. 'aes128'
 * @param  {Uint8Array} key               The key of cipher blocksize length to be used
 * @param  {Boolean} streaming            Whether to read this.encrypted as a stream
 * @returns {Promise<Boolean>}
 * @async
 */


SymEncryptedIntegrityProtected.prototype.decrypt = async function (sessionKeyAlgorithm, key, streaming) {
  if (!streaming) this.encrypted = await _webStreamTools.default.readToEnd(this.encrypted);

  const encrypted = _webStreamTools.default.clone(this.encrypted);

  const encryptedClone = _webStreamTools.default.passiveClone(encrypted);

  let decrypted;

  if (sessionKeyAlgorithm.substr(0, 3) === 'aes') {
    // AES optimizations. Native code for node, asmCrypto for browser.
    decrypted = aesDecrypt(sessionKeyAlgorithm, encrypted, key, streaming);
  } else {
    decrypted = _crypto.default.cfb.decrypt(sessionKeyAlgorithm, key, (await _webStreamTools.default.readToEnd(encrypted)), false);
  } // there must be a modification detection code packet as the
  // last packet and everything gets hashed except the hash itself


  const encryptedPrefix = await _webStreamTools.default.readToEnd(_webStreamTools.default.slice(encryptedClone, 0, _crypto.default.cipher[sessionKeyAlgorithm].blockSize + 2));

  const prefix = _crypto.default.cfb.mdc(sessionKeyAlgorithm, key, encryptedPrefix);

  const realHash = _webStreamTools.default.slice(_webStreamTools.default.passiveClone(decrypted), -20);

  const bytes = _webStreamTools.default.slice(decrypted, 0, -20);

  const tohash = _util.default.concat([prefix, _webStreamTools.default.passiveClone(bytes)]);

  const verifyHash = Promise.all([_webStreamTools.default.readToEnd(_crypto.default.hash.sha1(tohash)), _webStreamTools.default.readToEnd(realHash)]).then(([hash, mdc]) => {
    if (!_util.default.equalsUint8Array(hash, mdc)) {
      throw new Error('Modification detected.');
    }

    return new Uint8Array();
  });

  let packetbytes = _webStreamTools.default.slice(bytes, 0, -2);

  packetbytes = _webStreamTools.default.concat([packetbytes, _webStreamTools.default.fromAsync(() => verifyHash)]);

  if (!_util.default.isStream(encrypted) || !_config.default.allow_unauthenticated_stream) {
    packetbytes = await _webStreamTools.default.readToEnd(packetbytes);
  }

  await this.packets.read(packetbytes);
  return true;
};

var _default = SymEncryptedIntegrityProtected; //////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////

exports.default = _default;

function aesEncrypt(algo, pt, key) {
  if (nodeCrypto) {
    // Node crypto library.
    return nodeEncrypt(algo, pt, key);
  } // asm.js fallback


  const cfb = new _cfb.AES_CFB(key);
  return _webStreamTools.default.transform(pt, value => cfb.AES_Encrypt_process(value), () => cfb.AES_Encrypt_finish());
}

function aesDecrypt(algo, ct, key) {
  let pt;

  if (nodeCrypto) {
    // Node crypto library.
    pt = nodeDecrypt(algo, ct, key);
  } else {
    // asm.js fallback
    if (_util.default.isStream(ct)) {
      const cfb = new _cfb.AES_CFB(key);
      pt = _webStreamTools.default.transform(ct, value => cfb.AES_Decrypt_process(value), () => cfb.AES_Decrypt_finish());
    } else {
      pt = _cfb.AES_CFB.decrypt(ct, key);
    }
  }

  return _webStreamTools.default.slice(pt, _crypto.default.cipher[algo].blockSize + 2); // Remove random prefix
}

function nodeEncrypt(algo, pt, key) {
  key = new Buffer(key);
  const iv = new Buffer(new Uint8Array(_crypto.default.cipher[algo].blockSize));
  const cipherObj = new nodeCrypto.createCipheriv('aes-' + algo.substr(3, 3) + '-cfb', key, iv);
  return _webStreamTools.default.transform(pt, value => new Uint8Array(cipherObj.update(new Buffer(value))));
}

function nodeDecrypt(algo, ct, key) {
  key = new Buffer(key);
  const iv = new Buffer(new Uint8Array(_crypto.default.cipher[algo].blockSize));
  const decipherObj = new nodeCrypto.createDecipheriv('aes-' + algo.substr(3, 3) + '-cfb', key, iv);
  return _webStreamTools.default.transform(ct, value => new Uint8Array(decipherObj.update(new Buffer(value))));
}