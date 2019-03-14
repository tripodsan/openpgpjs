"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.CleartextMessage = CleartextMessage;
exports.readArmored = readArmored;
exports.fromText = fromText;

var _armor = _interopRequireDefault(require("./encoding/armor"));

var _enums = _interopRequireDefault(require("./enums"));

var _util = _interopRequireDefault(require("./util"));

var _packet = _interopRequireDefault(require("./packet"));

var _signature = require("./signature");

var _message = require("./message");

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
 * @requires encoding/armor
 * @requires enums
 * @requires util
 * @requires packet
 * @requires signature
 * @module cleartext
 */

/**
 * @class
 * @classdesc Class that represents an OpenPGP cleartext signed message.
 * See {@link https://tools.ietf.org/html/rfc4880#section-7}
 * @param  {String}           text       The cleartext of the signed message
 * @param  {module:signature.Signature} signature  The detached signature or an empty signature for unsigned messages
 */
function CleartextMessage(text, signature) {
  if (!(this instanceof CleartextMessage)) {
    return new CleartextMessage(text, signature);
  } // normalize EOL to canonical form <CR><LF>


  this.text = _util.default.canonicalizeEOL(_util.default.removeTrailingSpaces(text));

  if (signature && !(signature instanceof _signature.Signature)) {
    throw new Error('Invalid signature input');
  }

  this.signature = signature || new _signature.Signature(new _packet.default.List());
}
/**
 * Returns the key IDs of the keys that signed the cleartext message
 * @returns {Array<module:type/keyid>} array of keyid objects
 */


CleartextMessage.prototype.getSigningKeyIds = function () {
  const keyIds = [];
  const signatureList = this.signature.packets;
  signatureList.forEach(function (packet) {
    keyIds.push(packet.issuerKeyId);
  });
  return keyIds;
};
/**
 * Sign the cleartext message
 * @param  {Array<module:key.Key>} privateKeys private keys with decrypted secret key data for signing
 * @param  {Signature} signature             (optional) any existing detached signature
 * @param  {Date} date                       (optional) The creation time of the signature that should be created
 * @param  {Object} userId                   (optional) user ID to sign with, e.g. { name:'Steve Sender', email:'steve@openpgp.org' }
 * @returns {Promise<module:cleartext.CleartextMessage>} new cleartext message with signed content
 * @async
 */


CleartextMessage.prototype.sign = async function (privateKeys, signature = null, date = new Date(), userId = {}) {
  return new CleartextMessage(this.text, (await this.signDetached(privateKeys, signature, date, userId)));
};
/**
 * Sign the cleartext message
 * @param  {Array<module:key.Key>} privateKeys private keys with decrypted secret key data for signing
 * @param  {Signature} signature             (optional) any existing detached signature
 * @param  {Date} date                       (optional) The creation time of the signature that should be created
 * @param  {Object} userId                   (optional) user ID to sign with, e.g. { name:'Steve Sender', email:'steve@openpgp.org' }
 * @returns {Promise<module:signature.Signature>}      new detached signature of message content
 * @async
 */


CleartextMessage.prototype.signDetached = async function (privateKeys, signature = null, date = new Date(), userId = {}) {
  const literalDataPacket = new _packet.default.Literal();
  literalDataPacket.setText(this.text);
  return new _signature.Signature((await (0, _message.createSignaturePackets)(literalDataPacket, privateKeys, signature, date, userId)));
};
/**
 * Verify signatures of cleartext signed message
 * @param {Array<module:key.Key>} keys array of keys to verify signatures
 * @param {Date} date (optional) Verify the signature against the given date, i.e. check signature creation time < date < expiration time
 * @returns {Promise<Array<{keyid: module:type/keyid, valid: Boolean}>>} list of signer's keyid and validity of signature
 * @async
 */


CleartextMessage.prototype.verify = function (keys, date = new Date()) {
  return this.verifyDetached(this.signature, keys, date);
};
/**
 * Verify signatures of cleartext signed message
 * @param {Array<module:key.Key>} keys array of keys to verify signatures
 * @param {Date} date (optional) Verify the signature against the given date, i.e. check signature creation time < date < expiration time
 * @returns {Promise<Array<{keyid: module:type/keyid, valid: Boolean}>>} list of signer's keyid and validity of signature
 * @async
 */


CleartextMessage.prototype.verifyDetached = function (signature, keys, date = new Date()) {
  const signatureList = signature.packets;
  const literalDataPacket = new _packet.default.Literal(); // we assume that cleartext signature is generated based on UTF8 cleartext

  literalDataPacket.setText(this.text);
  return (0, _message.createVerificationObjects)(signatureList, [literalDataPacket], keys, date);
};
/**
 * Get cleartext
 * @returns {String} cleartext of message
 */


CleartextMessage.prototype.getText = function () {
  // normalize end of line to \n
  return _util.default.nativeEOL(this.text);
};
/**
 * Returns ASCII armored text of cleartext signed message
 * @returns {String | ReadableStream<String>} ASCII armor
 */


CleartextMessage.prototype.armor = function () {
  let hashes = this.signature.packets.map(function (packet) {
    return _enums.default.read(_enums.default.hash, packet.hashAlgorithm).toUpperCase();
  });
  hashes = hashes.filter(function (item, i, ar) {
    return ar.indexOf(item) === i;
  });
  const body = {
    hash: hashes.join(),
    text: this.text,
    data: this.signature.packets.write()
  };
  return _armor.default.encode(_enums.default.armor.signed, body);
};
/**
 * reads an OpenPGP cleartext signed message and returns a CleartextMessage object
 * @param {String | ReadableStream<String>} armoredText text to be parsed
 * @returns {module:cleartext.CleartextMessage} new cleartext message object
 * @async
 * @static
 */


async function readArmored(armoredText) {
  const input = await _armor.default.decode(armoredText);

  if (input.type !== _enums.default.armor.signed) {
    throw new Error('No cleartext signed message.');
  }

  const packetlist = new _packet.default.List();
  await packetlist.read(input.data);
  verifyHeaders(input.headers, packetlist);
  const signature = new _signature.Signature(packetlist);
  return new CleartextMessage(input.text, signature);
}
/**
 * Compare hash algorithm specified in the armor header with signatures
 * @param  {Array<String>} headers    Armor headers
 * @param  {module:packet.List} packetlist The packetlist with signature packets
 * @private
 */


function verifyHeaders(headers, packetlist) {
  const checkHashAlgos = function (hashAlgos) {
    const check = packet => algo => packet.hashAlgorithm === algo;

    for (let i = 0; i < packetlist.length; i++) {
      if (packetlist[i].tag === _enums.default.packet.signature && !hashAlgos.some(check(packetlist[i]))) {
        return false;
      }
    }

    return true;
  };

  let oneHeader = null;
  let hashAlgos = [];
  headers.forEach(function (header) {
    oneHeader = header.match(/Hash: (.+)/); // get header value

    if (oneHeader) {
      oneHeader = oneHeader[1].replace(/\s/g, ''); // remove whitespace

      oneHeader = oneHeader.split(',');
      oneHeader = oneHeader.map(function (hash) {
        hash = hash.toLowerCase();

        try {
          return _enums.default.write(_enums.default.hash, hash);
        } catch (e) {
          throw new Error('Unknown hash algorithm in armor header: ' + hash);
        }
      });
      hashAlgos = hashAlgos.concat(oneHeader);
    } else {
      throw new Error('Only "Hash" header allowed in cleartext signed message');
    }
  });

  if (!hashAlgos.length && !checkHashAlgos([_enums.default.hash.md5])) {
    throw new Error('If no "Hash" header in cleartext signed message, then only MD5 signatures allowed');
  } else if (hashAlgos.length && !checkHashAlgos(hashAlgos)) {
    throw new Error('Hash algorithm mismatch in armor header and signature');
  }
}
/**
 * Creates a new CleartextMessage object from text
 * @param {String} text
 * @static
 */


function fromText(text) {
  return new CleartextMessage(text);
}