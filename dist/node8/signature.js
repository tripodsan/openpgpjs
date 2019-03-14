"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Signature = Signature;
exports.readArmored = readArmored;
exports.read = read;

var _armor = _interopRequireDefault(require("./encoding/armor"));

var _packet = _interopRequireDefault(require("./packet"));

var _enums = _interopRequireDefault(require("./enums"));

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
 * @requires packet
 * @requires enums
 * @module signature
 */

/**
 * @class
 * @classdesc Class that represents an OpenPGP signature.
 * @param  {module:packet.List} packetlist The signature packets
 */
function Signature(packetlist) {
  if (!(this instanceof Signature)) {
    return new Signature(packetlist);
  }

  this.packets = packetlist || new _packet.default.List();
}
/**
 * Returns ASCII armored text of signature
 * @returns {ReadableStream<String>} ASCII armor
 */


Signature.prototype.armor = function () {
  return _armor.default.encode(_enums.default.armor.signature, this.packets.write());
};
/**
 * reads an OpenPGP armored signature and returns a signature object
 * @param {String | ReadableStream<String>} armoredText text to be parsed
 * @returns {Signature} new signature object
 * @async
 * @static
 */


async function readArmored(armoredText) {
  const input = await _armor.default.decode(armoredText);
  return read(input.data);
}
/**
 * reads an OpenPGP signature as byte array and returns a signature object
 * @param {Uint8Array | ReadableStream<Uint8Array>} input   binary signature
 * @returns {Signature}         new signature object
 * @async
 * @static
 */


async function read(input) {
  const packetlist = new _packet.default.List();
  await packetlist.read(input);
  return new Signature(packetlist);
}