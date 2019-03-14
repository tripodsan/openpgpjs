"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _util = _interopRequireDefault(require("./util"));

var _crypto = _interopRequireDefault(require("./crypto"));

var keyMod = _interopRequireWildcard(require("./key"));

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = Object.defineProperty && Object.getOwnPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : {}; if (desc.get || desc.set) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2018 Wiktor Kwapisiewicz
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
 * @fileoverview This class implements a client for the Web Key Directory (wkd) protocol
 * in order to lookup keys on designated servers.
 * See: https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/
 * @module wkd
 */

/**
 * Initialize the WKD client
 * @constructor
 */
function WKD() {
  this._fetch = typeof window !== 'undefined' ? window.fetch : require('node-fetch');
}
/**
 * Search for a public key using Web Key Directory protocol.
 * @param   {String}   options.email         User's email.
 * @param   {Boolean}  options.rawBytes      Returns Uint8Array instead of parsed key.
 * @returns {Promise<Uint8Array|
 *           {keys: Array<module:key.Key>,
 *            err: (Array<Error>|null)}>}     The public key.
 * @async
 */


WKD.prototype.lookup = function (options) {
  const fetch = this._fetch;

  if (!options.email) {
    throw new Error('You must provide an email parameter!');
  }

  if (!_util.default.isEmailAddress(options.email)) {
    throw new Error('Invalid e-mail address.');
  }

  const [, localPart, domain] = /(.*)@(.*)/.exec(options.email);

  const localEncoded = _util.default.encodeZBase32(_crypto.default.hash.sha1(_util.default.str_to_Uint8Array(localPart.toLowerCase())));

  const url = `https://${domain}/.well-known/openpgpkey/hu/${localEncoded}`;
  return fetch(url).then(function (response) {
    if (response.status === 200) {
      return response.arrayBuffer();
    }
  }).then(function (publicKey) {
    if (publicKey) {
      const rawBytes = new Uint8Array(publicKey);

      if (options.rawBytes) {
        return rawBytes;
      }

      return keyMod.read(rawBytes);
    }
  });
};

var _default = WKD;
exports.default = _default;