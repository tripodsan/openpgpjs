"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.clonePackets = clonePackets;
exports.parseClonedPackets = parseClonedPackets;

var _webStreamTools = _interopRequireDefault(require("web-stream-tools"));

var _key = require("../key");

var _message = require("../message");

var _cleartext = require("../cleartext");

var _signature = require("../signature");

var _packetlist = _interopRequireDefault(require("./packetlist"));

var _keyid = _interopRequireDefault(require("../type/keyid"));

var _util = _interopRequireDefault(require("../util"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015 Tankred Hase
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
 * @fileoverview This module implements packet list cloning required to
 * pass certain object types between the web worker and main thread using
 * the structured cloning algorithm.
 * @module packet/clone
 */
//////////////////////////////
//                          //
//   List --> Clone   //
//                          //
//////////////////////////////

/**
 * Create a packetlist from the correspoding object types.
 * @param  {Object} options   the object passed to and from the web worker
 * @returns {Object}           a mutated version of the options optject
 */
function clonePackets(options) {
  if (options.publicKeys) {
    options.publicKeys = options.publicKeys.map(key => key.toPacketlist());
  }

  if (options.privateKeys) {
    options.privateKeys = options.privateKeys.map(key => key.toPacketlist());
  }

  if (options.privateKey) {
    options.privateKey = options.privateKey.toPacketlist();
  }

  if (options.key) {
    options.key = options.key.toPacketlist();
  }

  if (options.message) {
    //could be either a Message or CleartextMessage object
    if (options.message instanceof _message.Message) {
      options.message = options.message.packets;
    } else if (options.message instanceof _cleartext.CleartextMessage) {
      options.message = {
        text: options.message.text,
        signature: options.message.signature.packets
      };
    }
  }

  if (options.signature && options.signature instanceof _signature.Signature) {
    options.signature = options.signature.packets;
  }

  if (options.signatures) {
    options.signatures.forEach(verificationObjectToClone);
  }

  return options;
}

function verificationObjectToClone(verObject) {
  const verified = verObject.verified;
  verObject.verified = _webStreamTools.default.fromAsync(() => verified);

  if (verObject.signature instanceof Promise) {
    const signature = verObject.signature;
    verObject.signature = _webStreamTools.default.fromAsync(async () => {
      const packets = (await signature).packets;
      await verified;
      delete packets[0].signature;
      return packets;
    });
  } else {
    verObject.signature = verObject.signature.packets;
  }

  return verObject;
} //////////////////////////////
//                          //
//   Clone --> List   //
//                          //
//////////////////////////////

/**
 * Creates an object with the correct prototype from a corresponding packetlist.
 * @param  {Object} options   the object passed to and from the web worker
 * @param  {String} method    the public api function name to be delegated to the worker
 * @returns {Object}           a mutated version of the options optject
 */


function parseClonedPackets(options) {
  if (options.publicKeys) {
    options.publicKeys = options.publicKeys.map(packetlistCloneToKey);
  }

  if (options.privateKeys) {
    options.privateKeys = options.privateKeys.map(packetlistCloneToKey);
  }

  if (options.privateKey) {
    options.privateKey = packetlistCloneToKey(options.privateKey);
  }

  if (options.key) {
    options.key = packetlistCloneToKey(options.key);
  }

  if (options.message && options.message.signature) {
    options.message = packetlistCloneToCleartextMessage(options.message);
  } else if (options.message) {
    options.message = packetlistCloneToMessage(options.message);
  }

  if (options.signatures) {
    options.signatures = options.signatures.map(packetlistCloneToSignatures);
  }

  if (options.signature) {
    options.signature = packetlistCloneToSignature(options.signature);
  }

  return options;
}

function packetlistCloneToKey(clone) {
  const packetlist = _packetlist.default.fromStructuredClone(clone);

  return new _key.Key(packetlist);
}

function packetlistCloneToMessage(clone) {
  const packetlist = _packetlist.default.fromStructuredClone(clone);

  return new _message.Message(packetlist);
}

function packetlistCloneToCleartextMessage(clone) {
  const packetlist = _packetlist.default.fromStructuredClone(clone.signature);

  return new _cleartext.CleartextMessage(clone.text, new _signature.Signature(packetlist));
} //verification objects


function packetlistCloneToSignatures(clone) {
  clone.keyid = _keyid.default.fromClone(clone.keyid);

  if (_util.default.isStream(clone.signature)) {
    clone.signature = _webStreamTools.default.readToEnd(clone.signature, ([signature]) => new _signature.Signature(_packetlist.default.fromStructuredClone(signature)));
  } else {
    clone.signature = new _signature.Signature(_packetlist.default.fromStructuredClone(clone.signature));
  }

  clone.verified = _webStreamTools.default.readToEnd(clone.verified, ([verified]) => verified);
  return clone;
}

function packetlistCloneToSignature(clone) {
  if (_util.default.isString(clone) || _util.default.isStream(clone)) {
    //signature is armored
    return clone;
  }

  const packetlist = _packetlist.default.fromStructuredClone(clone);

  return new _signature.Signature(packetlist);
}