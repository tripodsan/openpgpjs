"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _bn = _interopRequireDefault(require("bn.js"));

var _webStreamTools = _interopRequireDefault(require("web-stream-tools"));

var _curves = require("./curves");

var _util = _interopRequireDefault(require("../../../util"));

var _enums = _interopRequireDefault(require("../../../enums"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015-2016 Decentral
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
 * @fileoverview Wrapper for a KeyPair of an Elliptic Curve
 * @requires bn.js
 * @requires web-stream-tools
 * @requires crypto/public_key/elliptic/curves
 * @requires util
 * @requires enums
 * @requires asn1.js
 * @module crypto/public_key/elliptic/key
 */
const webCrypto = _util.default.getWebCrypto();

const nodeCrypto = _util.default.getNodeCrypto();
/**
 * @constructor
 */


function KeyPair(curve, options) {
  this.curve = curve;
  this.keyType = curve.curve.type === 'edwards' ? _enums.default.publicKey.eddsa : _enums.default.publicKey.ecdsa;
  this.keyPair = this.curve.curve.keyPair(options);
}

KeyPair.prototype.sign = async function (message, hash_algo, hashed) {
  if (message && !message.locked) {
    message = await _webStreamTools.default.readToEnd(message);

    if (this.curve.web && _util.default.getWebCrypto()) {
      // If browser doesn't support a curve, we'll catch it
      try {
        // need to await to make sure browser succeeds
        const signature = await webSign(this.curve, hash_algo, message, this.keyPair);
        return signature;
      } catch (err) {
        _util.default.print_debug("Browser did not support signing: " + err.message);
      }
    } else if (this.curve.node && _util.default.getNodeCrypto()) {
      return nodeSign(this.curve, hash_algo, message, this.keyPair);
    }
  }

  const digest = typeof hash_algo === 'undefined' ? message : hashed;
  return this.keyPair.sign(digest);
};

KeyPair.prototype.verify = async function (message, signature, hash_algo, hashed) {
  if (message && !message.locked) {
    message = await _webStreamTools.default.readToEnd(message);

    if (this.curve.web && _util.default.getWebCrypto()) {
      // If browser doesn't support a curve, we'll catch it
      try {
        // need to await to make sure browser succeeds
        const result = await webVerify(this.curve, hash_algo, signature, message, this.keyPair.getPublic());
        return result;
      } catch (err) {
        _util.default.print_debug("Browser did not support signing: " + err.message);
      }
    } else if (this.curve.node && _util.default.getNodeCrypto()) {
      return nodeVerify(this.curve, hash_algo, signature, message, this.keyPair.getPublic());
    }
  }

  const digest = typeof hash_algo === 'undefined' ? message : hashed;
  return this.keyPair.verify(digest, signature);
};

KeyPair.prototype.derive = function (pub) {
  if (this.keyType === _enums.default.publicKey.eddsa) {
    throw new Error('Key can only be used for EdDSA');
  }

  return this.keyPair.derive(pub.keyPair.getPublic());
};

KeyPair.prototype.getPublic = function () {
  const compact = this.curve.curve.curve.type === 'edwards' || this.curve.curve.curve.type === 'mont';
  return this.keyPair.getPublic('array', compact);
};

KeyPair.prototype.getPrivate = function () {
  if (this.curve.keyType === _enums.default.publicKey.eddsa) {
    return this.keyPair.getSecret();
  }

  return this.keyPair.getPrivate().toArray();
};

var _default = KeyPair; //////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////

exports.default = _default;

async function webSign(curve, hash_algo, message, keyPair) {
  const len = curve.payloadSize;
  const key = await webCrypto.importKey("jwk", {
    "kty": "EC",
    "crv": _curves.webCurves[curve.name],
    "x": _util.default.Uint8Array_to_b64(new Uint8Array(keyPair.getPublic().getX().toArray('be', len)), true),
    "y": _util.default.Uint8Array_to_b64(new Uint8Array(keyPair.getPublic().getY().toArray('be', len)), true),
    "d": _util.default.Uint8Array_to_b64(new Uint8Array(keyPair.getPrivate().toArray('be', len)), true),
    "use": "sig",
    "kid": "ECDSA Private Key"
  }, {
    "name": "ECDSA",
    "namedCurve": _curves.webCurves[curve.name],
    "hash": {
      name: _enums.default.read(_enums.default.webHash, curve.hash)
    }
  }, false, ["sign"]);
  const signature = new Uint8Array((await webCrypto.sign({
    "name": 'ECDSA',
    "namedCurve": _curves.webCurves[curve.name],
    "hash": {
      name: _enums.default.read(_enums.default.webHash, hash_algo)
    }
  }, key, message)));
  return {
    r: new _bn.default(signature.slice(0, len)),
    s: new _bn.default(signature.slice(len, len << 1))
  };
}

async function webVerify(curve, hash_algo, {
  r,
  s
}, message, publicKey) {
  const len = curve.payloadSize;
  const key = await webCrypto.importKey("jwk", {
    "kty": "EC",
    "crv": _curves.webCurves[curve.name],
    "x": _util.default.Uint8Array_to_b64(new Uint8Array(publicKey.getX().toArray('be', len)), true),
    "y": _util.default.Uint8Array_to_b64(new Uint8Array(publicKey.getY().toArray('be', len)), true),
    "use": "sig",
    "kid": "ECDSA Public Key"
  }, {
    "name": "ECDSA",
    "namedCurve": _curves.webCurves[curve.name],
    "hash": {
      name: _enums.default.read(_enums.default.webHash, curve.hash)
    }
  }, false, ["verify"]);

  const signature = _util.default.concatUint8Array([new Uint8Array(len - r.length), r, new Uint8Array(len - s.length), s]).buffer;

  return webCrypto.verify({
    "name": 'ECDSA',
    "namedCurve": _curves.webCurves[curve.name],
    "hash": {
      name: _enums.default.read(_enums.default.webHash, hash_algo)
    }
  }, key, signature, message);
}

async function nodeSign(curve, hash_algo, message, keyPair) {
  const sign = nodeCrypto.createSign(_enums.default.read(_enums.default.hash, hash_algo));
  sign.write(message);
  sign.end();
  const key = ECPrivateKey.encode({
    version: 1,
    parameters: curve.oid,
    privateKey: keyPair.getPrivate().toArray(),
    publicKey: {
      unused: 0,
      data: keyPair.getPublic().encode()
    }
  }, 'pem', {
    label: 'EC PRIVATE KEY'
  });
  return ECDSASignature.decode(sign.sign(key), 'der');
}

async function nodeVerify(curve, hash_algo, {
  r,
  s
}, message, publicKey) {
  const verify = nodeCrypto.createVerify(_enums.default.read(_enums.default.hash, hash_algo));
  verify.write(message);
  verify.end();
  const key = SubjectPublicKeyInfo.encode({
    algorithm: {
      algorithm: [1, 2, 840, 10045, 2, 1],
      parameters: curve.oid
    },
    subjectPublicKey: {
      unused: 0,
      data: publicKey.encode()
    }
  }, 'pem', {
    label: 'PUBLIC KEY'
  });
  const signature = ECDSASignature.encode({
    r: new _bn.default(r),
    s: new _bn.default(s)
  }, 'der');

  try {
    return verify.verify(key, signature);
  } catch (err) {
    return false;
  }
} // Originally written by Owen Smith https://github.com/omsmith
// Adapted on Feb 2018 from https://github.com/Brightspace/node-jwk-to-pem/

/* eslint-disable no-invalid-this */


const asn1 = nodeCrypto ? require('asn1.js') : undefined;
const ECDSASignature = nodeCrypto ? asn1.define('ECDSASignature', function () {
  this.seq().obj(this.key('r').int(), this.key('s').int());
}) : undefined;
const ECPrivateKey = nodeCrypto ? asn1.define('ECPrivateKey', function () {
  this.seq().obj(this.key('version').int(), this.key('privateKey').octstr(), this.key('parameters').explicit(0).optional().any(), this.key('publicKey').explicit(1).optional().bitstr());
}) : undefined;
const AlgorithmIdentifier = nodeCrypto ? asn1.define('AlgorithmIdentifier', function () {
  this.seq().obj(this.key('algorithm').objid(), this.key('parameters').optional().any());
}) : undefined;
const SubjectPublicKeyInfo = nodeCrypto ? asn1.define('SubjectPublicKeyInfo', function () {
  this.seq().obj(this.key('algorithm').use(AlgorithmIdentifier), this.key('subjectPublicKey').bitstr());
}) : undefined;