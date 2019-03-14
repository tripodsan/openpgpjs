"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _public_key = _interopRequireDefault(require("./public_key"));

var _cipher = _interopRequireDefault(require("./cipher"));

var _random = _interopRequireDefault(require("./random"));

var _ecdh_symkey = _interopRequireDefault(require("../type/ecdh_symkey"));

var _kdf_params = _interopRequireDefault(require("../type/kdf_params"));

var _mpi = _interopRequireDefault(require("../type/mpi"));

var _oid = _interopRequireDefault(require("../type/oid"));

var _enums = _interopRequireDefault(require("../enums"));

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
// The GPG4Browsers crypto interface

/**
 * @fileoverview Provides functions for asymmetric encryption and decryption as
 * well as key generation and parameter handling for all public-key cryptosystems.
 * @requires crypto/public_key
 * @requires crypto/cipher
 * @requires crypto/random
 * @requires type/ecdh_symkey
 * @requires type/kdf_params
 * @requires type/mpi
 * @requires type/oid
 * @requires enums
 * @module crypto/crypto
 */
function constructParams(types, data) {
  return types.map(function (type, i) {
    if (data && data[i]) {
      return new type(data[i]);
    }

    return new type();
  });
}

var _default = {
  /**
   * Encrypts data using specified algorithm and public key parameters.
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1} for public key algorithms.
   * @param {module:enums.publicKey}        algo        Public key algorithm
   * @param {Array<module:type/mpi|
                   module:type/oid|
                   module:type/kdf_params>} pub_params  Algorithm-specific public key parameters
   * @param {module:type/mpi}               data        Data to be encrypted as MPI
   * @param {String}                        fingerprint Recipient fingerprint
   * @returns {Array<module:type/mpi|
   *                 module:type/ecdh_symkey>}          encrypted session key parameters
   * @async
   */
  publicKeyEncrypt: async function (algo, pub_params, data, fingerprint) {
    const types = this.getEncSessionKeyParamTypes(algo);
    return async function () {
      switch (algo) {
        case _enums.default.publicKey.rsa_encrypt:
        case _enums.default.publicKey.rsa_encrypt_sign:
          {
            const m = data.toBN();
            const n = pub_params[0].toBN();
            const e = pub_params[1].toBN();
            const res = await _public_key.default.rsa.encrypt(m, n, e);
            return constructParams(types, [res]);
          }

        case _enums.default.publicKey.elgamal:
          {
            const m = data.toBN();
            const p = pub_params[0].toBN();
            const g = pub_params[1].toBN();
            const y = pub_params[2].toBN();
            const res = await _public_key.default.elgamal.encrypt(m, p, g, y);
            return constructParams(types, [res.c1, res.c2]);
          }

        case _enums.default.publicKey.ecdh:
          {
            const oid = pub_params[0];
            const Q = pub_params[1].toUint8Array();
            const kdf_params = pub_params[2];
            const res = await _public_key.default.elliptic.ecdh.encrypt(oid, kdf_params.cipher, kdf_params.hash, data, Q, fingerprint);
            return constructParams(types, [res.V, res.C]);
          }

        default:
          return [];
      }
    }();
  },

  /**
   * Decrypts data using specified algorithm and private key parameters.
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1} for public key algorithms.
   * @param {module:enums.publicKey}        algo        Public key algorithm
   * @param {Array<module:type/mpi|
                   module:type/oid|
                   module:type/kdf_params>} key_params  Algorithm-specific public, private key parameters
   * @param {Array<module:type/mpi|
                   module:type/ecdh_symkey>}
                                            data_params encrypted session key parameters
   * @param {String}                        fingerprint Recipient fingerprint
   * @returns {module:type/mpi}                         An MPI containing the decrypted data
   * @async
   */
  publicKeyDecrypt: async function (algo, key_params, data_params, fingerprint) {
    return new _mpi.default((await async function () {
      switch (algo) {
        case _enums.default.publicKey.rsa_encrypt_sign:
        case _enums.default.publicKey.rsa_encrypt:
          {
            const c = data_params[0].toBN();
            const n = key_params[0].toBN(); // n = pq

            const e = key_params[1].toBN();
            const d = key_params[2].toBN(); // de = 1 mod (p-1)(q-1)

            const p = key_params[3].toBN();
            const q = key_params[4].toBN();
            const u = key_params[5].toBN(); // q^-1 mod p

            return _public_key.default.rsa.decrypt(c, n, e, d, p, q, u);
          }

        case _enums.default.publicKey.elgamal:
          {
            const c1 = data_params[0].toBN();
            const c2 = data_params[1].toBN();
            const p = key_params[0].toBN();
            const x = key_params[3].toBN();
            return _public_key.default.elgamal.decrypt(c1, c2, p, x);
          }

        case _enums.default.publicKey.ecdh:
          {
            const oid = key_params[0];
            const kdf_params = key_params[2];
            const V = data_params[0].toUint8Array();
            const C = data_params[1].data;
            const d = key_params[3].toUint8Array();
            return _public_key.default.elliptic.ecdh.decrypt(oid, kdf_params.cipher, kdf_params.hash, V, C, d, fingerprint);
          }

        default:
          throw new Error('Invalid public key encryption algorithm.');
      }
    }()));
  },

  /** Returns the types comprising the private key of an algorithm
   * @param {String} algo The public key algorithm
   * @returns {Array<String>} The array of types
   */
  getPrivKeyParamTypes: function (algo) {
    switch (algo) {
      //   Algorithm-Specific Fields for RSA secret keys:
      //       - multiprecision integer (MPI) of RSA secret exponent d.
      //       - MPI of RSA secret prime value p.
      //       - MPI of RSA secret prime value q (p < q).
      //       - MPI of u, the multiplicative inverse of p, mod q.
      case _enums.default.publicKey.rsa_encrypt:
      case _enums.default.publicKey.rsa_encrypt_sign:
      case _enums.default.publicKey.rsa_sign:
        return [_mpi.default, _mpi.default, _mpi.default, _mpi.default];
      //   Algorithm-Specific Fields for Elgamal secret keys:
      //        - MPI of Elgamal secret exponent x.

      case _enums.default.publicKey.elgamal:
        return [_mpi.default];
      //   Algorithm-Specific Fields for DSA secret keys:
      //      - MPI of DSA secret exponent x.

      case _enums.default.publicKey.dsa:
        return [_mpi.default];
      //   Algorithm-Specific Fields for ECDSA or ECDH secret keys:
      //       - MPI of an integer representing the secret key.

      case _enums.default.publicKey.ecdh:
      case _enums.default.publicKey.ecdsa:
      case _enums.default.publicKey.eddsa:
        return [_mpi.default];

      default:
        throw new Error('Invalid public key encryption algorithm.');
    }
  },

  /** Returns the types comprising the public key of an algorithm
   * @param {String} algo The public key algorithm
   * @returns {Array<String>} The array of types
   */
  getPubKeyParamTypes: function (algo) {
    switch (algo) {
      //   Algorithm-Specific Fields for RSA public keys:
      //       - a multiprecision integer (MPI) of RSA public modulus n;
      //       - an MPI of RSA public encryption exponent e.
      case _enums.default.publicKey.rsa_encrypt:
      case _enums.default.publicKey.rsa_encrypt_sign:
      case _enums.default.publicKey.rsa_sign:
        return [_mpi.default, _mpi.default];
      //   Algorithm-Specific Fields for Elgamal public keys:
      //       - MPI of Elgamal prime p;
      //       - MPI of Elgamal group generator g;
      //       - MPI of Elgamal public key value y (= g**x mod p where x  is secret).

      case _enums.default.publicKey.elgamal:
        return [_mpi.default, _mpi.default, _mpi.default];
      //   Algorithm-Specific Fields for DSA public keys:
      //       - MPI of DSA prime p;
      //       - MPI of DSA group order q (q is a prime divisor of p-1);
      //       - MPI of DSA group generator g;
      //       - MPI of DSA public-key value y (= g**x mod p where x  is secret).

      case _enums.default.publicKey.dsa:
        return [_mpi.default, _mpi.default, _mpi.default, _mpi.default];
      //   Algorithm-Specific Fields for ECDSA/EdDSA public keys:
      //       - OID of curve;
      //       - MPI of EC point representing public key.

      case _enums.default.publicKey.ecdsa:
      case _enums.default.publicKey.eddsa:
        return [_oid.default, _mpi.default];
      //   Algorithm-Specific Fields for ECDH public keys:
      //       - OID of curve;
      //       - MPI of EC point representing public key.
      //       - KDF: variable-length field containing KDF parameters.

      case _enums.default.publicKey.ecdh:
        return [_oid.default, _mpi.default, _kdf_params.default];

      default:
        throw new Error('Invalid public key encryption algorithm.');
    }
  },

  /** Returns the types comprising the encrypted session key of an algorithm
   * @param {String} algo The public key algorithm
   * @returns {Array<String>} The array of types
   */
  getEncSessionKeyParamTypes: function (algo) {
    switch (algo) {
      //   Algorithm-Specific Fields for RSA encrypted session keys:
      //       - MPI of RSA encrypted value m**e mod n.
      case _enums.default.publicKey.rsa_encrypt:
      case _enums.default.publicKey.rsa_encrypt_sign:
        return [_mpi.default];
      //   Algorithm-Specific Fields for Elgamal encrypted session keys:
      //       - MPI of Elgamal value g**k mod p
      //       - MPI of Elgamal value m * y**k mod p

      case _enums.default.publicKey.elgamal:
        return [_mpi.default, _mpi.default];
      //   Algorithm-Specific Fields for ECDH encrypted session keys:
      //       - MPI containing the ephemeral key used to establish the shared secret
      //       - ECDH Symmetric Key

      case _enums.default.publicKey.ecdh:
        return [_mpi.default, _ecdh_symkey.default];

      default:
        throw new Error('Invalid public key encryption algorithm.');
    }
  },

  /** Generate algorithm-specific key parameters
   * @param {String}          algo The public key algorithm
   * @param {Integer}         bits Bit length for RSA keys
   * @param {module:type/oid} oid  Object identifier for ECC keys
   * @returns {Array}              The array of parameters
   * @async
   */
  generateParams: function (algo, bits, oid) {
    const types = [].concat(this.getPubKeyParamTypes(algo), this.getPrivKeyParamTypes(algo));

    switch (algo) {
      case _enums.default.publicKey.rsa_encrypt:
      case _enums.default.publicKey.rsa_encrypt_sign:
      case _enums.default.publicKey.rsa_sign:
        {
          return _public_key.default.rsa.generate(bits, "10001").then(function (keyObject) {
            return constructParams(types, [keyObject.n, keyObject.e, keyObject.d, keyObject.p, keyObject.q, keyObject.u]);
          });
        }

      case _enums.default.publicKey.dsa:
      case _enums.default.publicKey.elgamal:
        throw new Error('Unsupported algorithm for key generation.');

      case _enums.default.publicKey.ecdsa:
      case _enums.default.publicKey.eddsa:
        return _public_key.default.elliptic.generate(oid).then(function (keyObject) {
          return constructParams(types, [keyObject.oid, keyObject.Q, keyObject.d]);
        });

      case _enums.default.publicKey.ecdh:
        return _public_key.default.elliptic.generate(oid).then(function (keyObject) {
          return constructParams(types, [keyObject.oid, keyObject.Q, [keyObject.hash, keyObject.cipher], keyObject.d]);
        });

      default:
        throw new Error('Invalid public key algorithm.');
    }
  },

  /**
   * Generates a random byte prefix for the specified algorithm
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
   * @param {module:enums.symmetric} algo Symmetric encryption algorithm
   * @returns {Uint8Array}                Random bytes with length equal to the block size of the cipher
   * @async
   */
  getPrefixRandom: function (algo) {
    return _random.default.getRandomBytes(_cipher.default[algo].blockSize);
  },

  /**
   * Generating a session key for the specified symmetric algorithm
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
   * @param {module:enums.symmetric} algo Symmetric encryption algorithm
   * @returns {Uint8Array}                Random bytes as a string to be used as a key
   * @async
   */
  generateSessionKey: function (algo) {
    return _random.default.getRandomBytes(_cipher.default[algo].keySize);
  },
  constructParams: constructParams
};
exports.default = _default;