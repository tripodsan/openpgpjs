"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _bn = _interopRequireDefault(require("bn.js"));

var _public_key = _interopRequireDefault(require("./public_key"));

var _pkcs = _interopRequireDefault(require("./pkcs1"));

var _enums = _interopRequireDefault(require("../enums"));

var _util = _interopRequireDefault(require("../util"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @fileoverview Provides functions for asymmetric signing and signature verification
 * @requires bn.js
 * @requires crypto/public_key
 * @requires crypto/pkcs1
 * @requires enums
 * @requires util
 * @module crypto/signature
*/
var _default = {
  /**
   * Verifies the signature provided for data using specified algorithms and public key parameters.
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
   * and {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4}
   * for public key and hash algorithms.
   * @param {module:enums.publicKey} algo      Public key algorithm
   * @param {module:enums.hash}      hash_algo Hash algorithm
   * @param {Array<module:type/mpi>} msg_MPIs  Algorithm-specific signature parameters
   * @param {Array<module:type/mpi>} pub_MPIs  Algorithm-specific public key parameters
   * @param {Uint8Array}             data      Data for which the signature was created
   * @param {Uint8Array}             hashed    The hashed data
   * @returns {Boolean}                        True if signature is valid
   * @async
   */
  verify: async function (algo, hash_algo, msg_MPIs, pub_MPIs, data, hashed) {
    switch (algo) {
      case _enums.default.publicKey.rsa_encrypt_sign:
      case _enums.default.publicKey.rsa_encrypt:
      case _enums.default.publicKey.rsa_sign:
        {
          const m = msg_MPIs[0].toBN();
          const n = pub_MPIs[0].toBN();
          const e = pub_MPIs[1].toBN();
          const EM = await _public_key.default.rsa.verify(m, n, e);
          const EM2 = await _pkcs.default.emsa.encode(hash_algo, hashed, n.byteLength());
          return _util.default.Uint8Array_to_hex(EM) === EM2;
        }

      case _enums.default.publicKey.dsa:
        {
          const r = msg_MPIs[0].toBN();
          const s = msg_MPIs[1].toBN();
          const p = pub_MPIs[0].toBN();
          const q = pub_MPIs[1].toBN();
          const g = pub_MPIs[2].toBN();
          const y = pub_MPIs[3].toBN();
          return _public_key.default.dsa.verify(hash_algo, r, s, hashed, g, p, q, y);
        }

      case _enums.default.publicKey.ecdsa:
        {
          const oid = pub_MPIs[0];
          const signature = {
            r: msg_MPIs[0].toUint8Array(),
            s: msg_MPIs[1].toUint8Array()
          };
          const Q = pub_MPIs[1].toUint8Array();
          return _public_key.default.elliptic.ecdsa.verify(oid, hash_algo, signature, data, Q, hashed);
        }

      case _enums.default.publicKey.eddsa:
        {
          const oid = pub_MPIs[0]; // TODO refactor elliptic to accept Uint8Array
          // EdDSA signature params are expected in little-endian format

          const signature = {
            R: Array.from(msg_MPIs[0].toUint8Array('le', 32)),
            S: Array.from(msg_MPIs[1].toUint8Array('le', 32))
          };
          const Q = Array.from(pub_MPIs[1].toUint8Array('be', 33));
          return _public_key.default.elliptic.eddsa.verify(oid, hash_algo, signature, data, Q, hashed);
        }

      default:
        throw new Error('Invalid signature algorithm.');
    }
  },

  /**
   * Creates a signature on data using specified algorithms and private key parameters.
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
   * and {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4}
   * for public key and hash algorithms.
   * @param {module:enums.publicKey} algo       Public key algorithm
   * @param {module:enums.hash}      hash_algo  Hash algorithm
   * @param {Array<module:type/mpi>} key_params Algorithm-specific public and private key parameters
   * @param {Uint8Array}             data       Data to be signed
   * @param {Uint8Array}             hashed     The hashed data
   * @returns {Uint8Array}                      Signature
   * @async
   */
  sign: async function (algo, hash_algo, key_params, data, hashed) {
    switch (algo) {
      case _enums.default.publicKey.rsa_encrypt_sign:
      case _enums.default.publicKey.rsa_encrypt:
      case _enums.default.publicKey.rsa_sign:
        {
          const n = key_params[0].toBN();
          const e = key_params[1].toBN();
          const d = key_params[2].toBN();
          const m = new _bn.default((await _pkcs.default.emsa.encode(hash_algo, hashed, n.byteLength())), 16);
          const signature = await _public_key.default.rsa.sign(m, n, e, d);
          return _util.default.Uint8Array_to_MPI(signature);
        }

      case _enums.default.publicKey.dsa:
        {
          const p = key_params[0].toBN();
          const q = key_params[1].toBN();
          const g = key_params[2].toBN();
          const x = key_params[4].toBN();
          const signature = await _public_key.default.dsa.sign(hash_algo, hashed, g, p, q, x);
          return _util.default.concatUint8Array([_util.default.Uint8Array_to_MPI(signature.r), _util.default.Uint8Array_to_MPI(signature.s)]);
        }

      case _enums.default.publicKey.elgamal:
        {
          throw new Error('Signing with Elgamal is not defined in the OpenPGP standard.');
        }

      case _enums.default.publicKey.ecdsa:
        {
          const oid = key_params[0];
          const d = key_params[2].toUint8Array();
          const signature = await _public_key.default.elliptic.ecdsa.sign(oid, hash_algo, data, d, hashed);
          return _util.default.concatUint8Array([_util.default.Uint8Array_to_MPI(signature.r), _util.default.Uint8Array_to_MPI(signature.s)]);
        }

      case _enums.default.publicKey.eddsa:
        {
          const oid = key_params[0];
          const d = Array.from(key_params[2].toUint8Array('be', 32));
          const signature = await _public_key.default.elliptic.eddsa.sign(oid, hash_algo, data, d, hashed);
          return _util.default.concatUint8Array([_util.default.Uint8Array_to_MPI(signature.R), _util.default.Uint8Array_to_MPI(signature.S)]);
        }

      default:
        throw new Error('Invalid signature algorithm.');
    }
  }
};
exports.default = _default;