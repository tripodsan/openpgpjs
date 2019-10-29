"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _pako = _interopRequireDefault(require("pako"));

var _webStreamTools = _interopRequireDefault(require("@tripod/web-stream-tools"));

var _config = _interopRequireDefault(require("../config"));

var _enums = _interopRequireDefault(require("../enums"));

var _util = _interopRequireDefault(require("../util"));

var _bzip2Build = _interopRequireDefault(require("../compression/bzip2.build.js"));

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
 * @requires web-stream-tools
 * @requires pako
 * @requires config
 * @requires enums
 * @requires util
 * @requires compression/bzip2
 */

/**
 * Implementation of the Compressed Data Packet (Tag 8)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.6|RFC4880 5.6}:
 * The Compressed Data packet contains compressed data.  Typically,
 * this packet is found as the contents of an encrypted packet, or following
 * a Signature or One-Pass Signature packet, and contains a literal data packet.
 * @memberof module:packet
 * @constructor
 */
function Compressed() {
  /**
   * Packet type
   * @type {module:enums.packet}
   */
  this.tag = _enums.default.packet.compressed;
  /**
   * List of packets
   * @type {module:packet.List}
   */

  this.packets = null;
  /**
   * Compression algorithm
   * @type {compression}
   */

  this.algorithm = 'zip';
  /**
   * Compressed packet data
   * @type {Uint8Array | ReadableStream<Uint8Array>}
   */

  this.compressed = null;
}
/**
 * Parsing function for the packet.
 * @param {Uint8Array | ReadableStream<Uint8Array>} bytes Payload of a tag 8 packet
 */


Compressed.prototype.read = async function (bytes) {
  await _webStreamTools.default.parse(bytes, async reader => {
    // One octet that gives the algorithm used to compress the packet.
    this.algorithm = _enums.default.read(_enums.default.compression, (await reader.readByte())); // Compressed data, which makes up the remainder of the packet.

    this.compressed = reader.remainder();
    await this.decompress();
  });
};
/**
 * Return the compressed packet.
 * @returns {Uint8Array | ReadableStream<Uint8Array>} binary compressed packet
 */


Compressed.prototype.write = function () {
  if (this.compressed === null) {
    this.compress();
  }

  return _util.default.concat([new Uint8Array([_enums.default.write(_enums.default.compression, this.algorithm)]), this.compressed]);
};
/**
 * Decompression method for decompressing the compressed data
 * read by read_packet
 */


Compressed.prototype.decompress = async function () {
  if (!decompress_fns[this.algorithm]) {
    throw new Error("Compression algorithm unknown :" + this.algorithm);
  }

  await this.packets.read(decompress_fns[this.algorithm](this.compressed));
};
/**
 * Compress the packet data (member decompressedData)
 */


Compressed.prototype.compress = function () {
  if (!compress_fns[this.algorithm]) {
    throw new Error("Compression algorithm unknown :" + this.algorithm);
  }

  this.compressed = compress_fns[this.algorithm](this.packets.write());
};

var _default = Compressed; //////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////

exports.default = _default;

const nodeZlib = _util.default.getNodeZlib();

function node_zlib(func, options = {}) {
  return function (data) {
    return _webStreamTools.default.nodeToWeb(_webStreamTools.default.webToNode(data).pipe(func(options)));
  };
}

function pako_zlib(constructor, options = {}) {
  return function (data) {
    const obj = new constructor(options);
    return _webStreamTools.default.transform(data, value => {
      if (value.length) {
        obj.push(value, _pako.default.Z_SYNC_FLUSH);
        return obj.result;
      }
    });
  };
}

function bzip2(func) {
  return function (data) {
    return _webStreamTools.default.fromAsync(async () => func((await _webStreamTools.default.readToEnd(data))));
  };
}

let compress_fns;
let decompress_fns;

if (nodeZlib) {
  // Use Node native zlib for DEFLATE compression/decompression
  compress_fns = {
    // eslint-disable-next-line no-sync
    zip: node_zlib(nodeZlib.createDeflateRaw, {
      level: _config.default.deflate_level
    }),
    // eslint-disable-next-line no-sync
    zlib: node_zlib(nodeZlib.createDeflate, {
      level: _config.default.deflate_level
    }),
    bzip2: bzip2(_bzip2Build.default.compressFile)
  };
  decompress_fns = {
    // eslint-disable-next-line no-sync
    zip: node_zlib(nodeZlib.createInflateRaw),
    // eslint-disable-next-line no-sync
    zlib: node_zlib(nodeZlib.createInflate),
    bzip2: bzip2(_bzip2Build.default.decompressFile)
  };
} else {
  // Use JS fallbacks
  compress_fns = {
    zip: pako_zlib(_pako.default.Deflate, {
      raw: true,
      level: _config.default.deflate_level
    }),
    zlib: pako_zlib(_pako.default.Deflate, {
      level: _config.default.deflate_level
    }),
    bzip2: bzip2(_bzip2Build.default.compressFile)
  };
  decompress_fns = {
    zip: pako_zlib(_pako.default.Inflate, {
      raw: true
    }),
    zlib: pako_zlib(_pako.default.Inflate),
    bzip2: bzip2(_bzip2Build.default.decompressFile)
  };
}