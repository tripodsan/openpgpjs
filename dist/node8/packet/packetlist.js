"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _webStreamTools = _interopRequireDefault(require("web-stream-tools"));

var packets = _interopRequireWildcard(require("./all_packets"));

var _packet = _interopRequireDefault(require("./packet"));

var _config = _interopRequireDefault(require("../config"));

var _enums = _interopRequireDefault(require("../enums"));

var _util = _interopRequireDefault(require("../util"));

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = Object.defineProperty && Object.getOwnPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : {}; if (desc.get || desc.set) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/* eslint-disable callback-return */

/**
 * @requires web-stream-tools
 * @requires packet/all_packets
 * @requires packet/packet
 * @requires config
 * @requires enums
 * @requires util
 */

/**
 * This class represents a list of openpgp packets.
 * Take care when iterating over it - the packets themselves
 * are stored as numerical indices.
 * @memberof module:packet
 * @constructor
 * @extends Array
 */
function List() {
  /**
   * The number of packets contained within the list.
   * @readonly
   * @type {Integer}
   */
  this.length = 0;
}

List.prototype = [];
/**
 * Reads a stream of binary data and interprents it as a list of packets.
 * @param {Uint8Array | ReadableStream<Uint8Array>} A Uint8Array of bytes.
 */

List.prototype.read = async function (bytes) {
  this.stream = _webStreamTools.default.transformPair(bytes, async (readable, writable) => {
    const writer = _webStreamTools.default.getWriter(writable);

    try {
      while (true) {
        await writer.ready;
        const done = await _packet.default.read(readable, async parsed => {
          try {
            const tag = _enums.default.read(_enums.default.packet, parsed.tag);

            const packet = packets.newPacketFromTag(tag);
            packet.packets = new List();
            packet.fromStream = _util.default.isStream(parsed.packet);
            await packet.read(parsed.packet);
            await writer.write(packet);
          } catch (e) {
            if (!_config.default.tolerant || _packet.default.supportsStreaming(parsed.tag)) {
              // The packets that support streaming are the ones that contain
              // message data. Those are also the ones we want to be more strict
              // about and throw on parse errors for.
              await writer.abort(e);
            }

            _util.default.print_debug_error(e);
          }
        });

        if (done) {
          await writer.ready;
          await writer.close();
          return;
        }
      }
    } catch (e) {
      await writer.abort(e);
    }
  }); // Wait until first few packets have been read

  const reader = _webStreamTools.default.getReader(this.stream);

  while (true) {
    const {
      done,
      value
    } = await reader.read();

    if (!done) {
      this.push(value);
    } else {
      this.stream = null;
    }

    if (done || value.fromStream) {
      break;
    }
  }

  reader.releaseLock();
};
/**
 * Creates a binary representation of openpgp objects contained within the
 * class instance.
 * @returns {Uint8Array} A Uint8Array containing valid openpgp packets.
 */


List.prototype.write = function () {
  const arr = [];

  for (let i = 0; i < this.length; i++) {
    const packetbytes = this[i].write();

    if (_util.default.isStream(packetbytes) && _packet.default.supportsStreaming(this[i].tag)) {
      let buffer = [];
      let bufferLength = 0;
      const minLength = 512;
      arr.push(_packet.default.writeTag(this[i].tag));
      arr.push(_webStreamTools.default.transform(packetbytes, value => {
        buffer.push(value);
        bufferLength += value.length;

        if (bufferLength >= minLength) {
          const powerOf2 = Math.min(Math.log(bufferLength) / Math.LN2 | 0, 30);
          const chunkSize = 2 ** powerOf2;

          const bufferConcat = _util.default.concat([_packet.default.writePartialLength(powerOf2)].concat(buffer));

          buffer = [bufferConcat.subarray(1 + chunkSize)];
          bufferLength = buffer[0].length;
          return bufferConcat.subarray(0, 1 + chunkSize);
        }
      }, () => _util.default.concat([_packet.default.writeSimpleLength(bufferLength)].concat(buffer))));
    } else {
      if (_util.default.isStream(packetbytes)) {
        let length = 0;
        arr.push(_webStreamTools.default.transform(_webStreamTools.default.clone(packetbytes), value => {
          length += value.length;
        }, () => _packet.default.writeHeader(this[i].tag, length)));
      } else {
        arr.push(_packet.default.writeHeader(this[i].tag, packetbytes.length));
      }

      arr.push(packetbytes);
    }
  }

  return _util.default.concat(arr);
};
/**
 * Adds a packet to the list. This is the only supported method of doing so;
 * writing to packetlist[i] directly will result in an error.
 * @param {Object} packet Packet to push
 */


List.prototype.push = function (packet) {
  if (!packet) {
    return;
  }

  packet.packets = packet.packets || new List();
  this[this.length] = packet;
  this.length++;
};
/**
 * Creates a new PacketList with all packets from the given types
 */


List.prototype.filterByTag = function (...args) {
  const filtered = new List();

  const handle = tag => packetType => tag === packetType;

  for (let i = 0; i < this.length; i++) {
    if (args.some(handle(this[i].tag))) {
      filtered.push(this[i]);
    }
  }

  return filtered;
};
/**
 * Traverses packet tree and returns first matching packet
 * @param  {module:enums.packet} type The packet type
 * @returns {module:packet/packet|null}
 */


List.prototype.findPacket = function (type) {
  const packetlist = this.filterByTag(type);

  if (packetlist.length) {
    return packetlist[0];
  }

  let found = null;

  for (let i = 0; i < this.length; i++) {
    if (this[i].packets.length) {
      found = this[i].packets.findPacket(type);

      if (found) {
        return found;
      }
    }
  }

  return null;
};
/**
 * Returns array of found indices by tag
 */


List.prototype.indexOfTag = function (...args) {
  const tagIndex = [];
  const that = this;

  const handle = tag => packetType => tag === packetType;

  for (let i = 0; i < this.length; i++) {
    if (args.some(handle(that[i].tag))) {
      tagIndex.push(i);
    }
  }

  return tagIndex;
};
/**
 * Concatenates packetlist or array of packets
 */


List.prototype.concat = function (packetlist) {
  if (packetlist) {
    for (let i = 0; i < packetlist.length; i++) {
      this.push(packetlist[i]);
    }
  }

  return this;
};
/**
 * Allocate a new packetlist from structured packetlist clone
 * See {@link https://w3c.github.io/html/infrastructure.html#safe-passing-of-structured-data}
 * @param {Object} packetClone packetlist clone
 * @returns {Object} new packetlist object with data from packetlist clone
 */


List.fromStructuredClone = function (packetlistClone) {
  const packetlist = new List();

  for (let i = 0; i < packetlistClone.length; i++) {
    packetlist.push(packets.fromStructuredClone(packetlistClone[i]));

    if (packetlist[i].packets.length !== 0) {
      packetlist[i].packets = this.fromStructuredClone(packetlist[i].packets);
    } else {
      packetlist[i].packets = new List();
    }
  }

  return packetlist;
};

var _default = List;
exports.default = _default;