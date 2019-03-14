"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var packets = _interopRequireWildcard(require("./all_packets"));

var clone = _interopRequireWildcard(require("./clone"));

var _packetlist = _interopRequireDefault(require("./packetlist"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = Object.defineProperty && Object.getOwnPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : {}; if (desc.get || desc.set) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } } newObj.default = obj; return newObj; } }

/**
 * @fileoverview OpenPGP packet types
 * @see module:packet/all_packets
 * @see module:packet/clone
 * @see module:packet.List
 * @module packet
 */
const mod = {
  List: _packetlist.default,
  clone
};
Object.assign(mod, packets);
var _default = mod;
exports.default = _default;