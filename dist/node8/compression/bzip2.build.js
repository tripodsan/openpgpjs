"use strict";

var freeze, Stream, BitStream, Util, BWT, CRC32, HuffmanAllocator, Bzip2;
freeze = function () {
  return Object.freeze ? Object.freeze : function (e) {
    return e;
  };
}(), Stream = function (e) {
  var t = function () {};

  return t.prototype.readByte = function () {
    var e = [0];
    return 0 === this.read(e, 0, 1) ? (this._eof = !0, -1) : e[0];
  }, t.prototype.read = function (e, t, r) {
    for (var n, i = 0; i < r;) {
      if (-1 === (n = this.readByte())) {
        this._eof = !0;
        break;
      }

      e[t + i++] = n;
    }

    return i;
  }, t.prototype.eof = function () {
    return !!this._eof;
  }, t.prototype.seek = function (e) {
    throw new Error("Stream is not seekable.");
  }, t.prototype.tell = function () {
    throw new Error("Stream is not seekable.");
  }, t.prototype.writeByte = function (e) {
    var t = [e];
    this.write(t, 0, 1);
  }, t.prototype.write = function (e, t, r) {
    var n;

    for (n = 0; n < r; n++) this.writeByte(e[t + n]);

    return r;
  }, t.prototype.flush = function () {}, t.EOF = -1, e(t);
}(freeze), BitStream = function (e) {
  var t = function (t) {
    (function () {
      var r = 256;
      this.readBit = function () {
        if (0 == (255 & r)) {
          var n = t.readByte();
          if (n === e.EOF) return this._eof = !0, n;
          r = n << 1 | 1;
        }

        var i = 256 & r ? 1 : 0;
        return r <<= 1, i;
      }, this.seekBit = function (e) {
        var t = e >>> 3,
            r = e - 8 * t;
        this.seek(t), this._eof = !1, this.readBits(r);
      }, this.tellBit = function () {
        for (var e = 8 * t.tell(), n = r; 0 != (255 & n);) e--, n <<= 1;

        return e;
      }, this.readByte = function () {
        return 0 == (255 & r) ? t.readByte() : this.readBits(8);
      }, this.seek = function (e) {
        t.seek(e), r = 256;
      };
    }).call(this), function () {
      var e = 1;
      this.writeBit = function (r) {
        e <<= 1, r && (e |= 1), 256 & e && (t.writeByte(255 & e), e = 1);
      }, this.writeByte = function (r) {
        1 === e ? t.writeByte(r) : t.writeBits(8, r);
      }, this.flush = function () {
        for (; 1 !== e;) this.writeBit(0);

        t.flush && t.flush();
      };
    }.call(this);
  };

  return t.EOF = e.EOF, t.prototype = Object.create(e.prototype), t.prototype.readBits = function (e) {
    var t,
        r = 0;
    if (e > 31) return (r = 65536 * this.readBits(e - 16)) + this.readBits(16);

    for (t = 0; t < e; t++) r <<= 1, this.readBit() > 0 && r++;

    return r;
  }, t.prototype.writeBits = function (e, t) {
    if (e > 32) {
      var r = 65535 & t,
          n = (t - r) / 65536;
      return this.writeBits(e - 16, n), void this.writeBits(16, r);
    }

    var i;

    for (i = e - 1; i >= 0; i--) this.writeBit(t >>> i & 1);
  }, t;
}(Stream), Util = function (e, t) {
  var r = Object.create(null),
      n = t.EOF;

  r.coerceInputStream = function (e, r) {
    if ("readByte" in e) {
      if (r && !("read" in e)) {
        var i = e;
        e = new t(), e.readByte = function () {
          var e = i.readByte();
          return e === n && (this._eof = !0), e;
        }, "size" in i && (e.size = i.size), "seek" in i && (e.seek = function (e) {
          i.seek(e), this._eof = !1;
        }), "tell" in i && (e.tell = i.tell.bind(i));
      }
    } else {
      var o = e;
      e = new t(), e.size = o.length, e.pos = 0, e.readByte = function () {
        return this.pos >= this.size ? n : o[this.pos++];
      }, e.read = function (e, t, r) {
        for (var n = 0; n < r && this.pos < o.length;) e[t++] = o[this.pos++], n++;

        return n;
      }, e.seek = function (e) {
        this.pos = e;
      }, e.tell = function () {
        return this.pos;
      }, e.eof = function () {
        return this.pos >= o.length;
      };
    }

    return e;
  };

  var i = function (e, t) {
    this.buffer = e, this.resizeOk = t, this.pos = 0;
  };

  i.prototype = Object.create(t.prototype), i.prototype.writeByte = function (e) {
    if (this.resizeOk && this.pos >= this.buffer.length) {
      var t = r.makeU8Buffer(2 * this.buffer.length);
      t.set(this.buffer), this.buffer = t;
    }

    this.buffer[this.pos++] = e;
  }, i.prototype.getBuffer = function () {
    if (this.pos !== this.buffer.length) {
      if (!this.resizeOk) throw new TypeError("outputsize does not match decoded input");
      var e = r.makeU8Buffer(this.pos);
      e.set(this.buffer.subarray(0, this.pos)), this.buffer = e;
    }

    return this.buffer;
  }, r.coerceOutputStream = function (e, t) {
    var n = {
      stream: e,
      retval: e
    };

    if (e) {
      if ("object" == typeof e && "writeByte" in e) return n;
      "number" == typeof t ? (console.assert(t >= 0), n.stream = new i(r.makeU8Buffer(t), !1)) : n.stream = new i(e, !1);
    } else n.stream = new i(r.makeU8Buffer(16384), !0);

    return Object.defineProperty(n, "retval", {
      get: n.stream.getBuffer.bind(n.stream)
    }), n;
  }, r.compressFileHelper = function (e, t, n) {
    return function (i, o, f) {
      i = r.coerceInputStream(i);
      var a = r.coerceOutputStream(o, o);
      o = a.stream;
      var u;

      for (u = 0; u < e.length; u++) o.writeByte(e.charCodeAt(u));

      var s;

      if (s = "size" in i && i.size >= 0 ? i.size : -1, n) {
        var c = r.coerceOutputStream([]);

        for (r.writeUnsignedNumber(c.stream, s + 1), c = c.retval, u = 0; u < c.length - 1; u++) o.writeByte(c[u]);

        n = c[c.length - 1];
      } else r.writeUnsignedNumber(o, s + 1);

      return t(i, o, s, f, n), a.retval;
    };
  }, r.decompressFileHelper = function (e, t) {
    return function (n, i) {
      n = r.coerceInputStream(n);
      var o;

      for (o = 0; o < e.length; o++) if (e.charCodeAt(o) !== n.readByte()) throw new Error("Bad magic");

      var f = r.readUnsignedNumber(n) - 1,
          a = r.coerceOutputStream(i, f);
      return i = a.stream, t(n, i, f), a.retval;
    };
  }, r.compressWithModel = function (e, t, r) {
    for (var i = 0; i !== t;) {
      var o = e.readByte();

      if (o === n) {
        r.encode(256);
        break;
      }

      r.encode(o), i++;
    }
  }, r.decompressWithModel = function (e, t, r) {
    for (var n = 0; n !== t;) {
      var i = r.decode();
      if (256 === i) break;
      e.writeByte(i), n++;
    }
  }, r.writeUnsignedNumber = function (e, t) {
    console.assert(t >= 0);
    var r,
        n = [];

    do {
      n.push(127 & t), t = Math.floor(t / 128);
    } while (0 !== t);

    for (n[0] |= 128, r = n.length - 1; r >= 0; r--) e.writeByte(n[r]);

    return e;
  }, r.readUnsignedNumber = function (e) {
    for (var t, r = 0;;) {
      if (128 & (t = e.readByte())) {
        r += 127 & t;
        break;
      }

      r = 128 * (r + t);
    }

    return r;
  };

  var o = function (e) {
    for (var t = 0, r = e.length; t < r; t++) e[t] = 0;

    return e;
  },
      f = function (e) {
    return o(new Array(e));
  },
      a = function (e) {
    return e;
  };

  "undefined" != typeof process && Array.prototype.some.call(new Uint32Array(128), function (e) {
    return 0 !== e;
  }) && (a = o), r.makeU8Buffer = "undefined" != typeof Uint8Array ? function (e) {
    return a(new Uint8Array(e));
  } : f, r.makeU16Buffer = "undefined" != typeof Uint16Array ? function (e) {
    return a(new Uint16Array(e));
  } : f, r.makeU32Buffer = "undefined" != typeof Uint32Array ? function (e) {
    return a(new Uint32Array(e));
  } : f, r.makeS32Buffer = "undefined" != typeof Int32Array ? function (e) {
    return a(new Int32Array(e));
  } : f, r.arraycopy = function (e, t) {
    console.assert(e.length >= t.length);

    for (var r = 0, n = t.length; r < n; r++) e[r] = t[r];

    return e;
  };
  var u = [0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8];
  console.assert(256 === u.length);

  var s = r.fls = function (e) {
    return console.assert(e >= 0), e > 4294967295 ? 32 + s(Math.floor(e / 4294967296)) : 0 != (4294901760 & e) ? 0 != (4278190080 & e) ? 24 + u[e >>> 24 & 255] : 16 + u[e >>> 16] : 0 != (65280 & e) ? 8 + u[e >>> 8] : u[e];
  };

  return r.log2c = function (e) {
    return 0 === e ? -1 : s(e - 1);
  }, e(r);
}(freeze, Stream), BWT = function (e, t) {
  var r = console.assert.bind(console),
      n = function (e, t, r, n) {
    var i;

    for (i = 0; i < n; i++) t[i] = 0;

    for (i = 0; i < r; i++) t[e[i]]++;
  },
      i = function (e, t, r, n) {
    var i,
        o = 0;
    if (n) for (i = 0; i < r; i++) o += e[i], t[i] = o;else for (i = 0; i < r; i++) o += e[i], t[i] = o - e[i];
  },
      o = function (e, t, o, f, a, u) {
    var s, c, h, l, d;

    for (o === f && n(e, o, a, u), i(o, f, u, !1), h = a - 1, s = f[d = e[h]], h--, t[s++] = e[h] < d ? ~h : h, c = 0; c < a; c++) (h = t[c]) > 0 ? (r(e[h] >= e[h + 1]), (l = e[h]) !== d && (f[d] = s, s = f[d = l]), r(c < s), h--, t[s++] = e[h] < d ? ~h : h, t[c] = 0) : h < 0 && (t[c] = ~h);

    for (o === f && n(e, o, a, u), i(o, f, u, 1), c = a - 1, s = f[d = 0]; c >= 0; c--) (h = t[c]) > 0 && (r(e[h] <= e[h + 1]), (l = e[h]) !== d && (f[d] = s, s = f[d = l]), r(s <= c), h--, t[--s] = e[h] > d ? ~(h + 1) : h, t[c] = 0);
  },
      f = function (e, t, n, i) {
    var o, f, a, u, s, c, h, l, d, B;

    for (r(n > 0), o = 0; (a = t[o]) < 0; o++) t[o] = ~a, r(o + 1 < n);

    if (o < i) for (f = o, o++; r(o < n), !((a = t[o]) < 0 && (t[f++] = ~a, t[o] = 0, f === i)); o++);
    l = e[o = f = n - 1];

    do {
      d = l;
    } while (--o >= 0 && (l = e[o]) >= d);

    for (; o >= 0;) {
      do {
        d = l;
      } while (--o >= 0 && (l = e[o]) <= d);

      if (o >= 0) {
        t[i + (o + 1 >>> 1)] = f - o, f = o + 1;

        do {
          d = l;
        } while (--o >= 0 && (l = e[o]) >= d);
      }
    }

    for (o = 0, h = 0, u = n, c = 0; o < i; o++) {
      if (a = t[o], s = t[i + (a >>> 1)], B = !0, s === c && u + s < n) {
        for (f = 0; f < s && e[a + f] === e[u + f];) f++;

        f === s && (B = !1);
      }

      B && (h++, u = a, c = s), t[i + (a >>> 1)] = h;
    }

    return h;
  },
      a = function (e, t, o, f, a, u) {
    var s, c, h, l, d;

    for (o === f && n(e, o, a, u), i(o, f, u, !1), h = a - 1, s = f[d = e[h]], t[s++] = h > 0 && e[h - 1] < d ? ~h : h, c = 0; c < a; c++) h = t[c], t[c] = ~h, h > 0 && (h--, r(e[h] >= e[h + 1]), (l = e[h]) !== d && (f[d] = s, s = f[d = l]), r(c < s), t[s++] = h > 0 && e[h - 1] < d ? ~h : h);

    for (o === f && n(e, o, a, u), i(o, f, u, !0), c = a - 1, s = f[d = 0]; c >= 0; c--) (h = t[c]) > 0 ? (h--, r(e[h] <= e[h + 1]), (l = e[h]) !== d && (f[d] = s, s = f[d = l]), r(s <= c), t[--s] = 0 === h || e[h - 1] > d ? ~h : h) : t[c] = ~h;
  },
      u = function (e, t, o, f, a, u) {
    var s,
        c,
        h,
        l,
        d,
        B = -1;

    for (o === f && n(e, o, a, u), i(o, f, u, !1), h = a - 1, s = f[d = e[h]], t[s++] = h > 0 && e[h - 1] < d ? ~h : h, c = 0; c < a; c++) (h = t[c]) > 0 ? (h--, r(e[h] >= e[h + 1]), t[c] = ~(l = e[h]), l !== d && (f[d] = s, s = f[d = l]), r(c < s), t[s++] = h > 0 && e[h - 1] < d ? ~h : h) : 0 !== h && (t[c] = ~h);

    for (o === f && n(e, o, a, u), i(o, f, u, !0), c = a - 1, s = f[d = 0]; c >= 0; c--) (h = t[c]) > 0 ? (h--, r(e[h] <= e[h + 1]), t[c] = l = e[h], l !== d && (f[d] = s, s = f[d = l]), r(s <= c), t[--s] = h > 0 && e[h - 1] > d ? ~e[h - 1] : h) : 0 !== h ? t[c] = ~h : B = c;

    return B;
  },
      s = function (e, c, h, l, d, B) {
    var p,
        v,
        m,
        w,
        E,
        g,
        _,
        b,
        y,
        R,
        C,
        k,
        T,
        O = 0,
        S = 0;

    for (d <= 256 ? (p = t.makeS32Buffer(d), d <= h ? (v = c.subarray(l + h - d), S = 1) : (v = t.makeS32Buffer(d), S = 3)) : d <= h ? (p = c.subarray(l + h - d), d <= h - d ? (v = c.subarray(l + h - 2 * d), S = 0) : d <= 1024 ? (v = t.makeS32Buffer(d), S = 2) : (v = p, S = 8)) : (p = v = t.makeS32Buffer(d), S = 12), n(e, p, l, d), i(p, v, d, !0), w = 0; w < l; w++) c[w] = 0;

    g = -1, w = l - 1, E = l, _ = 0, k = e[l - 1];

    do {
      T = k;
    } while (--w >= 0 && (k = e[w]) >= T);

    for (; w >= 0;) {
      do {
        T = k;
      } while (--w >= 0 && (k = e[w]) <= T);

      if (w >= 0) {
        g >= 0 && (c[g] = E), g = --v[T], E = w, ++_;

        do {
          T = k;
        } while (--w >= 0 && (k = e[w]) >= T);
      }
    }

    if (_ > 1 ? (o(e, c, p, v, l, d), R = f(e, c, l, _)) : 1 === _ ? (c[g] = E + 1, R = 1) : R = 0, R < _) {
      for (0 != (4 & S) && (p = null, v = null), 0 != (2 & S) && (v = null), C = l + h - 2 * _, 0 == (13 & S) && (d + R <= C ? C -= d : S |= 8), r(l >>> 1 <= C + _), w = _ + (l >>> 1) - 1, E = 2 * _ + C - 1; _ <= w; w--) 0 !== c[w] && (c[E--] = c[w] - 1);

      m = c.subarray(_ + C), s(m, c, C, _, R, !1), m = null, w = l - 1, E = 2 * _ - 1, k = e[l - 1];

      do {
        T = k;
      } while (--w >= 0 && (k = e[w]) >= T);

      for (; w >= 0;) {
        do {
          T = k;
        } while (--w >= 0 && (k = e[w]) <= T);

        if (w >= 0) {
          c[E--] = w + 1;

          do {
            T = k;
          } while (--w >= 0 && (k = e[w]) >= T);
        }
      }

      for (w = 0; w < _; w++) c[w] = c[_ + c[w]];

      0 != (4 & S) && (p = v = t.makeS32Buffer(d)), 0 != (2 & S) && (v = t.makeS32Buffer(d));
    }

    if (0 != (8 & S) && n(e, p, l, d), _ > 1) {
      i(p, v, d, !0), w = _ - 1, E = l, b = c[_ - 1], T = e[b];

      do {
        for (y = v[k = T]; y < E;) c[--E] = 0;

        do {
          if (c[--E] = b, --w < 0) break;
          b = c[w];
        } while ((T = e[b]) === k);
      } while (w >= 0);

      for (; E > 0;) c[--E] = 0;
    }

    return B ? O = u(e, c, p, v, l, d) : a(e, c, p, v, l, d), p = null, v = null, O;
  },
      c = Object.create(null);

  return c.suffixsort = function (e, t, n, i) {
    if (r(e && t && e.length >= n && t.length >= n), n <= 1) return 1 === n && (t[0] = 0), 0;
    if (!i) if (1 === e.BYTES_PER_ELEMENT) i = 256;else {
      if (2 !== e.BYTES_PER_ELEMENT) throw new Error("Need to specify alphabetSize");
      i = 65536;
    }
    return r(i > 0), e.BYTES_PER_ELEMENT && r(i <= 1 << 8 * e.BYTES_PER_ELEMENT), s(e, t, 0, n, i, !1);
  }, c.bwtransform = function (e, t, n, i, o) {
    var f, a;
    if (r(e && t && n), r(e.length >= i && t.length >= i && n.length >= i), i <= 1) return 1 === i && (t[0] = e[0]), i;
    if (!o) if (1 === e.BYTES_PER_ELEMENT) o = 256;else {
      if (2 !== e.BYTES_PER_ELEMENT) throw new Error("Need to specify alphabetSize");
      o = 65536;
    }

    for (r(o > 0), e.BYTES_PER_ELEMENT && r(o <= 1 << 8 * e.BYTES_PER_ELEMENT), a = s(e, n, 0, i, o, !0), t[0] = e[i - 1], f = 0; f < a; f++) t[f + 1] = n[f];

    for (f += 1; f < i; f++) t[f] = n[f];

    return a + 1;
  }, c.unbwtransform = function (e, r, n, i, o) {
    var f,
        a,
        u = t.makeU32Buffer(256);

    for (f = 0; f < 256; f++) u[f] = 0;

    for (f = 0; f < i; f++) n[f] = u[e[f]]++;

    for (f = 0, a = 0; f < 256; f++) a += u[f], u[f] = a - u[f];

    for (f = i - 1, a = 0; f >= 0; f--) a = n[a] + u[r[f] = e[a]], a += a < o ? 1 : 0;

    u = null;
  }, c.bwtransform2 = function (e, n, i, o) {
    var f,
        a,
        u = 0;
    if (r(e && n), r(e.length >= i && n.length >= i), i <= 1) return 1 === i && (n[0] = e[0]), 0;
    if (!o) if (1 === e.BYTES_PER_ELEMENT) o = 256;else {
      if (2 !== e.BYTES_PER_ELEMENT) throw new Error("Need to specify alphabetSize");
      o = 65536;
    }
    r(o > 0), e.BYTES_PER_ELEMENT && r(o <= 1 << 8 * e.BYTES_PER_ELEMENT);
    var c;
    if ((c = e.length >= 2 * i ? e : o <= 256 ? t.makeU8Buffer(2 * i) : o <= 65536 ? t.makeU16Buffer(2 * i) : t.makeU32Buffer(2 * i)) !== e) for (f = 0; f < i; f++) c[f] = e[f];

    for (f = 0; f < i; f++) c[i + f] = c[f];

    var h = t.makeS32Buffer(2 * i);

    for (s(c, h, 0, 2 * i, o, !1), f = 0, a = 0; f < 2 * i; f++) {
      var l = h[f];
      l < i && (0 === l && (u = a), --l < 0 && (l = i - 1), n[a++] = e[l]);
    }

    return r(a === i), u;
  }, e(c);
}(freeze, Util), CRC32 = function (e) {
  var t = e.arraycopy(e.makeU32Buffer(256), [0, 79764919, 159529838, 222504665, 319059676, 398814059, 445009330, 507990021, 638119352, 583659535, 797628118, 726387553, 890018660, 835552979, 1015980042, 944750013, 1276238704, 1221641927, 1167319070, 1095957929, 1595256236, 1540665371, 1452775106, 1381403509, 1780037320, 1859660671, 1671105958, 1733955601, 2031960084, 2111593891, 1889500026, 1952343757, 2552477408, 2632100695, 2443283854, 2506133561, 2334638140, 2414271883, 2191915858, 2254759653, 3190512472, 3135915759, 3081330742, 3009969537, 2905550212, 2850959411, 2762807018, 2691435357, 3560074640, 3505614887, 3719321342, 3648080713, 3342211916, 3287746299, 3467911202, 3396681109, 4063920168, 4143685023, 4223187782, 4286162673, 3779000052, 3858754371, 3904687514, 3967668269, 881225847, 809987520, 1023691545, 969234094, 662832811, 591600412, 771767749, 717299826, 311336399, 374308984, 453813921, 533576470, 25881363, 88864420, 134795389, 214552010, 2023205639, 2086057648, 1897238633, 1976864222, 1804852699, 1867694188, 1645340341, 1724971778, 1587496639, 1516133128, 1461550545, 1406951526, 1302016099, 1230646740, 1142491917, 1087903418, 2896545431, 2825181984, 2770861561, 2716262478, 3215044683, 3143675388, 3055782693, 3001194130, 2326604591, 2389456536, 2200899649, 2280525302, 2578013683, 2640855108, 2418763421, 2498394922, 3769900519, 3832873040, 3912640137, 3992402750, 4088425275, 4151408268, 4197601365, 4277358050, 3334271071, 3263032808, 3476998961, 3422541446, 3585640067, 3514407732, 3694837229, 3640369242, 1762451694, 1842216281, 1619975040, 1682949687, 2047383090, 2127137669, 1938468188, 2001449195, 1325665622, 1271206113, 1183200824, 1111960463, 1543535498, 1489069629, 1434599652, 1363369299, 622672798, 568075817, 748617968, 677256519, 907627842, 853037301, 1067152940, 995781531, 51762726, 131386257, 177728840, 240578815, 269590778, 349224269, 429104020, 491947555, 4046411278, 4126034873, 4172115296, 4234965207, 3794477266, 3874110821, 3953728444, 4016571915, 3609705398, 3555108353, 3735388376, 3664026991, 3290680682, 3236090077, 3449943556, 3378572211, 3174993278, 3120533705, 3032266256, 2961025959, 2923101090, 2868635157, 2813903052, 2742672763, 2604032198, 2683796849, 2461293480, 2524268063, 2284983834, 2364738477, 2175806836, 2238787779, 1569362073, 1498123566, 1409854455, 1355396672, 1317987909, 1246755826, 1192025387, 1137557660, 2072149281, 2135122070, 1912620623, 1992383480, 1753615357, 1816598090, 1627664531, 1707420964, 295390185, 358241886, 404320391, 483945776, 43990325, 106832002, 186451547, 266083308, 932423249, 861060070, 1041341759, 986742920, 613929101, 542559546, 756411363, 701822548, 3316196985, 3244833742, 3425377559, 3370778784, 3601682597, 3530312978, 3744426955, 3689838204, 3819031489, 3881883254, 3928223919, 4007849240, 4037393693, 4100235434, 4180117107, 4259748804, 2310601993, 2373574846, 2151335527, 2231098320, 2596047829, 2659030626, 2470359227, 2550115596, 2947551409, 2876312838, 2788305887, 2733848168, 3165939309, 3094707162, 3040238851, 2985771188]);
  return function () {
    var e = 4294967295;
    this.getCRC = function () {
      return ~e >>> 0;
    }, this.updateCRC = function (r) {
      e = e << 8 ^ t[255 & (e >>> 24 ^ r)];
    }, this.updateCRCRun = function (r, n) {
      for (; n-- > 0;) e = e << 8 ^ t[255 & (e >>> 24 ^ r)];
    };
  };
}(Util), HuffmanAllocator = function (e, t) {
  var r = function (e, t, r) {
    for (var n = e.length, i = t, o = e.length - 2; t >= r && e[t] % n > i;) o = t, t -= i - t + 1;

    for (t = Math.max(r - 1, t); o > t + 1;) {
      var f = t + o >> 1;
      e[f] % n > i ? o = f : t = f;
    }

    return o;
  },
      n = function (e) {
    var t = e.length;
    e[0] += e[1];
    var r, n, i, o;

    for (r = 0, n = 1, i = 2; n < t - 1; n++) i >= t || e[r] < e[i] ? (o = e[r], e[r++] = n) : o = e[i++], i >= t || r < n && e[r] < e[i] ? (o += e[r], e[r++] = n + t) : o += e[i++], e[n] = o;
  },
      i = function (e, t) {
    var n,
        i = e.length - 2;

    for (n = 1; n < t - 1 && i > 1; n++) i = r(e, i - 1, 0);

    return i;
  },
      o = function (e) {
    var t,
        n,
        i,
        o,
        f = e.length - 2,
        a = e.length - 1;

    for (t = 1, n = 2; n > 0; t++) {
      for (i = f, f = r(e, i - 1, 0), o = n - (i - f); o > 0; o--) e[a--] = t;

      n = i - f << 1;
    }
  },
      f = function (e, t, n) {
    var i,
        o,
        f,
        a,
        u = e.length - 2,
        s = e.length - 1,
        c = 1 == n ? 2 : 1,
        h = 1 == n ? t - 2 : t;

    for (i = c << 1; i > 0; c++) {
      for (o = u, u = u <= t ? u : r(e, o - 1, t), f = 0, c >= n ? f = Math.min(h, 1 << c - n) : c == n - 1 && (f = 1, e[u] == o && u++), a = i - (o - u + f); a > 0; a--) e[s--] = c;

      h -= f, i = o - u + f << 1;
    }
  };

  return e({
    allocateHuffmanCodeLengths: function (e, r) {
      switch (e.length) {
        case 2:
          e[1] = 1;

        case 1:
          return void (e[0] = 1);
      }

      n(e);
      var a = i(e, r);
      if (e[0] % e.length >= a) o(e);else {
        var u = r - t.fls(a - 1);
        f(e, a, u);
      }
    }
  });
}(freeze, Util), Bzip2 = function (e, t, r, n, i, o, f) {
  var a = o.EOF,
      u = function (e, t) {
    var r,
        n = e[t];

    for (r = t; r > 0; r--) e[r] = e[r - 1];

    return e[0] = n, n;
  },
      s = {
    OK: 0,
    LAST_BLOCK: -1,
    NOT_BZIP_DATA: -2,
    UNEXPECTED_INPUT_EOF: -3,
    UNEXPECTED_OUTPUT_EOF: -4,
    DATA_ERROR: -5,
    OUT_OF_MEMORY: -6,
    OBSOLETE_INPUT: -7,
    END_OF_BLOCK: -8
  },
      c = {};

  c[s.LAST_BLOCK] = "Bad file checksum", c[s.NOT_BZIP_DATA] = "Not bzip data", c[s.UNEXPECTED_INPUT_EOF] = "Unexpected input EOF", c[s.UNEXPECTED_OUTPUT_EOF] = "Unexpected output EOF", c[s.DATA_ERROR] = "Data error", c[s.OUT_OF_MEMORY] = "Out of memory", c[s.OBSOLETE_INPUT] = "Obsolete (pre 0.9.5) bzip format not supported.";

  var h = function (e, t) {
    var r = c[e] || "unknown error";
    t && (r += ": " + t);
    var n = new TypeError(r);
    throw n.errorCode = e, n;
  },
      l = function (e, t) {
    this.writePos = this.writeCurrent = this.writeCount = 0, this._start_bunzip(e, t);
  };

  l.prototype._init_block = function () {
    return this._get_next_block() ? (this.blockCRC = new n(), !0) : (this.writeCount = -1, !1);
  }, l.prototype._start_bunzip = function (e, r) {
    var n = f.makeU8Buffer(4);
    4 === e.read(n, 0, 4) && "BZh" === String.fromCharCode(n[0], n[1], n[2]) || h(s.NOT_BZIP_DATA, "bad magic");
    var i = n[3] - 48;
    (i < 1 || i > 9) && h(s.NOT_BZIP_DATA, "level out of range"), this.reader = new t(e), this.dbufSize = 1e5 * i, this.nextoutput = 0, this.outputStream = r, this.streamCRC = 0;
  }, l.prototype._get_next_block = function () {
    var e,
        t,
        r,
        n = this.reader,
        i = n.readBits(48);
    if (25779555029136 === i) return !1;
    54156738319193 !== i && h(s.NOT_BZIP_DATA), this.targetBlockCRC = n.readBits(32), this.streamCRC = (this.targetBlockCRC ^ (this.streamCRC << 1 | this.streamCRC >>> 31)) >>> 0, n.readBits(1) && h(s.OBSOLETE_INPUT);
    var o = n.readBits(24);
    o > this.dbufSize && h(s.DATA_ERROR, "initial position out of bounds");
    var a = n.readBits(16),
        c = f.makeU8Buffer(256),
        l = 0;

    for (e = 0; e < 16; e++) if (a & 1 << 15 - e) {
      var d = 16 * e;

      for (r = n.readBits(16), t = 0; t < 16; t++) r & 1 << 15 - t && (c[l++] = d + t);
    }

    var B = n.readBits(3);
    (B < 2 || B > 6) && h(s.DATA_ERROR);
    var p = n.readBits(15);
    0 === p && h(s.DATA_ERROR);
    var v = f.makeU8Buffer(256);

    for (e = 0; e < B; e++) v[e] = e;

    var m = f.makeU8Buffer(p);

    for (e = 0; e < p; e++) {
      for (t = 0; n.readBits(1); t++) t >= B && h(s.DATA_ERROR);

      m[e] = u(v, t);
    }

    var w,
        E = l + 2,
        g = [];

    for (t = 0; t < B; t++) {
      var _ = f.makeU8Buffer(E),
          b = f.makeU16Buffer(21);

      for (a = n.readBits(5), e = 0; e < E; e++) {
        for (; (a < 1 || a > 20) && h(s.DATA_ERROR), n.readBits(1);) n.readBits(1) ? a-- : a++;

        _[e] = a;
      }

      var y, R;

      for (y = R = _[0], e = 1; e < E; e++) _[e] > R ? R = _[e] : _[e] < y && (y = _[e]);

      w = {}, g.push(w), w.permute = f.makeU16Buffer(258), w.limit = f.makeU32Buffer(22), w.base = f.makeU32Buffer(21), w.minLen = y, w.maxLen = R;
      var C = 0;

      for (e = y; e <= R; e++) for (b[e] = w.limit[e] = 0, a = 0; a < E; a++) _[a] === e && (w.permute[C++] = a);

      for (e = 0; e < E; e++) b[_[e]]++;

      for (C = a = 0, e = y; e < R; e++) C += b[e], w.limit[e] = C - 1, C <<= 1, a += b[e], w.base[e + 1] = C - a;

      w.limit[R + 1] = Number.MAX_VALUE, w.limit[R] = C + b[R] - 1, w.base[y] = 0;
    }

    var k = f.makeU32Buffer(256);

    for (e = 0; e < 256; e++) v[e] = e;

    var T,
        O = 0,
        S = 0,
        U = 0,
        A = this.dbuf = f.makeU32Buffer(this.dbufSize);

    for (E = 0;;) {
      for (E-- || (E = 49, U >= p && h(s.DATA_ERROR), w = g[m[U++]]), e = w.minLen, t = n.readBits(e); e > w.maxLen && h(s.DATA_ERROR), !(t <= w.limit[e]); e++) t = t << 1 | n.readBits(1);

      t -= w.base[e], (t < 0 || t >= 258) && h(s.DATA_ERROR);
      var z = w.permute[t];

      if (0 !== z && 1 !== z) {
        if (O) for (O = 0, S + a > this.dbufSize && h(s.DATA_ERROR), T = c[v[0]], k[T] += a; a--;) A[S++] = T;
        if (z > l) break;
        S >= this.dbufSize && h(s.DATA_ERROR), e = z - 1, T = u(v, e), T = c[T], k[T]++, A[S++] = T;
      } else O || (O = 1, a = 0), a += 0 === z ? O : 2 * O, O <<= 1;
    }

    for ((o < 0 || o >= S) && h(s.DATA_ERROR), t = 0, e = 0; e < 256; e++) r = t + k[e], k[e] = t, t = r;

    for (e = 0; e < S; e++) T = 255 & A[e], A[k[T]] |= e << 8, k[T]++;

    var N = 0,
        L = 0,
        P = 0;
    return S && (N = A[o], L = 255 & N, N >>= 8, P = -1), this.writePos = N, this.writeCurrent = L, this.writeCount = S, this.writeRun = P, !0;
  }, l.prototype._read_bunzip = function (e, t) {
    var r, n, i;
    if (this.writeCount < 0) return 0;

    for (var o = this.dbuf, f = this.writePos, a = this.writeCurrent, u = this.writeCount, c = (this.outputsize, this.writeRun); u;) {
      for (u--, n = a, f = o[f], a = 255 & f, f >>= 8, 3 == c++ ? (r = a, i = n, a = -1) : (r = 1, i = a), this.blockCRC.updateCRCRun(i, r); r--;) this.outputStream.writeByte(i), this.nextoutput++;

      a != n && (c = 0);
    }

    return this.writeCount = u, this.blockCRC.getCRC() !== this.targetBlockCRC && h(s.DATA_ERROR, "Bad block CRC (got " + this.blockCRC.getCRC().toString(16) + " expected " + this.targetBlockCRC.toString(16) + ")"), this.nextoutput;
  }, l.Err = s, l.decode = function (e, t, r) {
    for (var n = f.coerceInputStream(e), i = f.coerceOutputStream(t, t), o = i.stream, a = new l(n, o);;) {
      if ("eof" in n && n.eof()) break;
      if (a._init_block()) a._read_bunzip();else {
        var u = a.reader.readBits(32);
        if (u !== a.streamCRC && h(s.DATA_ERROR, "Bad stream CRC (got " + a.streamCRC.toString(16) + " expected " + u.toString(16) + ")"), !(r && "eof" in n) || n.eof()) break;

        a._start_bunzip(n, o);
      }
    }

    return i.retval;
  }, l.decodeBlock = function (e, t, r) {
    var i = f.coerceInputStream(e),
        o = f.coerceOutputStream(r, r),
        a = o.stream,
        u = new l(i, a);
    return u.reader.seekBit(t), u._get_next_block() && (u.blockCRC = new n(), u.writeCopies = 0, u._read_bunzip()), o.retval;
  }, l.table = function (e, t, r) {
    var n = new o();
    n.delegate = f.coerceInputStream(e), n.pos = 0, n.readByte = function () {
      return this.pos++, this.delegate.readByte();
    }, n.tell = function () {
      return this.pos;
    }, n.delegate.eof && (n.eof = n.delegate.eof.bind(n.delegate));
    var i = new o();
    i.pos = 0, i.writeByte = function () {
      this.pos++;
    };

    for (var a = new l(n, i), u = a.dbufSize;;) {
      if ("eof" in n && n.eof()) break;
      var s = a.reader.tellBit();

      if (a._init_block()) {
        var c = i.pos;
        a._read_bunzip(), t(s, i.pos - c);
      } else {
        a.reader.readBits(32);
        if (!(r && "eof" in n) || n.eof()) break;
        a._start_bunzip(n, i), console.assert(a.dbufSize === u, "shouldn't change block size within multistream file");
      }
    }
  };

  var d = function (e, t) {
    var r,
        n = [];

    for (r = 0; r < t; r++) n[r] = e[r] << 9 | r;

    n.sort(function (e, t) {
      return e - t;
    });
    var o = n.map(function (e) {
      return e >>> 9;
    });

    for (i.allocateHuffmanCodeLengths(o, 20), this.codeLengths = f.makeU8Buffer(t), r = 0; r < t; r++) {
      var a = 511 & n[r];
      this.codeLengths[a] = o[r];
    }
  };

  d.prototype.computeCanonical = function () {
    var e,
        t = this.codeLengths.length,
        r = [];

    for (e = 0; e < t; e++) r[e] = this.codeLengths[e] << 9 | e;

    r.sort(function (e, t) {
      return e - t;
    }), this.code = f.makeU32Buffer(t);
    var n = 0,
        i = 0;

    for (e = 0; e < t; e++) {
      var o = r[e] >>> 9,
          a = 511 & r[e];
      console.assert(i <= o), n <<= o - i, this.code[a] = n++, i = o;
    }
  }, d.prototype.cost = function (e, t, r) {
    var n,
        i = 0;

    for (n = 0; n < r; n++) i += this.codeLengths[e[t + n]];

    return i;
  }, d.prototype.emit = function (e) {
    var t,
        r = this.codeLengths[0];

    for (e.writeBits(5, r), t = 0; t < this.codeLengths.length; t++) {
      var n,
          i,
          o = this.codeLengths[t];

      for (console.assert(o > 0 && o <= 20), r < o ? (n = 2, i = o - r) : (n = 3, i = r - o); i-- > 0;) e.writeBits(2, n);

      e.writeBit(0), r = o;
    }
  }, d.prototype.encode = function (e, t) {
    e.writeBits(this.codeLengths[t], this.code[t]);
  };

  var B = function (e, t, r, n) {
    for (var i = 0, o = -1, f = 0; i < r && !(4 === f && (t[i++] = 0, i >= r));) {
      var u = e.readByte();
      if (u === a) break;
      if (n.updateCRC(u), u !== o) o = u, f = 1;else if (++f > 4) {
        if (f < 256) {
          t[i - 1]++;
          continue;
        }

        f = 1;
      }
      t[i++] = u;
    }

    return i;
  },
      p = function (e, t, r) {
    var n, i, o;

    for (n = 0, o = 0; n < r.length; n += 50) {
      var f = Math.min(50, r.length - n),
          a = 0,
          u = t[0].cost(r, n, f);

      for (i = 1; i < t.length; i++) {
        var s = t[i].cost(r, n, f);
        s < u && (a = i, u = s);
      }

      e[o++] = a;
    }
  },
      v = function (e, t, r, n, i) {
    for (var o, f, a, u = []; e.length < t;) {
      for (p(n, e, r), o = 0; o < e.length; o++) u[o] = 0;

      for (o = 0; o < n.length; o++) u[n[o]]++;

      var s = u.indexOf(Math.max.apply(Math, u)),
          c = [];

      for (o = 0, f = 0; o < n.length; o++) if (n[o] === s) {
        var h = 50 * o,
            l = Math.min(h + 50, r.length);
        c.push({
          index: o,
          cost: e[s].cost(r, h, l - h)
        });
      }

      for (c.sort(function (e, t) {
        return e.cost - t.cost;
      }), o = c.length >>> 1; o < c.length; o++) n[c[o].index] = e.length;

      e.push(null);
      var B,
          v = [];

      for (o = 0; o < e.length; o++) for (B = v[o] = [], f = 0; f < i; f++) B[f] = 0;

      for (o = 0, f = 0; o < r.length;) for (B = v[n[f++]], a = 0; a < 50 && o < r.length; a++) B[r[o++]]++;

      for (o = 0; o < e.length; o++) e[o] = new d(v[o], i);
    }
  },
      m = function (e, t, n) {
    var i,
        o,
        a,
        s,
        c = f.makeU8Buffer(t),
        h = r.bwtransform2(e, c, t, 256);
    n.writeBit(0), n.writeBits(24, h);
    var l = [],
        B = [];

    for (o = 0; o < t; o++) i = e[o], l[i] = !0, B[i >>> 4] = !0;

    for (o = 0; o < 16; o++) n.writeBit(!!B[o]);

    for (o = 0; o < 16; o++) if (B[o]) for (a = 0; a < 16; a++) n.writeBit(!!l[o << 4 | a]);

    var m = 0;

    for (o = 0; o < 256; o++) l[o] && m++;

    var w = f.makeU16Buffer(t + 1),
        E = m + 1,
        g = [];

    for (o = 0; o <= E; o++) g[o] = 0;

    var _ = f.makeU8Buffer(m);

    for (o = 0, a = 0; o < 256; o++) l[o] && (_[a++] = o);

    l = null, B = null;

    var b = 0,
        y = 0,
        R = function (e) {
      w[b++] = e, g[e]++;
    },
        C = function () {
      for (; 0 !== y;) 1 & y ? (R(0), y -= 1) : (R(1), y -= 2), y >>>= 1;
    };

    for (o = 0; o < c.length; o++) {
      for (i = c[o], a = 0; a < m && _[a] !== i; a++);

      console.assert(a !== m), u(_, a), 0 === a ? y++ : (C(), R(a + 1), y = 0);
    }

    C(), R(E), w = w.subarray(0, b);
    var k,
        T = [];

    for (k = b >= 2400 ? 6 : b >= 1200 ? 5 : b >= 600 ? 4 : b >= 200 ? 3 : 2, T.push(new d(g, E + 1)), o = 0; o <= E; o++) g[o] = 1;

    T.push(new d(g, E + 1)), g = null;
    var O = f.makeU8Buffer(Math.ceil(b / 50));

    for (v(T, k, w, O, E + 1), p(O, T, w), console.assert(T.length >= 2 && T.length <= 6), n.writeBits(3, T.length), n.writeBits(15, O.length), o = 0; o < T.length; o++) _[o] = o;

    for (o = 0; o < O.length; o++) {
      var S = O[o];

      for (a = 0; a < T.length && _[a] !== S; a++);

      for (console.assert(a < T.length), u(_, a); a > 0; a--) n.writeBit(1);

      n.writeBit(0);
    }

    for (o = 0; o < T.length; o++) T[o].emit(n), T[o].computeCanonical();

    for (o = 0, s = 0; o < b;) {
      var U = T[O[s++]];

      for (a = 0; a < 50 && o < b; a++) U.encode(n, w[o++]);
    }
  },
      w = Object.create(null);

  return w.compressFile = function (e, r, i) {
    e = f.coerceInputStream(e);
    var o = f.coerceOutputStream(r, r);
    r = new t(o.stream);
    var a = 9;
    if ("number" == typeof i && (a = i), a < 1 || a > 9) throw new Error("Invalid block size multiplier");
    var u = 1e5 * a;
    u -= 19, r.writeByte("B".charCodeAt(0)), r.writeByte("Z".charCodeAt(0)), r.writeByte("h".charCodeAt(0)), r.writeByte("0".charCodeAt(0) + a);
    var s,
        c = f.makeU8Buffer(u),
        h = 0;

    do {
      var l = new n();
      s = B(e, c, u, l), s > 0 && (h = ((h << 1 | h >>> 31) ^ l.getCRC()) >>> 0, r.writeBits(48, 54156738319193), r.writeBits(32, l.getCRC()), m(c, s, r));
    } while (s === u);

    return r.writeBits(48, 25779555029136), r.writeBits(32, h), r.flush(), o.retval;
  }, w.decompressFile = l.decode, w.decompressBlock = l.decodeBlock, w.table = l.table, w;
}(0, BitStream, BWT, CRC32, HuffmanAllocator, Stream, Util), module.exports = Bzip2;