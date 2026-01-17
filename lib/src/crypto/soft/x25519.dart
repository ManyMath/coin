/// X25519 (RFC 7748) - Curve25519 Diffie-Hellman, pure Dart.
///
/// Implements the Montgomery ladder described in RFC 7748 sec. 5 using only
/// `dart:typed_data` and `BigInt`. No third-party crypto dependencies.
///
/// Field prime p = 2^255 - 19, curve constant a24 = 121665.
library;

import 'dart:typed_data';

/// Field prime: p = 2^255 - 19.
final BigInt _p = (BigInt.one << 255) - BigInt.from(19);

/// (A - 2) / 4 = 121665, per RFC 7748 for Curve25519.
final BigInt _a24 = BigInt.from(121665);

/// Number of bits in a scalar/u-coordinate for X25519.
const int _bits = 255;

/// Decodes a 32-byte little-endian buffer into a [BigInt].
BigInt _decodeLittleEndian(Uint8List b) {
  BigInt result = BigInt.zero;
  for (int i = 0; i < 32; i++) {
    result |= BigInt.from(b[i]) << (8 * i);
  }
  return result;
}

/// Encodes a field element to 32 bytes little-endian (reduced mod p).
Uint8List _encodeUCoordinate(BigInt u) {
  final BigInt v = u % _p;
  final Uint8List out = Uint8List(32);
  BigInt t = v;
  for (int i = 0; i < 32; i++) {
    out[i] = (t & BigInt.from(0xff)).toInt();
    t >>= 8;
  }
  return out;
}

/// Decodes and clamps the scalar per RFC 7748 sec. 5.
BigInt _decodeScalar(Uint8List scalar) {
  final Uint8List k = Uint8List.fromList(scalar);
  k[0] &= 248; // clear bits 0, 1, 2
  k[31] &= 127; // clear bit 7 (255)
  k[31] |= 64; // set bit 6 (254)
  return _decodeLittleEndian(k);
}

/// Decodes the u-coordinate, masking the high bit of the last byte
/// (u mod 2^255), per RFC 7748 sec. 5.
BigInt _decodeUCoordinate(Uint8List u) {
  final Uint8List b = Uint8List.fromList(u);
  // Mask the most significant bit of the final byte.
  b[31] &= 0x7f;
  return _decodeLittleEndian(b) % _p;
}

/// Modular multiplicative inverse via Fermat's little theorem: a^(p-2) mod p.
BigInt _inv(BigInt a) => a.modPow(_p - BigInt.two, _p);

/// Constant-time-ish conditional swap of two values based on [swap] (0 or 1).
///
/// Returns the (possibly swapped) pair. Implemented with masking to avoid
/// branching on secret-dependent bits.
List<BigInt> _cswap(int swap, BigInt a, BigInt b) {
  // mask = 0 when swap==0, all-ones (within field width) when swap==1.
  final BigInt mask =
      swap == 1 ? ((BigInt.one << 256) - BigInt.one) : BigInt.zero;
  final BigInt dummy = mask & (a ^ b);
  return <BigInt>[a ^ dummy, b ^ dummy];
}

/// Core X25519 function: computes X25519(k, u) per RFC 7748 sec. 5.
///
/// [scalar32] is the 32-byte scalar (clamped internally); [uCoordinate32] is
/// the 32-byte little-endian u-coordinate. Returns 32 bytes little-endian.
Uint8List x25519(Uint8List scalar32, Uint8List uCoordinate32) {
  if (scalar32.length != 32) {
    throw ArgumentError('scalar must be 32 bytes, got ${scalar32.length}');
  }
  if (uCoordinate32.length != 32) {
    throw ArgumentError(
      'u-coordinate must be 32 bytes, got ${uCoordinate32.length}',
    );
  }

  final BigInt k = _decodeScalar(scalar32);
  final BigInt u = _decodeUCoordinate(uCoordinate32);

  final BigInt x1 = u;
  BigInt x2 = BigInt.one;
  BigInt z2 = BigInt.zero;
  BigInt x3 = u;
  BigInt z3 = BigInt.one;
  int swap = 0;

  for (int t = _bits - 1; t >= 0; t--) {
    final int kT = ((k >> t) & BigInt.one).toInt();
    swap ^= kT;
    List<BigInt> s;
    s = _cswap(swap, x2, x3);
    x2 = s[0];
    x3 = s[1];
    s = _cswap(swap, z2, z3);
    z2 = s[0];
    z3 = s[1];
    swap = kT;

    final BigInt a = (x2 + z2) % _p;
    final BigInt aa = (a * a) % _p;
    final BigInt b = (x2 - z2) % _p;
    final BigInt bb = (b * b) % _p;
    final BigInt e = (aa - bb) % _p;
    final BigInt c = (x3 + z3) % _p;
    final BigInt d = (x3 - z3) % _p;
    final BigInt da = (d * a) % _p;
    final BigInt cb = (c * b) % _p;

    final BigInt x3New = (da + cb) % _p;
    x3 = (x3New * x3New) % _p;
    final BigInt z3Diff = (da - cb) % _p;
    z3 = (x1 * ((z3Diff * z3Diff) % _p)) % _p;

    x2 = (aa * bb) % _p;
    z2 = (e * ((aa + (_a24 * e) % _p) % _p)) % _p;
  }

  // Final conditional swap.
  List<BigInt> s;
  s = _cswap(swap, x2, x3);
  x2 = s[0];
  x3 = s[1];
  s = _cswap(swap, z2, z3);
  z2 = s[0];
  z3 = s[1];

  // Normalize results modulo p (subtraction above can yield negatives).
  final BigInt resultNum = (x2 % _p + _p) % _p;
  final BigInt resultDen = (z2 % _p + _p) % _p;
  final BigInt result = (resultNum * _inv(resultDen)) % _p;

  return _encodeUCoordinate(result);
}

/// Computes X25519(k, 9): the public key for private scalar [scalar32].
///
/// The base point u = 9 is encoded as the byte 0x09 followed by 31 zero bytes.
Uint8List x25519Base(Uint8List scalar32) {
  final Uint8List base = Uint8List(32);
  base[0] = 9;
  return x25519(scalar32, base);
}
