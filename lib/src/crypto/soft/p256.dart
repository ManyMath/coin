import 'dart:convert';
import 'dart:typed_data';

/// NIST P-256 (secp256r1 / prime256v1) ECDSA **signature verification**, from
/// scratch, in pure Dart. coin already has secp256k1, Ed25519 and X25519; P-256
/// is the one curve missing, and it is what ES256 (the WalletConnect Verify
/// attestation JWT) needs. Only verification is implemented - there is no need
/// to sign with this curve in coin.
///
/// ECDSA-P256/SHA-256 test vectors live in `test/crypto/p256_test.dart`: a
/// WalletConnect Verify attestation JWT from reown's verify test suite, plus
/// vectors generated with the `cryptography` reference library.
class P256 {
  P256._();

  /// Field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
  static final BigInt p = BigInt.parse(
      'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
      radix: 16);

  /// Curve order n.
  static final BigInt n = BigInt.parse(
      'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
      radix: 16);

  /// Curve coefficient a = -3 mod p.
  static final BigInt a = p - BigInt.from(3);

  /// Curve coefficient b.
  static final BigInt b = BigInt.parse(
      '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
      radix: 16);

  /// Base point G.
  static final BigInt gx = BigInt.parse(
      '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
      radix: 16);
  static final BigInt gy = BigInt.parse(
      '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
      radix: 16);

  static final BigInt _two = BigInt.two;

  /// True if the affine point (x, y) satisfies y^2 = x^3 + a*x + b (mod p) and is
  /// not the point at infinity (null coordinates).
  static bool isOnCurve(BigInt? x, BigInt? y) {
    if (x == null || y == null) return false;
    if (x < BigInt.zero || x >= p || y < BigInt.zero || y >= p) return false;
    final lhs = (y * y) % p;
    final rhs = (((x * x) % p) * x + a * x + b) % p;
    return lhs == rhs;
  }

  // Affine point arithmetic over the prime field. Infinity is (null, null).
  static (BigInt?, BigInt?) _double(BigInt? x, BigInt? y) {
    if (x == null || y == null) return (null, null);
    if (y == BigInt.zero) return (null, null);
    final num = (BigInt.from(3) * x * x + a) % p;
    final den = (_two * y) % p;
    final lam = (num * den.modInverse(p)) % p;
    final x3 = (lam * lam - _two * x) % p;
    final y3 = (lam * (x - x3) - y) % p;
    return (x3 % p, y3 % p);
  }

  static (BigInt?, BigInt?) _add(
      BigInt? x1, BigInt? y1, BigInt? x2, BigInt? y2) {
    if (x1 == null || y1 == null) return (x2, y2);
    if (x2 == null || y2 == null) return (x1, y1);
    if (x1 == x2) {
      if ((y1 + y2) % p == BigInt.zero) return (null, null); // P + (-P)
      return _double(x1, y1);
    }
    final lam = ((y2 - y1) % p * (x2 - x1).modInverse(p)) % p;
    final x3 = (lam * lam - x1 - x2) % p;
    final y3 = (lam * (x1 - x3) - y1) % p;
    return (x3 % p, y3 % p);
  }

  static (BigInt?, BigInt?) _mul(BigInt k, BigInt? x, BigInt? y) {
    BigInt? rx, ry; // infinity
    var ax = x, ay = y;
    var kk = k % n;
    while (kk > BigInt.zero) {
      if (kk.isOdd) {
        final r = _add(rx, ry, ax, ay);
        rx = r.$1;
        ry = r.$2;
      }
      final d = _double(ax, ay);
      ax = d.$1;
      ay = d.$2;
      kk = kk >> 1;
    }
    return (rx, ry);
  }

  /// Reduce a message digest to the integer e used by ECDSA: the leftmost
  /// `n.bitLength` bits of [hash] (for SHA-256 + P-256 the two lengths match, so
  /// e is just the big-endian integer).
  static BigInt _hashToInt(Uint8List hash) {
    var e = BigInt.zero;
    for (final byte in hash) {
      e = (e << 8) | BigInt.from(byte);
    }
    final excess = hash.length * 8 - n.bitLength;
    if (excess > 0) e = e >> excess;
    return e;
  }

  /// Verify an ECDSA signature ([r], [s]) over a message [hash] (already
  /// digested, e.g. SHA-256) against the public key ([qx], [qy]). Returns false
  /// for an off-curve key, out-of-range scalars, or a non-matching signature -
  /// never throws.
  static bool verify({
    required Uint8List hash,
    required BigInt r,
    required BigInt s,
    required BigInt qx,
    required BigInt qy,
  }) {
    if (r <= BigInt.zero || r >= n) return false;
    if (s <= BigInt.zero || s >= n) return false;
    if (!isOnCurve(qx, qy)) return false;
    final e = _hashToInt(hash);
    final w = s.modInverse(n);
    final u1 = (e * w) % n;
    final u2 = (r * w) % n;
    final (p1x, p1y) = _mul(u1, gx, gy);
    final (p2x, p2y) = _mul(u2, qx, qy);
    final (x, y) = _add(p1x, p1y, p2x, p2y);
    if (x == null || y == null) return false;
    return x % n == r;
  }

  /// Verify with the raw 32-byte big-endian [r]/[s] of a JOSE/raw signature
  /// (e.g. the 64-byte `r||s` of an ES256 JWT, split in half).
  static bool verifyRaw({
    required Uint8List hash,
    required Uint8List r,
    required Uint8List s,
    required BigInt qx,
    required BigInt qy,
  }) =>
      verify(
        hash: hash,
        r: _be(r),
        s: _be(s),
        qx: qx,
        qy: qy,
      );

  /// Decode a JWK EC public key's base64url `x`/`y` coordinates to the affine
  /// point (qx, qy). Pads the base64url as JWK omits trailing `=`.
  static (BigInt, BigInt) pointFromJwk(String x, String y) =>
      (_be(_b64u(x)), _be(_b64u(y)));

  static BigInt _be(Uint8List bytes) {
    var v = BigInt.zero;
    for (final byte in bytes) {
      v = (v << 8) | BigInt.from(byte);
    }
    return v;
  }

  static Uint8List _b64u(String s) {
    final padded = s.padRight((s.length + 3) ~/ 4 * 4, '=');
    return base64Url.decode(padded);
  }
}
