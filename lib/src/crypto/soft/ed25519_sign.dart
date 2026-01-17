import 'dart:typed_data';

import '../../hash/digest.dart';
import '../../monero/ed25519/ed25519_constants.dart';
import '../../monero/ed25519/ed25519_math.dart';

/// Standard Ed25519 (RFC 8032, PureEdDSA over edwards25519) implemented in
/// pure Dart on top of the repo's existing edwards25519 group arithmetic.
///
/// Uses coin's [sha512] helper (so [VaultKeeper] must be initialized before
/// calling these functions) and the BigInt-based group ops from the Monero
/// ed25519 module.

/// Derives the clamped scalar `s` and the SHA-512 `prefix` from a 32-byte seed.
class _ExpandedKey {
  final BigInt s;
  final Uint8List prefix;
  _ExpandedKey(this.s, this.prefix);
}

_ExpandedKey _expandSeed(Uint8List seed32) {
  if (seed32.length != 32) {
    throw ArgumentError('Ed25519 seed must be 32 bytes (${seed32.length})');
  }
  final h = sha512(seed32);
  final a = Uint8List.fromList(h.sublist(0, 32));
  // Clamp per RFC 8032.
  a[0] &= 248;
  a[31] &= 127;
  a[31] |= 64;
  final s = edBytesToBigInt(a);
  final prefix = Uint8List.fromList(h.sublist(32, 64));
  return _ExpandedKey(s, prefix);
}

Uint8List _concat(List<Uint8List> parts) {
  var total = 0;
  for (final p in parts) {
    total += p.length;
  }
  final out = Uint8List(total);
  var off = 0;
  for (final p in parts) {
    out.setRange(off, off + p.length, p);
    off += p.length;
  }
  return out;
}

/// Reduces a 64-byte little-endian hash output modulo the group order L.
BigInt _hashToScalar(Uint8List hash64) => edBytesToBigInt(hash64) % ed25519L;

/// Returns the 32-byte Ed25519 public key A for the given 32-byte [seed32].
Uint8List ed25519PublicKeyFromSeed(Uint8List seed32) {
  final expanded = _expandSeed(seed32);
  final aPoint = edScalarMult(expanded.s, ed25519G);
  return edPointToBytes(aPoint);
}

/// Signs [message] with the Ed25519 key derived from [seed32].
///
/// Returns the 64-byte signature `Renc(32) || S_le(32)`.
Uint8List ed25519Sign(Uint8List seed32, Uint8List message) {
  final expanded = _expandSeed(seed32);
  final s = expanded.s;
  final prefix = expanded.prefix;

  final aEnc = edPointToBytes(edScalarMult(s, ed25519G));

  // r = SHA-512(prefix || msg) reduced mod L.
  final r = _hashToScalar(sha512(_concat([prefix, message])));
  final rEnc = edPointToBytes(edScalarMult(r, ed25519G));

  // k = SHA-512(Renc || A || msg) reduced mod L.
  final k = _hashToScalar(sha512(_concat([rEnc, aEnc, message])));

  final sScalar = (r + k * s) % ed25519L;
  final sEnc = edBigIntToBytes(sScalar, 32);

  return _concat([rEnc, sEnc]);
}

/// Verifies a 64-byte Ed25519 [signature64] over [message] under [publicKey32].
bool ed25519Verify(
  Uint8List publicKey32,
  Uint8List message,
  Uint8List signature64,
) {
  if (publicKey32.length != 32) return false;
  if (signature64.length != 64) return false;

  final rEnc = Uint8List.fromList(signature64.sublist(0, 32));
  final sEnc = Uint8List.fromList(signature64.sublist(32, 64));

  final sScalar = edBytesToBigInt(sEnc);
  // Reject non-canonical S (S must be < L).
  if (sScalar >= ed25519L) return false;

  EdPoint aPoint;
  EdPoint rPoint;
  try {
    aPoint = edBytesToPoint(publicKey32);
    rPoint = edBytesToPoint(rEnc);
  } on ArgumentError {
    return false;
  }

  // k = SHA-512(Renc || A || msg) reduced mod L.
  final k = _hashToScalar(sha512(_concat([rEnc, publicKey32, message])));

  // Check [S]B == R + [k]A.
  final lhs = edScalarMult(sScalar, ed25519G);
  final rhs = edPointAdd(rPoint, edScalarMult(k, aPoint));

  return _bytesEqual(edPointToBytes(lhs), edPointToBytes(rhs));
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
