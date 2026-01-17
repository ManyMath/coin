// ChaCha20-Poly1305 AEAD - pure Dart implementation per RFC 8439 (RFC 7539).
//
// This is a clean-room, dependency-free re-implementation. It uses only
// `dart:typed_data` and intentionally avoids package:pointycastle,
// package:cryptography and package:crypto (supply-chain re-implementation).

import 'dart:typed_data';

const int _mask32 = 0xFFFFFFFF;

int _rotl32(int v, int n) =>
    ((v << n) & _mask32) | (v >> (32 - n));

void _quarterRound(Uint32List s, int a, int b, int c, int d) {
  s[a] = (s[a] + s[b]) & _mask32;
  s[d] = _rotl32(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) & _mask32;
  s[b] = _rotl32(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) & _mask32;
  s[d] = _rotl32(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) & _mask32;
  s[b] = _rotl32(s[b] ^ s[c], 7);
}

int _le32(Uint8List b, int off) =>
    b[off] |
    (b[off + 1] << 8) |
    (b[off + 2] << 16) |
    (b[off + 3] << 24);

/// Generates one 64-byte ChaCha20 keystream block for the given 32-byte [key32],
/// 32-bit block [counter] and 12-byte [nonce12].
Uint8List chacha20Block(Uint8List key32, int counter, Uint8List nonce12) {
  if (key32.length != 32) {
    throw ArgumentError('key must be 32 bytes');
  }
  if (nonce12.length != 12) {
    throw ArgumentError('nonce must be 12 bytes');
  }

  final state = Uint32List(16);
  // Constants: "expand 32-byte k"
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  // Key
  for (var i = 0; i < 8; i++) {
    state[4 + i] = _le32(key32, i * 4);
  }
  // Counter
  state[12] = counter & _mask32;
  // Nonce
  state[13] = _le32(nonce12, 0);
  state[14] = _le32(nonce12, 4);
  state[15] = _le32(nonce12, 8);

  final working = Uint32List.fromList(state);
  for (var i = 0; i < 10; i++) {
    // Column rounds
    _quarterRound(working, 0, 4, 8, 12);
    _quarterRound(working, 1, 5, 9, 13);
    _quarterRound(working, 2, 6, 10, 14);
    _quarterRound(working, 3, 7, 11, 15);
    // Diagonal rounds
    _quarterRound(working, 0, 5, 10, 15);
    _quarterRound(working, 1, 6, 11, 12);
    _quarterRound(working, 2, 7, 8, 13);
    _quarterRound(working, 3, 4, 9, 14);
  }

  final out = Uint8List(64);
  for (var i = 0; i < 16; i++) {
    final word = (working[i] + state[i]) & _mask32;
    out[i * 4] = word & 0xff;
    out[i * 4 + 1] = (word >> 8) & 0xff;
    out[i * 4 + 2] = (word >> 16) & 0xff;
    out[i * 4 + 3] = (word >> 24) & 0xff;
  }
  return out;
}

/// XORs [data] with the ChaCha20 keystream starting at [initialCounter].
Uint8List _chacha20Xor(
  Uint8List key32,
  Uint8List nonce12,
  Uint8List data,
  int initialCounter,
) {
  final out = Uint8List(data.length);
  var counter = initialCounter;
  var offset = 0;
  while (offset < data.length) {
    final block = chacha20Block(key32, counter, nonce12);
    final chunk = data.length - offset;
    final n = chunk < 64 ? chunk : 64;
    for (var i = 0; i < n; i++) {
      out[offset + i] = data[offset + i] ^ block[i];
    }
    offset += n;
    counter = (counter + 1) & _mask32;
  }
  return out;
}

final BigInt _p1305 = (BigInt.one << 130) - BigInt.from(5);
final BigInt _clampMask =
    BigInt.parse('0ffffffc0ffffffc0ffffffc0fffffff', radix: 16);

/// Computes the 16-byte Poly1305 MAC of [message] under the 32-byte
/// one-time key [oneTimeKey32], per RFC 8439 sec. 2.5.
Uint8List poly1305Mac(Uint8List oneTimeKey32, Uint8List message) {
  if (oneTimeKey32.length != 32) {
    throw ArgumentError('one-time key must be 32 bytes');
  }

  // r = le_bytes_to_num(key[0..15]) & clamp ; s = le_bytes_to_num(key[16..31])
  var r = BigInt.zero;
  for (var i = 15; i >= 0; i--) {
    r = (r << 8) | BigInt.from(oneTimeKey32[i]);
  }
  r = r & _clampMask;

  var s = BigInt.zero;
  for (var i = 31; i >= 16; i--) {
    s = (s << 8) | BigInt.from(oneTimeKey32[i]);
  }

  var acc = BigInt.zero;
  var offset = 0;
  while (offset < message.length) {
    final chunk = message.length - offset;
    final n = chunk < 16 ? chunk : 16;
    // Read block as little-endian and append a 1 byte at the top.
    var block = BigInt.zero;
    for (var i = n - 1; i >= 0; i--) {
      block = (block << 8) | BigInt.from(message[offset + i]);
    }
    block = block | (BigInt.one << (n * 8));

    acc = (acc + block);
    acc = (r * acc) % _p1305;
    offset += n;
  }

  acc = (acc + s) & ((BigInt.one << 128) - BigInt.one);

  final tag = Uint8List(16);
  var t = acc;
  for (var i = 0; i < 16; i++) {
    tag[i] = (t & BigInt.from(0xff)).toInt();
    t = t >> 8;
  }
  return tag;
}

Uint8List _poly1305KeyGen(Uint8List key32, Uint8List nonce12) {
  final block = chacha20Block(key32, 0, nonce12);
  return Uint8List.sublistView(block, 0, 32);
}

void _writeLe64(BytesBuilder bb, int value) {
  final b = Uint8List(8);
  var v = value;
  for (var i = 0; i < 8; i++) {
    b[i] = v & 0xff;
    v = v >> 8;
  }
  bb.add(b);
}

Uint8List _aeadMacData(Uint8List aad, Uint8List ciphertext) {
  final bb = BytesBuilder();
  bb.add(aad);
  final aadPad = (16 - (aad.length % 16)) % 16;
  if (aadPad > 0) bb.add(Uint8List(aadPad));
  bb.add(ciphertext);
  final ctPad = (16 - (ciphertext.length % 16)) % 16;
  if (ctPad > 0) bb.add(Uint8List(ctPad));
  _writeLe64(bb, aad.length);
  _writeLe64(bb, ciphertext.length);
  return bb.toBytes();
}

/// Encrypts [plaintext] with ChaCha20-Poly1305 AEAD (RFC 8439 sec. 2.8).
///
/// Returns ciphertext concatenated with the 16-byte Poly1305 tag, so the
/// result length is `plaintext.length + 16`. [aad] defaults to empty.
Uint8List chacha20Poly1305Encrypt({
  required Uint8List key32,
  required Uint8List nonce12,
  required Uint8List plaintext,
  Uint8List? aad,
}) {
  final ad = aad ?? Uint8List(0);
  final otk = _poly1305KeyGen(key32, nonce12);
  final ciphertext = _chacha20Xor(key32, nonce12, plaintext, 1);
  final macData = _aeadMacData(ad, ciphertext);
  final tag = poly1305Mac(otk, macData);

  final out = Uint8List(ciphertext.length + 16);
  out.setRange(0, ciphertext.length, ciphertext);
  out.setRange(ciphertext.length, out.length, tag);
  return out;
}

/// Verifies and decrypts [ciphertextWithTag] (ciphertext || 16-byte tag).
///
/// Returns the plaintext, or throws `FormatException('invalid tag')` if the
/// authentication tag does not match.
Uint8List chacha20Poly1305Decrypt({
  required Uint8List key32,
  required Uint8List nonce12,
  required Uint8List ciphertextWithTag,
  Uint8List? aad,
}) {
  if (ciphertextWithTag.length < 16) {
    throw FormatException('invalid tag');
  }
  final ad = aad ?? Uint8List(0);
  final ctLen = ciphertextWithTag.length - 16;
  final ciphertext = Uint8List.sublistView(ciphertextWithTag, 0, ctLen);
  final tag = Uint8List.sublistView(ciphertextWithTag, ctLen);

  final otk = _poly1305KeyGen(key32, nonce12);
  final macData = _aeadMacData(ad, ciphertext);
  final expected = poly1305Mac(otk, macData);

  // Constant-time comparison.
  var diff = 0;
  for (var i = 0; i < 16; i++) {
    diff |= tag[i] ^ expected[i];
  }
  if (diff != 0) {
    throw FormatException('invalid tag');
  }

  return _chacha20Xor(key32, nonce12, ciphertext, 1);
}
