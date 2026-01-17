// Pure-Dart AES-256 + CBC + PKCS7 (FIPS-197 / NIST SP800-38A).
//
// No third-party crypto dependencies; only `dart:typed_data`. This is a
// supply-chain-hardened re-implementation intended to avoid pulling in
// external crypto packages.
//
// References:
//   - FIPS-197 (Advanced Encryption Standard)
//   - NIST SP800-38A (Block cipher modes of operation; CBC)
//   - RFC 5652 section 6.3 (PKCS#7 padding)

import 'dart:typed_data';

const int _blockSize = 16;
const int _keyBytes = 32; // AES-256
const int _nk = 8; // 256-bit key = 8 words
const int _nr = 14; // 14 rounds for AES-256
const int _nb = 4; // block = 4 words

// AES S-box.
final Uint8List _sbox = Uint8List.fromList(const <int>[
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, //
  0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
  0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
  0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
  0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
  0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
  0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
  0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
  0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
  0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
  0xb0, 0x54, 0xbb, 0x16,
]);

// Inverse S-box, derived from _sbox.
final Uint8List _invSbox = _buildInvSbox();

Uint8List _buildInvSbox() {
  final inv = Uint8List(256);
  for (var i = 0; i < 256; i++) {
    inv[_sbox[i]] = i;
  }
  return inv;
}

// Round constants for key expansion.
const List<int> _rcon = <int>[
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, //
  0xab, 0x4d,
];

// GF(2^8) multiply by 2 (xtime).
int _xtime(int x) {
  final r = (x << 1) & 0xff;
  return (x & 0x80) != 0 ? r ^ 0x1b : r;
}

// GF(2^8) multiply.
int _gmul(int a, int b) {
  var p = 0;
  var aa = a;
  var bb = b;
  for (var i = 0; i < 8; i++) {
    if ((bb & 1) != 0) p ^= aa;
    final hi = aa & 0x80;
    aa = (aa << 1) & 0xff;
    if (hi != 0) aa ^= 0x1b;
    bb >>= 1;
  }
  return p & 0xff;
}

/// Expands a 32-byte AES-256 key into the round key schedule.
///
/// Returns 4 * (Nr + 1) words = 60 words = 240 bytes, big-endian per word.
Uint8List _expandKey(Uint8List key32) {
  final totalWords = _nb * (_nr + 1); // 60
  final w = Uint8List(totalWords * 4); // 240 bytes

  // First Nk words are the key itself.
  for (var i = 0; i < _nk * 4; i++) {
    w[i] = key32[i];
  }

  final temp = Uint8List(4);
  for (var i = _nk; i < totalWords; i++) {
    final prev = (i - 1) * 4;
    temp[0] = w[prev];
    temp[1] = w[prev + 1];
    temp[2] = w[prev + 2];
    temp[3] = w[prev + 3];

    if (i % _nk == 0) {
      // RotWord.
      final t = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = t;
      // SubWord.
      temp[0] = _sbox[temp[0]];
      temp[1] = _sbox[temp[1]];
      temp[2] = _sbox[temp[2]];
      temp[3] = _sbox[temp[3]];
      // XOR Rcon.
      temp[0] ^= _rcon[(i ~/ _nk) - 1];
    } else if (_nk > 6 && i % _nk == 4) {
      // SubWord only (AES-256 specific extra SubWord step).
      temp[0] = _sbox[temp[0]];
      temp[1] = _sbox[temp[1]];
      temp[2] = _sbox[temp[2]];
      temp[3] = _sbox[temp[3]];
    }

    final cur = i * 4;
    final back = (i - _nk) * 4;
    w[cur] = w[back] ^ temp[0];
    w[cur + 1] = w[back + 1] ^ temp[1];
    w[cur + 2] = w[back + 2] ^ temp[2];
    w[cur + 3] = w[back + 3] ^ temp[3];
  }
  return w;
}

void _addRoundKey(Uint8List state, Uint8List roundKeys, int round) {
  final off = round * _blockSize;
  for (var i = 0; i < _blockSize; i++) {
    state[i] ^= roundKeys[off + i];
  }
}

void _subBytes(Uint8List state) {
  for (var i = 0; i < _blockSize; i++) {
    state[i] = _sbox[state[i]];
  }
}

void _invSubBytes(Uint8List state) {
  for (var i = 0; i < _blockSize; i++) {
    state[i] = _invSbox[state[i]];
  }
}

// ShiftRows: state is column-major (state[r + 4*c]).
void _shiftRows(Uint8List s) {
  // Row 1: shift left by 1.
  var t = s[1];
  s[1] = s[5];
  s[5] = s[9];
  s[9] = s[13];
  s[13] = t;
  // Row 2: shift left by 2.
  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;
  // Row 3: shift left by 3 (== right by 1).
  t = s[15];
  s[15] = s[11];
  s[11] = s[7];
  s[7] = s[3];
  s[3] = t;
}

void _invShiftRows(Uint8List s) {
  // Row 1: shift right by 1.
  var t = s[13];
  s[13] = s[9];
  s[9] = s[5];
  s[5] = s[1];
  s[1] = t;
  // Row 2: shift right by 2.
  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;
  // Row 3: shift right by 3 (== left by 1).
  t = s[3];
  s[3] = s[7];
  s[7] = s[11];
  s[11] = s[15];
  s[15] = t;
}

void _mixColumns(Uint8List s) {
  for (var c = 0; c < 4; c++) {
    final i = c * 4;
    final a0 = s[i];
    final a1 = s[i + 1];
    final a2 = s[i + 2];
    final a3 = s[i + 3];
    s[i] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3;
    s[i + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3;
    s[i + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3);
    s[i + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3);
  }
}

void _invMixColumns(Uint8List s) {
  for (var c = 0; c < 4; c++) {
    final i = c * 4;
    final a0 = s[i];
    final a1 = s[i + 1];
    final a2 = s[i + 2];
    final a3 = s[i + 3];
    s[i] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9);
    s[i + 1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13);
    s[i + 2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11);
    s[i + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14);
  }
}

/// Encrypts a single 16-byte [block16] under the expanded [roundKeys] schedule
/// (240 bytes from [_expandKey]). Returns a new 16-byte block.
Uint8List aesEncryptBlock(Uint8List roundKeys, Uint8List block16) {
  if (block16.length != _blockSize) {
    throw ArgumentError('block must be 16 bytes, got ${block16.length}');
  }
  final state = Uint8List.fromList(block16);
  _addRoundKey(state, roundKeys, 0);
  for (var round = 1; round < _nr; round++) {
    _subBytes(state);
    _shiftRows(state);
    _mixColumns(state);
    _addRoundKey(state, roundKeys, round);
  }
  _subBytes(state);
  _shiftRows(state);
  _addRoundKey(state, roundKeys, _nr);
  return state;
}

/// Decrypts a single 16-byte [block16] under the expanded [roundKeys] schedule.
Uint8List _aesDecryptBlock(Uint8List roundKeys, Uint8List block16) {
  final state = Uint8List.fromList(block16);
  _addRoundKey(state, roundKeys, _nr);
  for (var round = _nr - 1; round >= 1; round--) {
    _invShiftRows(state);
    _invSubBytes(state);
    _addRoundKey(state, roundKeys, round);
    _invMixColumns(state);
  }
  _invShiftRows(state);
  _invSubBytes(state);
  _addRoundKey(state, roundKeys, 0);
  return state;
}

void _checkKeyIv(Uint8List key32, Uint8List iv16) {
  if (key32.length != _keyBytes) {
    throw ArgumentError('AES-256 key must be 32 bytes, got ${key32.length}');
  }
  if (iv16.length != _blockSize) {
    throw ArgumentError('IV must be 16 bytes, got ${iv16.length}');
  }
}

/// AES-256-CBC encryption with PKCS#7 padding.
///
/// PKCS#7 padding is always applied, even when the plaintext is already a
/// multiple of the block size (in which case a full extra block of 0x10 bytes
/// is appended). Output length is always a positive multiple of 16.
Uint8List aes256CbcEncrypt(Uint8List key32, Uint8List iv16, Uint8List plaintext) {
  _checkKeyIv(key32, iv16);
  final roundKeys = _expandKey(key32);

  // Apply PKCS#7 padding.
  final padLen = _blockSize - (plaintext.length % _blockSize);
  final padded = Uint8List(plaintext.length + padLen);
  padded.setRange(0, plaintext.length, plaintext);
  for (var i = plaintext.length; i < padded.length; i++) {
    padded[i] = padLen;
  }

  final out = Uint8List(padded.length);
  final prev = Uint8List.fromList(iv16);
  final block = Uint8List(_blockSize);
  for (var off = 0; off < padded.length; off += _blockSize) {
    for (var i = 0; i < _blockSize; i++) {
      block[i] = padded[off + i] ^ prev[i];
    }
    final enc = aesEncryptBlock(roundKeys, block);
    out.setRange(off, off + _blockSize, enc);
    prev.setRange(0, _blockSize, enc);
  }
  return out;
}

/// AES-256-CBC decryption with PKCS#7 padding validation.
///
/// Throws [FormatException] if the ciphertext length is not a positive
/// multiple of 16, or if the PKCS#7 padding is invalid.
Uint8List aes256CbcDecrypt(Uint8List key32, Uint8List iv16, Uint8List ciphertext) {
  _checkKeyIv(key32, iv16);
  if (ciphertext.isEmpty || ciphertext.length % _blockSize != 0) {
    throw FormatException(
      'ciphertext length must be a positive multiple of 16, '
      'got ${ciphertext.length}',
    );
  }
  final roundKeys = _expandKey(key32);

  final out = Uint8List(ciphertext.length);
  final prev = Uint8List.fromList(iv16);
  for (var off = 0; off < ciphertext.length; off += _blockSize) {
    final cblock = Uint8List.sublistView(ciphertext, off, off + _blockSize);
    final dec = _aesDecryptBlock(roundKeys, cblock);
    for (var i = 0; i < _blockSize; i++) {
      out[off + i] = dec[i] ^ prev[i];
    }
    prev.setRange(0, _blockSize, cblock);
  }

  // Validate and strip PKCS#7 padding.
  final padLen = out[out.length - 1];
  if (padLen < 1 || padLen > _blockSize) {
    throw const FormatException('invalid PKCS#7 padding length');
  }
  for (var i = out.length - padLen; i < out.length; i++) {
    if (out[i] != padLen) {
      throw const FormatException('invalid PKCS#7 padding bytes');
    }
  }
  return Uint8List.sublistView(out, 0, out.length - padLen);
}
