import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:unorm_dart/unorm_dart.dart' as unorm;

import '_gf_poly.dart';
import '_polyseed_birthday.dart';
import '_polyseed_data.dart';
import '_polyseed_features.dart';
import '_polyseed_lang.dart';

/// 16-word polyseed mnemonic for Monero.
///
/// Polyseed uses GF(2048) Reed-Solomon codes with PBKDF2-HMAC-SHA256 key
/// derivation. Use [PolyseedMnemonic.decode] to parse a phrase, then call
/// [generateSpendKey] to get the 32-byte seed for [MoneroKeys.fromSeed].
///
/// Spec: https://github.com/tevador/polyseed
class PolyseedMnemonic {
  static const int wordCount = 16;

  // Polyseed coin index for Monero (index 0 per the spec).
  static const int _moneroIndex = 0;

  final PolyseedData _data;

  PolyseedMnemonic._(this._data);

  // ---------------------------------------------------------------------------
  // Construction
  // ---------------------------------------------------------------------------

  /// Decode a 16-word polyseed [phrase]. Language is auto-detected.
  ///
  /// Throws [FormatException] if the phrase has the wrong word count, an
  /// unknown word, a checksum mismatch, or unsupported feature flags.
  factory PolyseedMnemonic.decode(String phrase) {
    final lang = PolyseedLang.getByPhrase(phrase); // throws on unknown lang
    final normalised = lang.normalizeSeparator(phrase);
    final words = normalised.split(lang.separator);

    if (words.length != wordCount) {
      throw const FormatException('Polyseed phrase must be 16 words');
    }

    final poly = GFPoly();
    poly.coefficients = lang.decodePhrase(phrase);

    // decodePhrase returns the raw findWord results; -1 means unknown word.
    if (poly.coefficients.any((c) => c < 0)) {
      throw const FormatException('Unknown word in polyseed phrase');
    }

    // Domain-separate by coin before checking the Reed-Solomon checksum.
    poly.finalize(_moneroIndex);

    if (!poly.check()) {
      throw const FormatException('Polyseed checksum mismatch');
    }

    final data = poly.toPolyseedData();

    if (!PolyseedFeatures.isSupported(data.features)) {
      throw const FormatException('Unsupported polyseed feature flags');
    }

    return PolyseedMnemonic._(data);
  }

  // ---------------------------------------------------------------------------
  // Validation
  // ---------------------------------------------------------------------------

  /// Returns true iff [phrase] is a structurally valid Monero polyseed.
  static bool isValid(String phrase) {
    try {
      PolyseedMnemonic.decode(phrase);
      return true;
    } on FormatException {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Properties
  // ---------------------------------------------------------------------------

  /// Wallet birthday as a Unix timestamp in seconds (~ monthly resolution).
  ///
  /// Use this to start a blockchain scan from the wallet's creation date
  /// instead of genesis block, saving significant sync time.
  int get birthday => PolyseedBirthday.decode(_data.birthday);

  /// Whether this seed has been passphrase-encrypted.
  ///
  /// If true, call [decrypt] before [generateSpendKey].
  bool get isEncrypted => PolyseedFeatures.isEncrypted(_data.features);

  // ---------------------------------------------------------------------------
  // Decryption
  // ---------------------------------------------------------------------------

  /// Decrypt this seed with [passphrase] and return an unencrypted copy.
  ///
  /// The crypt operation is symmetric: applying it twice with the same
  /// passphrase returns the original seed.  A wrong passphrase produces no
  /// error  -  it silently yields a different (invalid) seed, matching every
  /// other PBKDF2-based scheme.
  ///
  /// Throws [StateError] if [isEncrypted] is false.
  PolyseedMnemonic decrypt(String passphrase) {
    if (!isEncrypted) {
      throw StateError('Seed is not encrypted.');
    }

    // Mask salt layout (16 bytes, zero-initialised):
    //  [0..12]  "POLYSEED mask" (UTF-8, 13 bytes)
    //  [13]      0x00 (pad)
    //  [14..15]  0xff 0xff
    final salt = Uint8List(16);
    const label = 'POLYSEED mask';
    salt.setRange(0, label.length, utf8.encode(label));
    salt[14] = 0xff;
    salt[15] = 0xff;

    final mask = _pbkdf2HmacSha256(
      password: Uint8List.fromList(utf8.encode(unorm.nfkd(passphrase))),
      salt: salt,
      iterations: 10000,
      keyLength: 32,
    );

    // XOR the 19 secret bytes with the mask, then clear the 2 unused high
    // bits of byte 18 (150 secret bits span 19 bytes, leaving 2 bits spare).
    const clearMask = 0x3f; // 0xff >> (19*8 - 150)
    final newSecret = Uint8List.fromList(_data.secret);
    for (var i = 0; i < GFPoly.secretSize; i++) {
      newSecret[i] ^= mask[i];
    }
    newSecret[GFPoly.secretSize - 1] &= clearMask;

    return PolyseedMnemonic._(PolyseedData(
      birthday: _data.birthday,
      features: _data.features ^ PolyseedFeatures.encryptedBitMask,
      secret: newSecret,
      checksum: _data.checksum,
    ));
  }

  // ---------------------------------------------------------------------------
  // Key derivation
  // ---------------------------------------------------------------------------

  /// Derive the 32-byte private spend seed for Monero.
  ///
  /// The returned bytes are the raw PBKDF2-HMAC-SHA256 output (10 000
  /// iterations, coin-domain-separated salt). Pass them to
  /// [MoneroKeys.fromSeed], which performs the required Ed25519 scalar
  /// reduction (mod l) before use as a private spend key.
  ///
  /// Throws [StateError] if [isEncrypted] is true  -  decrypt the seed with
  /// the correct passphrase before calling this method.
  Uint8List generateSpendKey() {
    if (isEncrypted) {
      throw StateError(
        'Cannot derive a spend key from an encrypted polyseed. '
        'Decrypt the seed with the correct passphrase first.',
      );
    }

    // Salt layout (32 bytes, all fields little-endian):
    //  [0..11]  "POLYSEED key" (UTF-8, 12 bytes)
    //  [12]      0x00 (separator, never written)
    //  [13..15]  0xff 0xff 0xff
    //  [16..19]  coin index (uint32 LE)  -  Monero = 0
    //  [20..23]  encoded birthday (uint32 LE)
    //  [24..27]  features (uint32 LE)
    //  [28..31]  0x00 0x00 0x00 0x00
    final salt = Uint8List(32); // zero-initialised
    const label = 'POLYSEED key'; // 12 chars -> bytes 0-11
    salt.setRange(0, label.length, utf8.encode(label));
    // byte 12 stays 0x00
    salt[13] = 0xff;
    salt[14] = 0xff;
    salt[15] = 0xff;
    _store32(salt, 16, _moneroIndex);
    _store32(salt, 20, _data.birthday);
    _store32(salt, 24, _data.features);
    // bytes 28-31 stay 0x00

    return _pbkdf2HmacSha256(
      password: _data.secret,
      salt: salt,
      iterations: 10000,
      keyLength: 32,
    );
  }

  // ---------------------------------------------------------------------------
  // PBKDF2-HMAC-SHA256 (RFC 2898 sec. 5.2, single block)
  //
  // Polyseed always requests exactly 32 bytes (one SHA-256 block), so we
  // implement only the first block (PRF block counter = 1) and avoid the
  // loop over multiple blocks.
  // ---------------------------------------------------------------------------

  static Uint8List _pbkdf2HmacSha256({
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int keyLength,
  }) {
    assert(keyLength <= 32, 'Only single-block (<=32-byte) output is supported');

    // U1 = HMAC-SHA256(password, salt || INT(1))
    // INT(1) = 0x00000001 in big-endian (RFC 2898 sec. 5.2 step 3).
    final prfInput = Uint8List(salt.length + 4);
    prfInput.setRange(0, salt.length, salt);
    prfInput[salt.length] = 0;
    prfInput[salt.length + 1] = 0;
    prfInput[salt.length + 2] = 0;
    prfInput[salt.length + 3] = 1;

    var u = Uint8List.fromList(
        crypto.Hmac(crypto.sha256, password).convert(prfInput).bytes);
    final t = Uint8List.fromList(u); // T1 = U1

    // T1 = U1 XOR U2 XOR ... XOR U_{iterations}
    for (var i = 1; i < iterations; i++) {
      u = Uint8List.fromList(
          crypto.Hmac(crypto.sha256, password).convert(u).bytes);
      for (var j = 0; j < t.length; j++) {
        t[j] ^= u[j];
      }
    }

    return Uint8List.fromList(t.sublist(0, keyLength));
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /// Write [value] as a little-endian uint32 at [offset] in [buf].
  static void _store32(Uint8List buf, int offset, int value) {
    buf[offset] = value & 0xff;
    buf[offset + 1] = (value >> 8) & 0xff;
    buf[offset + 2] = (value >> 16) & 0xff;
    buf[offset + 3] = (value >> 24) & 0xff;
  }
}
