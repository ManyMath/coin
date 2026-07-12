import 'dart:math';
import 'dart:typed_data';

import '_polyseed_birthday.dart';
import '_polyseed_data.dart';
import '_polyseed_features.dart';

/// GF(2048) Reed-Solomon polynomial arithmetic for polyseed.
///
/// The field is GF(2)[x]/(p(x)) where the irreducible polynomial p(x) is
/// encoded in [_mul2Table]. Coefficients are 11-bit words (values 0-2047).
/// The codeword is 16 words: 1 checksum word + 15 data words.
class GFPoly {
  static const int numberOfWords = 16;
  static const int _numberOfCheckDigits = 1;
  static const int _dataWords = numberOfWords - _numberOfCheckDigits; // 15

  static const int _bits = 11; // bits per coefficient
  static const int size = 1 << _bits; // 2048  -  alphabet size
  static const int bitMask = size - 1; // 0x7ff

  // 150 secret bits packed into 15 data words at 10 bits each.
  static const int secretSize = 19; // ceil(150 / 8)
  static const int _secretBits = 150;
  static const int _shareBits = 10; // secret bits per word
  static const int _secretBufferSize = 32;
  static const int _charBit = 8;

  // Multiplication-by-2 lookup for elements >= 1024 in GF(2048).
  // Encodes reduction mod the field polynomial evaluated at the high bit.
  static const List<int> _mul2Table = [5, 7, 1, 3, 13, 15, 9, 11];

  List<int> coefficients = Uint16List(numberOfWords);

  GFPoly();

  /// Populate coefficients from [data], optionally forcing [checksum] into
  /// coefficient[0] (used for encode/check roundtrips).
  GFPoly.fromPolyseedData(PolyseedData data, {int? checksum}) {
    if (checksum != null) coefficients[0] = checksum;

    // Extra bits: 5 feature bits (high) | 10 birthday bits (low) = 15 bits.
    final extraVal =
        (data.features << PolyseedBirthday.dateBits) | data.birthday;
    var extraBits = PolyseedFeatures.featureBits + PolyseedBirthday.dateBits;

    var secretIdx = 0;
    var secretVal = data.secret[secretIdx];
    var secretBits = _charBit;
    var seedRemBits = _secretBits - _charBit;

    for (var i = 0; i < _dataWords; ++i) {
      var wordBits = 0;
      var wordVal = 0;
      while (wordBits < _shareBits) {
        if (secretBits == 0) {
          secretIdx++;
          secretBits = min(seedRemBits, _charBit);
          secretVal = data.secret[secretIdx];
          seedRemBits -= secretBits;
        }

        final chunkBits = min(secretBits, _shareBits - wordBits);
        secretBits -= chunkBits;
        wordBits += chunkBits;
        wordVal <<= chunkBits;
        wordVal |= (secretVal >> secretBits) & ((1 << chunkBits) - 1);
      }
      // Append one extra bit (the LSB of each coefficient encodes extra data).
      wordVal <<= 1;
      extraBits--;
      wordVal |= (extraVal >> extraBits) & 1;
      coefficients[_numberOfCheckDigits + i] = wordVal;
    }

    assert(seedRemBits == 0);
    assert(secretBits == 0);
    assert(extraBits == 0);
  }

  /// True iff this is a valid codeword (polynomial evaluates to 0 at alpha=2).
  bool check() => eval() == 0;

  /// Evaluate the polynomial at alpha=2 using Horner's method in GF(2048).
  int eval() {
    var result = coefficients[numberOfWords - 1];
    for (var i = numberOfWords - 2; i >= 0; --i) {
      result = _elemMul2(result) ^ coefficients[i];
    }
    return result;
  }

  /// Multiply element [x] by 2 (i.e., by alpha) in GF(2048).
  int _elemMul2(int x) {
    if (x < 1024) return 2 * x;
    return _mul2Table[x % 8] + 16 * ((x - 1024) ~/ 8);
  }

  /// Set coefficients[0] so the polynomial is a valid codeword.
  void encode() => coefficients[0] = eval();

  /// XOR coefficients[1] with [value] to domain-separate by coin.
  void finalize(int value) => coefficients[_numberOfCheckDigits] ^= value;

  /// Unpack coefficients into a [PolyseedData] instance.
  PolyseedData toPolyseedData() {
    final secret = Uint8List(_secretBufferSize);
    final checksum = coefficients[0];

    var extraVal = 0;
    var extraBits = 0;
    var wordBits = 0;
    var wordVal = 0;
    var secretIdx = 0;
    var secretBits = 0;
    var seedBits = 0;

    for (int i = _numberOfCheckDigits; i < numberOfWords; ++i) {
      wordVal = coefficients[i];

      // LSB encodes one extra bit (birthday/features).
      extraVal <<= 1;
      extraVal |= wordVal & 1;
      wordVal >>= 1;
      wordBits = _bits - 1; // 10 secret bits remain
      extraBits++;

      while (wordBits > 0) {
        if (secretBits == _charBit) {
          secretIdx++;
          seedBits += secretBits;
          secretBits = 0;
        }

        final chunkBits = min(wordBits, _charBit - secretBits);
        wordBits -= chunkBits;
        final chunkMask = (1 << chunkBits) - 1;
        if (chunkBits < _charBit) {
          secret[secretIdx] <<= chunkBits;
        }
        secret[secretIdx] |= (wordVal >> wordBits) & chunkMask;
        secretBits += chunkBits;
      }
    }

    seedBits += secretBits;

    assert(wordBits == 0);
    assert(seedBits == _secretBits);
    assert(
        extraBits == PolyseedFeatures.featureBits + PolyseedBirthday.dateBits);

    return PolyseedData(
      birthday: extraVal & PolyseedBirthday.dateBitMask,
      features: extraVal >> PolyseedBirthday.dateBits,
      secret: secret,
      checksum: checksum,
    );
  }
}
