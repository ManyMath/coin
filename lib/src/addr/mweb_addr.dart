import 'dart:typed_data';

import '../chain/chain.dart';
import '../crypto/vault_keeper.dart';

/// A Litecoin MWEB ("Mimblewimble Extension Block") stealth address.
///
/// Slice A scope: this is a STANDALONE parser/encoder. It deliberately does
/// NOT implement the [Addr] interface and is NOT routed through [SegwitAddr]:
///
/// - The [Addr] contract (`toLocking()` / `scriptPubKey`) is meaningless for
///   an MWEB address, which has no canonical-chain script.
/// - [SegwitAddr] hard-rejects anything but a 20/32-byte witness program at
///   version 0, whereas a real `ltcmweb1...` address carries a ~66-byte payload
///   (a scan pubkey + a spend pubkey).
///
/// The encoding matches Litecoin Core's MWEB address codec: plain bech32 (NOT
/// bech32m) over a 5-bit data part whose FIRST group is a witness-version
/// byte fixed at `0`; the remaining groups ConvertBits<5,8,false> to exactly
/// 66 payload bytes (a 33-byte scan pubkey followed by a 33-byte spend
/// pubkey, both compressed secp256k1). There is no 20/32-byte segwit length
/// cap. We do NOT validate that the payload is a legitimate stealth address
/// or attempt to derive the underlying scan/spend pubkey pair - that is
/// `mwebd`'s job.
class MwebAddr {
  /// The human-readable prefix (e.g. `ltcmweb`, `tmweb`).
  final String hrp;

  /// The decoded raw payload bytes (8-bit). For real MWEB addresses this is
  /// ~66 bytes (scan + spend compressed pubkeys).
  final Uint8List payload;

  MwebAddr({required this.hrp, required this.payload});

  /// Parse [s] as an MWEB address for [chain]. The HRP must match
  /// [chain.mwebHrp]. Throws [FormatException] on HRP mismatch, mixed case,
  /// bad characters, or checksum failure.
  factory MwebAddr.fromString(String s, Chain chain) {
    final expectedHrp = chain.mwebHrp;
    if (expectedHrp == null) {
      throw FormatException('Chain does not support MWEB addresses');
    }
    final (hrp, data) = _bech32DecodeRaw(s);
    if (hrp != expectedHrp) {
      throw FormatException('MWEB HRP mismatch: expected $expectedHrp, got $hrp');
    }
    return MwebAddr(hrp: hrp, payload: data);
  }

  /// Encode the [payload] as an MWEB address using [chain.mwebHrp]. Provided
  /// primarily for round-trip testing; in production MWEB addresses come from
  /// `mwebd`.
  String encode(Chain chain) {
    final hrpToUse = chain.mwebHrp;
    if (hrpToUse == null) {
      throw FormatException('Chain does not support MWEB addresses');
    }
    return _bech32EncodeRaw(hrpToUse, payload);
  }

  // --- Standalone bech32 (raw payload, no witness-version byte) ---

  static const _charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  static const _bech32Const = 1; // bech32 (not bech32m)

  static String _bech32EncodeRaw(String hrp, Uint8List data) {
    // 8-bit payload -> 5-bit groups, then PREPEND the witness-version byte (0)
    // as the leading 5-bit group, matching Litecoin Core's MWEB encoding.
    final converted = VaultKeeper.vault.codec.convertBits(data, 8, 5);
    final values = Uint8List(1 + converted.length);
    values[0] = 0; // witness version 0
    values.setRange(1, values.length, converted);
    final checksum = _checksum(hrp, values);
    final buf = StringBuffer('${hrp}1');
    for (final v in values) {
      buf.write(_charset[v]);
    }
    for (final v in checksum) {
      buf.write(_charset[v]);
    }
    return buf.toString();
  }

  static (String hrp, Uint8List payload) _bech32DecodeRaw(String encoded) {
    // BIP-173: mixed-case strings are invalid.
    if (encoded != encoded.toLowerCase() &&
        encoded != encoded.toUpperCase()) {
      throw FormatException('Bech32 mixed case');
    }
    final lower = encoded.toLowerCase();
    final sepIdx = lower.lastIndexOf('1');
    if (sepIdx < 1) throw FormatException('No separator in bech32');
    final hrp = lower.substring(0, sepIdx);
    final dataStr = lower.substring(sepIdx + 1);
    if (dataStr.length < 6) throw FormatException('Bech32 data too short');

    final values = Uint8List(dataStr.length);
    for (var i = 0; i < dataStr.length; i++) {
      final idx = _charset.indexOf(dataStr[i]);
      if (idx < 0) throw FormatException('Invalid bech32 character: ${dataStr[i]}');
      values[i] = idx;
    }

    final dataPart = Uint8List.sublistView(values, 0, values.length - 6);
    final checksum = Uint8List.sublistView(values, values.length - 6);
    final expected = _checksum(hrp, dataPart);
    for (var i = 0; i < 6; i++) {
      if (checksum[i] != expected[i]) {
        throw FormatException('Bech32 checksum mismatch');
      }
    }

    // Litecoin Core MWEB decode: the first 5-bit group is a witness-version
    // byte that must be 0; ConvertBits<5,8,false> the remainder to 8-bit
    // bytes. (For a 66-byte stealth address there is no segwit length cap.)
    if (dataPart.isEmpty) throw FormatException('MWEB address has no data');
    final version = dataPart[0];
    if (version != 0) {
      throw FormatException('MWEB witness version must be 0, got $version');
    }
    final program = Uint8List.sublistView(dataPart, 1);
    final payload =
        VaultKeeper.vault.codec.convertBits(program, 5, 8, pad: false);
    return (hrp, payload);
  }

  static Uint8List _checksum(String hrp, Uint8List data) {
    final values = <int>[
      ..._hrpExpand(hrp),
      ...data,
      0, 0, 0, 0, 0, 0,
    ];
    final polymod = _polymod(values) ^ _bech32Const;
    final result = Uint8List(6);
    for (var i = 0; i < 6; i++) {
      result[i] = (polymod >> (5 * (5 - i))) & 31;
    }
    return result;
  }

  static List<int> _hrpExpand(String hrp) {
    final result = <int>[];
    for (final c in hrp.codeUnits) {
      result.add(c >> 5);
    }
    result.add(0);
    for (final c in hrp.codeUnits) {
      result.add(c & 31);
    }
    return result;
  }

  static int _polymod(List<int> values) {
    const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var chk = 1;
    for (final v in values) {
      final b = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (var i = 0; i < 5; i++) {
        if (((b >> i) & 1) != 0) {
          chk ^= gen[i];
        }
      }
    }
    return chk;
  }
}
