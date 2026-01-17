import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/digests/ripemd160.dart' as pc;

import '../gates/digest_gate.dart';
import 'keccak_sponge.dart';

class SoftDigestGate implements DigestGate {
  final Map<String, Uint8List> _tagCache = {};

  @override
  Uint8List sha256(Uint8List data) =>
      Uint8List.fromList(crypto.sha256.convert(data).bytes);

  @override
  Uint8List sha512(Uint8List data) =>
      Uint8List.fromList(crypto.sha512.convert(data).bytes);

  @override
  Uint8List sha256d(Uint8List data) => sha256(sha256(data));

  @override
  Uint8List ripemd160(Uint8List data) {
    final digest = pc.RIPEMD160Digest();
    return digest.process(data);
  }

  @override
  Uint8List hash160(Uint8List data) => ripemd160(sha256(data));

  @override
  Uint8List keccak256(Uint8List data) => keccakDigest(data);

  @override
  Uint8List hmacSha512(Uint8List key, Uint8List data) {
    final hmac = crypto.Hmac(crypto.sha512, key);
    return Uint8List.fromList(hmac.convert(data).bytes);
  }

  @override
  Uint8List hmacSha256(Uint8List key, Uint8List data) {
    final hmac = crypto.Hmac(crypto.sha256, key);
    return Uint8List.fromList(hmac.convert(data).bytes);
  }

  @override
  Uint8List taggedHash(String tag, Uint8List data) {
    final tagHash = _tagCache.putIfAbsent(tag, () => sha256(
        Uint8List.fromList(tag.codeUnits)));
    final input = Uint8List(64 + data.length);
    input.setAll(0, tagHash);
    input.setAll(32, tagHash);
    input.setAll(64, data);
    return sha256(input);
  }
}
