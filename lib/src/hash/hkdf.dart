import 'dart:typed_data';

import 'hmac.dart';

/// HKDF-SHA256 (RFC 5869).
///
/// [salt] defaults to a zero-filled block of HashLen (32) bytes when null or
/// empty, matching the RFC. [info] defaults to empty.
Uint8List hkdfSha256(
  Uint8List ikm, {
  Uint8List? salt,
  Uint8List? info,
  required int length,
}) {
  final usedSalt =
      (salt == null || salt.isEmpty) ? Uint8List(32) : salt;
  final usedInfo = info ?? Uint8List(0);

  // Extract.
  final prk = hmacSha256(usedSalt, ikm);

  // Expand.
  final out = Uint8List(length);
  var written = 0;
  var counter = 1;
  var prev = Uint8List(0);
  while (written < length) {
    final input = Uint8List(prev.length + usedInfo.length + 1);
    input.setAll(0, prev);
    input.setAll(prev.length, usedInfo);
    input[input.length - 1] = counter;
    final block = hmacSha256(prk, input);
    final take = (length - written) < block.length
        ? (length - written)
        : block.length;
    out.setRange(written, written + take, block);
    written += take;
    prev = block;
    counter++;
  }
  return out;
}
