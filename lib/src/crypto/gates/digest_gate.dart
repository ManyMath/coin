import 'dart:typed_data';

abstract class DigestGate {
  Uint8List sha256(Uint8List data);
  Uint8List sha512(Uint8List data);
  Uint8List sha256d(Uint8List data);
  Uint8List ripemd160(Uint8List data);
  Uint8List hash160(Uint8List data);
  Uint8List keccak256(Uint8List data);
  Uint8List hmacSha512(Uint8List key, Uint8List data);
  Uint8List hmacSha256(Uint8List key, Uint8List data);
  Uint8List taggedHash(String tag, Uint8List data);
}
