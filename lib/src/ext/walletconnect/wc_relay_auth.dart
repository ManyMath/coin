import 'dart:convert';
import 'dart:typed_data';

import '../../crypto/soft/ed25519_sign.dart';

/// WalletConnect v2 relay authentication (the `irn` relay JWT).
///
/// The client signs a short-lived EdDSA (Ed25519) JWT whose issuer is a
/// `did:key` encoding of its public key. Matches reown_core's
/// relay_auth_test fixtures.

const String _multicodecEd25519Header = 'z'; // multibase base58btc prefix
// multicodec varint for ed25519-pub (0xed) => 0xed 0x01
final Uint8List _ed25519PubMulticodec = Uint8List.fromList([0xed, 0x01]);

const String _base58Alphabet =
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/// Encode an Ed25519 public key as a did:key issuer string.
String wcEncodeIss(Uint8List publicKey32) {
  final payload = Uint8List(_ed25519PubMulticodec.length + publicKey32.length)
    ..setAll(0, _ed25519PubMulticodec)
    ..setAll(_ed25519PubMulticodec.length, publicKey32);
  return 'did:key:$_multicodecEd25519Header${_base58Encode(payload)}';
}

/// Decode a did:key issuer string back to the 32-byte Ed25519 public key.
Uint8List wcDecodeIss(String iss) {
  const prefix = 'did:key:';
  if (!iss.startsWith(prefix)) {
    throw FormatException('not a did:key: $iss');
  }
  final multibase = iss.substring(prefix.length);
  if (!multibase.startsWith(_multicodecEd25519Header)) {
    throw FormatException('unexpected multibase prefix');
  }
  final decoded = _base58Decode(multibase.substring(1));
  if (decoded.length < 2 ||
      decoded[0] != _ed25519PubMulticodec[0] ||
      decoded[1] != _ed25519PubMulticodec[1]) {
    throw FormatException('unexpected multicodec prefix');
  }
  return Uint8List.fromList(decoded.sublist(2));
}

/// Sign a relay-auth JWT.
///
/// [seed32] is the Ed25519 seed (the first 32 bytes of the stored secret key).
/// [iat] is the issued-at unix timestamp in seconds; [ttl] is the lifetime in
/// seconds (exp = iat + ttl). Returns the compact JWT `header.payload.sig`.
String wcSignJwt({
  required Uint8List seed32,
  required String sub,
  required String aud,
  required int iat,
  required int ttl,
}) {
  final publicKey = ed25519PublicKeyFromSeed(seed32);
  final iss = wcEncodeIss(publicKey);
  final exp = iat + ttl;

  final header = _b64Url(utf8.encode(jsonEncode({
    'alg': 'EdDSA',
    'typ': 'JWT',
  })));
  // Key order matters: iss, sub, aud, iat, exp.
  final payload = _b64Url(utf8.encode(jsonEncode({
    'iss': iss,
    'sub': sub,
    'aud': aud,
    'iat': iat,
    'exp': exp,
  })));

  final data = '$header.$payload';
  final sig = ed25519Sign(seed32, Uint8List.fromList(utf8.encode(data)));
  return '$data.${_b64Url(sig)}';
}

/// Verify a relay-auth JWT against the public key embedded in its `iss` claim.
bool wcVerifyJwt(String jwt) {
  final parts = jwt.split('.');
  if (parts.length != 3) return false;
  final data = '${parts[0]}.${parts[1]}';
  final sig = _b64UrlDecode(parts[2]);
  final payload =
      jsonDecode(utf8.decode(_b64UrlDecode(parts[1]))) as Map<String, dynamic>;
  final pub = wcDecodeIss(payload['iss'] as String);
  return ed25519Verify(pub, Uint8List.fromList(utf8.encode(data)), sig);
}

String _b64Url(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

Uint8List _b64UrlDecode(String s) {
  final rem = s.length % 4;
  final padded = rem == 0 ? s : s + ('=' * (4 - rem));
  return base64Url.decode(padded);
}

// --- raw base58btc (no checksum) -------------------------------------------

String _base58Encode(Uint8List data) {
  var zeros = 0;
  while (zeros < data.length && data[zeros] == 0) {
    zeros++;
  }
  var num = BigInt.zero;
  for (final b in data) {
    num = num * BigInt.from(256) + BigInt.from(b);
  }
  final buf = StringBuffer();
  final base = BigInt.from(58);
  while (num > BigInt.zero) {
    final rem = (num % base).toInt();
    num = num ~/ base;
    buf.write(_base58Alphabet[rem]);
  }
  for (var i = 0; i < zeros; i++) {
    buf.write(_base58Alphabet[0]);
  }
  return buf.toString().split('').reversed.join();
}

Uint8List _base58Decode(String encoded) {
  var num = BigInt.zero;
  final base = BigInt.from(58);
  for (final c in encoded.split('')) {
    final idx = _base58Alphabet.indexOf(c);
    if (idx < 0) throw FormatException('invalid base58 char: $c');
    num = num * base + BigInt.from(idx);
  }
  final bytes = <int>[];
  while (num > BigInt.zero) {
    bytes.add((num % BigInt.from(256)).toInt());
    num = num ~/ BigInt.from(256);
  }
  var zeros = 0;
  while (zeros < encoded.length && encoded[zeros] == _base58Alphabet[0]) {
    zeros++;
  }
  final out = <int>[...List.filled(zeros, 0), ...bytes.reversed];
  return Uint8List.fromList(out);
}
