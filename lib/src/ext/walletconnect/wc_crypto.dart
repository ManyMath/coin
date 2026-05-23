import 'dart:convert';
import 'dart:typed_data';

import '../../core/hex.dart';
import '../../crypto/soft/chacha20_poly1305.dart';
import '../../crypto/soft/x25519.dart';
import '../../hash/digest.dart';
import '../../hash/hkdf.dart';

/// WalletConnect v2 transport crypto (Reown / WC v2 wire format).
///
/// Pipeline: X25519 ECDH -> HKDF-SHA256 -> symKey -> SHA-256 topic ->
/// ChaCha20-Poly1305 AEAD envelopes (type 0 / type 1), base64-encoded.
///
/// Matches the reown_core / wallet_connect_dart_v2 test fixtures.

/// Parsed WC v2 envelope.
class WcEnvelope {
  final int type;
  final Uint8List? senderPublicKey; // type 1 only, 32 bytes
  final Uint8List iv; // 12 bytes
  final Uint8List sealed; // ciphertext || poly1305 tag

  WcEnvelope({
    required this.type,
    required this.senderPublicKey,
    required this.iv,
    required this.sealed,
  });
}

const int _ivLength = 12;
const int _keyLength = 32;

/// Derive the shared symmetric key from our private key and the peer public key.
/// Returns the 32-byte symKey as hex. symKey = HKDF-SHA256(X25519(priv, pub)).
String wcDeriveSymKey(String privKeyHex, String pubKeyHex) {
  final shared = x25519(hexDecode(privKeyHex), hexDecode(pubKeyHex));
  final sym = hkdfSha256(shared, length: _keyLength);
  return hexEncode(sym);
}

/// topic = SHA-256(symKey-bytes), as hex. Also used to hash any hex key.
String wcHashKey(String keyHex) => hexEncode(sha256(hexDecode(keyHex)));

/// SHA-256 of a UTF-8 message, as hex (WC `hashMessage`).
String wcHashMessage(String message) =>
    hexEncode(sha256(Uint8List.fromList(utf8.encode(message))));

/// Convenience alias: the pairing/session topic is SHA-256 of the symKey.
String wcTopicFromSymKey(String symKeyHex) => wcHashKey(symKeyHex);

/// Encrypt [message] into a base64 WC envelope.
///
/// type 0: base64( 0x00 || iv(12) || ciphertext || tag )
/// type 1: base64( 0x01 || senderPublicKey(32) || iv(12) || ciphertext || tag )
String wcEncrypt({
  required String message,
  required String symKeyHex,
  int type = 0,
  required Uint8List iv,
  String? senderPublicKeyHex,
}) {
  if (iv.length != _ivLength) {
    throw ArgumentError('iv must be $_ivLength bytes');
  }
  if (type == 1 && senderPublicKeyHex == null) {
    throw ArgumentError('type 1 envelope requires senderPublicKey');
  }
  final ct = chacha20Poly1305Encrypt(
    key32: hexDecode(symKeyHex),
    nonce12: iv,
    plaintext: Uint8List.fromList(utf8.encode(message)),
  );

  final out = <int>[type];
  if (type == 1) {
    final pub = hexDecode(senderPublicKeyHex!);
    if (pub.length != _keyLength) {
      throw ArgumentError('senderPublicKey must be $_keyLength bytes');
    }
    out.addAll(pub);
  }
  out.addAll(iv);
  out.addAll(ct);
  return base64.encode(out);
}

/// Encode a type-2 (link-mode) envelope: `base64url( 0x02 || plaintext )`.
///
/// Type-2 envelopes are NOT encrypted - they carry the JSON-RPC plaintext for
/// out-of-band (deep-link / universal-link) delivery, where the OS link routing
/// is the trust boundary rather than the relay symKey.
String wcEncodeType2({required String message}) {
  final out = <int>[2, ...utf8.encode(message)];
  return base64Url.encode(out);
}

/// Decode a type-2 (link-mode) envelope back to its plaintext message.
/// Tolerates URL-safe alphabet and missing padding (deep links may strip it).
String wcDecodeType2(String encoded) {
  final urlSafe = encoded.replaceAll('+', '-').replaceAll('/', '_');
  final bytes = base64Url.decode(_padBase64(urlSafe));
  if (bytes.isEmpty || bytes[0] != 2) {
    throw ArgumentError('not a type-2 envelope');
  }
  return utf8.decode(bytes.sublist(1));
}

/// Parse a base64 WC envelope into its components.
WcEnvelope wcDeserialize(String encoded) {
  final bytes = base64.decode(_padBase64(encoded));
  final type = bytes[0];
  var index = 1;
  Uint8List? senderPublicKey;
  if (type == 1) {
    senderPublicKey =
        Uint8List.fromList(bytes.sublist(index, index + _keyLength));
    index += _keyLength;
  }
  final iv = Uint8List.fromList(bytes.sublist(index, index + _ivLength));
  final sealed = Uint8List.fromList(bytes.sublist(index + _ivLength));
  return WcEnvelope(
    type: type,
    senderPublicKey: senderPublicKey,
    iv: iv,
    sealed: sealed,
  );
}

/// Decrypt a base64 WC envelope, returning the plaintext message.
String wcDecrypt({required String symKeyHex, required String encoded}) {
  final env = wcDeserialize(encoded);
  final pt = chacha20Poly1305Decrypt(
    key32: hexDecode(symKeyHex),
    nonce12: env.iv,
    ciphertextWithTag: env.sealed,
  );
  return utf8.decode(pt);
}

String _padBase64(String s) {
  final rem = s.length % 4;
  if (rem == 0) return s;
  return s + ('=' * (4 - rem));
}
