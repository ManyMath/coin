import 'dart:convert';
import 'dart:typed_data';

import '../../core/hex.dart';
import '../../hash/hmac.dart';
import '../../crypto/soft/aes.dart';

/// WalletConnect v1 transport crypto.
///
/// Scheme: AES-256-CBC (PKCS7) for the payload, HMAC-SHA256 over
/// `ciphertext || iv` (that order) using the same 32-byte key. The wire payload
/// is `{data: hex(ciphertext), hmac: hex(mac), iv: hex(iv)}`.
///
/// WC v1 is a dead protocol (public bridges offline since 2023); this is
/// provided for legacy/self-hosted interop. Matches walletconnect_dart's
/// cipher fixtures.

class WcV1Payload {
  final String data; // hex(ciphertext)
  final String hmac; // hex(mac)
  final String iv; // hex(iv)

  const WcV1Payload({required this.data, required this.hmac, required this.iv});

  Map<String, String> toJson() => {'data': data, 'hmac': hmac, 'iv': iv};

  factory WcV1Payload.fromJson(Map<String, dynamic> j) => WcV1Payload(
        data: j['data'] as String,
        hmac: j['hmac'] as String,
        iv: j['iv'] as String,
      );
}

/// Encrypt [plaintext] (a UTF-8 string, typically JSON) under [key32].
WcV1Payload wcV1Encrypt({
  required Uint8List key32,
  required Uint8List iv16,
  required String plaintext,
}) {
  final ct = aes256CbcEncrypt(
    key32,
    iv16,
    Uint8List.fromList(utf8.encode(plaintext)),
  );
  final mac = hmacSha256(key32, _concat(ct, iv16));
  return WcV1Payload(
    data: hexEncode(ct),
    hmac: hexEncode(mac),
    iv: hexEncode(iv16),
  );
}

/// Verify the HMAC of a payload (over `ciphertext || iv`).
bool wcV1VerifyHmac(WcV1Payload payload, Uint8List key32) {
  final ct = hexDecode(payload.data);
  final iv = hexDecode(payload.iv);
  final mac = hmacSha256(key32, _concat(ct, iv));
  return _constantTimeEquals(hexEncode(mac), payload.hmac);
}

/// Verify HMAC then AES-256-CBC decrypt, returning the UTF-8 plaintext.
String wcV1Decrypt(WcV1Payload payload, Uint8List key32) {
  if (!wcV1VerifyHmac(payload, key32)) {
    throw FormatException('WC v1: invalid HMAC');
  }
  final pt = aes256CbcDecrypt(
    key32,
    hexDecode(payload.iv),
    hexDecode(payload.data),
  );
  return utf8.decode(pt);
}

Uint8List _concat(Uint8List a, Uint8List b) {
  final out = Uint8List(a.length + b.length);
  out.setAll(0, a);
  out.setAll(a.length, b);
  return out;
}

bool _constantTimeEquals(String a, String b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
  }
  return diff == 0;
}
