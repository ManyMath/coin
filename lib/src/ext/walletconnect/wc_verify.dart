import 'dart:convert';
import 'dart:typed_data';

import '../../crypto/soft/p256.dart';
import '../../hash/digest.dart';

/// WalletConnect Verify API (R26): verify the ES256 attestation JWT the relay
/// attaches to a delivery (`WcRelayMessage.attestation`) against the Verify
/// service's P-256 public key, decode its claims, and compare the attested
/// origin to the peer's declared origin - yielding VALID / INVALID / SCAM.
///
/// The ES256 verification rides coin's in-house [P256]; the public-key fetch is
/// injected (a [WcHttpGet]) so this layer stays web-safe and node-agnostic, the
/// same pattern as `WcAuth`'s `WcEthCall`. The default endpoints match reown's
/// (`verify.walletconnect.org`).

/// An HTTP GET returning the response body as text, injected so the verify
/// client makes no assumption about the HTTP stack (wire it to `dart:io`,
/// `package:http`, a browser fetch, ...).
typedef WcHttpGet = Future<String> Function(String url);

/// The result of validating an attestation against a declared origin.
enum WcVerifyStatus {
  /// Signature valid and the attested origin matches the peer's.
  valid,

  /// Signature invalid, or the attested origin does not match.
  invalid,

  /// The Verify service flagged the origin as a known scam.
  scam,

  /// No attestation present / could not be evaluated.
  unknown,
}

/// The decoded claims of a Verify attestation JWT.
class WcAttestationClaims {
  final String? origin;
  final bool? isScam;
  final bool? isVerified;
  final int? exp;
  final String? id;

  WcAttestationClaims({
    this.origin,
    this.isScam,
    this.isVerified,
    this.exp,
    this.id,
  });

  factory WcAttestationClaims.fromJson(Map<String, dynamic> j) =>
      WcAttestationClaims(
        origin: j['origin'] as String?,
        isScam: j['isScam'] as bool?,
        isVerified: j['isVerified'] as bool?,
        exp: (j['exp'] as num?)?.toInt(),
        id: j['id'] as String?,
      );
}

/// The Verify service's ES256 public key (a JWK), plus its `expiresAt`.
class WcVerifyKey {
  final BigInt qx;
  final BigInt qy;
  final int? expiresAt;

  WcVerifyKey({required this.qx, required this.qy, this.expiresAt});

  /// Parse the `/v2/public-key` response: `{publicKey: {crv,x,y,...}, expiresAt}`.
  factory WcVerifyKey.fromPublicKeyJson(Map<String, dynamic> j) {
    final pk = (j['publicKey'] as Map).cast<String, dynamic>();
    final (qx, qy) =
        P256.pointFromJwk(pk['x'] as String, pk['y'] as String);
    return WcVerifyKey(
        qx: qx, qy: qy, expiresAt: (j['expiresAt'] as num?)?.toInt());
  }
}

/// Stateless Verify helpers: JWT shape, ES256 verification, claim decoding, and
/// the origin/scam decision.
class WcVerify {
  WcVerify._();

  static const defaultPublicKeyUrl =
      'https://verify.walletconnect.org/v2/public-key';

  static String _normalizeB64(String s) =>
      s.padRight((s.length + 3) ~/ 4 * 4, '=');

  /// Decode an attestation JWT's claims (its middle segment) without verifying.
  static WcAttestationClaims decodeClaims(String jwt) {
    final parts = jwt.split('.');
    if (parts.length != 3) {
      throw FormatException('not a JWT: expected 3 segments');
    }
    final json = utf8.decode(base64Url.decode(_normalizeB64(parts[1])));
    return WcAttestationClaims.fromJson(
        (jsonDecode(json) as Map).cast<String, dynamic>());
  }

  /// Verify an ES256 [jwt]'s signature against the Verify key ([qx], [qy]):
  /// P-256 ECDSA over SHA-256(`header.claims`), the 64-byte `r||s` signature.
  /// Returns false on any malformation - never throws.
  static bool verifyJwt(String jwt, {required BigInt qx, required BigInt qy}) {
    try {
      final parts = jwt.split('.');
      if (parts.length != 3) return false;
      final sig = base64Url.decode(_normalizeB64(parts[2]));
      if (sig.length != 64) return false;
      final signed =
          Uint8List.fromList(utf8.encode('${parts[0]}.${parts[1]}'));
      final hash = sha256(signed);
      return P256.verifyRaw(
        hash: hash,
        r: Uint8List.fromList(sig.sublist(0, 32)),
        s: Uint8List.fromList(sig.sublist(32)),
        qx: qx,
        qy: qy,
      );
    } catch (_) {
      return false;
    }
  }

  /// Decide the validation status for already-decoded [claims] against the
  /// peer's declared [origin]: SCAM if flagged, VALID if the origins match,
  /// otherwise INVALID. (Signature validity is assumed already checked.)
  static WcVerifyStatus statusForClaims(
    WcAttestationClaims claims, {
    required String origin,
  }) {
    if (claims.isScam == true) return WcVerifyStatus.scam;
    return claims.origin == origin
        ? WcVerifyStatus.valid
        : WcVerifyStatus.invalid;
  }

  /// Verify [jwt] against ([qx], [qy]) and, if valid, decide its status against
  /// the declared [origin]. INVALID on a bad signature.
  static WcVerifyStatus validate(
    String jwt, {
    required BigInt qx,
    required BigInt qy,
    required String origin,
  }) {
    if (!verifyJwt(jwt, qx: qx, qy: qy)) return WcVerifyStatus.invalid;
    return statusForClaims(decodeClaims(jwt), origin: origin);
  }
}

/// A Verify client that fetches and caches the service public key (until its
/// `expiresAt`) via an injected [WcHttpGet], then validates attestations.
class WcVerifyClient {
  final WcHttpGet httpGet;
  final String publicKeyUrl;

  WcVerifyKey? _cachedKey;

  WcVerifyClient(
    this.httpGet, {
    this.publicKeyUrl = WcVerify.defaultPublicKeyUrl,
  });

  /// The current public key, fetched (and cached) on first use and refetched
  /// once the cached one is past its `expiresAt`. [nowSeconds] overrides the
  /// clock for testing.
  Future<WcVerifyKey> publicKey({int? nowSeconds}) async {
    final now =
        nowSeconds ?? (DateTime.now().millisecondsSinceEpoch ~/ 1000);
    final cached = _cachedKey;
    if (cached != null &&
        (cached.expiresAt == null || cached.expiresAt! > now)) {
      return cached;
    }
    final body = await httpGet(publicKeyUrl);
    final key = WcVerifyKey.fromPublicKeyJson(
        (jsonDecode(body) as Map).cast<String, dynamic>());
    _cachedKey = key;
    return key;
  }

  /// Fetch/cache the key, verify [attestationJwt], and return its status against
  /// the peer's declared [origin].
  Future<WcVerifyStatus> getValidation(
    String attestationJwt, {
    required String origin,
    int? nowSeconds,
  }) async {
    final key = await publicKey(nowSeconds: nowSeconds);
    return WcVerify.validate(attestationJwt,
        qx: key.qx, qy: key.qy, origin: origin);
  }
}
