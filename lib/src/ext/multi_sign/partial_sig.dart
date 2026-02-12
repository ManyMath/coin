import 'dart:typed_data';

import '../../core/bytes.dart';
import '../../crypto/public_key.dart';
import '../../crypto/soft/ec_math.dart';
import '../../crypto/vault_keeper.dart';
import '../../hash/tagged.dart';
import 'aggregated_key.dart';
import 'nonce_session.dart';

/// One participant's partial signature in a MuSig2 session.
class PartialSig {
  final PublicKey signerKey;
  final Uint8List partialS;

  const PartialSig({
    required this.signerKey,
    required this.partialS,
  });

  /// BIP-327 Sign:
  /// 1. Aggregate nonces -> R, compute coefficient b.
  /// 2. e = H("BIP0340/challenge", R_x || Q_x || msg) mod n.
  /// 3. k = k1 + b*k2 (mod n); negate if R has odd y.
  /// 4. d = a * sk (mod n); negate if Q has odd y.
  /// 5. s = k + e*d (mod n).
  factory PartialSig.sign({
    required Uint8List secretKey,
    required List<Uint8List> secretNonces,
    required NonceSession session,
  }) {
    if (secretNonces.length != 2) {
      throw ArgumentError('Expected 2 secret nonces (k1, k2)');
    }

    final pubKeyBytes = VaultKeeper.vault.curve.derivePublicKey(secretKey);
    final signerPubKey = PublicKey(pubKeyBytes);

    final aggR = session.aggregateNonces();
    final rPoint = ecBytesToPoint(aggR);

    EcPoint aggR1 = EcPoint.infinity();
    EcPoint aggR2 = EcPoint.infinity();
    for (final nonce in session.nonces) {
      aggR1 = ecPointAdd(aggR1, ecBytesToPoint(nonce.r1));
      aggR2 = ecPointAdd(aggR2, ecBytesToPoint(nonce.r2));
    }
    // BIP-327 sec. GetSessionValues: noncecoef DOES include the message (b is
    // hashed over aggnonce || Q_x || msg).
    final aggR1Bytes = aggR1.isInfinity ? Uint8List(33) : ecPointToBytes(aggR1, compressed: true);
    final aggR2Bytes = aggR2.isInfinity ? Uint8List(33) : ecPointToBytes(aggR2, compressed: true);
    final bInput = concatBytes(
        [aggR1Bytes, aggR2Bytes, session.aggKey.xOnly, session.message]);
    final bHash = taggedHash('MuSig/noncecoef', bInput);
    final b = bytesToBigInt(bHash) % secp256k1N;

    // e = H("BIP0340/challenge", R_x || Q_x || msg) mod n
    final rX = bigIntToBytes(rPoint.x, 32);
    final challengeInput = concatBytes([
      rX,
      session.aggKey.xOnly,
      session.message,
    ]);
    final eHash = taggedHash('BIP0340/challenge', challengeInput);
    final e = bytesToBigInt(eHash) % secp256k1N;

    // k = k1 + b*k2; negate if R has odd y
    final k1 = bytesToBigInt(secretNonces[0]);
    final k2 = bytesToBigInt(secretNonces[1]);
    BigInt k = (k1 + b * k2) % secp256k1N;
    if (!rPoint.y.isEven) {
      k = (secp256k1N - k) % secp256k1N;
    }

    // d = a * sk; negate if Q has odd y
    final aBytes = session.aggKey.coefficient(signerPubKey);
    final a = bytesToBigInt(aBytes);
    BigInt d = (a * bytesToBigInt(secretKey)) % secp256k1N;
    if (!session.aggKey.yIsEven) {
      d = (secp256k1N - d) % secp256k1N;
    }

    // s = k + e * d (mod n)
    final s = (k + e * d) % secp256k1N;

    return PartialSig(
      signerKey: signerPubKey,
      partialS: bigIntToBytes(s, 32),
    );
  }

  /// BIP-327 PartialSigVerify: s*G == R_i + e*a_i*P_i
  bool verify(NonceSession session) {
    final aggR = session.aggregateNonces();
    final rPoint = ecBytesToPoint(aggR);

    EcPoint aggR1 = EcPoint.infinity();
    EcPoint aggR2 = EcPoint.infinity();
    for (final nonce in session.nonces) {
      aggR1 = ecPointAdd(aggR1, ecBytesToPoint(nonce.r1));
      aggR2 = ecPointAdd(aggR2, ecBytesToPoint(nonce.r2));
    }
    // BIP-327 sec. GetSessionValues: noncecoef DOES include the message (b is
    // hashed over aggnonce || Q_x || msg).
    final vR1Bytes = aggR1.isInfinity ? Uint8List(33) : ecPointToBytes(aggR1, compressed: true);
    final vR2Bytes = aggR2.isInfinity ? Uint8List(33) : ecPointToBytes(aggR2, compressed: true);
    final bInput = concatBytes(
        [vR1Bytes, vR2Bytes, session.aggKey.xOnly, session.message]);
    final bHash = taggedHash('MuSig/noncecoef', bInput);
    final b = bytesToBigInt(bHash) % secp256k1N;

    final rX = bigIntToBytes(rPoint.x, 32);
    final challengeInput = concatBytes([
      rX,
      session.aggKey.xOnly,
      session.message,
    ]);
    final eHash = taggedHash('BIP0340/challenge', challengeInput);
    final e = bytesToBigInt(eHash) % secp256k1N;

    NoncePair? signerNonce;
    final signerIdx = session.aggKey.publicKeys.indexWhere(
        (pk) => bytesEqual(pk.bytes, signerKey.bytes));
    if (signerIdx >= 0 && signerIdx < session.nonces.length) {
      signerNonce = session.nonces[signerIdx];
    }
    if (signerNonce == null) {
      return false; // signer not found in session
    }

    // R_i = R1_i + b * R2_i
    final r1i = ecBytesToPoint(signerNonce.r1);
    final r2i = ecBytesToPoint(signerNonce.r2);
    EcPoint rI = ecPointAdd(r1i, ecScalarMult(b, r2i));

    if (!rPoint.y.isEven) {
      rI = EcPoint(rI.x, (secp256k1P - rI.y) % secp256k1P);
    }

    final aBytes = session.aggKey.coefficient(signerKey);
    final a = bytesToBigInt(aBytes);
    EcPoint pi = ecBytesToPoint(signerKey.bytes);
    BigInt effectiveA = a;
    if (!session.aggKey.yIsEven) {
      effectiveA = (secp256k1N - a) % secp256k1N;
    }

    final eaPi = ecScalarMult((e * effectiveA) % secp256k1N, pi);

    // s*G == R_i + e*a_i*P_i
    final s = bytesToBigInt(partialS);
    final sG = ecScalarMult(s, secp256k1G);
    final expected = ecPointAdd(rI, eaPi);
    return sG == expected;
  }

  /// Combine partials into a BIP-340 Schnorr sig (64 bytes: R_x || s).
  /// s_final = sum(s_i) mod n.
  static Uint8List combine(
    AggregatedKey aggKey,
    NonceSession session,
    List<PartialSig> partials,
  ) {
    if (partials.isEmpty) {
      throw ArgumentError('No partial signatures to combine');
    }

    final aggR = session.aggregateNonces();
    final rPoint = ecBytesToPoint(aggR);
    final rX = bigIntToBytes(rPoint.x, 32);

    BigInt sSum = BigInt.zero;
    for (final partial in partials) {
      sSum = (sSum + bytesToBigInt(partial.partialS)) % secp256k1N;
    }

    final sig = Uint8List(64);
    sig.setRange(0, 32, rX);
    sig.setRange(32, 64, bigIntToBytes(sSum, 32));
    return sig;
  }
}
