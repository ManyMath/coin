import 'dart:typed_data';

import '../../core/bytes.dart';
import '../../core/random.dart';
import '../../crypto/soft/ec_math.dart';
import '../../crypto/vault_keeper.dart';
import '../../hash/tagged.dart';
import 'aggregated_key.dart';

/// A pair of public nonce points (33-byte compressed each).
class NoncePair {
  final Uint8List r1;
  final Uint8List r2;

  const NoncePair({required this.r1, required this.r2});
}

/// BIP-327 MuSig2 two-round nonce session: generate nonce pairs, exchange,
/// aggregate, then compute partial signatures.
class NonceSession {
  final AggregatedKey aggKey;
  final Uint8List message;
  final List<NoncePair> nonces;

  NonceSession({
    required this.aggKey,
    required this.message,
  }) : nonces = [];

  /// Generate a nonce pair per BIP-327 NonceGen.
  ///
  /// Secret nonce scalars (k1, k2) can be re-derived from the same
  /// inputs via [deriveSecretScalars].
  NoncePair generateNonce(Uint8List secretKey) {
    // BIP-327 NonceGen:
    // rand' = H("MuSig/nonce", rand || sk || pk || aggpk || msg)
    // k1 = int(H("MuSig/aux", rand')) mod n
    // k2 = int(H("MuSig/aux", rand' || 0x01)) mod n
    // R1 = k1*G, R2 = k2*G

    final rand = generateSecureBytes(32);
    final pk = VaultKeeper.vault.curve.derivePublicKey(secretKey);

    final auxInput = concatBytes([
      rand,
      secretKey,
      pk,
      aggKey.xOnly,
      message,
    ]);
    final randPrime = taggedHash('MuSig/nonce', auxInput);

    final k1Hash = taggedHash('MuSig/aux', randPrime);
    final k1 = bytesToBigInt(k1Hash) % secp256k1N;
    if (k1 == BigInt.zero) {
      throw StateError('Nonce generation produced zero k1');
    }

    final k2Input = concatBytes([randPrime, Uint8List.fromList([0x01])]);
    final k2Hash = taggedHash('MuSig/aux', k2Input);
    final k2 = bytesToBigInt(k2Hash) % secp256k1N;
    if (k2 == BigInt.zero) {
      throw StateError('Nonce generation produced zero k2');
    }

    final r1Point = ecScalarMult(k1, secp256k1G);
    final r2Point = ecScalarMult(k2, secp256k1G);

    return NoncePair(
      r1: ecPointToBytes(r1Point, compressed: true),
      r2: ecPointToBytes(r2Point, compressed: true),
    );
  }

  static List<BigInt> deriveSecretScalars(
    Uint8List rand,
    Uint8List secretKey,
    Uint8List compressedPubKey,
    Uint8List aggXOnly,
    Uint8List message,
  ) {
    final auxInput = concatBytes([
      rand,
      secretKey,
      compressedPubKey,
      aggXOnly,
      message,
    ]);
    final randPrime = taggedHash('MuSig/nonce', auxInput);

    final k1Hash = taggedHash('MuSig/aux', randPrime);
    final k1 = bytesToBigInt(k1Hash) % secp256k1N;

    final k2Input = concatBytes([randPrime, Uint8List.fromList([0x01])]);
    final k2Hash = taggedHash('MuSig/aux', k2Input);
    final k2 = bytesToBigInt(k2Hash) % secp256k1N;

    return [k1, k2];
  }

  void addNonce(NoncePair nonce) {
    nonces.add(nonce);
  }

  /// BIP-327 NonceAgg: sum each participant's R1 and R2, then
  /// b = H("MuSig/noncecoef", R1_agg || R2_agg || Q_x || msg) mod n,
  /// R = R1_agg + b*R2_agg (or G if R = infinity). Returns 33-byte compressed R.
  ///
  /// Per BIP-327 sec. GetSessionValues the noncecoef hash input is
  /// aggnonce (R1_agg || R2_agg) || x-only aggregate key || message - the message
  /// IS included (its omission was the cause of the non-empty-message vector
  /// failures). infinity is serialised as 33 zero bytes in the hash input and, if the
  /// final R is infinity, it is replaced by the generator G.
  Uint8List aggregateNonces() {
    if (nonces.isEmpty) {
      throw StateError('No nonces have been collected');
    }

    EcPoint aggR1 = EcPoint.infinity();
    EcPoint aggR2 = EcPoint.infinity();

    for (final nonce in nonces) {
      aggR1 = ecPointAdd(aggR1, ecBytesToPoint(nonce.r1));
      aggR2 = ecPointAdd(aggR2, ecBytesToPoint(nonce.r2));
    }

    // Serialise infinity as 33 zero bytes per BIP-327.
    final aggR1Bytes = aggR1.isInfinity
        ? Uint8List(33)
        : ecPointToBytes(aggR1, compressed: true);
    final aggR2Bytes = aggR2.isInfinity
        ? Uint8List(33)
        : ecPointToBytes(aggR2, compressed: true);

    final bInput =
        concatBytes([aggR1Bytes, aggR2Bytes, aggKey.xOnly, message]);
    final bHash = taggedHash('MuSig/noncecoef', bInput);
    final b = bytesToBigInt(bHash) % secp256k1N;

    // R = R1 + b*R2; if R = infinity use G.
    EcPoint aggR;
    if (aggR1.isInfinity && aggR2.isInfinity) {
      aggR = secp256k1G;
    } else if (aggR2.isInfinity) {
      aggR = aggR1.isInfinity ? secp256k1G : aggR1;
    } else {
      final bR2 = ecScalarMult(b, aggR2);
      final candidate = aggR1.isInfinity ? bR2 : ecPointAdd(aggR1, bR2);
      aggR = candidate.isInfinity ? secp256k1G : candidate;
    }

    return ecPointToBytes(aggR, compressed: true);
  }

  bool get isComplete => nonces.length == aggKey.publicKeys.length;
}
