import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;

import '../gates/curve_gate.dart';
import 'ec_math.dart';
import 'rfc6979.dart';

class SoftCurveGate extends CurveGate {
  @override
  bool isValidPrivateKey(Uint8List privKey) {
    if (privKey.length != 32) return false;
    final d = bytesToBigInt(privKey);
    return d > BigInt.zero && d < secp256k1N;
  }

  @override
  Uint8List derivePublicKey(Uint8List privKey, {bool compressed = true}) {
    final d = bytesToBigInt(privKey);
    if (d <= BigInt.zero || d >= secp256k1N) {
      throw ArgumentError('Invalid private key');
    }
    final point = ecScalarMult(d, secp256k1G);
    return ecPointToBytes(point, compressed: compressed);
  }

  @override
  Uint8List ecdsaSign(Uint8List hash32, Uint8List privKey) {
    final (sig, _) = ecdsaSignRecoverable(hash32, privKey);
    return sig;
  }

  @override
  bool ecdsaVerify(Uint8List signature, Uint8List hash32, Uint8List pubKey) {
    try {
      if (signature.length != 64 || hash32.length != 32) return false;
      final r = bytesToBigInt(signature.sublist(0, 32));
      final s = bytesToBigInt(signature.sublist(32, 64));
      final z = bytesToBigInt(hash32);

      if (r >= secp256k1N || s >= secp256k1N ||
          r == BigInt.zero || s == BigInt.zero) return false;

      final point = ecBytesToPoint(pubKey);
      if (!ecIsOnCurve(point)) return false;

      final sInv = s.modInverse(secp256k1N);
      final u1 = (z * sInv) % secp256k1N;
      final u2 = (r * sInv) % secp256k1N;

      final p1 = ecScalarMult(u1, secp256k1G);
      final p2 = ecScalarMult(u2, point);
      final result = ecPointAdd(p1, p2);

      return result.x % secp256k1N == r;
    } catch (_) {
      return false;
    }
  }

  @override
  (Uint8List, int) ecdsaSignRecoverable(Uint8List hash32, Uint8List privKey) {
    final d = bytesToBigInt(privKey);
    final z = bytesToBigInt(hash32);
    final k = generateDeterministicK(hash32, privKey);

    final point = ecScalarMult(k, secp256k1G);
    final r = point.x % secp256k1N;
    if (r == BigInt.zero) throw StateError('Invalid signature: r is zero');

    final kInv = k.modInverse(secp256k1N);
    var s = (kInv * (z + r * d)) % secp256k1N;
    if (s == BigInt.zero) throw StateError('Invalid signature: s is zero');

    var recId = point.y.isOdd ? 1 : 0;
    if (s > secp256k1HalfN) {
      s = secp256k1N - s;
      recId ^= 1;
    }

    final sig = Uint8List(64);
    sig.setRange(0, 32, bigIntToBytes(r, 32));
    sig.setRange(32, 64, bigIntToBytes(s, 32));

    return (sig, recId);
  }

  @override
  Uint8List ecdsaRecover(
      Uint8List signature, int recId, Uint8List hash32,
      {bool compressed = true}) {
    final r = bytesToBigInt(signature.sublist(0, 32));
    final s = bytesToBigInt(signature.sublist(32, 64));
    final z = bytesToBigInt(hash32);

    final x = r + (BigInt.from(recId ~/ 2) * secp256k1N);
    if (x >= secp256k1P) throw ArgumentError('Invalid recovery parameter');

    final alpha = (x * x * x + BigInt.from(7)) % secp256k1P;
    final beta = alpha.modPow((secp256k1P + BigInt.one) >> 2, secp256k1P);
    final y = (recId & 1) == 0
        ? (beta.isEven ? beta : secp256k1P - beta)
        : (beta.isOdd ? beta : secp256k1P - beta);

    final rPoint = EcPoint(x, y);
    if (!ecIsOnCurve(rPoint)) throw ArgumentError('Recovery point not on curve');

    final rInv = r.modInverse(secp256k1N);
    final e = (-z) % secp256k1N;

    final p1 = ecScalarMult(s, rPoint);
    final p2 = ecScalarMult(e, secp256k1G);
    final pubPoint = ecScalarMult(rInv, ecPointAdd(p1, p2));

    return ecPointToBytes(pubPoint, compressed: compressed);
  }

  @override
  Uint8List schnorrSign(Uint8List hash32, Uint8List privKey,
      {Uint8List? auxRand}) {
    if (hash32.length != 32) {
      throw ArgumentError('BIP-340 message must be 32 bytes');
    }
    if (!isValidPrivateKey(privKey)) {
      throw ArgumentError('Invalid private key for Schnorr signing');
    }
    if (auxRand != null && auxRand.length != 32) {
      throw ArgumentError('BIP-340 auxiliary randomness must be 32 bytes');
    }
    var d = bytesToBigInt(privKey);
    final pubPoint = ecScalarMult(d, secp256k1G);
    if (pubPoint.y.isOdd) d = secp256k1N - d;

    // BIP-340 nonce generation
    // https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing
    final dBytes = bigIntToBytes(d, 32);
    final px = bigIntToBytes(pubPoint.x, 32);
    final aux = auxRand ?? Uint8List(32);
    final tBytes = _taggedHash('BIP0340/aux', aux);
    final t = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      t[i] = dBytes[i] ^ tBytes[i];
    }
    final rand = _taggedHash(
        'BIP0340/nonce', Uint8List.fromList([...t, ...px, ...hash32]));
    var k0 = bytesToBigInt(rand) % secp256k1N;
    if (k0 == BigInt.zero) throw StateError('k is zero');

    final rPoint = ecScalarMult(k0, secp256k1G);
    final k = rPoint.y.isEven ? k0 : secp256k1N - k0;

    final rx = bigIntToBytes(rPoint.x, 32);

    final eBytes = _taggedHash('BIP0340/challenge',
        Uint8List.fromList([...rx, ...px, ...hash32]));
    final e = bytesToBigInt(eBytes) % secp256k1N;

    final s = (k + e * d) % secp256k1N;

    final sig = Uint8List(64);
    sig.setRange(0, 32, rx);
    sig.setRange(32, 64, bigIntToBytes(s, 32));
    if (!schnorrVerify(sig, hash32, px)) {
      throw StateError('Schnorr signature self-verification failed');
    }
    return sig;
  }

  @override
  bool schnorrVerify(
      Uint8List signature, Uint8List hash32, Uint8List xPubKey) {
    try {
      if (signature.length != 64 ||
          hash32.length != 32 ||
          xPubKey.length != 32) {
        return false;
      }

      final rx = bytesToBigInt(signature.sublist(0, 32));
      final s = bytesToBigInt(signature.sublist(32, 64));
      if (rx >= secp256k1P || s >= secp256k1N) return false;

      final alpha = (rx * rx * rx + BigInt.from(7)) % secp256k1P;
      final beta = alpha.modPow((secp256k1P + BigInt.one) >> 2, secp256k1P);
      if ((beta * beta - alpha) % secp256k1P != BigInt.zero) return false;

      final eBytes = _taggedHash('BIP0340/challenge',
          Uint8List.fromList([
            ...signature.sublist(0, 32), ...xPubKey, ...hash32
          ]));
      final e = bytesToBigInt(eBytes) % secp256k1N;

      final px = bytesToBigInt(xPubKey);
      if (px >= secp256k1P) return false;
      final pAlpha = (px * px * px + BigInt.from(7)) % secp256k1P;
      final pBeta = pAlpha.modPow((secp256k1P + BigInt.one) >> 2, secp256k1P);
      if ((pBeta * pBeta - pAlpha) % secp256k1P != BigInt.zero) return false;
      final py = pBeta.isEven ? pBeta : secp256k1P - pBeta;
      final pubPoint = EcPoint(px, py);

      final sG = ecScalarMult(s, secp256k1G);
      final eP = ecScalarMult(e, pubPoint);
      final negEP = EcPoint(eP.x, (secp256k1P - eP.y) % secp256k1P);
      final result = ecPointAdd(sG, negEP);

      return !result.isInfinity && result.y.isEven && result.x == rx;
    } catch (_) {
      return false;
    }
  }

  @override
  Uint8List? privateKeyTweakAdd(Uint8List privKey, Uint8List scalar) {
    final d = bytesToBigInt(privKey);
    final t = bytesToBigInt(scalar);
    final result = (d + t) % secp256k1N;
    if (result == BigInt.zero) return null;
    return bigIntToBytes(result, 32);
  }

  @override
  Uint8List? publicKeyTweakAdd(Uint8List pubKey, Uint8List scalar,
      {bool compressed = true}) {
    try {
      final point = ecBytesToPoint(pubKey);
      final tweakPoint = ecScalarMult(bytesToBigInt(scalar), secp256k1G);
      final result = ecPointAdd(point, tweakPoint);
      if (result.isInfinity) return null;
      return ecPointToBytes(result, compressed: compressed);
    } catch (_) {
      return null;
    }
  }

  @override
  Uint8List privateKeyNegate(Uint8List privKey) {
    final d = bytesToBigInt(privKey);
    return bigIntToBytes((secp256k1N - d) % secp256k1N, 32);
  }

  @override
  Uint8List ecdh(Uint8List privKey, Uint8List pubKey) {
    final point = ecBytesToPoint(pubKey);
    final d = bytesToBigInt(privKey);
    final shared = ecScalarMult(d, point);
    return bigIntToBytes(shared.x, 32);
  }

  @override
  Uint8List ecdsaCompactToDer(Uint8List compact) {
    if (compact.length != 64) throw ArgumentError('Expected 64-byte compact');
    final r = _trimLeadingZeros(compact.sublist(0, 32));
    final s = _trimLeadingZeros(compact.sublist(32, 64));
    final rEnc = _derInteger(r);
    final sEnc = _derInteger(s);
    final body = Uint8List.fromList([...rEnc, ...sEnc]);
    return Uint8List.fromList([0x30, body.length, ...body]);
  }

  @override
  Uint8List ecdsaDerToCompact(Uint8List der) {
    if (der[0] != 0x30) throw ArgumentError('Invalid DER signature');
    var pos = 2;
    if (der[pos] != 0x02) throw ArgumentError('Invalid DER R marker');
    pos++;
    final rLen = der[pos++];
    final rBytes = der.sublist(pos, pos + rLen);
    pos += rLen;
    if (der[pos] != 0x02) throw ArgumentError('Invalid DER S marker');
    pos++;
    final sLen = der[pos++];
    final sBytes = der.sublist(pos, pos + sLen);

    final out = Uint8List(64);
    final rTrimmed = _trimLeadingZeros(rBytes);
    final sTrimmed = _trimLeadingZeros(sBytes);
    out.setRange(32 - rTrimmed.length, 32, rTrimmed);
    out.setRange(64 - sTrimmed.length, 64, sTrimmed);
    return out;
  }

  @override
  Uint8List ecdsaNormalize(Uint8List signature) {
    final s = bytesToBigInt(signature.sublist(32, 64));
    if (s > secp256k1HalfN) {
      final out = Uint8List.fromList(signature);
      out.setRange(32, 64, bigIntToBytes(secp256k1N - s, 32));
      return out;
    }
    return Uint8List.fromList(signature);
  }

  Uint8List _taggedHash(String tag, Uint8List data) {
    final tagHash = Uint8List.fromList(
        crypto.sha256.convert(tag.codeUnits).bytes);
    final input = Uint8List(tagHash.length * 2 + data.length);
    input.setAll(0, tagHash);
    input.setAll(tagHash.length, tagHash);
    input.setAll(tagHash.length * 2, data);
    return Uint8List.fromList(crypto.sha256.convert(input).bytes);
  }

  Uint8List _trimLeadingZeros(Uint8List bytes) {
    var start = 0;
    while (start < bytes.length - 1 && bytes[start] == 0) {
      start++;
    }
    return bytes.sublist(start);
  }

  Uint8List _derInteger(Uint8List val) {
    final needsPad = val[0] >= 0x80;
    final len = val.length + (needsPad ? 1 : 0);
    final out = Uint8List(2 + len);
    out[0] = 0x02;
    out[1] = len;
    if (needsPad) {
      out[2] = 0x00;
      out.setRange(3, 3 + val.length, val);
    } else {
      out.setRange(2, 2 + val.length, val);
    }
    return out;
  }
}
