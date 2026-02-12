import 'dart:typed_data';

final BigInt secp256k1P = BigInt.parse(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
    radix: 16);
final BigInt secp256k1N = BigInt.parse(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
    radix: 16);
final BigInt secp256k1Gx = BigInt.parse(
    '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
    radix: 16);
final BigInt secp256k1Gy = BigInt.parse(
    '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
    radix: 16);
final BigInt secp256k1HalfN = secp256k1N >> 1;

class EcPoint {
  final BigInt x;
  final BigInt y;
  final bool isInfinity;

  EcPoint(this.x, this.y) : isInfinity = false;
  EcPoint.infinity()
      : x = BigInt.zero,
        y = BigInt.zero,
        isInfinity = true;

  @override
  bool operator ==(Object other) {
    if (other is! EcPoint) return false;
    if (isInfinity && other.isInfinity) return true;
    if (isInfinity || other.isInfinity) return false;
    return x == other.x && y == other.y;
  }

  @override
  int get hashCode => isInfinity ? 0 : x.hashCode ^ y.hashCode;
}

final EcPoint secp256k1G = EcPoint(secp256k1Gx, secp256k1Gy);

EcPoint ecPointAdd(EcPoint p1, EcPoint p2) {
  if (p1.isInfinity) return p2;
  if (p2.isInfinity) return p1;

  if (p1.x == p2.x) {
    if (p1.y == p2.y) return ecPointDouble(p1);
    return EcPoint.infinity();
  }

  final dx = (p2.x - p1.x) % secp256k1P;
  final dy = (p2.y - p1.y) % secp256k1P;
  final s = (dy * dx.modInverse(secp256k1P)) % secp256k1P;
  final x3 = (s * s - p1.x - p2.x) % secp256k1P;
  final y3 = (s * (p1.x - x3) - p1.y) % secp256k1P;
  return EcPoint(x3, y3);
}

EcPoint ecPointDouble(EcPoint p) {
  if (p.isInfinity) return p;
  final s = (BigInt.from(3) * p.x * p.x *
          (BigInt.from(2) * p.y).modInverse(secp256k1P)) %
      secp256k1P;
  final x3 = (s * s - BigInt.from(2) * p.x) % secp256k1P;
  final y3 = (s * (p.x - x3) - p.y) % secp256k1P;
  return EcPoint(x3, y3);
}

EcPoint ecScalarMult(BigInt k, EcPoint point) {
  if (k == BigInt.zero) return EcPoint.infinity();
  if (k == BigInt.one) return point;

  var result = EcPoint.infinity();
  var addend = point;
  var tempK = k % secp256k1N;

  while (tempK > BigInt.zero) {
    if (tempK.isOdd) {
      result = ecPointAdd(result, addend);
    }
    addend = ecPointDouble(addend);
    tempK >>= 1;
  }
  return result;
}

bool ecIsOnCurve(EcPoint point) {
  if (point.isInfinity) return true;
  final left = (point.y * point.y) % secp256k1P;
  final right =
      (point.x * point.x * point.x + BigInt.from(7)) % secp256k1P;
  return left == right;
}

BigInt bytesToBigInt(Uint8List bytes) {
  var result = BigInt.zero;
  for (var i = 0; i < bytes.length; i++) {
    result = (result << 8) + BigInt.from(bytes[i]);
  }
  return result;
}

Uint8List bigIntToBytes(BigInt value, int length) {
  final bytes = Uint8List(length);
  var temp = value;
  for (var i = length - 1; i >= 0; i--) {
    bytes[i] = (temp & BigInt.from(0xFF)).toInt();
    temp >>= 8;
  }
  return bytes;
}

Uint8List ecPointToBytes(EcPoint point, {bool compressed = true}) {
  if (point.isInfinity) {
    throw ArgumentError('Cannot encode point at infinity');
  }
  if (compressed) {
    final bytes = Uint8List(33);
    bytes[0] = point.y.isEven ? 0x02 : 0x03;
    final xb = bigIntToBytes(point.x, 32);
    bytes.setRange(1, 33, xb);
    return bytes;
  } else {
    final bytes = Uint8List(65);
    bytes[0] = 0x04;
    bytes.setRange(1, 33, bigIntToBytes(point.x, 32));
    bytes.setRange(33, 65, bigIntToBytes(point.y, 32));
    return bytes;
  }
}

EcPoint ecBytesToPoint(Uint8List bytes) {
  if (bytes.length == 65 && bytes[0] == 0x04) {
    final x = bytesToBigInt(bytes.sublist(1, 33));
    final y = bytesToBigInt(bytes.sublist(33, 65));
    // Reject coordinates outside the field or a point not on y^2 = x^3 + 7.
    if (x >= secp256k1P || y >= secp256k1P || !_isOnCurve(x, y)) {
      throw ArgumentError('Public key is not a valid curve point');
    }
    return EcPoint(x, y);
  } else if (bytes.length == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03)) {
    final x = bytesToBigInt(bytes.sublist(1, 33));
    // An x >= field size cannot encode a curve point.
    if (x >= secp256k1P) {
      throw ArgumentError('Public key x-coordinate exceeds the field size');
    }
    final alpha = (x * x * x + BigInt.from(7)) % secp256k1P;
    final beta = alpha.modPow((secp256k1P + BigInt.one) >> 2, secp256k1P);
    final y = (bytes[0] == 0x02)
        ? (beta.isEven ? beta : secp256k1P - beta)
        : (beta.isOdd ? beta : secp256k1P - beta);
    // modPow yields a true sqrt only when alpha is a quadratic residue;
    // otherwise x is not on the curve. Verify before trusting the point.
    if (!_isOnCurve(x, y)) {
      throw ArgumentError('Public key x-coordinate is not on the curve');
    }
    return EcPoint(x, y);
  } else {
    throw ArgumentError('Invalid public key format (${bytes.length} bytes)');
  }
}

/// Whether (x, y) satisfies the secp256k1 curve equation y^2 == x^3 + 7 (mod p).
bool _isOnCurve(BigInt x, BigInt y) =>
    (y * y - (x * x * x + BigInt.from(7))) % secp256k1P == BigInt.zero;
