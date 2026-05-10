import 'dart:typed_data';

import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

// EIP-2930 (type 1, access-list transaction) and EIP-1559 (type 2) vectors.
//
// EIP-2930 source: go-ethereum transaction_test.go TestEIP2718TransactionSigHash
//   https://github.com/ethereum/go-ethereum/blob/master/core/types/transaction_test.go
//   (var emptyEip2718Tx / signedEip2718Tx)
//
// EIP-1559 source: ethereumjs-monorepo / Hyperledger Besu fixtures
//   https://github.com/ethereumjs/ethereumjs-monorepo/blob/master/packages/tx/test/testData/eip1559.ts
//   (vector index 0, chainId=4, produced by Besu)

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // -------------------------------------------------------------------------
  // EIP-2930 (type 1) - go-ethereum TestEIP2718TransactionSigHash vector
  // -------------------------------------------------------------------------
  group('EIP-2930 (type 1) - go-ethereum test vector', () {
    // Fields: chainId=1, nonce=3, gasPrice=1, gasLimit=25000,
    //         to=0xb94f5374fce5edbc8e2a8697c15331677e6ebf0b,
    //         value=10, data=0x5544, accessList=[].
    // Published signature on this tx (go-ethereum signedEip2718Tx, supplied to
    // WithSignature, NOT RFC6979): yParity=1,
    //   r=c9519f4f2b30335884581971573fadf60c6204f59a911df35ee8a540456b2660
    //   s=32f1e8e2c5dd761f9e4f88f41c8310aeaba26a8bfcdacfedfa12ec3862d37521
    //
    // Signing hash (EIP-2930 pre-image hash, chainId=1):
    //   49b486f0ec0a60dfbbca2d30cb07c9e8ffb2a2ff41f29a1ab6737475f6ff69f3
    // Source: TestEIP2718TransactionSigHash / signedEip2718Tx in
    //   go-ethereum/core/types/transaction_test.go

    test('EIP-2930 signing hash matches go-ethereum', () {
      final tx = Envelope(
        kind: EnvelopeKind.eip2930,
        chainId: BigInt.one,
        nonce: BigInt.from(3),
        gasPrice: BigInt.one,
        gasLimit: BigInt.from(25000),
        to: hexDecode('b94f5374fce5edbc8e2a8697c15331677e6ebf0b'),
        value: BigInt.from(10),
        data: hexDecode('5544'),
        accessList: const [],
      );

      final hash = tx.signingHash();
      expect(hash.length, 32);
      expect(
        hexEncode(hash),
        '49b486f0ec0a60dfbbca2d30cb07c9e8ffb2a2ff41f29a1ab6737475f6ff69f3',
      );
    });

    // Assert the full signed serialization against go-ethereum's
    // signedEip2718Tx.MarshalBinary() output. The signature is injected (the
    // go-ethereum vector supplies it via WithSignature, not RFC6979).
    test('EIP-2930 signed serialization matches go-ethereum MarshalBinary', () {
      final tx = Envelope(
        kind: EnvelopeKind.eip2930,
        chainId: BigInt.one,
        nonce: BigInt.from(3),
        gasPrice: BigInt.one,
        gasLimit: BigInt.from(25000),
        to: hexDecode('b94f5374fce5edbc8e2a8697c15331677e6ebf0b'),
        value: BigInt.from(10),
        data: hexDecode('5544'),
        accessList: const [],
      );
      final signed = tx.withSignature(
        v: 1,
        r: hexDecode(
            'c9519f4f2b30335884581971573fadf60c6204f59a911df35ee8a540456b2660'),
        s: hexDecode(
            '32f1e8e2c5dd761f9e4f88f41c8310aeaba26a8bfcdacfedfa12ec3862d37521'),
      );
      final raw = signed.serialize();
      expect(raw[0], 0x01);
      // go-ethereum signedEip2718Tx MarshalBinary, transaction_test.go.
      expect(
        hexEncode(raw),
        '01f8630103018261a894b94f5374fce5edbc8e2a8697c15331677e6ebf0b0a8255'
        '44c001a0c9519f4f2b30335884581971573fadf60c6204f59a911df35ee8a54045'
        '6b2660a032f1e8e2c5dd761f9e4f88f41c8310aeaba26a8bfcdacfedfa12ec3862'
        'd37521',
      );
    });
  });

  // -------------------------------------------------------------------------
  // EIP-1559 (type 2) - ethereumjs / Hyperledger Besu fixture (index 0)
  // -------------------------------------------------------------------------
  group('EIP-1559 (type 2) - ethereumjs/Besu cross-client fixture', () {
    // Fields: chainId=4, nonce=819, maxPriorityFeePerGas=75853,
    //         maxFeePerGas=121212, gasLimit=35552,
    //         to=0x000000000000000000000000000000000000aaaa,
    //         value=43203529, data=empty, accessList=[],
    //         yParity=0, r=0f924cb6..., s=7dd1c500...
    //
    // Signed transaction bytes (type 0x02 + RLP payload) from the fixture:
    // 02f86e048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c080a00f924...

    // Signing the fixture key over the fixture fields reproduces the
    // ethereumjs/Besu signed RLP (RFC6979).
    test('EIP-1559 signed serialization matches ethereumjs vector', () {
      final key = SecretKey(hexDecode(
          '8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63'));
      final tx = Envelope(
        kind: EnvelopeKind.eip1559,
        chainId: BigInt.from(4),
        nonce: BigInt.from(819),
        maxPriorityFeePerGas: BigInt.from(75853),
        maxFeePerGas: BigInt.from(121212),
        gasLimit: BigInt.from(35552),
        to: hexDecode('000000000000000000000000000000000000aaaa'),
        value: BigInt.from(43203529),
        data: Uint8List(0),
        accessList: const [],
      );
      final signed = EnvelopeSigner.sign(tx, key);
      final raw = signed.serialize();
      expect(raw[0], 0x02);
      // ethereumjs eip1559.ts vector index 0, full signed RLP.
      expect(
        hexEncode(raw),
        '02f86e048203338301284d8301d97c828ae09400000000000000000000000000'
        '0000000000aaaa8402933bc980c080a00f924cb68412c8f1cfd74d9b581c71ee'
        'af94fff6abdde3e5b02ca6b2931dcf47a07dd1c50027c3e31f8b565e25ce68a5'
        '072110f61fce5eee81b195dd51273c2f83',
      );
    });

    // Verify yParity (v) is 0 or 1 for typed transactions (no chain-replay
    // encoding - EIP-1559 uses raw recovery id).
    test('EIP-1559 yParity is 0 or 1 (no chain-replay offset)', () {
      final key = SecretKey(hexDecode(
          '8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63'));
      final tx = Envelope(
        kind: EnvelopeKind.eip1559,
        chainId: BigInt.from(4),
        nonce: BigInt.from(819),
        maxPriorityFeePerGas: BigInt.from(75853),
        maxFeePerGas: BigInt.from(121212),
        gasLimit: BigInt.from(35552),
        to: hexDecode('000000000000000000000000000000000000aaaa'),
        value: BigInt.from(43203529),
        accessList: const [],
      );
      final signed = EnvelopeSigner.sign(tx, key);
      expect(signed.v, anyOf(0, 1));
    });

    // The signing hash must differ from a legacy tx with same params.
    test('EIP-1559 signing hash differs from legacy for same params', () {
      final eip1559 = Envelope(
        kind: EnvelopeKind.eip1559,
        chainId: BigInt.from(4),
        nonce: BigInt.from(819),
        maxPriorityFeePerGas: BigInt.from(75853),
        maxFeePerGas: BigInt.from(121212),
        gasLimit: BigInt.from(35552),
        to: hexDecode('000000000000000000000000000000000000aaaa'),
        value: BigInt.from(43203529),
        accessList: const [],
      );
      final legacy = Envelope(
        kind: EnvelopeKind.legacy,
        chainId: BigInt.from(4),
        nonce: BigInt.from(819),
        gasPrice: BigInt.from(121212),
        gasLimit: BigInt.from(35552),
        to: hexDecode('000000000000000000000000000000000000aaaa'),
        value: BigInt.from(43203529),
      );
      expect(eip1559.signingHash(), isNot(equals(legacy.signingHash())));
    });
  });
}
