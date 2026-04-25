import 'dart:typed_data';

import 'package:coin/coin_chains.dart';
import 'package:test/test.dart';

// Most cases exercise the TxAssembler with fixed private keys, synthetic
// outpoints, and a real ECDSA/Schnorr signer; their assertions are internal
// invariants (sighash recomputed and verified, scriptSig/witness structure,
// byte-level serialization).
//
// The "TxAssembler pins BIP-143 P2WPKH vector" group drives the assembler with
// the BIP-143 native-P2WPKH example's keys/outpoints/amounts/outputs and
// checks the produced P2WPKH scriptWitness against BIP-143's published
// signed-tx witness stack - a value from the spec, not from the implementation
// under test. See that group for the source citation.
/// Deterministic key material used across the tests.
final _priv = SecretKey.fromHex(
    '619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9');
final _pub = _priv.publicKey.bytes; // 025476c2...aeee6357

Uint8List _txid(int seed) =>
    Uint8List.fromList(List<int>.generate(32, (i) => (seed + i) & 0xff));

/// Real ECDSA signer: returns bare DER bytes (no sighash flag).
Uint8List _signer(Tx tx, int i, Uint8List digest, SigHashType ht) =>
    EcdsaSig.sign(digest, _priv.bytes).toDer();

/// Recompute the BIP-143 P2WPKH scriptCode for [pub].
Uint8List _p2wpkhScriptCode(Uint8List pub) {
  final h = hash160(pub);
  return Uint8List.fromList([0x76, 0xa9, 0x14, ...h, 0x88, 0xac]);
}

Uint8List _p2wpkhSpk(Uint8List pub) =>
    Uint8List.fromList([0x00, 0x14, ...hash160(pub)]);

Uint8List _p2pkhSpk(Uint8List pub) => Uint8List.fromList(
    [0x76, 0xa9, 0x14, ...hash160(pub), 0x88, 0xac]);

Uint8List _p2shP2wpkhSpk(Uint8List pub) {
  // P2SH of the witness redeemScript (OP_0 <20-byte keyhash>).
  final redeem = Uint8List.fromList([0x00, 0x14, ...hash160(pub)]);
  return Uint8List.fromList([0xa9, 0x14, ...hash160(redeem), 0x87]);
}

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  final chain = BitcoinParams.bitcoin;
  final amount = BigInt.from(100000000);

  AssemblerInput input(AssemblerInputType type, int seed) {
    Uint8List spk;
    switch (type) {
      case AssemblerInputType.p2pkh:
        spk = _p2pkhSpk(_pub);
        break;
      case AssemblerInputType.p2wpkh:
        spk = _p2wpkhSpk(_pub);
        break;
      case AssemblerInputType.p2shP2wpkh:
        spk = _p2shP2wpkhSpk(_pub);
        break;
      case AssemblerInputType.p2tr:
        spk = Uint8List(0);
        break;
    }
    return AssemblerInput(
      outpoint: Outpoint(txid: _txid(seed), vout: 0),
      value: amount,
      scriptPubKey: spk,
      type: type,
      publicKey: _pub,
    );
  }

  TxOutput payOut() => TxOutput(
        value: BigInt.from(90000000),
        scriptPubKey: _p2pkhSpk(_pub),
      );

  group('TxAssembler.build attaches signatures', () {
    test('P2WPKH: complete, witness present, sig verifies', () {
      final asm = TxAssembler(
        chainParams: chain,
        inputs: [input(AssemblerInputType.p2wpkh, 1)],
        outputs: [payOut()],
        ordering: TxOrdering.none,
      );
      final tx = asm.build(_signer);

      expect(tx.complete, isTrue);
      expect(tx.isWitness, isTrue);
      expect(tx.inputs[0].witness.length, 2);
      // witness = [sig+flag, pubkey]
      expect(tx.inputs[0].witness[1], _pub);

      // Recompute the BIP-143 digest and verify the attached signature.
      final digest = WitnessSigHasher().hash(
        tx,
        0,
        SigHashType.all,
        prevScript: _p2wpkhScriptCode(_pub),
        amount: amount,
      );
      final sigWithFlag = tx.inputs[0].witness[0];
      expect(sigWithFlag.last, SigHashType.all.flag);
      final der = Uint8List.fromList(
          sigWithFlag.sublist(0, sigWithFlag.length - 1));
      expect(EcdsaSig.fromDer(der).verify(digest, _pub), isTrue);

      // Round-trips through serialization with same txid.
      final reparsed = Tx.fromBytes(tx.toBytes());
      expect(reparsed.txid, tx.txid);
    });

    test('P2PKH: complete, scriptSig present, sig verifies', () {
      final asm = TxAssembler(
        chainParams: chain,
        inputs: [input(AssemblerInputType.p2pkh, 2)],
        outputs: [payOut()],
        ordering: TxOrdering.none,
      );
      final tx = asm.build(_signer);

      expect(tx.complete, isTrue);
      expect(tx.inputs[0].scriptSig.isNotEmpty, isTrue);
      expect(tx.inputs[0].witness, isEmpty);

      final digest = LegacySigHasher().hash(
        tx,
        0,
        SigHashType.all,
        prevScript: _p2pkhSpk(_pub),
      );
      // scriptSig = push(sig+flag) push(pubkey); extract the sig.
      final ss = tx.inputs[0].scriptSig;
      final sigLen = ss[0];
      final sigWithFlag = ss.sublist(1, 1 + sigLen);
      expect(sigWithFlag.last, SigHashType.all.flag);
      final der = Uint8List.fromList(
          sigWithFlag.sublist(0, sigWithFlag.length - 1));
      expect(EcdsaSig.fromDer(der).verify(digest, _pub), isTrue);

      final reparsed = Tx.fromBytes(tx.toBytes());
      expect(reparsed.txid, tx.txid);
    });

    test('P2SH-P2WPKH: complete, scriptSig + witness, sig verifies', () {
      final asm = TxAssembler(
        chainParams: chain,
        inputs: [input(AssemblerInputType.p2shP2wpkh, 3)],
        outputs: [payOut()],
        ordering: TxOrdering.none,
      );
      final tx = asm.build(_signer);

      expect(tx.complete, isTrue);
      expect(tx.isWitness, isTrue);
      // scriptSig is a single push of the redeemScript (OP_0 <20>).
      final ss = tx.inputs[0].scriptSig;
      expect(ss[0], 0x16); // push 22 bytes
      expect(ss[1], 0x00); // OP_0
      expect(ss[2], 0x14); // push 20
      expect(tx.inputs[0].witness.length, 2);
      expect(tx.inputs[0].witness[1], _pub);

      // BIP-143 digest uses the P2WPKH-form scriptCode, not the redeemScript.
      final digest = WitnessSigHasher().hash(
        tx,
        0,
        SigHashType.all,
        prevScript: _p2wpkhScriptCode(_pub),
        amount: amount,
      );
      final sigWithFlag = tx.inputs[0].witness[0];
      final der = Uint8List.fromList(
          sigWithFlag.sublist(0, sigWithFlag.length - 1));
      expect(EcdsaSig.fromDer(der).verify(digest, _pub), isTrue);

      final reparsed = Tx.fromBytes(tx.toBytes());
      expect(reparsed.txid, tx.txid);
    });

    test('mixed inputs: all complete and verify', () {
      final asm = TxAssembler(
        chainParams: chain,
        inputs: [
          input(AssemblerInputType.p2pkh, 10),
          input(AssemblerInputType.p2wpkh, 20),
          input(AssemblerInputType.p2shP2wpkh, 30),
        ],
        outputs: [payOut()],
        ordering: TxOrdering.none,
      );
      final tx = asm.build(_signer);

      expect(tx.complete, isTrue);
      expect(tx.inputs.length, 3);

      // P2PKH input 0
      final d0 = LegacySigHasher()
          .hash(tx, 0, SigHashType.all, prevScript: _p2pkhSpk(_pub));
      final ss = tx.inputs[0].scriptSig;
      final sig0 = ss.sublist(1, 1 + ss[0]);
      expect(
          EcdsaSig.fromDer(
                  Uint8List.fromList(sig0.sublist(0, sig0.length - 1)))
              .verify(d0, _pub),
          isTrue);

      // P2WPKH input 1
      final d1 = WitnessSigHasher().hash(tx, 1, SigHashType.all,
          prevScript: _p2wpkhScriptCode(_pub), amount: amount);
      final w1 = tx.inputs[1].witness[0];
      expect(
          EcdsaSig.fromDer(Uint8List.fromList(w1.sublist(0, w1.length - 1)))
              .verify(d1, _pub),
          isTrue);

      // P2SH-P2WPKH input 2
      final d2 = WitnessSigHasher().hash(tx, 2, SigHashType.all,
          prevScript: _p2wpkhScriptCode(_pub), amount: amount);
      final w2 = tx.inputs[2].witness[0];
      expect(
          EcdsaSig.fromDer(Uint8List.fromList(w2.sublist(0, w2.length - 1)))
              .verify(d2, _pub),
          isTrue);

      final reparsed = Tx.fromBytes(tx.toBytes());
      expect(reparsed.txid, tx.txid);
    });
  });

  group('TxAssembler pins BIP-143 P2WPKH vector', () {
    // The BIP-143 native-P2WPKH example, published at
    // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    // ("Native P2WPKH" section). The example has two inputs:
    //   input 0: an ordinary P2PK (scriptPubKey 21<33-byte pubkey>AC), and
    //   input 1: a P2WPKH controlled by _priv / _pub (= the BIP-143 second
    //            input's private/public key).
    //
    // The unsigned tx, outpoints, amounts, outputs and nLockTime are
    // reproduced below from the spec. The published final signed
    // transaction encodes input 1's scriptWitness as:
    //   <sig+SIGHASH_ALL> <pubkey>
    // with the exact bytes in _bip143In1WitnessSig / _bip143In1Pubkey
    // (from BIP-143's "serialized signed transaction").
    //
    // Because input 0 is a *P2PK* spend, which TxAssembler does not build (it
    // only supports p2pkh / p2shP2wpkh / p2wpkh / p2tr - see AssemblerInputType),
    // we cannot reproduce the full signed-tx hex (option (a)). We therefore use
    // option (b): drive the assembler with the BIP-143 keys/outpoints/amounts/
    // outputs and assert the P2WPKH input's produced scriptWitness equals the
    // published BIP-143 witness stack for that input. ECDSA here is RFC-6979
    // deterministic, so the (r,s) - and thus the whole witness - is reproducible.

    // BIP-143 published witness stack for input 1 (the P2WPKH input), from
    // the spec's serialized signed transaction. The first stack
    // item is the DER signature with the trailing SIGHASH_ALL (0x01) flag.
    const bip143In1WitnessSig =
        '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a'
        '0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01';
    const bip143In1Pubkey =
        '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357';

    // Build the two BIP-143 inputs. input 0 stands in for the spec's P2PK input
    // (its concrete sig is discarded - see below); only its outpoint, value and
    // sequence matter for input 1's BIP-143 digest.
    AssemblerInput bip143In0() => AssemblerInput(
          outpoint: Outpoint(
            txid: hexDecode(
                'fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f'),
            vout: 0,
          ),
          value: BigInt.from(625000000),
          scriptPubKey: _p2pkhSpk(_pub),
          type: AssemblerInputType.p2pkh,
          publicKey: _pub,
          sequence: 0xffffffee,
        );
    AssemblerInput bip143In1() => AssemblerInput(
          outpoint: Outpoint(
            txid: hexDecode(
                'ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a'),
            vout: 1,
          ),
          value: BigInt.from(600000000),
          scriptPubKey: _p2wpkhSpk(_pub),
          type: AssemblerInputType.p2wpkh,
          publicKey: _pub,
        );

    TxAssembler bip143Assembler() => TxAssembler(
          chainParams: chain,
          version: 1,
          locktime: 0x11,
          inputs: [bip143In0(), bip143In1()],
          outputs: [
            TxOutput(
              value: BigInt.from(0x06b22c20),
              scriptPubKey: hexDecode(
                  '76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac'),
            ),
            TxOutput(
              value: BigInt.from(0x0d519390),
              scriptPubKey: hexDecode(
                  '76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac'),
            ),
          ],
          ordering: TxOrdering.none,
        );

    test('computes the canonical BIP-143 digest for the P2WPKH input', () {
      // BIP-143 publishes the sigHash for the second input as
      // c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670.
      final captured = <int, Uint8List>{};
      bip143Assembler().build((tx, i, digest, ht) {
        captured[i] = digest;
        return EcdsaSig.sign(digest, _priv.bytes).toDer();
      });

      expect(
        hexEncode(captured[1]!),
        'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670',
      );
    });

    test('P2WPKH input scriptWitness equals BIP-143 published witness stack',
        () {
      // Drive the assembler with the real RFC-6979 signer (deterministic), so
      // the produced witness must match BIP-143's published bytes exactly.
      final tx = bip143Assembler().build(_signer);

      // No BIP-69 reordering (ordering: none), so input 1 stays the P2WPKH input.
      final witness = tx.inputs[1].witness;
      expect(witness.length, 2);
      // Stack item 0: DER signature + SIGHASH_ALL flag == BIP-143 published.
      expect(hexEncode(witness[0]), bip143In1WitnessSig);
      // Stack item 1: the compressed pubkey == BIP-143 published.
      expect(hexEncode(witness[1]), bip143In1Pubkey);
    });
  });

  group('TxAssembler.buildAsync parity', () {
    test('buildAsync produces an identical signed tx as build', () async {
      List<AssemblerInput> mk() => [
            input(AssemblerInputType.p2wpkh, 5),
            input(AssemblerInputType.p2pkh, 6),
          ];

      final sync = TxAssembler(
        chainParams: chain,
        inputs: mk(),
        outputs: [payOut()],
        ordering: TxOrdering.none,
      ).build(_signer);

      final async = await TxAssembler(
        chainParams: chain,
        inputs: mk(),
        outputs: [payOut()],
        ordering: TxOrdering.none,
      ).buildAsync((tx, i, digest, ht) async =>
          EcdsaSig.sign(digest, _priv.bytes).toDer());

      expect(async.complete, isTrue);
      expect(async.txid, sync.txid);
    });
  });

  group('TxAssembler BIP-69 ordering', () {
    test('inputs/outputs are sorted before signing', () {
      // Two inputs whose txids are out of BIP-69 order, two outputs.
      final hi = AssemblerInput(
        outpoint: Outpoint(txid: _txid(0xf0), vout: 0),
        value: amount,
        scriptPubKey: _p2wpkhSpk(_pub),
        type: AssemblerInputType.p2wpkh,
        publicKey: _pub,
      );
      final lo = AssemblerInput(
        outpoint: Outpoint(txid: _txid(0x01), vout: 0),
        value: amount,
        scriptPubKey: _p2wpkhSpk(_pub),
        type: AssemblerInputType.p2wpkh,
        publicKey: _pub,
      );
      final tx = TxAssembler(
        chainParams: chain,
        inputs: [hi, lo],
        outputs: [
          TxOutput(value: BigInt.from(50), scriptPubKey: _p2pkhSpk(_pub)),
          TxOutput(value: BigInt.from(10), scriptPubKey: _p2pkhSpk(_pub)),
        ],
      ).build(_signer);

      // Lower txid first.
      expect(tx.inputs[0].prevOut.txid[0], 0x01);
      expect(tx.inputs[1].prevOut.txid[0], 0xf0);
      // Lower value output first.
      expect(tx.outputs[0].value, BigInt.from(10));
      expect(tx.complete, isTrue);
    });
  });

  group('ForkedTxAssembler SIGHASH_FORKID', () {
    test('signs with fork-id sighash and verifies', () {
      final bch = BitcoinCashParams.bitcoinCash;
      expect(bch.usesForkId, isTrue);

      final asm = ForkedTxAssembler(
        chainParams: bch,
        inputs: [input(AssemblerInputType.p2pkh, 7)],
        outputs: [payOut()],
        ordering: TxOrdering.none,
        forkId: 0,
      );

      final captured = <int, Uint8List>{};
      final tx = asm.build((tx, i, digest, ht) {
        captured[i] = digest;
        return EcdsaSig.sign(digest, _priv.bytes).toDer();
      });

      expect(tx.complete, isTrue);
      expect(tx.inputs[0].scriptSig.isNotEmpty, isTrue);

      // The attached signature verifies against the fork-id digest.
      final ss = tx.inputs[0].scriptSig;
      final sig = ss.sublist(1, 1 + ss[0]);
      final der = Uint8List.fromList(sig.sublist(0, sig.length - 1));
      expect(
          EcdsaSig.fromDer(der).verify(captured[0]!, _pub), isTrue);
    });
  });
}
