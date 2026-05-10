import 'dart:convert';
import 'dart:typed_data';

import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // EIP-191 personal_sign (version 0x45 - "Ethereum Signed Message").
  // Source: ethereumjs-monorepo/packages/util test suite:
  // https://github.com/ethereumjs/ethereumjs-monorepo/blob/master/packages/util/test/signature.spec.ts
  //
  // The prefix applied: "\x19Ethereum Signed Message:\n" + len(msg) + msg.
  // keccak256("Hello world" with prefix) = 0x8144a6fa...
  group('EIP-191 personal_sign message hash (ethereumjs fixtures)', () {
    // "Hello world" - 11 bytes.
    // Expected: keccak256("\x19Ethereum Signed Message:\n11Hello world")
    //         = 0x8144a6fa26be252b86456491fbcd43c1de7e022241845ffea1c3df066f7cfede
    // Source: ethereumjs/ethereumjs-monorepo util/test/signature.spec.ts
    test('messageHash of "Hello world"', () {
      expect(
        hexEncode(PersonalSign.messageHashString('Hello world')),
        '8144a6fa26be252b86456491fbcd43c1de7e022241845ffea1c3df066f7cfede',
      );
    });

    test('prefix is \\x19Ethereum Signed Message:\\n<len>', () {
      const msg = 'Hello world';
      final msgBytes = Uint8List.fromList(utf8.encode(msg));
      final prefix = utf8.encode('\x19Ethereum Signed Message:\n${msgBytes.length}');
      final combined = Uint8List.fromList([...prefix, ...msgBytes]);
      expect(
        PersonalSign.messageHashString(msg),
        equals(keccak256(combined)),
      );
    });

    test('empty message hash is distinct from non-empty', () {
      final empty = PersonalSign.messageHashString('');
      final hello = PersonalSign.messageHashString('Hello world');
      expect(empty, isNot(equals(hello)));
      expect(empty.length, 32);
    });

    test('messageHash and messageHashString produce the same result', () {
      const msg = 'test message';
      final byStr = PersonalSign.messageHashString(msg);
      final byBytes = PersonalSign.messageHash(
          Uint8List.fromList(utf8.encode(msg)));
      expect(byStr, equals(byBytes));
    });

    // Sign then recover, and pin the recovered address to an EXTERNAL value.
    // The signing key is the well-known EIP-155 example private key
    //   0x4646464646464646464646464646464646464646464646464646464646464646
    // whose EVM address is the published
    //   0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F
    // (the sender of the EIP-155 "Example" transaction;
    //  https://eips.ethereum.org/EIPS/eip-155 - also widely reproduced, e.g.
    //  https://github.com/ethereum/go-ethereum tests for this key).
    // We sign an EIP-191 message, recover the public key, derive its address,
    // and assert it equals that published address. This makes recovery
    // meaningful against an independent authority rather than a length check.
    test('sign and recover -> recovered address equals published EIP-155 address',
        () {
      final key = SecretKey.fromHex(
          '4646464646464646464646464646464646464646464646464646464646464646');
      const msg = 'Test message for EIP-191';
      final sig = PersonalSign.signString(msg, key);
      expect(sig.length, 65);
      expect(sig[64], anyOf(27, 28));

      final recoveredPub = PersonalSign.recoverPublicKey(
          Uint8List.fromList(utf8.encode(msg)), sig);
      // Recovered uncompressed pubkey -> keccak256[12:] -> EIP-55 address.
      final recoveredAddr = EvmAddr.fromPublicKey(recoveredPub);
      // Published address for privkey 0x4646...46 (EIP-155).
      expect(
        recoveredAddr.toChecksumHex(),
        '0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F',
      );
    });
  });
}
