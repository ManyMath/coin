import 'dart:typed_data';

import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

// EIP-1014 CREATE2 deterministic-address examples.
//
// Source: EIP-1014 "Examples" section, https://eips.ethereum.org/EIPS/eip-1014
//   address = keccak256(0xff ++ address ++ salt ++ keccak256(init_code))[12:]

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  String create2(String deployer, String salt, String initCode) {
    return EvmAddr.create2(
      deployer: hexDecode(deployer),
      salt: hexDecode(salt),
      initCode: hexDecode(initCode),
    ).toChecksumHex();
  }

  group('EIP-1014 CREATE2 - spec reference examples', () {
    // Example 0
    test('example 0 (zero deployer, zero salt, initCode 0x00)', () {
      expect(
        create2(
          '0000000000000000000000000000000000000000',
          '0000000000000000000000000000000000000000000000000000000000000000',
          '00',
        ),
        '0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38',
      );
    });

    // Example 1
    test('example 1 (deadbeef deployer, zero salt, initCode 0x00)', () {
      expect(
        create2(
          'deadbeef00000000000000000000000000000000',
          '0000000000000000000000000000000000000000000000000000000000000000',
          '00',
        ),
        '0xB928f69Bb1D91Cd65274e3c79d8986362984fDA3',
      );
    });

    // Example 2
    test('example 2 (deadbeef deployer, feed... salt, initCode 0x00)', () {
      expect(
        create2(
          'deadbeef00000000000000000000000000000000',
          '000000000000000000000000feed000000000000000000000000000000000000',
          '00',
        ),
        '0xD04116cDd17beBE565EB2422F2497E06cC1C9833',
      );
    });

    // Example 3
    test('example 3 (zero deployer, zero salt, initCode 0xdeadbeef)', () {
      expect(
        create2(
          '0000000000000000000000000000000000000000',
          '0000000000000000000000000000000000000000000000000000000000000000',
          'deadbeef',
        ),
        '0x70f2b2914A2a4b783FaEFb75f459A580616Fcb5e',
      );
    });

    // Example 4
    test('example 4 (deadbeef deployer, cafebabe salt, initCode 0xdeadbeef)',
        () {
      expect(
        create2(
          '00000000000000000000000000000000deadbeef',
          '00000000000000000000000000000000000000000000000000000000cafebabe',
          'deadbeef',
        ),
        '0x60f3f640a8508fC6a86d45DF051962668E1e8AC7',
      );
    });

    // Example 5 (long init code)
    test('example 5 (deadbeef deployer, cafebabe salt, long initCode)', () {
      expect(
        create2(
          '00000000000000000000000000000000deadbeef',
          '00000000000000000000000000000000000000000000000000000000cafebabe',
          'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
              'deadbeefdeadbeefdeadbeef',
        ),
        '0x1d8bfDC5D46DC4f61D6b6115972536eBE6A8854C',
      );
    });

    // Example 6 (empty init code)
    test('example 6 (zero deployer, zero salt, empty initCode)', () {
      expect(
        create2(
          '0000000000000000000000000000000000000000',
          '0000000000000000000000000000000000000000000000000000000000000000',
          '',
        ),
        '0xE33C0C7F7df4809055C3ebA6c09CFe4BaF1BD9e0',
      );
    });

    test('rejects non-32-byte salt', () {
      expect(
        () => EvmAddr.create2(
          deployer: hexDecode('0000000000000000000000000000000000000000'),
          salt: hexDecode('00'),
          initCode: hexDecode('00'),
        ),
        throwsArgumentError,
      );
    });

    test('rejects non-20-byte deployer', () {
      expect(
        () => EvmAddr.create2(
          deployer: hexDecode('dead'),
          salt: Uint8List(32),
          initCode: hexDecode('00'),
        ),
        throwsArgumentError,
      );
    });
  });
}
