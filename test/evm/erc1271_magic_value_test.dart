import 'dart:typed_data';

import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

// ERC-1271 isValidSignature magic values.
//
//   magic = bytes4(keccak256("isValidSignature(bytes32,bytes)")) == 0x1626ba7e
//
// EXTERNAL/recomputable: the magic value 0x1626ba7e is defined in ERC-1271
// (https://eips.ethereum.org/EIPS/eip-1271) as the 4-byte function selector of
// `isValidSignature(bytes32,bytes)`. The selector is deterministically derived
// from the published signature string, recomputed here with coin's keccak.

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  Uint8List selector(String signature) {
    return keccak256(Uint8List.fromList(signature.codeUnits)).sublist(0, 4);
  }

  group('ERC-1271 magic value', () {
    test('bytes4(keccak256("isValidSignature(bytes32,bytes)")) == 0x1626ba7e',
        () {
      expect(
        hexEncode(selector('isValidSignature(bytes32,bytes)')),
        '1626ba7e',
      );
    });

    // The original (draft) ERC-1271 signature took (bytes,bytes); its selector
    // 0x20c13b0b is still used by some legacy validators. Recomputable.
    test('legacy bytes4(keccak256("isValidSignature(bytes,bytes)")) == 0x20c13b0b',
        () {
      expect(
        hexEncode(selector('isValidSignature(bytes,bytes)')),
        '20c13b0b',
      );
    });
  });
}
