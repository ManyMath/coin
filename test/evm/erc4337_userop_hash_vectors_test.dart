import 'dart:typed_data';

import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

// ERC-4337 UserOperation hash (getUserOpHash) - EntryPoint v0.6.
//
// userOpHash = keccak256(abi.encode(keccak256(pack(userOp)), entryPoint, chainId))
//
// EXTERNAL vector source: viem getUserOperationHash test,
//   https://github.com/wevm/viem/blob/main/src/account-abstraction/utils/userOperation/getUserOperationHash.test.ts
//   (entryPointVersion '0.6'). The expected hash below is the published value.
// Spec: https://eips.ethereum.org/EIPS/eip-4337

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('ERC-4337 userOpHash - EntryPoint v0.6 (viem vector)', () {
    test('matches viem getUserOperationHash 0.6 example', () {
      // viem userOperation fields (0.6):
      //   sender=0x1234...7890, nonce=0, initCode=0x (empty), callData=0x,
      //   callGasLimit=6942069, verificationGasLimit=6942069,
      //   preVerificationGas=6942069, maxFeePerGas=69420,
      //   maxPriorityFeePerGas=69,
      //   paymasterAndData=0x1234567890123456789012345678901234567890,
      //   signature=0x
      // entryPointAddress=0x1234...7890, chainId=1
      final op = UserIntent(
        sender: EvmAddr.fromHex('1234567890123456789012345678901234567890'),
        nonce: BigInt.zero,
        initCode: Uint8List(0),
        callData: Uint8List(0),
        callGasLimit: BigInt.from(6942069),
        verificationGasLimit: BigInt.from(6942069),
        preVerificationGas: BigInt.from(6942069),
        maxFeePerGas: BigInt.from(69420),
        maxPriorityFeePerGas: BigInt.from(69),
        paymasterAndData:
            hexDecode('1234567890123456789012345678901234567890'),
        signature: Uint8List(0),
      );

      final hash = op.hash(
        entryPoint: EvmAddr.fromHex('1234567890123456789012345678901234567890'),
        chainId: BigInt.one,
      );

      expect(
        hexEncode(hash),
        '72bb2d82af9e9da2079fab165bc219c967c6ca0a63dfa55f382c5914ba2f77c5',
      );
    });
  });
}
