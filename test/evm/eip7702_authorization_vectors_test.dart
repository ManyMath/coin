import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

// EIP-7702 authorization-tuple signing hash.
//
//   signingHash = keccak256(MAGIC(0x05) || rlp([chainId, address, nonce]))
//
// EXTERNAL vector source: MetaMask eth-sig-util,
//   https://github.com/MetaMask/eth-sig-util/blob/main/src/sign-eip7702-authorization.test.ts
//   chainId=8545, contractAddress=0x1234...7890, nonce=1.
// The expected hash below is the published authorization hash from that test.
// Spec: https://eips.ethereum.org/EIPS/eip-7702

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('EIP-7702 authorization hash - MetaMask eth-sig-util vector', () {
    test('matches published authorization hash', () {
      final auth = Authorization(
        chainId: BigInt.from(8545),
        address: hexDecode('1234567890123456789012345678901234567890'),
        nonce: BigInt.one,
      );

      expect(
        hexEncode(auth.signingHash()),
        'b847dee5b33802280f3279d57574e1eb6bf5d628d7f63049e3cb20bad211056c',
      );
    });

    // Self-consistency: chainId 0 ("valid on any chain") must produce a
    // different domain-separated hash than a concrete chainId.
    // SELF-DERIVED (no published expected value for this pair).
    test('chainId 0 differs from chainId 8545 (self-derived)', () {
      final anyChain = Authorization(
        chainId: BigInt.zero,
        address: hexDecode('1234567890123456789012345678901234567890'),
        nonce: BigInt.one,
      );
      final besu = Authorization(
        chainId: BigInt.from(8545),
        address: hexDecode('1234567890123456789012345678901234567890'),
        nonce: BigInt.one,
      );
      expect(anyChain.signingHash(), isNot(equals(besu.signingHash())));
    });
  });
}
