import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // Keccak-256 digests. Ethereum uses Keccak-256, which differs from NIST
  // SHA3-256 (FIPS 202) in the domain-separation padding byte (0x01 vs 0x06).
  group('Keccak-256 test vectors', () {
    // Ethereum Yellow Paper, Appendix F (also: go-ethereum, py-evm, ethers.js).
    // keccak256('') = c5d246... - the canonical Ethereum empty-input digest.
    // https://ethereum.github.io/yellowpaper/paper.pdf (Appendix F)
    test('keccak256 of empty input', () {
      expect(
        hexEncode(keccak256(Uint8List(0))),
        'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
      );
    });

    // "abc" -> [0x61, 0x62, 0x63]. Matches go-ethereum
    // crypto.Keccak256([]byte("abc")):
    // https://github.com/ethereum/go-ethereum/blob/master/crypto/crypto_test.go
    test('keccak256 of "abc" (UTF-8)', () {
      expect(
        hexEncode(keccak256(Uint8List.fromList([0x61, 0x62, 0x63]))),
        '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
      );
    });

    // ERC-20 transfer(address,uint256) function selector = first 4 bytes of
    // keccak256 of the canonical signature string.
    // Reproduced in every ERC-20 contract and the Solidity ABI spec.
    test('keccak256 of ERC-20 transfer selector preimage - first 4 bytes = a9059cbb', () {
      final hash = keccak256(Uint8List.fromList('transfer(address,uint256)'.codeUnits));
      expect(hexEncode(hash.sublist(0, 4)), 'a9059cbb');
    });

    // keccak256 of 32 zero bytes - the Ethereum empty-storage-slot marker.
    // Used in the Ethereum state trie and reproduced in go-ethereum.
    // https://github.com/ethereum/go-ethereum/blob/master/core/rawdb/accessors_state.go
    test('keccak256 of 32 zero bytes', () {
      expect(
        hexEncode(keccak256(Uint8List(32))),
        '290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563',
      );
    });
  });
}
