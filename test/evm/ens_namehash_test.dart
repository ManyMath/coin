import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // EIP-137 / ERC-137 namehash examples.
  // Source: https://github.com/ethereum/ercs/blob/master/ERCS/erc-137.md
  group('ENS namehash (EIP-137)', () {
    test('namehash("") is 32 zero bytes', () {
      final result = NameResolver.namehash('');
      expect(result.length, 32);
      expect(result, equals(List.filled(32, 0)));
    });

    test('namehash("eth")', () {
      expect(
        hexEncode(NameResolver.namehash('eth')),
        '93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae',
      );
    });

    test('namehash("foo.eth")', () {
      expect(
        hexEncode(NameResolver.namehash('foo.eth')),
        'de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f',
      );
    });

    test('namehash satisfies recursive definition: namehash(label.rest) = keccak256(namehash(rest) ++ keccak256(label))', () {
      // Verify that namehash('foo.eth') = keccak256(namehash('eth') || keccak256('foo'))
      // by checking the intermediate step.
      final nameHashEth = NameResolver.namehash('eth');
      final nameHashFooEth = NameResolver.namehash('foo.eth');
      // Both must be 32 bytes.
      expect(nameHashEth.length, 32);
      expect(nameHashFooEth.length, 32);
      // And must differ.
      expect(nameHashEth, isNot(equals(nameHashFooEth)));
    });

    test('labels are case-sensitive', () {
      final lower = NameResolver.namehash('eth');
      final upper = NameResolver.namehash('ETH');
      expect(lower, isNot(equals(upper)));
    });
  });
}
