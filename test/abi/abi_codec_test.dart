import 'dart:convert';
import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

// Word-level encoding layouts (left-padded uint/address, right-padded
// fixed-bytes, the offset+length+padded-data form of string/bytes, dynamic and
// fixed array layouts, tuple/head-tail layout) follow the Solidity Contract
// ABI Specification, "Formal Specification of the Encoding":
//   https://docs.soliditylang.org/en/latest/abi-spec.html
//
// Function selectors (a9059cbb, 095ea7b3, 70a08231, 23b872dd) are the ERC-20
// selectors: selector = bytes4(keccak256("<signature>")).
//   https://eips.ethereum.org/EIPS/eip-20, https://www.4byte.directory/
//
// The address 0xd8dA6BF2...96045 used throughout is the public vitalik.eth
// address (input data only, not a spec vector).
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('SolUint encoding', () {
    test('encode uint256(0) is 32 zero bytes', () {
      final t = SolUint(256);
      final encoded = t.encode(BigInt.zero);
      expect(encoded.length, 32);
      expect(encoded, equals(Uint8List(32)));
    });

    test('encode uint256(1) has 1 in last byte', () {
      final t = SolUint(256);
      final encoded = t.encode(BigInt.one);
      expect(encoded.length, 32);
      final expected = Uint8List(32);
      expected[31] = 1;
      expect(encoded, equals(expected));
    });

    test('encode uint256(256) produces 0x...0100', () {
      final t = SolUint(256);
      final encoded = t.encode(BigInt.from(256));
      expect(encoded.length, 32);
      final expected = Uint8List(32);
      expected[30] = 0x01;
      expected[31] = 0x00;
      expect(encoded, equals(expected));
    });

    test('encode uint256 max value', () {
      final t = SolUint(256);
      final maxVal = (BigInt.one << 256) - BigInt.one;
      final encoded = t.encode(maxVal);
      expect(encoded.length, 32);
      expect(encoded, equals(Uint8List.fromList(List.filled(32, 0xff))));
    });

    test('uint8 encode small value', () {
      final t = SolUint(8);
      final encoded = t.encode(42);
      expect(encoded.length, 32);
      final expected = Uint8List(32);
      expected[31] = 42;
      expect(encoded, equals(expected));
    });

    test('uint256 rejects negative value', () {
      final t = SolUint(256);
      expect(() => t.encode(BigInt.from(-1)), throwsArgumentError);
    });

    test('uint8 rejects overflow', () {
      final t = SolUint(8);
      expect(() => t.encode(BigInt.from(256)), throwsArgumentError);
    });
  });

  group('SolUint decode', () {
    test('decode uint256 round-trip', () {
      final t = SolUint(256);
      final value = BigInt.from(123456789);
      final encoded = t.encode(value);
      final (decoded, consumed) = t.decode(encoded, 0);
      expect(decoded, equals(value));
      expect(consumed, 32);
    });

    test('decode uint8 masks to 8 bits', () {
      final t = SolUint(8);
      final encoded = t.encode(255);
      final (decoded, consumed) = t.decode(encoded, 0);
      expect(decoded, equals(BigInt.from(255)));
      expect(consumed, 32);
    });
  });

  // Address d8dA6BF2... is vitalik.eth (a well-known public address).
  group('SolAddress encoding', () {
    test('address is left-padded to 32 bytes', () {
      final t = SolAddress();
      final addr = hexDecode('d8dA6BF26964aF9D7eEd9e03E53415D37aA96045');
      final encoded = t.encode(addr);
      expect(encoded.length, 32);
      expect(encoded.sublist(0, 12), equals(Uint8List(12)));
      expect(encoded.sublist(12, 32), equals(addr));
    });

    test('address from hex string', () {
      final t = SolAddress();
      final encoded = t.encode('d8dA6BF26964aF9D7eEd9e03E53415D37aA96045');
      expect(encoded.length, 32);
      expect(encoded.sublist(0, 12), equals(Uint8List(12)));
    });

    test('address rejects wrong length', () {
      final t = SolAddress();
      expect(
          () => t.encode(Uint8List(19)), throwsArgumentError);
      expect(
          () => t.encode(Uint8List(21)), throwsArgumentError);
    });
  });

  group('SolAddress decode', () {
    test('decode address round-trip', () {
      final t = SolAddress();
      final addr = hexDecode('d8dA6BF26964aF9D7eEd9e03E53415D37aA96045');
      final encoded = t.encode(addr);
      final (decoded, consumed) = t.decode(encoded, 0);
      expect(decoded as Uint8List, equals(addr));
      expect(consumed, 32);
    });
  });

  group('SolString encoding', () {
    test('string encoding: offset + length + padded data', () {
      final t = SolString();
      final encoded = t.encode('Hello, World!');
      expect(encoded.length, 64);

      final lengthSlot = Uint8List(32);
      lengthSlot[31] = 13;
      expect(encoded.sublist(0, 32), equals(lengthSlot));

      final strBytes = encoded.sublist(32, 32 + 13);
      expect(String.fromCharCodes(strBytes), 'Hello, World!');

      final padding = encoded.sublist(45, 64);
      expect(padding, equals(Uint8List(19)));
    });

    test('empty string', () {
      final t = SolString();
      final encoded = t.encode('');
      expect(encoded.length, 32);
    });

    test('string exactly 32 bytes', () {
      final t = SolString();
      final s = 'a' * 32;
      final encoded = t.encode(s);
      expect(encoded.length, 64);
    });

    test('string 33 bytes requires second data slot', () {
      final t = SolString();
      final s = 'a' * 33;
      final encoded = t.encode(s);
      expect(encoded.length, 96);
    });
  });

  group('SolString decode', () {
    test('decode string round-trip', () {
      final t = SolString();
      final encoded = t.encode('Hello, World!');
      final (decoded, _) = t.decode(encoded, 0);
      expect(decoded, 'Hello, World!');
    });

    test('decode empty string', () {
      final t = SolString();
      final encoded = t.encode('');
      final (decoded, _) = t.decode(encoded, 0);
      expect(decoded, '');
    });
  });

  group('SolBool encoding', () {
    test('true encodes to 1 in last byte', () {
      final t = SolBool();
      final encoded = t.encode(true);
      expect(encoded.length, 32);
      final expected = Uint8List(32);
      expected[31] = 1;
      expect(encoded, equals(expected));
    });

    test('false encodes to all zeros', () {
      final t = SolBool();
      final encoded = t.encode(false);
      expect(encoded, equals(Uint8List(32)));
    });

    test('round-trip', () {
      final t = SolBool();
      final (trueVal, _) = t.decode(t.encode(true), 0);
      final (falseVal, _) = t.decode(t.encode(false), 0);
      expect(trueVal, isTrue);
      expect(falseVal, isFalse);
    });
  });

  group('Tuple encoding (multiple params)', () {
    test('encode (uint256, address) tuple', () {
      final types = [SolUint(256), SolAddress()];
      final values = [
        BigInt.from(1000),
        hexDecode('d8dA6BF26964aF9D7eEd9e03E53415D37aA96045'),
      ];

      final encoded = SolCodec.encodeParameters(types, values);
      expect(encoded.length, 64);

      final decoded = SolCodec.decodeParameters(types, encoded);
      expect(decoded[0], equals(BigInt.from(1000)));
      expect(decoded[1] as Uint8List,
          equals(hexDecode('d8dA6BF26964aF9D7eEd9e03E53415D37aA96045')));
    });

    test('encode (address, uint256, string) with dynamic type', () {
      final types = [SolAddress(), SolUint(256), SolString()];
      final values = [
        hexDecode('d8dA6BF26964aF9D7eEd9e03E53415D37aA96045'),
        BigInt.from(100),
        'hello',
      ];

      final encoded = SolCodec.encodeParameters(types, values);
      expect(encoded.length, 160);

      final decoded = SolCodec.decodeParameters(types, encoded);
      expect(decoded[0] as Uint8List,
          equals(hexDecode('d8dA6BF26964aF9D7eEd9e03E53415D37aA96045')));
      expect(decoded[1], equals(BigInt.from(100)));
      expect(decoded[2], 'hello');
    });

    test('SolTuple type with named fields', () {
      final tupleType = SolTuple(
        [SolUint(256), SolBool()],
        names: ['amount', 'active'],
      );

      final encoded = tupleType.encode([BigInt.from(42), true]);
      expect(encoded.length, 64);

      final (decoded, consumed) = tupleType.decode(encoded, 0);
      final list = decoded as List;
      expect(list[0], equals(BigInt.from(42)));
      expect(list[1], isTrue);
      expect(consumed, 64);
    });
  });

  group('Dynamic array encoding', () {
    test('encode uint256[] dynamic array', () {
      final t = SolArray(SolUint(256));
      final values = [BigInt.from(1), BigInt.from(2), BigInt.from(3)];
      final encoded = t.encode(values);
      expect(encoded.length, 128);

      final (decoded, _) = t.decode(encoded, 0);
      final list = decoded as List;
      expect(list.length, 3);
      expect(list[0], equals(BigInt.from(1)));
      expect(list[1], equals(BigInt.from(2)));
      expect(list[2], equals(BigInt.from(3)));
    });

    test('encode empty dynamic array', () {
      final t = SolArray(SolUint(256));
      final encoded = t.encode([]);
      expect(encoded.length, 32);

      final (decoded, _) = t.decode(encoded, 0);
      expect((decoded as List).length, 0);
    });

    test('encode dynamic array of strings', () {
      final t = SolArray(SolString());
      final values = ['hello', 'world'];
      final encoded = t.encode(values);

      final (decoded, _) = t.decode(encoded, 0);
      final list = decoded as List;
      expect(list.length, 2);
      expect(list[0], 'hello');
      expect(list[1], 'world');
    });

    test('fixed-size array uint256[2]', () {
      final t = SolArray(SolUint(256), 2);
      expect(t.name, 'uint256[2]');
      expect(t.isDynamic, isFalse);

      final encoded = t.encode([BigInt.from(10), BigInt.from(20)]);
      expect(encoded.length, 64);

      final (decoded, _) = t.decode(encoded, 0);
      final list = decoded as List;
      expect(list[0], equals(BigInt.from(10)));
      expect(list[1], equals(BigInt.from(20)));
    });

    test('fixed array rejects wrong length', () {
      final t = SolArray(SolUint(256), 2);
      expect(() => t.encode([BigInt.from(1)]), throwsArgumentError);
      expect(
        () => t.encode([BigInt.from(1), BigInt.from(2), BigInt.from(3)]),
        throwsArgumentError,
      );
    });
  });

  // ERC-20 function selectors are the first 4 bytes of keccak256(signature).
  // https://eips.ethereum.org/EIPS/eip-20, https://www.4byte.directory/
  group('Function selector', () {
    test('transfer(address,uint256) selector', () {
      final sel = SolCodec.selector('transfer(address,uint256)');
      expect(sel.length, 4);
      expect(hexEncode(sel), 'a9059cbb');
    });

    test('approve(address,uint256) selector', () {
      final sel = SolCodec.selector('approve(address,uint256)');
      expect(sel.length, 4);
      expect(hexEncode(sel), '095ea7b3');
    });

    test('balanceOf(address) selector', () {
      final sel = SolCodec.selector('balanceOf(address)');
      expect(sel.length, 4);
      expect(hexEncode(sel), '70a08231');
    });

    test('transferFrom(address,address,uint256) selector', () {
      final sel = SolCodec.selector('transferFrom(address,address,uint256)');
      expect(sel.length, 4);
      expect(hexEncode(sel), '23b872dd');
    });
  });

  group('SolFunction', () {
    test('encodeCall produces selector + params', () {
      final fn = SolFunction(
        name: 'transfer',
        inputs: [SolAddress(), SolUint(256)],
        outputs: [SolBool()],
      );

      expect(fn.signature, 'transfer(address,uint256)');
      expect(hexEncode(fn.selector), 'a9059cbb');

      final calldata = fn.encodeCall([
        hexDecode('d8dA6BF26964aF9D7eEd9e03E53415D37aA96045'),
        BigInt.from(1000000),
      ]);
      expect(calldata.length, 68);
      expect(hexEncode(calldata.sublist(0, 4)), 'a9059cbb');
    });

    test('decodeResult extracts return values', () {
      final fn = SolFunction(
        name: 'balanceOf',
        inputs: [SolAddress()],
        outputs: [SolUint(256)],
      );

      final returnData = SolUint(256).encode(BigInt.from(1000));
      final result = fn.decodeResult(returnData);
      expect(result.length, 1);
      expect(result[0], equals(BigInt.from(1000)));
    });

    test('isReadOnly for view/pure functions', () {
      final viewFn = SolFunction(
        name: 'balanceOf',
        inputs: [SolAddress()],
        outputs: [SolUint(256)],
        stateMutability: 'view',
      );
      expect(viewFn.isReadOnly, isTrue);

      final pureFn = SolFunction(
        name: 'add',
        inputs: [SolUint(256), SolUint(256)],
        outputs: [SolUint(256)],
        stateMutability: 'pure',
      );
      expect(pureFn.isReadOnly, isTrue);

      final writeFn = SolFunction(
        name: 'transfer',
        inputs: [SolAddress(), SolUint(256)],
        outputs: [SolBool()],
      );
      expect(writeFn.isReadOnly, isFalse);
    });
  });

  group('SolCodec.encodeCall', () {
    test('encodeCall produces selector + ABI-encoded params', () {
      final calldata = SolCodec.encodeCall(
        'transfer(address,uint256)',
        [SolAddress(), SolUint(256)],
        [
          hexDecode('d8dA6BF26964aF9D7eEd9e03E53415D37aA96045'),
          BigInt.from(1000000),
        ],
      );

      expect(calldata.length, 68);
      expect(hexEncode(calldata.sublist(0, 4)), 'a9059cbb');
    });
  });

  group('SolInt encoding', () {
    test('encode int256(-1) is all 0xff', () {
      final t = SolInt(256);
      final encoded = t.encode(BigInt.from(-1));
      expect(encoded, equals(Uint8List.fromList(List.filled(32, 0xff))));
    });

    test('encode int256(0)', () {
      final t = SolInt(256);
      final encoded = t.encode(BigInt.zero);
      expect(encoded, equals(Uint8List(32)));
    });

    test('int256 round-trip with negative value', () {
      final t = SolInt(256);
      final value = BigInt.from(-12345);
      final encoded = t.encode(value);
      final (decoded, consumed) = t.decode(encoded, 0);
      expect(decoded, equals(value));
      expect(consumed, 32);
    });

    test('int8 range check', () {
      final t = SolInt(8);
      expect(() => t.encode(128), throwsArgumentError);
      expect(() => t.encode(-129), throwsArgumentError);
      // Valid boundary
      final encoded127 = t.encode(127);
      final (d127, _) = t.decode(encoded127, 0);
      expect(d127, equals(BigInt.from(127)));

      final encodedNeg128 = t.encode(-128);
      final (dNeg128, _) = t.decode(encodedNeg128, 0);
      expect(dNeg128, equals(BigInt.from(-128)));
    });
  });

  group('SolFixedBytes encoding', () {
    test('bytes4 right-padded to 32', () {
      final t = SolFixedBytes(4);
      final value = Uint8List.fromList([0xde, 0xad, 0xbe, 0xef]);
      final encoded = t.encode(value);
      expect(encoded.length, 32);
      expect(encoded.sublist(0, 4), equals(value));
      expect(encoded.sublist(4), equals(Uint8List(28)));
    });

    test('bytes32 full slot', () {
      final t = SolFixedBytes(32);
      final value = Uint8List.fromList(List.filled(32, 0xab));
      final encoded = t.encode(value);
      expect(encoded, equals(value));
    });

    test('bytes4 round-trip', () {
      final t = SolFixedBytes(4);
      final value = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);
      final encoded = t.encode(value);
      final (decoded, consumed) = t.decode(encoded, 0);
      expect(decoded as Uint8List, equals(value));
      expect(consumed, 32);
    });
  });

  group('SolBytes (dynamic) encoding', () {
    test('encode dynamic bytes', () {
      final t = SolBytes();
      final value = Uint8List.fromList([0xca, 0xfe]);
      final encoded = t.encode(value);
      expect(encoded.length, 64);

      final (decoded, _) = t.decode(encoded, 0);
      expect(decoded as Uint8List, equals(value));
    });

    test('empty bytes', () {
      final t = SolBytes();
      final encoded = t.encode(Uint8List(0));
      expect(encoded.length, 32);

      final (decoded, _) = t.decode(encoded, 0);
      expect((decoded as Uint8List).length, 0);
    });
  });

  // Per the Solidity ABI spec head-tail encoding
  // (https://docs.soliditylang.org/en/latest/abi-spec.html): selector a9059cbb
  // (= bytes4(keccak256("transfer(address,uint256)"))) ++ left-padded address
  // word ++ uint256 word. 0x0de0b6b3a7640000 == 1e18 (1 ETH).
  group('Full ABI encoding vectors', () {
    test('transfer(address,uint256) full calldata', () {
      final to = hexDecode('dEAD000000000000000000000000000000000000');
      final amount = BigInt.parse('1000000000000000000');

      final calldata = SolCodec.encodeCall(
        'transfer(address,uint256)',
        [SolAddress(), SolUint(256)],
        [to, amount],
      );

      final hex = hexEncode(calldata);
      expect(hex.substring(0, 8), 'a9059cbb');
      expect(hex.substring(8, 72),
          '000000000000000000000000dead000000000000000000000000000000000000');
      expect(hex.substring(72),
          '0000000000000000000000000000000000000000000000000de0b6b3a7640000');
    });
  });

  // Two examples from the Solidity Contract ABI Specification, "Use of
  // Dynamic Types" / Examples:
  //   https://docs.soliditylang.org/en/latest/abi-spec.html
  group('Solidity ABI spec examples', () {
    // Spec example: f(uint256,uint32[],bytes10,bytes) with arguments
    //   (0x123, [0x456, 0x789], "1234567890", "Hello, world!").
    // Selector keccak256("f(uint256,uint32[],bytes10,bytes)")[:4] = 0x8be65246.
    // Calldata from the spec's "All together, the encoding is" block:
    test('f(uint256,uint32[],bytes10,bytes) matches spec calldata', () {
      final calldata = SolCodec.encodeCall(
        'f(uint256,uint32[],bytes10,bytes)',
        [
          SolUint(256),
          SolArray(SolUint(32)),
          SolFixedBytes(10),
          SolBytes(),
        ],
        [
          BigInt.from(0x123),
          [BigInt.from(0x456), BigInt.from(0x789)],
          Uint8List.fromList(utf8.encode('1234567890')),
          Uint8List.fromList(utf8.encode('Hello, world!')),
        ],
      );

      expect(
        hexEncode(calldata),
        // Source: https://docs.soliditylang.org/en/latest/abi-spec.html
        '8be65246'
        '0000000000000000000000000000000000000000000000000000000000000123'
        '0000000000000000000000000000000000000000000000000000000000000080'
        '3132333435363738393000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000e0'
        '0000000000000000000000000000000000000000000000000000000000000002'
        '0000000000000000000000000000000000000000000000000000000000000456'
        '0000000000000000000000000000000000000000000000000000000000000789'
        '000000000000000000000000000000000000000000000000000000000000000d'
        '48656c6c6f2c20776f726c642100000000000000000000000000000000000000',
      );
    });

    // Spec example: sam(bytes,bool,uint256[]) with arguments
    //   ("dave", true, [1, 2, 3]).
    // Selector keccak256("sam(bytes,bool,uint256[])")[:4] = 0xa5643bf2.
    // The 292-byte calldata from the spec:
    test('sam(bytes,bool,uint256[]) matches spec calldata', () {
      final calldata = SolCodec.encodeCall(
        'sam(bytes,bool,uint256[])',
        [
          SolBytes(),
          SolBool(),
          SolArray(SolUint(256)),
        ],
        [
          Uint8List.fromList(utf8.encode('dave')),
          true,
          [BigInt.from(1), BigInt.from(2), BigInt.from(3)],
        ],
      );

      expect(
        hexEncode(calldata),
        // Source: https://docs.soliditylang.org/en/latest/abi-spec.html
        'a5643bf2'
        '0000000000000000000000000000000000000000000000000000000000000060'
        '0000000000000000000000000000000000000000000000000000000000000001'
        '00000000000000000000000000000000000000000000000000000000000000a0'
        '0000000000000000000000000000000000000000000000000000000000000004'
        '6461766500000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000003'
        '0000000000000000000000000000000000000000000000000000000000000001'
        '0000000000000000000000000000000000000000000000000000000000000002'
        '0000000000000000000000000000000000000000000000000000000000000003',
      );
    });
  });
}
