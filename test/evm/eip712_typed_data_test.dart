import 'dart:typed_data';

import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  // EIP-712 typed-data hashing - official "Mail" example.
  // Source: https://github.com/ethereum/EIPs/blob/master/assets/eip-712/Example.js
  // (The Example.sol / Example.js from the EIP-712 canonical reference assets,
  //  confirmed by the in-source assertions in Example.js.)
  //
  // Domain:
  //   name              = "Ether Mail"
  //   version           = "1"
  //   chainId           = 1
  //   verifyingContract = 0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC
  //
  // Types:
  //   EIP712Domain(string name, string version, uint256 chainId, address verifyingContract)
  //   Person(string name, address wallet)
  //   Mail(Person from, Person to, string contents)
  //
  // Message:
  //   from     = { name: "Cow",  wallet: 0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826 }
  //   to       = { name: "Bob",  wallet: 0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB }
  //   contents = "Hello, Bob!"
  group('EIP-712 typed data - Mail example (EIP-712 Example.js)', () {
    late TypedPayload mail;

    setUp(() {
      mail = TypedPayload(
        domain: {
          'name': 'Ether Mail',
          'version': '1',
          'chainId': 1,
          'verifyingContract': 'CcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
        primaryType: 'Mail',
        types: {
          'EIP712Domain': [
            {'name': 'name', 'type': 'string'},
            {'name': 'version', 'type': 'string'},
            {'name': 'chainId', 'type': 'uint256'},
            {'name': 'verifyingContract', 'type': 'address'},
          ],
          'Person': [
            {'name': 'name', 'type': 'string'},
            {'name': 'wallet', 'type': 'address'},
          ],
          'Mail': [
            {'name': 'from', 'type': 'Person'},
            {'name': 'to', 'type': 'Person'},
            {'name': 'contents', 'type': 'string'},
          ],
        },
        message: {
          'from': {'name': 'Cow', 'wallet': 'CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826'},
          'to': {'name': 'Bob', 'wallet': 'bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB'},
          'contents': 'Hello, Bob!',
        },
      );
    });

    // Domain separator = hashStruct("EIP712Domain", domain).
    // Source: Example.js assertion: assert.equal(structHash("EIP712Domain", ...) = 0xf2cee375...)
    test('domain separator matches Example.js', () {
      expect(
        hexEncode(mail.domainSeparator()),
        'f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f',
      );
    });

    // Struct hash = hashStruct("Mail", message).
    // Source: Example.js assertion: structHash("Mail", ...) = 0xc52c0ee5...
    test('struct hash (Mail message) matches Example.js', () {
      expect(
        hexEncode(mail.structHash()),
        'c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e',
      );
    });

    // Final signing hash = keccak256("\x19\x01" || domainSeparator || structHash).
    // Source: Example.js assertion: signingHash = 0xbe609aee...
    test('signing hash matches Example.js', () {
      expect(
        hexEncode(mail.signingHash()),
        'be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2',
      );
    });

    test('signing hash has correct EIP-191 prefix (\\x19\\x01)', () {
      // The signing hash is keccak256 of exactly "\x19\x01" + domain + struct.
      final ds = mail.domainSeparator();
      final sh = mail.structHash();
      final expected = keccak256(
          Uint8List.fromList([0x19, 0x01, ...ds, ...sh]));
      expect(mail.signingHash(), equals(expected));
    });
  });
}
