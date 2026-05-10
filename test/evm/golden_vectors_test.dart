import 'dart:typed_data';

import 'package:coin/coin_evm.dart';
import 'package:test/test.dart';

/// EVM primitive vectors.
///
/// - keccak256 digests: empty and "quick brown fox" as used in go-ethereum
///   crypto tests
///   (https://github.com/ethereum/go-ethereum/blob/master/crypto/crypto_test.go);
///   "dog" is the RLP-spec string hashed.
/// - EIP-55 checksum addresses: the five EIP-55 "Test Cases",
///   https://eips.ethereum.org/EIPS/eip-55.
/// - secp256k1 RFC-6979 sign, address-from-private-key, EIP-191 personal_sign:
///   deterministic RFC-6979 ECDSA over repo fixture inputs
///   (https://eips.ethereum.org/EIPS/eip-191).
/// - RLP encodings: examples from the RLP spec
///   (https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
///   and ethereum/tests RLPTests,
///   https://github.com/ethereum/tests/blob/develop/RLPTests/rlptest.json).
/// - legacy EIP-155 signed tx: the example transaction from EIP-155,
///   https://eips.ethereum.org/EIPS/eip-155 ("Example"), privkey 0x4646..46.
/// - ABI selector baz(uint32,bool)->0xcdcd77c0: the example from the Solidity
///   ABI spec, https://docs.soliditylang.org/en/latest/abi-spec.html#examples.
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  String kc(String ascii) =>
      hexEncode(keccak256(Uint8List.fromList(ascii.codeUnits)));

  group('keccak256 (Keccak-256, 0x01 padding - not SHA3-256)', () {
    test('empty (std)', () {
      expect(kc(''),
          'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
    });
    test('"dog"', () {
      expect(kc('dog'),
          '41791102999c339c844880b23950704cc43aa840f3739e365323cda4dfa89e7a');
    });
    test('quick brown fox (std)', () {
      expect(kc('The quick brown fox jumps over the lazy dog'),
          '4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15');
    });
  });

  group('EIP-55 checksum address (std)', () {
    String cs(String addr) => EvmAddr.fromHex(addr).toChecksumHex();
    test('all-caps eligible 1', () {
      expect(cs('0x52908400098527886e0f7030069857d2e4169ee7'),
          '0x52908400098527886E0F7030069857D2E4169EE7');
    });
    test('all-caps eligible 2', () {
      expect(cs('0x8617e340b3d01fa5f11f306f4090fd50e238070d'),
          '0x8617E340B3D01FA5F11F306F4090FD50E238070D');
    });
    test('all-lower', () {
      expect(cs('0xde709f2102306220921060314715629080e2fb77'),
          '0xde709f2102306220921060314715629080e2fb77');
    });
    test('mixed 1', () {
      expect(cs('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'),
          '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed');
    });
    test('mixed 2', () {
      expect(cs('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359'),
          '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359');
    });
  });

  // RFC-6979 deterministic ECDSA (low-S) over repo fixture inputs.
  test('secp256k1 ECDSA sign of a 32-byte hash (RFC-6979, low-S) -> r,s,v=27',
      () {
    final hash = hexDecode(
        '82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28');
    final priv = hexDecode(
        '3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1');
    final sig = RecoverableEcdsaSig.sign(
        Uint8List.fromList(hash), Uint8List.fromList(priv));
    final r = hexEncode(sig.bytes.sublist(0, 32));
    final s = hexEncode(sig.bytes.sublist(32, 64));
    expect(r,
        '99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9');
    expect(s,
        '129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66');
    expect(sig.recId + 27, 27);
  });

  // privkey -> uncompressed pubkey -> keccak256[12:] -> EIP-55.
  // Private key is a repo fixture; address is deterministic.
  test('address from private key (uncompressed pubkey -> EIP-55)', () {
    final priv = hexDecode(
        'a2fd51b96dc55aeb14b30d55a6b3121c7b9c599500c1beb92a389c3377adc86e');
    final pub = VaultKeeper.vault.curve
        .derivePublicKey(Uint8List.fromList(priv), compressed: false);
    expect(EvmAddr.fromPublicKey(pub).toChecksumHex(),
        '0x76778e046D73a5B8ce3d03749cE6B1b3D6a12E36');
  });

  // The EIP-155 example private key 0x4646...46 derives to address
  // 0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F (the sender of the EIP-155
  // "Example" transaction, https://eips.ethereum.org/EIPS/eip-155).
  test('address from private key 0x4646..46 -> published EIP-155 address', () {
    final priv = hexDecode(
        '4646464646464646464646464646464646464646464646464646464646464646');
    final pub = VaultKeeper.vault.curve
        .derivePublicKey(Uint8List.fromList(priv), compressed: false);
    expect(EvmAddr.fromPublicKey(pub).toChecksumHex(),
        '0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F');
  });

  // EIP-191 (https://eips.ethereum.org/EIPS/eip-191) prefixed message signed
  // with RFC-6979 deterministic ECDSA; key/message are repo fixtures.
  test('EIP-191 personal_sign -> r||s||v 65 bytes (std)', () {
    final key = SecretKey(hexDecode(
        'a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6'));
    final sig = PersonalSign.signString('A test message', key);
    expect(
      '0x${hexEncode(sig)}',
      '0x0464eee9e2fe1a10ffe48c78b80de1ed8dcf996f3f60955cb2e03cb21903d930'
      '06624da478b3f862582e85b31c6a21c6cae2eee2bd50f55c93c4faad9d9c8d7f1c',
    );
  });

  group('RLP encode (std)', () {
    String rlp(dynamic v) => hexEncode(Rlp.encode(v));
    test('"dog"', () => expect(rlp('dog'), '83646f67'));
    test('empty string', () => expect(rlp(''), '80'));
    test('int 0', () => expect(rlp(0), '80'));
    test('int 1', () => expect(rlp(1), '01'));
    test('int 128', () => expect(rlp(128), '8180'));
    test('int 1024', () => expect(rlp(1024), '820400'));
    test('empty list', () => expect(rlp(<dynamic>[]), 'c0'));
    test('["dog","god","cat"]', () {
      expect(rlp(['dog', 'god', 'cat']), 'cc83646f6783676f6483636174');
    });
  });

  // Example transaction + signed RLP from EIP-155,
  // https://eips.ethereum.org/EIPS/eip-155 ("Example"). Key 0x4646..46.
  test('legacy EIP-155 transaction signing (std spec example)', () {
    final key = SecretKey(hexDecode(
        '4646464646464646464646464646464646464646464646464646464646464646'));
    final tx = Envelope(
      kind: EnvelopeKind.legacy,
      nonce: BigInt.from(9),
      gasPrice: BigInt.from(20000000000),
      gasLimit: BigInt.from(21000),
      to: hexDecode('3535353535353535353535353535353535353535'),
      value: BigInt.parse('1000000000000000000'),
      chainId: BigInt.one,
    );
    final signed = EnvelopeSigner.sign(tx, key);
    expect(
      hexEncode(signed.serialize()),
      'f86c098504a817c800825208943535353535353535353535353535353535353535'
      '880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c'
      '71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc'
      '64214b297fb1966a3b6d83',
    );
  });

  test('ABI function selector (std): baz(uint32,bool) -> 0xcdcd77c0', () {
    expect(hexEncode(SolCodec.selector('baz(uint32,bool)')), 'cdcd77c0');
  });
}
