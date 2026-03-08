import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:coin/src/ext/chains/chain_params.dart';
import 'package:coin/src/ext/chains/firo_params.dart';
import 'package:coin/src/ext/chains/registry.dart';
import 'package:test/test.dart';

// Firo chain parameters sourced from firoorg/firo src/chainparams.cpp
// base58Prefixes. Firo is legacy-base58 only (no SegWit / Bech32).
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  group('FiroParams', () {
    test('firo mainnet has correct values', () {
      final p = FiroParams.firo;
      expect(p.wifPrefix, 0xd2);
      expect(p.p2pkhPrefix, 0x52);
      expect(p.p2shPrefix, 0x07);
      expect(p.bech32Hrp, isNull);
      expect(p.chainName, 'Firo');
      expect(p.ticker, 'FIRO');
      expect(p.identifier, 'firo');
      expect(p.bip44CoinType, 136);
      expect(p.supportsSegwit, isFalse);
      expect(p.supportsTaproot, isFalse);
      expect(p.supportedAddrTypes, [AddrType.p2pkh, AddrType.p2sh]);
    });

    test('firo testnet has correct values', () {
      final p = FiroParams.firoTestnet;
      expect(p.wifPrefix, 0xb9);
      expect(p.p2pkhPrefix, 0x41);
      expect(p.p2shPrefix, 0xb2);
      expect(p.bech32Hrp, isNull);
      expect(p.chainName, 'Firo Testnet');
      expect(p.ticker, 'tFIRO');
      expect(p.identifier, 'firo-testnet');
      expect(p.bip44CoinType, 1);
      expect(p.supportsSegwit, isFalse);
      expect(p.supportsTaproot, isFalse);
      expect(p.supportedAddrTypes, [AddrType.p2pkh, AddrType.p2sh]);
    });
  });

  group('ChainRegistry', () {
    test('byTicker FIRO returns mainnet', () {
      final p = ChainRegistry.byTicker('FIRO');
      expect(p, isNotNull);
      expect(p!.identifier, 'firo');
      expect(p.chainName, 'Firo');
    });

    test('byIdentifier firo-testnet returns testnet', () {
      final p = ChainRegistry.byIdentifier('firo-testnet');
      expect(p, isNotNull);
      expect(p!.ticker, 'tFIRO');
      expect(p.chainName, 'Firo Testnet');
    });
  });

  group('address encoding', () {
    // No public "known" Firo address was sourced, so we pin the exact
    // base58check output for the fixed hash160 0x11 * 20 under Firo's
    // mainnet version bytes. The pinned strings were derived once by
    // encoding with FiroParams.firo.chain and committed here; they fix the
    // version byte (0x52 P2PKH, 0x07 P2SH) and the base58check checksum.
    final hash = Uint8List.fromList(List<int>.filled(20, 0x11));

    test('P2PKH encodes to the pinned Firo address', () {
      final encoded = P2pkhAddr(hash).encode(FiroParams.firo.chain);
      expect(encoded, 'a2GhfyjF8ohJedyaQhQHjHodX4k9Z6VA7U');
    });

    test('P2SH encodes to a Firo P2SH address (leading 3/4)', () {
      final encoded = P2shAddr(hash).encode(FiroParams.firo.chain);
      expect(encoded[0], anyOf(equals('3'), equals('4')));
      expect(encoded, '3qvTpqNdtGwbK8X5aERPMtPdKERQDzrPqk');
    });
  });
}
