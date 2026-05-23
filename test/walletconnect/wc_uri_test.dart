import 'package:coin/coin_walletconnect.dart';
import 'package:test/test.dart';

/// WalletConnect `wc:` URI (EIP-1328) parse/serialize round-trips.
///
/// The scheme/param layout is EIP-1328
/// (https://eips.ethereum.org/EIPS/eip-1328). The v1Uri/v2Uri fixtures
/// (topic/version/bridge/key, symKey/relay-protocol) were captured with
/// wallet_connect_uri_validator@0.1.0, repo
/// https://github.com/SimplioOfficial/wallet-connect-uri-validator
/// (goldens/uri.out). The swapped-param variant is a permutation of the same
/// v2 URI (parser-order tolerance).
void main() {
  const v1Uri =
      'wc:8a5e5bdc-a0e4-4702-ba63-8f1a5655744f@1?bridge=https%3A%2F%2Fbridge.walletconnect.org&key=41791102999c339c844880b23950704cc43aa840f3739e365323cda4dfa89e7a';
  const v2Uri =
      'wc:7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9@2?relay-protocol=irn&symKey=587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303';

  test('parses a v1 URI', () {
    final u = WcUri.parse(v1Uri);
    expect(u.version, 1);
    expect(u.topic, '8a5e5bdc-a0e4-4702-ba63-8f1a5655744f');
    expect(u.bridge, 'https://bridge.walletconnect.org');
    expect(u.key,
        '41791102999c339c844880b23950704cc43aa840f3739e365323cda4dfa89e7a');
  });

  test('v1 URI round-trips exactly', () {
    expect(WcUri.parse(v1Uri).serialize(), v1Uri);
  });

  test('parses a v2 URI', () {
    final u = WcUri.parse(v2Uri);
    expect(u.version, 2);
    expect(u.topic,
        '7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9');
    expect(u.relayProtocol, 'irn');
    expect(u.symKey,
        '587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303');
  });

  test('v2 URI round-trips exactly', () {
    expect(WcUri.parse(v2Uri).serialize(), v2Uri);
  });

  test('parse tolerates v2 param order variation', () {
    const swapped =
        'wc:7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9@2?symKey=587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303&relay-protocol=irn';
    final u = WcUri.parse(swapped);
    expect(u.relayProtocol, 'irn');
    expect(u.symKey,
        '587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303');
  });
}
