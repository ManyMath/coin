import 'dart:typed_data';

import 'package:coin/coin.dart';
import 'package:test/test.dart';

/// Regression test: the legacy (pre-segwit) signature hash preimage must NOT
/// include the MWEB extension-block bytes. Litecoin Core's
/// CTransactionSignatureSerializer::Serialize omits the MWEB block, so two
/// transactions that differ ONLY in mwebBytes must produce identical legacy
/// sighashes. This pins the invariant so a future refactor cannot silently
/// regress it.
void main() {
  setUpAll(() async {
    await VaultKeeper.initialize();
  });

  final prevScript = hexDecode('76a914000000000000000000000000000000000000000088ac');

  Tx buildTx({Uint8List? mwebBytes}) => Tx(
        version: 2,
        inputs: [
          RawInput(prevOut: Outpoint(txid: Uint8List(32), vout: 0)),
        ],
        outputs: [
          TxOutput(value: BigInt.from(1000), scriptPubKey: Uint8List(0)),
        ],
        mwebBytes: mwebBytes,
      );

  test('legacy sighash ignores mwebBytes', () {
    final plain = buildTx();
    final withMweb = buildTx(mwebBytes: Uint8List.fromList([0x01, 0x02, 0x03]));

    // Sanity: ensure we are actually exercising the filtering, not a no-op.
    expect(plain.mwebBytes, isNull);
    expect(withMweb.mwebBytes, isNotNull);

    final hasher = LegacySigHasher();
    final hashPlain =
        hasher.hash(plain, 0, SigHashType.all, prevScript: prevScript);
    final hashMweb =
        hasher.hash(withMweb, 0, SigHashType.all, prevScript: prevScript);

    expect(hashMweb, equals(hashPlain));
  });
}
