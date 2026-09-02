import 'dart:async';

import 'package:coin/src/crypto/soft/soft_curve_gate.dart';
import 'package:coin/src/crypto/vault_keeper.dart';
import 'package:test/test.dart';

void main() {
  setUp(VaultKeeper.reset);
  tearDown(VaultKeeper.reset);

  test('concurrent initialize calls share one backend construction', () async {
    final entered = Completer<void>();
    final release = Completer<void>();
    var calls = 0;
    VaultKeeper.registerAsync(curve: () async {
      calls++;
      entered.complete();
      await release.future;
      return SoftCurveGate();
    });

    final first = VaultKeeper.initialize();
    final second = VaultKeeper.initialize();
    await entered.future;

    expect(calls, 1);
    expect(identical(first, second), isTrue);
    release.complete();
    await Future.wait([first, second]);
    expect(VaultKeeper.vault.curve, isA<SoftCurveGate>());
  });

  test('reset prevents stale initialization from publishing a vault', () async {
    final entered = Completer<void>();
    final release = Completer<void>();
    VaultKeeper.registerAsync(curve: () async {
      entered.complete();
      await release.future;
      return SoftCurveGate();
    });

    final stale = VaultKeeper.initialize();
    await entered.future;
    VaultKeeper.reset();

    expect(() => VaultKeeper.vault, throwsStateError);
    await VaultKeeper.initialize();
    final freshVault = VaultKeeper.vault;

    release.complete();
    await stale;
    expect(identical(VaultKeeper.vault, freshVault), isTrue);
  });
}
