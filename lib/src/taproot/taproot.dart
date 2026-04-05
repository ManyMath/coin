import 'dart:typed_data';
import '../core/bytes.dart';
import '../hash/tagged.dart';
import '../crypto/vault_keeper.dart';
import '../crypto/secret_key.dart';
import '../crypto/public_key.dart';

abstract class TapTree {
  Uint8List get hash;
}

class TapLeaf implements TapTree {
  final int leafVersion;
  final Uint8List script;

  TapLeaf({this.leafVersion = 0xc0, required this.script});

  @override
  Uint8List get hash => taggedHash('TapLeaf',
      Uint8List.fromList([leafVersion, ...script.length.toVarBytes(), ...script]));
}

class TapBranch implements TapTree {
  final TapTree left;
  final TapTree right;

  TapBranch(this.left, this.right);

  @override
  Uint8List get hash {
    final a = left.hash;
    final b = right.hash;
    // Lexicographic ordering
    if (compareBytes(a, b) <= 0) {
      return taggedHash('TapBranch', concatBytes([a, b]));
    } else {
      return taggedHash('TapBranch', concatBytes([b, a]));
    }
  }
}

class Taproot {
  final PublicKey internalKey;
  final TapTree? tree;

  Taproot({required this.internalKey, this.tree});

  Uint8List get tweak {
    final xOnly = internalKey.xOnly;
    if (tree == null) {
      return taggedHash('TapTweak', xOnly);
    }
    return taggedHash('TapTweak', concatBytes([xOnly, tree!.hash]));
  }

  /// The even-Y lift of the internal key (BIP-340 `lift_x` of its x-only
  /// coordinate), as a 33-byte compressed point. BIP-341 tweaking operates on
  /// this, NOT the raw-parity internal point - otherwise an odd-Y internal key
  /// yields an output key (and address) inconsistent with the tweaked secret
  /// key produced by [tweakSecretKey].
  Uint8List get _evenInternalKey =>
      Uint8List.fromList([0x02, ...internalKey.xOnly]);

  /// Returns the x-only tweaked output key (32 bytes).
  Uint8List get tweakedKey {
    final tweaked = VaultKeeper.vault.curve
        .publicKeyTweakAdd(_evenInternalKey, tweak);
    if (tweaked == null) throw StateError('Failed to tweak public key');
    return PublicKey(tweaked).xOnly;
  }

  SecretKey tweakSecretKey(SecretKey key) {
    // BIP-341: taproot tweaking operates on the x-only (even-Y) representation
    // of the internal key. If the internal public key has an odd Y, the secret
    // key must be negated so that d*G has even Y before adding the tweak.
    final effective = key.publicKey.yIsEven ? key : key.negate();
    final tweaked = effective.tweak(tweak);
    if (tweaked == null) throw StateError('Failed to tweak secret key');
    return tweaked;
  }

  Uint8List controlBlockForLeaf(TapLeaf leaf) {
    final path = _merkleProof(tree!, leaf);
    if (path == null) throw ArgumentError('Leaf not found in tree');
    final xOnly = internalKey.xOnly;
    final parity = PublicKey(
        VaultKeeper.vault.curve.publicKeyTweakAdd(
            _evenInternalKey, tweak)!).yIsEven
        ? 0
        : 1;
    return Uint8List.fromList([
      leaf.leafVersion | parity,
      ...xOnly,
      ...path,
    ]);
  }

  List<int>? _merkleProof(TapTree node, TapLeaf target) {
    if (node is TapLeaf) {
      if (bytesEqual(node.hash, target.hash)) return [];
      return null;
    }
    if (node is TapBranch) {
      final leftProof = _merkleProof(node.left, target);
      if (leftProof != null) return [...leftProof, ...node.right.hash];
      final rightProof = _merkleProof(node.right, target);
      if (rightProof != null) return [...rightProof, ...node.left.hash];
    }
    return null;
  }
}

extension _VarInt on int {
  Uint8List toVarBytes() {
    if (this < 0xfd) return Uint8List.fromList([this]);
    if (this <= 0xffff) {
      return Uint8List.fromList([0xfd, this & 0xff, (this >> 8) & 0xff]);
    }
    return Uint8List.fromList([
      0xfe,
      this & 0xff, (this >> 8) & 0xff,
      (this >> 16) & 0xff, (this >> 24) & 0xff,
    ]);
  }
}
