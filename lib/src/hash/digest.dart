import 'dart:typed_data';
import '../crypto/vault_keeper.dart';

Uint8List sha256(Uint8List data) => VaultKeeper.vault.digest.sha256(data);
Uint8List sha512(Uint8List data) => VaultKeeper.vault.digest.sha512(data);
Uint8List sha256d(Uint8List data) => VaultKeeper.vault.digest.sha256d(data);
Uint8List hash160(Uint8List data) => VaultKeeper.vault.digest.hash160(data);
Uint8List ripemd160(Uint8List data) => VaultKeeper.vault.digest.ripemd160(data);
Uint8List keccak256(Uint8List data) => VaultKeeper.vault.digest.keccak256(data);
