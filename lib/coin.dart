import 'src/crypto/vault_keeper.dart';

// Core
export 'src/core/bytes.dart';
export 'src/core/hex.dart';
export 'src/core/checks.dart';
export 'src/core/wire.dart';
export 'src/core/random.dart';

// Crypto engine
export 'src/crypto/gates/curve_gate.dart';
export 'src/crypto/gates/ed25519_gate.dart';
export 'src/crypto/gates/digest_gate.dart';
export 'src/crypto/gates/key_forge.dart';
export 'src/crypto/gates/codec_gate.dart';
export 'src/crypto/crypto_vault.dart';
export 'src/crypto/vault_keeper.dart';

// Keys & signatures
export 'src/crypto/secret_key.dart';
export 'src/crypto/public_key.dart';
export 'src/crypto/derived_key.dart';
export 'src/crypto/mnemonic.dart';
export 'src/crypto/ecdsa_sig.dart';
export 'src/crypto/schnorr_sig.dart';
export 'src/crypto/message_sig.dart';

// Hash
export 'src/hash/digest.dart';
export 'src/hash/hmac.dart';
export 'src/hash/tagged.dart';

// Encode (RLP is in coin_evm)
export 'src/encode/base58.dart';
export 'src/encode/bech32.dart';
export 'src/encode/wif.dart';

// Script
export 'src/script/opcodes.dart';
export 'src/script/operations.dart';
export 'src/script/script.dart';
export 'src/script/locking.dart';
export 'src/script/lockings/pay_to_pubkey_hash.dart';
export 'src/script/lockings/pay_to_script_hash.dart';
export 'src/script/lockings/pay_to_witness_pubkey.dart';
export 'src/script/lockings/pay_to_witness_script.dart';
export 'src/script/lockings/pay_to_taproot.dart';
export 'src/script/lockings/pay_to_witness.dart';
export 'src/script/lockings/multisig.dart';

// Transaction
export 'src/tx/outpoint.dart';
export 'src/tx/tx_output.dart';
export 'src/tx/tx.dart';
export 'src/tx/ext_tx.dart';
export 'src/tx/funding.dart';
export 'src/tx/inputs/tx_input.dart';
export 'src/tx/inputs/input_sig.dart';
export 'src/tx/inputs/legacy_input.dart';
export 'src/tx/inputs/witness_input.dart';
export 'src/tx/inputs/p2pkh_input.dart';
export 'src/tx/inputs/p2wpkh_input.dart';
export 'src/tx/inputs/p2sh_multisig_input.dart';
export 'src/tx/inputs/taproot_key_input.dart';
export 'src/tx/inputs/taproot_script_input.dart';
export 'src/tx/sighash/sighash_type.dart';
export 'src/tx/sighash/hasher.dart';
export 'src/tx/sighash/legacy_hasher.dart';
export 'src/tx/sighash/witness_hasher.dart';
export 'src/tx/sighash/taproot_hasher.dart';

// Address
export 'src/addr/addr.dart';
export 'src/addr/legacy_addr.dart';
export 'src/addr/segwit_addr.dart';
export 'src/addr/taproot_addr.dart';
export 'src/addr/unknown_witness_addr.dart';

// Taproot
export 'src/taproot/taproot.dart';

// Chain
export 'src/chain/chain.dart';
export 'src/chain/denomination.dart';

// Wallet (HD account address derivation)
export 'src/wallet/hd_account.dart';

Future<void> initCoin() => VaultKeeper.initialize();
