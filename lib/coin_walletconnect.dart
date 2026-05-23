/// WalletConnect transport cryptography (web-safe).
///
/// This barrel exposes only the WalletConnect transport primitives: the v2
/// envelope crypto (X25519 -> HKDF symKey, SHA-256 topic, ChaCha20-Poly1305
/// type-0/1 envelopes), the EdDSA relay-auth JWT (did:key), the `wc:` URI
/// (v1 + v2), and the WC v1 AES-CBC+HMAC cipher - plus the underlying
/// in-house primitives they build on. The higher-level Sign/Auth protocol
/// engine is not part of this build.
library;

export 'coin.dart';

// In-house crypto primitives the WC transport builds on.
export 'src/hash/hkdf.dart';
export 'src/crypto/soft/aes.dart';
export 'src/crypto/soft/chacha20_poly1305.dart';
export 'src/crypto/soft/x25519.dart';
export 'src/crypto/soft/ed25519_sign.dart';

// WC transport crypto (reown / wallet_connect_dart_v2 fixtures).
export 'src/ext/walletconnect/wc_crypto.dart';
export 'src/ext/walletconnect/wc_relay_auth.dart';
export 'src/ext/walletconnect/wc_uri.dart';
export 'src/ext/walletconnect/wc_v1_cipher.dart';
