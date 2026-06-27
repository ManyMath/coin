# Changelog

## Unreleased

- Crypto primitives: X25519 (RFC 7748), ChaCha20-Poly1305 (RFC 8439),
  Ed25519 (RFC 8032), AES-256-CBC, HKDF (RFC 5869), SHA-256/512, HMAC
  (RFC 4231), RIPEMD-160; NIST P-256 ES256 verify + JWK decode.
- BIP-327 MuSig2 noncecoef fix; off-curve public-key rejection. secp256k1
  ECDSA, Schnorr (BIP-340), BIP-32/39, Base58Check, bech32/bech32m, RLP.
- Firo/Dash special transactions (DIP-2 / ExTx); MWEB (Litecoin) parse/txid
  + ltcmweb address parsing; taproot BIP-341 key-path fix; PSBT BIP-174;
  TxAssembler BIP-143 witness + BIP-69 ordering.
- EVM: EIP-1014 CREATE2; EIP-55/155/2930/1559/191/712/137, RLP, ABI,
  ERC-4337 userOpHash, EIP-7702, ERC-1271.
- WalletConnect transport crypto only (no Sign/Auth engine): v2 envelopes,
  SHA-256 topic, EdDSA relay-auth JWT, `wc:` URI, v1 AES-CBC+HMAC cipher;
  Verify API attestation via the in-house P-256.
- HD account address derivation (BIP-44/49/84/86).

## 0.1.0

- Initial release.
- Bitcoin: P2PKH, P2SH, P2WPKH, P2WSH, P2TR address types and signing.
- BIP-32 HD key derivation (`DerivedKey`, `DerivedSecretKey`, `DerivedPublicKey`).
- BIP-39 mnemonic generation and BIP-39 seed derivation (PBKDF2-HMAC-SHA512).
- BIP-340 Schnorr signing and verification (`SchnorrSig`).
- BIP-143 witness sighash (`WitnessSigHasher`) and legacy sighash (`LegacySigHasher`).
- BIP-174 PSBT builder.
- BIP-47 payment codes and shared address derivation.
- BIP-327 MuSig2 key aggregation and partial signing.
- UTXO chain support: BCH (SIGHASH_FORKID), Litecoin, Dogecoin.
- Ethereum / EVM: EIP-55 addresses, EIP-1559 and legacy transactions, ABI codec.
- Monero: Ed25519 keys, primary and subaddresses, ring signature primitives.
- secp256k1 via native FFI (`libsecp256k1`) on native targets; pure-Dart fallback for web.
- Ed25519 via native FFI on native targets; pure-Dart fallback.
- Bech32 and Bech32m encode/decode (BIP-173, BIP-350).
- Base58Check encode/decode.
- Hash functions: SHA-256, SHA-512, RIPEMD-160, HMAC-SHA-256/512, PBKDF2.
