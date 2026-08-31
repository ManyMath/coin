# Changelog

## 0.2.1

### Fixed: Schnorr/secp256k1 input validation and PSBT v0 map counts

**BIP-340 Schnorr (pure-Dart backend and public API).** Malformed signing
inputs were not rejected consistently: a zero or out-of-range secret key, a
non-32-byte message, or wrongly-sized auxiliary randomness could be hashed
or negated into a signature that does not commit to the supplied input.
`SchnorrSig.sign` and `SchnorrSig.verify` now validate the message, secret
key, and auxiliary randomness up front and throw `ArgumentError`; the
pure-Dart gate also rejects x-only public keys with x >= the field size and
candidate points that fail the lift-x square-root check, and each produced
signature is self-verified before it is returned.

**PSBT v0 (BIP-174).** Parsing no longer accepts a number of input/output maps
inconsistent with the unsigned transaction: `fromBytes` requires one global
map plus one map per unsigned-transaction input and output, and serialization
builds and pads its maps from the transaction's authoritative input/output
counts, failing closed on excess instead of producing an invalid PSBT.

**Who is affected:** anyone using 0.2.0 to verify BIP-340 signatures or sign
with supplied key material, and anyone parsing or building PSBT v0
documents. Verification results for well-formed inputs are unchanged.

**What to do:** upgrade. No API or migration changes are required.

Regression coverage: BIP-340 signing-input rejection cases and the official
BIP-340 verification-failure vectors (indices 6-14, including x-only pubkey
at the field size), and PSBT v0 missing/extra-map parse rejections.

## 0.2.0

### Fixed: taproot output keys and addresses were wrong for odd-Y internal keys

`Taproot.tweakedKey` tweaked the internal key as derived instead of its BIP-341
`lift_x` (even-Y) form. Roughly half of all internal keys have an odd Y, and for
every one of those the computed output key, and therefore the P2TR address, was
wrong. `Taproot.tweakSecretKey` had the mirror defect, so a key-path spend
signed with the wrong tweaked key.

**Who is affected:** anyone using 0.1.0 to derive, display or store P2TR
addresses, or to sign key-path spends. Funds sent to an affected address are not
spendable by the key the caller believes owns them; they are recoverable only
with the correct internal key and external tooling.

**What to do:** upgrade, then re-derive any P2TR address produced by 0.1.0 and
compare. Addresses that change were wrong. Treat any 0.1.0-derived P2TR address
already given out as suspect until re-derived.

The fix normalises the internal key to its even-Y form before tweaking, in
`tweakedKey`, in `tweakSecretKey` (by negating the secret key when the public Y
is odd) and in the control-block parity bit. Regression coverage uses the
BIP-86 address vectors, including an odd-Y case, and the BIP-341 key-path
vectors. 0.1.0 shipped this defect because the suite had no
assertion on a taproot tweak at all.

### Also in this release

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
