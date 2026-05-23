# WalletConnect test goldens

Each `*.out` file in this directory is a JSON capture produced by running an
external reference implementation against fixed inputs, committed here so
coin's implementation can be tested against those bytes without depending on
the external package at test time.

The canonical inputs (keys, IVs, plaintexts, URIs) are listed in
`walletconnect/survey/interop/CANON.txt`. The captures were produced by the
probe harnesses under `walletconnect/survey/interop/`.

| Golden file   | Produced by (tool@version)              | Upstream repo                                                  | Capture               | Consumed by |
|---------------|------------------------------------------|----------------------------------------------------------------|-----------------------|-------------|
| `wcdart.out`  | `walletconnect_dart@0.0.11`              | https://github.com/RootSoft/walletconnect-dart-sdk             | `interop/wcdart.out`  | `wc_v1_cipher_test.dart` (v1 AES-256-CBC + HMAC `data`/`hmac`), and the v1 `wc:` URI fields |
| `uri.out`     | `wallet_connect_uri_validator@0.1.0`     | https://github.com/SimplioOfficial/wallet-connect-uri-validator | `interop/uri.out`     | `wc_uri_test.dart` (v1/v2 `wc:` URI parse expectations, EIP-1328) |
| `web3dart.out`| `web3dart@3.0.2`                         | https://github.com/xclud/web3dart                              | (web3dart probe)      | EVM-primitive checks (keccak / EIP-55 / secp256k1 / RLP / EIP-155 tx / personal_sign). These cover the EVM seam that WC reuses (e.g. PersonalSign, EvmAddr). |

Notes
- `web3dart.out` values are EVM primitives, not WC-protocol bytes; they cover
  the shared `coin_evm` primitives that the WC suite signs/recovers with.
- Do not regenerate a golden without re-running the matching
  `survey/interop/` probe and updating the version column above.
