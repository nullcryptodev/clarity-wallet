# @claritychain/wallet

Browser-compatible keystore and signer for the CLRTY chain.

This package handles the cryptographic operations the DEX, the block
explorer, and any other consumer needs to sign transactions: mnemonic
generation, BIP-39 seed derivation, SLIP-10 Ed25519 key derivation,
keystore encryption, and Ed25519 signing. It is the browser
counterpart to the CLI's keystore and produces byte-identical files.

## Install

```
npm install @claritychain/wallet
```

## Quick start

Create a new wallet:

```typescript
import { Wallet } from "@claritychain/wallet";

const { mnemonic, keystore, wallet } = await Wallet.create("my-password");

// Show the mnemonic to the user. Write it down. Never store it
// in plaintext anywhere.
console.log(mnemonic);

// Persist the keystore. This is the file to save.
const json = JSON.stringify(keystore, null, 2);
// ... write `json` to disk, or download it, or store it ...

// The wallet is already unlocked and can sign.
const signer = wallet.signer();
```

Import an existing mnemonic:

```typescript
const { keystore, wallet } = await Wallet.fromMnemonic(mnemonic, "my-password");
```

Load a saved keystore and unlock it:

```typescript
const parsed = JSON.parse(fileContents);
const wallet = await Wallet.load(parsed);
await wallet.unlock("my-password");

const signer = wallet.signer();
```

Sign a transaction (using the `@claritychain/rpc` builder):

```typescript
import { TxBuilder } from "@claritychain/rpc";

const unsigned = TxBuilder.transfer({
  from: wallet.address(),
  to: recipient,
  amount: 1_000_000n,
  fee: 1_000n,
  nonce: 0n,
  chainId: 0x434c5247n,
});

const signed = await unsigned.sign(wallet.signer());
const txid = await rpc.sendRawTransaction(signed.toHex());
```

## API

### `Wallet`

- `Wallet.create(password, options)` → `{ mnemonic, keystore, wallet }`
- `Wallet.fromMnemonic(mnemonic, password, options)` → `{ keystore, wallet }`
- `Wallet.load(keystore, options)` → `Wallet` (locked)
- `wallet.unlock(password)` → `Promise<void>`
- `wallet.lock()` → `void`
- `wallet.isLoaded()` / `wallet.isUnlocked()` → `boolean`
- `wallet.rewardPublicKey()` / `wallet.consensusPublicKey()` → `Uint8Array`
- `wallet.rewardSecretKey()` / `wallet.consensusSecretKey()` → `Uint8Array`
- `wallet.signer()` → `SignerFn`
- `wallet.keystoreFile()` → `KeystoreFile | null`

### Keystore functions

- `encodeKeystore(seed, password, options)` → `Promise<KeystoreFile>`
- `decodeKeystore(file, password)` → `Promise<Uint8Array>` (the seed)
- `validateKeystoreShape(value)` → `KeystoreFile`

### Derivation

- `rewardPath(account, index)` / `consensusPath(account, index)` → `number[]`
- `deriveWalletKeys(seed)` → `WalletKeys`
- `deriveEd25519(seed, path)` → `{ secret, public }`

## Compatibility

A keystore written by this package opens in the CLI, and vice versa.
The derivation paths, KDF parameters, AEAD construction, and
fingerprint scheme all match the C++ implementations in
`Wallet/EncryptedKeyStore.cpp`, `Wallet/HdPath.cpp`, and
`Wallet/Bip39.cpp`.

The `__tests__/vectors.ts` file contains the cross-implementation
test vectors. If a future change to either side breaks
compatibility, the tests here will fail.

## Security notes

- **The seed is decrypted in memory when the wallet is unlocked.**
  There is no way around this: to sign, you need the key, and the
  key is derived from the seed. The wallet wipes the derived keys
  on `lock()`, but the JavaScript runtime may have copied them
  elsewhere, and a heap dump can contain them. Treat an unlocked
  wallet as holding key material.

- **The keystore is the file to back up.** If it's lost, the
  mnemonic is the only recovery. If both are lost, the funds are
  unrecoverable.

- **The password is not stored.** The wallet cannot recover a
  forgotten password. If the user has the mnemonic, they can
  re-import; otherwise the funds are lost.

- **Run under a strict Content Security Policy.** A page that
  holds an unlocked wallet is one XSS away from a key compromise.
  A CSP with no `unsafe-inline` and no `unsafe-eval` is the
  minimum mitigation.

- **Reject third-party scripts.** A wallet page should not load
  analytics, ads, or any other third-party JavaScript.

## License

MIT
