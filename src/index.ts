/**
 * Public entry point for `@claritychain/wallet`.
 *
 * Everything a consumer needs is re-exported here. Internal
 * helpers (the AEAD primitives, the KDF wrappers, the individual
 * SLIP-10 steps) are not part of the stable surface.
 */

// Core
export { Wallet } from "./wallet.js";
export type { WalletOptions, CreateResult } from "./wallet.js";

// Signer
export { signerFromSecret } from "./signer.js";
export type { SignerFn } from "./signer.js";

// Keystore
export { encodeKeystore } from "./keystore/encode.js";
export type { EncodeOptions } from "./keystore/encode.js";
export { decodeKeystore, validateKeystoreShape } from "./keystore/decode.js";
export { DEFAULT_ARGON2ID_PARAMS } from "./keystore/argon2.js";

// Mnemonic
export {
  generateMnemonic,
  isValidMnemonic,
  mnemonicToSeed,
} from "./bip39.js";

// Derivation
export {
  CLRTY_COIN_TYPE,
  REWARD_BRANCH,
  CONSENSUS_BRANCH,
  rewardPath,
  consensusPath,
  deriveWalletKeys,
} from "./derivation.js";

export { deriveSlip10, deriveEd25519 } from "./slip10.js";

// Fingerprint
export {
  fingerprintFromSeed,
  fingerprintToHex,
  fingerprintFromHex,
} from "./fingerprint.js";

// Errors
export {
  WalletError,
  InvalidMnemonicError,
  InvalidKeystoreError,
  DecryptionError,
  LockedError,
  AlreadyUnlockedError,
  DerivationError,
} from "./errors.js";

// Types
export type {
  KeystoreFile,
  Kdf,
  KdfParams,
  Argon2idParams,
  Pbkdf2Params,
  DerivedKey,
  WalletKeys,
  Network,
  HexString,
  Bech32mAddress,
} from "./types.js";
export { NETWORK_HRP } from "./types.js";