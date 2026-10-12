/**
 * Typed error classes for the wallet package.
 *
 * Every error the wallet throws is one of these. Callers that want
 * to distinguish failure modes (a wrong password vs. a corrupted
 * keystore) can switch on the class rather than parsing the message.
 */

export class WalletError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WalletError";
  }
}

/** The mnemonic is not a valid BIP-39 phrase. */
export class InvalidMnemonicError extends WalletError {
  constructor(message = "invalid BIP-39 mnemonic") {
    super(message);
    this.name = "InvalidMnemonicError";
  }
}

/** The keystore file is malformed, or has an unexpected version. */
export class InvalidKeystoreError extends WalletError {
  constructor(message = "invalid keystore") {
    super(message);
    this.name = "InvalidKeystoreError";
  }
}

/** The keystore could not be decrypted (wrong password or tampered). */
export class DecryptionError extends WalletError {
  constructor(message = "could not decrypt keystore") {
    super(message);
    this.name = "DecryptionError";
  }
}

/** The wallet is not unlocked. */
export class LockedError extends WalletError {
  constructor(message = "wallet is locked") {
    super(message);
    this.name = "LockedError";
  }
}

/** The wallet is already unlocked. */
export class AlreadyUnlockedError extends WalletError {
  constructor(message = "wallet is already unlocked") {
    super(message);
    this.name = "AlreadyUnlockedError";
  }
}

/** A key derivation parameter is out of range. */
export class DerivationError extends WalletError {
  constructor(message: string) {
    super(message);
    this.name = "DerivationError";
  }
}