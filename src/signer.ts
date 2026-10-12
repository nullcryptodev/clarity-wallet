/**
 * Signer over an unlocked wallet.
 *
 * The `SignerFn` type matches `@claritychain/rpc`'s `SignerFn`, so
 * a `WalletSigner` can be passed directly to any `TxBuilder` method
 * that accepts a signer.
 *
 * Signing algorithm: the input to `sign` is a 32-byte signing
 * hash. This module signs it with Ed25519 and returns the 64-byte
 * signature. The hash construction — Blake2b-256 of the domain tag
 * and the transaction body — is done by the caller (the
 * transaction builder), not here.
 */

import { ed25519 } from "@noble/curves/ed25519";

import { LockedError } from "./errors.js";

export type SignerFn = (hash: Uint8Array) => Promise<Uint8Array>;

/**
 * Build a `SignerFn` from a 32-byte Ed25519 secret key.
 *
 * The returned function is async to match the interface, but the
 * signing itself is synchronous. It throws `LockedError` if the
 * secret is empty (which shouldn't happen when constructed via
 * `Wallet.signer()` — that method refuses to produce a signer for
 * a locked wallet).
 */
export function signerFromSecret(secret: Uint8Array): SignerFn {
  if (secret.length !== 32) {
    throw new Error(`secret must be 32 bytes, got ${secret.length}`);
  }
  return async (hash: Uint8Array): Promise<Uint8Array> => {
    if (hash.length !== 32) {
      throw new Error(`signing hash must be 32 bytes, got ${hash.length}`);
    }
    if (secret.every((b) => b === 0)) {
      throw new LockedError("secret key has been wiped");
    }
    return ed25519.sign(hash, secret);
  };
}