/**
 * BIP-39 mnemonic handling.
 *
 * Thin wrapper around `@scure/bip39` with the specific entry points
 * the wallet needs. The mnemonic wordlist is English; the wallet
 * does not support other wordlists because the CLI does not.
 */

import {
  generateMnemonic as scureGenerate,
  validateMnemonic as scureValidate,
  mnemonicToSeedSync as scureMnemonicToSeed,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";

import { InvalidMnemonicError } from "./errors.js";

const DEFAULT_WORD_COUNT = 24;

/**
 * Generate a fresh mnemonic. The default word count is 24 (256 bits
 * of entropy), matching the CLI's `address --new`.
 */
export function generateMnemonic(wordCount: 12 | 24 = DEFAULT_WORD_COUNT): string {
  const strength = wordCount === 12 ? 128 : 256;
  return scureGenerate(wordlist, strength);
}

/**
 * Check whether a phrase is a valid BIP-39 mnemonic for the
 * English wordlist. Does not check the passphrase (BIP-39 does
 * not have one that affects validity).
 */
export function isValidMnemonic(mnemonic: string): boolean {
  return scureValidate(mnemonic, wordlist);
}

/**
 * Derive the 64-byte BIP-39 seed from a mnemonic. Throws if the
 * mnemonic is invalid.
 *
 * The optional passphrase is BIP-39's own "passphrase" field, not
 * the encryption password. The CLI does not use it and neither
 * does this package; the parameter exists for callers that want it.
 */
export function mnemonicToSeed(
  mnemonic: string,
  passphrase: string = "",
): Uint8Array {
  if (!isValidMnemonic(mnemonic)) {
    throw new InvalidMnemonicError();
  }
  return scureMnemonicToSeed(mnemonic, passphrase);
}