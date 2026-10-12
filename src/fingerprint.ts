/**
 * Mnemonic fingerprints.
 *
 * A fingerprint is a short, stable identifier derived from the
 * seed. It is *not* secret — it doesn't reveal any bits of the key
 * — and it is *not* reversible — you can't recover the seed from
 * it. It exists so a keystore can declare "I was created from
 * mnemonic X" and the wallet can check that claim on unlock.
 *
 * The format is the first 4 bytes of Blake2b-256(seed || "clrty-fp"),
 * hex-encoded. The C++ side uses the same construction.
 */

import { blake2b } from "@noble/hashes/blake2b";

const FP_DOMAIN = new TextEncoder().encode("clrty-fp");

/**
 * Compute the 4-byte fingerprint of a BIP-39 seed.
 */
export function fingerprintFromSeed(seed: Uint8Array): Uint8Array {
  const input = new Uint8Array(seed.length + FP_DOMAIN.length);
  input.set(seed, 0);
  input.set(FP_DOMAIN, seed.length);

  const h = blake2b(input, { dkLen: 32 });
  return h.slice(0, 4);
}

/** Hex-encode a fingerprint, lowercase, no "0x". */
export function fingerprintToHex(fp: Uint8Array): string {
  let s = "";
  for (const b of fp) s += b.toString(16).padStart(2, "0");
  return s;
}

/** Parse a fingerprint hex string back to bytes. */
export function fingerprintFromHex(hex: string): Uint8Array {
  if (hex.length !== 8) {
    throw new Error(`fingerprint must be 8 hex chars, got ${hex.length}`);
  }
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}