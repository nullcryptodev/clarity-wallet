/**
 * SLIP-10 HD derivation for Ed25519.
 *
 * Ed25519 SLIP-10 requires hardened-only derivation, so every
 * path component has a hardened bit set. The chain uses BIP-44
 * paths under coin type 9000:
 *
 *   m/44'/9000'/account'/0'/index'    reward addresses
 *   m/44'/9000'/account'/2'/index'    consensus keys
 *
 * The `2'` branch is not a BIP-44 standard (which uses 0 for
 * receive and 1 for change); the chain reserves it for validator
 * identity. This matches the CLI's `HdPath.cpp`.
 */

import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import { ed25519 } from "@noble/curves/ed25519";

import { DerivationError } from "./errors.js";

const HARDENED_OFFSET = 0x80000000;
const CURVE_SEED = new TextEncoder().encode("ed25519 seed");

/**
 * The SLIP-10 master key: HMAC-SHA512 over "ed25519 seed" with the
 * BIP-39 seed as the message. The left 32 bytes are the master
 * secret; the right 32 bytes are the chain code.
 */
function masterKeyFromSeed(seed: Uint8Array): {
  key: Uint8Array;
  chainCode: Uint8Array;
} {
  const I = hmac(sha512, CURVE_SEED, seed);
  return {
    key: I.slice(0, 32),
    chainCode: I.slice(32, 64),
  };
}

/**
 * One SLIP-10 child step. `index` must have the hardened bit set.
 */
function deriveChild(
  parentKey: Uint8Array,
  parentChainCode: Uint8Array,
  index: number,
): { key: Uint8Array; chainCode: Uint8Array } {
  if ((index & HARDENED_OFFSET) === 0) {
    throw new DerivationError(
      "SLIP-10 for Ed25519 requires hardened derivation",
    );
  }

  //  Data = 0x00 || parentKey || index (BE u32)
  const data = new Uint8Array(1 + 32 + 4);
  data[0] = 0x00;
  data.set(parentKey, 1);
  data[33] = (index >>> 24) & 0xff;
  data[34] = (index >>> 16) & 0xff;
  data[35] = (index >>> 8) & 0xff;
  data[36] = index & 0xff;

  const I = hmac(sha512, parentChainCode, data);
  return {
    key: I.slice(0, 32),
    chainCode: I.slice(32, 64),
  };
}

/**
 * Derive the key at a full SLIP-10 path. The path is an array of
 * numeric components; every component is treated as hardened.
 */
export function deriveSlip10(
  seed: Uint8Array,
  path: number[],
): { secret: Uint8Array; chainCode: Uint8Array } {
  if (seed.length < 16 || seed.length > 64) {
    throw new DerivationError("seed must be 16..64 bytes");
  }

  let { key, chainCode } = masterKeyFromSeed(seed);

  for (const component of path) {
    if (component < 0 || component >= HARDENED_OFFSET) {
      throw new DerivationError(
        `path component out of range: ${component}`,
      );
    }
    const hardened = component | HARDENED_OFFSET;
    ({ key, chainCode } = deriveChild(key, chainCode, hardened));
  }

  return { secret: key, chainCode };
}

/**
 * Derive an Ed25519 keypair at a path. Returns the 32-byte secret
 * (which is the seed Ed25519 uses) and the corresponding public
 * key.
 */
export function deriveEd25519(
  seed: Uint8Array,
  path: number[],
): { secret: Uint8Array; public: Uint8Array } {
  const { secret } = deriveSlip10(seed, path);
  const publicKey = ed25519.getPublicKey(secret);
  return { secret, public: publicKey };
}