/**
 * Argon2id wrapper around `hash-wasm`.
 *
 * The C++ side uses the reference Argon2 implementation with the
 * parameters in `EncryptedKeyStore.cpp`. For a keystore to be
 * portable in both directions, the JS side must use the same
 * parameters and the same output encoding.
 *
 * `hash-wasm`'s Argon2id produces the raw key, which is what the
 * C++ side does too. The parameters (`m`, `t`, `p`) are stored in
 * the keystore file, so this function takes them as inputs rather
 * than hardcoding them.
 */

import { argon2id as wasmArgon2id } from "hash-wasm";
import { DecryptionError } from "../errors.js";

export interface Argon2idOptions {
  /** Memory cost in KiB. */
  m: number;
  /** Time cost (iterations). */
  t: number;
  /** Parallelism (lanes). */
  p: number;
  /** Output length in bytes. */
  outputLength: number;
}

/**
 * Derive `outputLength` bytes from `password` and `salt` using
 * Argon2id with the given parameters.
 */
export async function argon2id(
  password: Uint8Array,
  salt: Uint8Array,
  options: Argon2idOptions,
): Promise<Uint8Array> {
  //  hash-wasm takes strings or Uint8Arrays; both work.
  try {
    const result = await wasmArgon2id({
      password,
      salt,
      parallelism: options.p,
      iterations: options.t,
      memorySize: options.m,
      hashLength: options.outputLength,
      outputType: "binary",
    });
    return result;
  } catch (e) {
    throw new DecryptionError(
      `Argon2id failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}

/**
 * The default parameters the CLI uses for new keystores.
 *
 * These are conservative for a wallet: 64 MiB of memory, 3
 * iterations, 1 lane. On a modern browser, derivation takes a few
 * hundred milliseconds.
 */
export const DEFAULT_ARGON2ID_PARAMS: Argon2idOptions = {
  m: 65536, // 64 MiB
  t: 3,
  p: 1,
  outputLength: 32,
};