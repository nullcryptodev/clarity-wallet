/**
 * Keystore encoding.
 *
 * `encodeKeystore` takes a seed, a password, and optional
 * parameters, derives an encryption key with Argon2id (or PBKDF2),
 * encrypts the seed, and produces a `KeystoreFile` that serializes
 * to the exact JSON shape `EncryptedKeyStore.cpp` reads.
 *
 * The AAD covers the version, kdf name, and the kdf params minus
 * the salt. The salt is part of the KDF input but not the AAD,
 * because the KDF's output already depends on it — if the salt is
 * tampered with, decryption produces a different key and the MAC
 * fails.
 */

import { randomBytes } from "@noble/hashes/utils";
import { pbkdf2 } from "@noble/hashes/pbkdf2";
import { sha512 } from "@noble/hashes/sha512";

import { fingerprintFromSeed, fingerprintToHex } from "../fingerprint.js";
import { argon2id, DEFAULT_ARGON2ID_PARAMS } from "./argon2.js";
import { encrypt } from "./crypto.js";
import type {
  Argon2idParams,
  KeystoreFile,
  Kdf,
  KdfParams,
  Pbkdf2Params,
} from "../types.js";

const KEYSTORE_VERSION = 1;
const CIPHER_NAME = "xchacha20poly1305";

export interface EncodeOptions {
  /** Optional label for UI display. */
  label?: string;
  /** KDF to use. Defaults to argon2id. */
  kdf?: Kdf;
  /** Override Argon2id parameters. */
  argon2id?: Partial<Argon2idParams>;
  /** Override PBKDF2 parameters. */
  pbkdf2?: Partial<Pbkdf2Params>;
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`hex string must have even length: ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Build the AAD that binds the ciphertext to the keystore's
 * header fields. This is a canonical serialization: version ||
 * kdf name || cipher name || (kdf params minus salt).
 */
function buildAAD(kdf: Kdf, cipher: string, params: KdfParams): Uint8Array {
  const parts: string[] = [
    String(KEYSTORE_VERSION),
    kdf,
    cipher,
  ];
  if (kdf === "argon2id") {
    const p = params as Argon2idParams;
    parts.push(String(p.m), String(p.t), String(p.p));
  } else {
    const p = params as Pbkdf2Params;
    parts.push(String(p.iterations));
  }
  return new TextEncoder().encode(parts.join("|"));
}

async function deriveKey(
  password: Uint8Array,
  kdf: Kdf,
  params: KdfParams,
): Promise<Uint8Array> {
  if (kdf === "argon2id") {
    const p = params as Argon2idParams;
    return argon2id(password, hexToBytes(p.salt), {
      m: p.m,
      t: p.t,
      p: p.p,
      outputLength: 32,
    });
  }

  const p = params as Pbkdf2Params;
  return pbkdf2(sha512, password, hexToBytes(p.salt), {
    c: p.iterations,
    dkLen: 32,
  });
}

/**
 * Encrypt a seed into a keystore file.
 */
export async function encodeKeystore(
  seed: Uint8Array,
  password: string,
  options: EncodeOptions = {},
): Promise<KeystoreFile> {
  if (seed.length !== 64) {
    throw new Error(`seed must be 64 bytes, got ${seed.length}`);
  }
  if (password.length === 0) {
    throw new Error("password must not be empty");
  }

  const kdf: Kdf = options.kdf ?? "argon2id";
  const passwordBytes = new TextEncoder().encode(password);

  let params: KdfParams;
  if (kdf === "argon2id") {
    const defaults = DEFAULT_ARGON2ID_PARAMS;
    params = {
      m: options.argon2id?.m ?? defaults.m,
      t: options.argon2id?.t ?? defaults.t,
      p: options.argon2id?.p ?? defaults.p,
      salt: bytesToHex(randomBytes(16)),
    };
  } else {
    params = {
      iterations: options.pbkdf2?.iterations ?? 600_000,
      salt: bytesToHex(randomBytes(16)),
    };
  }

  const key = await deriveKey(passwordBytes, kdf, params);
  const nonce = randomBytes(24);
  const aad = buildAAD(kdf, CIPHER_NAME, params);

  const { ciphertext, mac } = encrypt(key, nonce, seed, aad);

  const fingerprint = fingerprintFromSeed(seed);

  const file: KeystoreFile = {
    version: KEYSTORE_VERSION,
    kdf,
    kdf_params: params,
    cipher: CIPHER_NAME,
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext),
    mac: bytesToHex(mac),
    fingerprint: fingerprintToHex(fingerprint),
  };
  if (options.label) file.label = options.label;
  return file;
}

export { bytesToHex, hexToBytes, buildAAD, deriveKey, KEYSTORE_VERSION };