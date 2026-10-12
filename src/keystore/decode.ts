/**
 * Keystore decoding.
 *
 * `decodeKeystore` takes a `KeystoreFile`, a password, and returns
 * the decrypted seed. The keystore's declared fingerprint is
 * checked against the seed's actual fingerprint; a mismatch means
 * the file was constructed for a different mnemonic, which is a
 * corruption or tampering signal.
 */

import { fingerprintFromSeed, fingerprintFromHex, fingerprintToHex } from "../fingerprint.js";
import { DecryptionError, InvalidKeystoreError } from "../errors.js";
import { decrypt } from "./crypto.js";
import { buildAAD, deriveKey, hexToBytes, KEYSTORE_VERSION } from "./encode.js";
import type { KeystoreFile } from "../types.js";

/**
 * Validate the shape of a parsed keystore object. Throws
 * `InvalidKeystoreError` if any required field is missing or has
 * the wrong type.
 */
export function validateKeystoreShape(value: unknown): KeystoreFile {
  if (typeof value !== "object" || value === null) {
    throw new InvalidKeystoreError("keystore must be an object");
  }
  const k = value as Record<string, unknown>;

  if (k.version !== KEYSTORE_VERSION) {
    throw new InvalidKeystoreError(
      `unsupported keystore version: ${k.version}`,
    );
  }

  if (k.kdf !== "argon2id" && k.kdf !== "pbkdf2") {
    throw new InvalidKeystoreError(`unknown kdf: ${k.kdf}`);
  }

  if (k.cipher !== "xchacha20poly1305") {
    throw new InvalidKeystoreError(`unknown cipher: ${k.cipher}`);
  }

  if (typeof k.nonce !== "string" || k.nonce.length !== 48) {
    throw new InvalidKeystoreError("nonce must be a 48-char hex string");
  }
  if (typeof k.ciphertext !== "string") {
    throw new InvalidKeystoreError("ciphertext must be a hex string");
  }
  if (typeof k.mac !== "string" || k.mac.length !== 32) {
    throw new InvalidKeystoreError("mac must be a 32-char hex string");
  }
  if (typeof k.fingerprint !== "string" || k.fingerprint.length !== 8) {
    throw new InvalidKeystoreError(
      "fingerprint must be an 8-char hex string",
    );
  }
  if (typeof k.kdf_params !== "object" || k.kdf_params === null) {
    throw new InvalidKeystoreError("kdf_params must be an object");
  }

  return k as unknown as KeystoreFile;
}

/**
 * Decrypt a keystore file with a password. Returns the 64-byte
 * seed.
 *
 * Throws `DecryptionError` on wrong password or tampered file, and
 * `InvalidKeystoreError` if the fingerprint doesn't match the
 * decrypted seed.
 */
export async function decodeKeystore(
  file: KeystoreFile,
  password: string,
): Promise<Uint8Array> {
  if (password.length === 0) {
    throw new DecryptionError("password must not be empty");
  }

  const aad = buildAAD(file.kdf, file.cipher, file.kdf_params);
  const key = await deriveKey(
    new TextEncoder().encode(password),
    file.kdf,
    file.kdf_params,
  );

  const seed = decrypt(
    key,
    hexToBytes(file.nonce),
    hexToBytes(file.ciphertext),
    hexToBytes(file.mac),
    aad,
  );

  if (seed.length !== 64) {
    throw new InvalidKeystoreError(
      `decrypted seed is ${seed.length} bytes, expected 64`,
    );
  }

  //  Verify the declared fingerprint matches the derived one.
  const actual = fingerprintToHex(fingerprintFromSeed(seed));
  if (actual !== file.fingerprint) {
    throw new InvalidKeystoreError(
      `fingerprint mismatch: declared ${file.fingerprint}, actual ${actual}`,
    );
  }

  //  Also validate the fingerprint parses, as a shape check.
  fingerprintFromHex(file.fingerprint);

  return seed;
}