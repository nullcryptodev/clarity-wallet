/**
 * AEAD primitives for the keystore.
 *
 * The C++ side uses XChaCha20-Poly1305 with a 24-byte nonce and a
 * 16-byte authentication tag, and the tag is stored separately from
 * the ciphertext in the keystore file. This module mirrors that:
 * `encrypt` returns `{ ciphertext, mac }` and `decrypt` takes them
 * back separately.
 *
 * The AAD is the keystore's "associated data" — a serialized form
 * of the version and kdf fields — which binds the ciphertext to
 * the file's metadata. Tampering with the version, kdf, or params
 * causes decryption to fail with an auth error rather than
 * producing garbage.
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { DecryptionError } from "../errors.js";

const NONCE_LENGTH = 24;
const TAG_LENGTH = 16;

export interface EncryptResult {
  ciphertext: Uint8Array;
  mac: Uint8Array;
}

/**
 * Encrypt `plaintext` with the given key and nonce. The AAD is
 * authenticated but not encrypted. Returns the ciphertext and the
 * MAC as separate buffers.
 */
export function encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): EncryptResult {
  if (key.length !== 32) {
    throw new Error(`key must be 32 bytes, got ${key.length}`);
  }
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error(`nonce must be ${NONCE_LENGTH} bytes, got ${nonce.length}`);
  }

  const cipher = xchacha20poly1305(key, nonce, aad);
  //  @noble/ciphers' `encrypt` returns ciphertext || tag.
  const combined = cipher.encrypt(plaintext);
  const ciphertext = combined.slice(0, combined.length - TAG_LENGTH);
  const mac = combined.slice(combined.length - TAG_LENGTH);
  return { ciphertext, mac };
}

/**
 * Decrypt and authenticate. Throws `DecryptionError` if the MAC
 * fails or the inputs are malformed.
 */
export function decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  mac: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== 32) {
    throw new DecryptionError(`key must be 32 bytes, got ${key.length}`);
  }
  if (nonce.length !== NONCE_LENGTH) {
    throw new DecryptionError(
      `nonce must be ${NONCE_LENGTH} bytes, got ${nonce.length}`,
    );
  }
  if (mac.length !== TAG_LENGTH) {
    throw new DecryptionError(
      `mac must be ${TAG_LENGTH} bytes, got ${mac.length}`,
    );
  }

  const cipher = xchacha20poly1305(key, nonce, aad);
  //  Reconstruct the ciphertext || tag form that @noble/ciphers
  //  expects.
  const combined = new Uint8Array(ciphertext.length + mac.length);
  combined.set(ciphertext, 0);
  combined.set(mac, ciphertext.length);

  try {
    return cipher.decrypt(combined);
  } catch (e) {
    throw new DecryptionError(
      `authentication failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}