/**
 * Keystore module entry point.
 */

export { encodeKeystore } from "./encode.js";
export type { EncodeOptions } from "./encode.js";
export { decodeKeystore, validateKeystoreShape } from "./decode.js";
export { argon2id, DEFAULT_ARGON2ID_PARAMS } from "./argon2.js";
export type { Argon2idOptions } from "./argon2.js";
export { encrypt, decrypt } from "./crypto.js";
export type { EncryptResult } from "./crypto.js";