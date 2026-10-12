/**
 * Public types for the wallet package.
 *
 * These mirror the wire format the C++ `EncryptedKeyStore` uses. A
 * keystore file written by the CLI opens in the browser and vice
 * versa; that compatibility is the package's whole point.
 */

/** Hex-encoded string, "0x"-prefixed, lowercase. */
export type HexString = string;

/** A bech32m address, "clrty" / "tclrty" / "rclrty" HRP. */
export type Bech32mAddress = string;

/**
 * The KDF used to derive the keystore's encryption key from the
 * password. `argon2id` is the default and what the CLI writes for
 * new keystores; `pbkdf2` is supported for older files.
 */
export type Kdf = "argon2id" | "pbkdf2";

/**
 * The keystore file format. JSON-serializable; the CLI's output
 * parses into this shape, and this shape serializes back to a file
 * the CLI can open.
 */
export interface KeystoreFile {
  /** Format version. Currently 1. */
  version: number;

  /** Which KDF was used to derive the encryption key. */
  kdf: Kdf;

  /**
   * KDF parameters. For argon2id: { m, t, p, salt }. For pbkdf2:
   * { iterations, salt }. Both salts are hex strings.
   */
  kdf_params: KdfParams;

  /** The AEAD algorithm. Currently only "xchacha20poly1305". */
  cipher: string;

  /**
   * The AEAD nonce, hex. XChaCha20-Poly1305 uses a 24-byte nonce.
   */
  nonce: HexString;

  /**
   * The ciphertext, hex. Encrypts the seed (not the mnemonic) so
   * the keystore can be opened without the wordlist.
   */
  ciphertext: HexString;

  /**
   * The AEAD authentication tag, hex. 16 bytes.
   */
  mac: HexString;

  /**
   * A stable, per-mnemonic identifier. Used to detect when a
   * keystore's declared fingerprint doesn't match the one derived
   * on unlock. 4-byte hex.
   */
  fingerprint: HexString;

  /** Optional user label, for UI display. */
  label?: string;
}

export interface Argon2idParams {
  /** Memory cost in KiB. */
  m: number;
  /** Time cost (iterations). */
  t: number;
  /** Parallelism (lanes). */
  p: number;
  /** Salt, hex. */
  salt: HexString;
}

export interface Pbkdf2Params {
  /** Iteration count. */
  iterations: number;
  /** Salt, hex. */
  salt: HexString;
}

export type KdfParams = Argon2idParams | Pbkdf2Params;

/** A derived Ed25519 keypair. */
export interface DerivedKey {
  /** 32-byte secret (the seed, not the expanded key). */
  secret: Uint8Array;
  /** 32-byte public key. */
  public: Uint8Array;
}

/** The two keys a validator identity has. */
export interface WalletKeys {
  /** The reward address' public key. */
  rewardPublic: Uint8Array;
  /** The reward address' secret key. */
  rewardSecret: Uint8Array;
  /** The consensus key's public key. */
  consensusPublic: Uint8Array;
  /** The consensus key's secret key. */
  consensusSecret: Uint8Array;
}

/** Network selector, matching the CLI's `--network`. */
export type Network = "mainnet" | "testnet" | "regtest";

/** The HRP for a given network. */
export const NETWORK_HRP: Record<Network, string> = {
  mainnet: "clrty",
  testnet: "tclrty",
  regtest: "rclrty",
};