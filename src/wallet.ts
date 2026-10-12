/**
 * The Wallet class.
 *
 * State machine:
 *
 *   empty     → (load | fromMnemonic | fromSeed) → loaded
 *   loaded    → unlock → unlocked
 *   unlocked  → lock → loaded
 *
 * In `loaded` state, the encrypted keystore is held in memory and
 * no secret material exists. In `unlocked` state, the derived keys
 * are held in memory and the signer is available. `lock` wipes the
 * derived keys.
 *
 * The wallet does not persist anything. It's the caller's job to
 * decide where the keystore file lives (disk, IndexedDB, a
 * download) and when to reconstruct a wallet around it.
 */

import { generateMnemonic, mnemonicToSeed } from "./bip39.js";
import { deriveWalletKeys } from "./derivation.js";
import {
  AlreadyUnlockedError,
  InvalidMnemonicError,
  LockedError,
} from "./errors.js";
import { decodeKeystore, validateKeystoreShape } from "./keystore/decode.js";
import { encodeKeystore, type EncodeOptions } from "./keystore/encode.js";
import { signerFromSecret, type SignerFn } from "./signer.js";
import type { KeystoreFile, Network, WalletKeys } from "./types.js";

export interface WalletOptions {
  /** The network this wallet is configured for. */
  network?: Network;
}

export interface CreateResult {
  /** The BIP-39 mnemonic. The caller must show this to the user. */
  mnemonic: string;
  /** The keystore file to persist. */
  keystore: KeystoreFile;
  /** The wallet, already unlocked and ready to sign. */
  wallet: Wallet;
}

export class Wallet {
  private readonly network: Network;
  private keystore: KeystoreFile | null = null;
  private keys: WalletKeys | null = null;

  constructor(options: WalletOptions = {}) {
    this.network = options.network ?? "mainnet";
  }

  // ---- Static constructors ---------------------------------------

  /**
   * Create a fresh wallet with a new mnemonic. Returns the
   * mnemonic, the keystore file, and the unlocked wallet.
   *
   * The caller is responsible for showing the mnemonic to the user
   * and confirming they've written it down before discarding it.
   */
  static async create(
    password: string,
    options: WalletOptions & EncodeOptions & { wordCount?: 12 | 24 } = {},
  ): Promise<CreateResult> {
    const mnemonic = generateMnemonic(options.wordCount ?? 24);
    const seed = mnemonicToSeed(mnemonic);
    const keystore = await encodeKeystore(seed, password, options);
    const wallet = new Wallet(options);
    wallet.keystore = keystore;
    wallet.keys = deriveWalletKeys(seed);
    return { mnemonic, keystore, wallet };
  }

  /**
   * Import a wallet from an existing mnemonic. Returns the
   * keystore file and the unlocked wallet.
   */
  static async fromMnemonic(
    mnemonic: string,
    password: string,
    options: WalletOptions & EncodeOptions = {},
  ): Promise<{ keystore: KeystoreFile; wallet: Wallet }> {
    let seed: Uint8Array;
    try {
      seed = mnemonicToSeed(mnemonic);
    } catch (e) {
      throw new InvalidMnemonicError(
        e instanceof Error ? e.message : String(e),
      );
    }
    const keystore = await encodeKeystore(seed, password, options);
    const wallet = new Wallet(options);
    wallet.keystore = keystore;
    wallet.keys = deriveWalletKeys(seed);
    return { keystore, wallet };
  }

  /**
   * Load a keystore file into a new wallet. The wallet starts
   * locked; call `unlock` with the password to derive keys.
   */
  static async load(
    keystore: KeystoreFile | unknown,
    options: WalletOptions = {},
  ): Promise<Wallet> {
    const file = validateKeystoreShape(keystore);
    const wallet = new Wallet(options);
    wallet.keystore = file;
    return wallet;
  }

  // ---- State transitions -----------------------------------------

  /**
   * Unlock the wallet, deriving the reward and consensus keys.
   * Throws `AlreadyUnlockedError` if it's already unlocked.
   * Throws `DecryptionError` on wrong password.
   */
  async unlock(password: string): Promise<void> {
    if (this.keys !== null) {
      throw new AlreadyUnlockedError();
    }
    if (this.keystore === null) {
      throw new LockedError("no keystore loaded");
    }
    const seed = await decodeKeystore(this.keystore, password);
    this.keys = deriveWalletKeys(seed);
  }

  /**
   * Lock the wallet, wiping the derived keys from memory. The
   * keystore file remains in memory, so `unlock` can be called
   * again with the password.
   */
  lock(): void {
    if (this.keys !== null) {
      //  Overwrite the secret material before releasing the
      //  reference, so a heap dump after `lock()` doesn't contain
      //  the keys.
      this.keys.rewardSecret.fill(0);
      this.keys.consensusSecret.fill(0);
      this.keys = null;
    }
  }

  // ---- Accessors -------------------------------------------------

  /** Whether the wallet has a keystore loaded. */
  isLoaded(): boolean {
    return this.keystore !== null;
  }

  /** Whether the wallet is unlocked. */
  isUnlocked(): boolean {
    return this.keys !== null;
  }

  /** The network this wallet is configured for. */
  getNetwork(): Network {
    return this.network;
  }

  /**
   * The reward public key. Available whether or not the wallet is
   * unlocked, because the public key is derived from the keystore's
   * fingerprint match, not from the secret.
   *
   * Actually — the public key is derived from the *seed*, which is
   * only available after unlock. So this throws if the wallet is
   * locked. The keystore doesn't contain the public key.
   */
  rewardPublicKey(): Uint8Array {
    if (this.keys === null) throw new LockedError();
    return this.keys.rewardPublic;
  }

  /** The consensus public key. Throws if locked. */
  consensusPublicKey(): Uint8Array {
    if (this.keys === null) throw new LockedError();
    return this.keys.consensusPublic;
  }

  /** The reward secret key. Throws if locked. */
  rewardSecretKey(): Uint8Array {
    if (this.keys === null) throw new LockedError();
    return this.keys.rewardSecret;
  }

  /** The consensus secret key. Throws if locked. */
  consensusSecretKey(): Uint8Array {
    if (this.keys === null) throw new LockedError();
    return this.keys.consensusSecret;
  }

  /** The currently loaded keystore file, or null. */
  keystoreFile(): KeystoreFile | null {
    return this.keystore;
  }

  // ---- Signing ---------------------------------------------------

  /**
   * A `SignerFn` that signs with the reward key. Throws if locked.
   *
   * The reward key is the one that signs user transactions; the
   * consensus key signs BLS-style consensus messages, which the
   * browser wallet does not do.
   */
  signer(): SignerFn {
    if (this.keys === null) throw new LockedError();
    //  Copy the secret so the signer isn't holding a reference to
    //  the key that `lock()` will wipe. The copy is wiped when the
    //  signer is garbage-collected — best-effort, not guaranteed.
    const secret = this.keys.rewardSecret.slice();
    return signerFromSecret(secret);
  }
}