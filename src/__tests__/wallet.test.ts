import { describe, expect, it } from "vitest";
import { Wallet } from "../wallet.js";
import {
  AlreadyUnlockedError,
  LockedError,
} from "../errors.js";
import { KEYSTORE_VECTOR, DERIVATION_VECTOR } from "./vectors.js";

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

describe("Wallet state machine", () => {
  it("starts empty", () => {
    const w = new Wallet();
    expect(w.isLoaded()).toBe(false);
    expect(w.isUnlocked()).toBe(false);
  });

  it("creates a wallet, unlocks it, and derives keys", async () => {
    const { wallet, mnemonic, keystore } = await Wallet.create(
      "test-password",
      { wordCount: 12 },
    );
    expect(mnemonic.split(" ").length).toBe(12);
    expect(keystore.fingerprint.length).toBe(8);
    expect(wallet.isLoaded()).toBe(true);
    expect(wallet.isUnlocked()).toBe(true);
    expect(wallet.rewardPublicKey().length).toBe(32);
    expect(wallet.consensusPublicKey().length).toBe(32);
  });

  it("imports from a mnemonic and derives the CLI's keys", async () => {
    const { wallet } = await Wallet.fromMnemonic(
      KEYSTORE_VECTOR.mnemonic,
      KEYSTORE_VECTOR.password,
    );
    expect(wallet.isUnlocked()).toBe(true);
    expect(bytesToHex(wallet.rewardPublicKey())).toBe(
      DERIVATION_VECTOR.rewardPublic,
    );
    expect(bytesToHex(wallet.consensusPublicKey())).toBe(
      DERIVATION_VECTOR.consensusPublic,
    );
  });

  it("locks and unlocks", async () => {
    const { wallet } = await Wallet.fromMnemonic(
      KEYSTORE_VECTOR.mnemonic,
      KEYSTORE_VECTOR.password,
    );
    wallet.lock();
    expect(wallet.isUnlocked()).toBe(false);
    expect(() => wallet.rewardPublicKey()).toThrow(LockedError);
    expect(() => wallet.signer()).toThrow(LockedError);

    await wallet.unlock(KEYSTORE_VECTOR.password);
    expect(wallet.isUnlocked()).toBe(true);
    expect(bytesToHex(wallet.rewardPublicKey())).toBe(
      DERIVATION_VECTOR.rewardPublic,
    );
  });

  it("rejects unlock when already unlocked", async () => {
    const { wallet } = await Wallet.fromMnemonic(
      KEYSTORE_VECTOR.mnemonic,
      KEYSTORE_VECTOR.password,
    );
    await expect(wallet.unlock(KEYSTORE_VECTOR.password)).rejects.toThrow(
      AlreadyUnlockedError,
    );
  });

  it("rejects unlock with a wrong password", async () => {
    const { keystore } = await Wallet.fromMnemonic(
      KEYSTORE_VECTOR.mnemonic,
      KEYSTORE_VECTOR.password,
    );
    const w = await Wallet.load(keystore);
    await expect(w.unlock("wrong")).rejects.toThrow();
    expect(w.isUnlocked()).toBe(false);
  });

  it("returns a working signer", async () => {
    const { wallet } = await Wallet.fromMnemonic(
      KEYSTORE_VECTOR.mnemonic,
      KEYSTORE_VECTOR.password,
    );
    const signer = wallet.signer();
    const hash = new Uint8Array(32).fill(0x42);
    const sig = await signer(hash);
    expect(sig.length).toBe(64);
  });

  it("wipes secrets on lock", async () => {
    const { wallet } = await Wallet.fromMnemonic(
      KEYSTORE_VECTOR.mnemonic,
      KEYSTORE_VECTOR.password,
    );
    const secret = wallet.rewardSecretKey();
    const copy = secret.slice();
    wallet.lock();
    //  The original array must have been overwritten with zeros.
    expect(Array.from(secret)).toEqual(Array.from(new Uint8Array(32)));
    //  The copy is unaffected, as expected — `slice()` made a copy.
    expect(bytesToHex(copy)).toBe(DERIVATION_VECTOR.rewardSecret);
  });
});