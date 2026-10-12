import { describe, expect, it } from "vitest";
import {
  generateMnemonic,
  isValidMnemonic,
  mnemonicToSeed,
} from "../bip39.js";
import { BIP39_VECTOR } from "./vectors.js";

describe("bip39", () => {
  it("validates a known mnemonic", () => {
    expect(isValidMnemonic(BIP39_VECTOR.mnemonic)).toBe(true);
  });

  it("rejects an invalid mnemonic", () => {
    expect(isValidMnemonic("not a real mnemonic")).toBe(false);
    expect(
      isValidMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
      ),
    ).toBe(false); // correct words, bad checksum
  });

  it("derives the BIP-39 test vector seed", () => {
    const seed = mnemonicToSeed(BIP39_VECTOR.mnemonic);
    const hex = Array.from(seed)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe(BIP39_VECTOR.seed);
  });

  it("generates a 24-word mnemonic by default", () => {
    const m = generateMnemonic();
    expect(m.split(" ").length).toBe(24);
    expect(isValidMnemonic(m)).toBe(true);
  });

  it("generates a 12-word mnemonic when asked", () => {
    const m = generateMnemonic(12);
    expect(m.split(" ").length).toBe(12);
    expect(isValidMnemonic(m)).toBe(true);
  });

  it("produces distinct mnemonics on consecutive calls", () => {
    const a = generateMnemonic();
    const b = generateMnemonic();
    expect(a).not.toBe(b);
  });

  it("throws on an invalid mnemonic passed to mnemonicToSeed", () => {
    expect(() => mnemonicToSeed("invalid")).toThrow();
  });
});