import { describe, expect, it } from "vitest";
import {
  deriveWalletKeys,
  rewardPath,
  consensusPath,
  CLRTY_COIN_TYPE,
  REWARD_BRANCH,
  CONSENSUS_BRANCH,
} from "../derivation.js";
import { mnemonicToSeed } from "../bip39.js";
import { DERIVATION_VECTOR, KEYSTORE_VECTOR } from "./vectors.js";

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

describe("derivation paths", () => {
  it("builds the reward path in BIP-44 form", () => {
    expect(rewardPath(0, 0)).toEqual([44, CLRTY_COIN_TYPE, 0, REWARD_BRANCH, 0]);
  });

  it("builds the consensus path with the chain-specific branch", () => {
    expect(consensusPath(0, 0)).toEqual([
      44,
      CLRTY_COIN_TYPE,
      0,
      CONSENSUS_BRANCH,
      0,
    ]);
  });

  it("uses the same branch for all consensus keys", () => {
    expect(consensusPath(1, 5)[3]).toBe(CONSENSUS_BRANCH);
    expect(consensusPath(99, 42)[3]).toBe(CONSENSUS_BRANCH);
  });
});

describe("derivation against C++ vectors", () => {
  it("derives the same keys as the CLI", () => {
    const seed = mnemonicToSeed(KEYSTORE_VECTOR.mnemonic);
    const keys = deriveWalletKeys(seed);

    expect(bytesToHex(keys.rewardPublic)).toBe(DERIVATION_VECTOR.rewardPublic);
    expect(bytesToHex(keys.rewardSecret)).toBe(DERIVATION_VECTOR.rewardSecret);
    expect(bytesToHex(keys.consensusPublic)).toBe(
      DERIVATION_VECTOR.consensusPublic,
    );
    expect(bytesToHex(keys.consensusSecret)).toBe(
      DERIVATION_VECTOR.consensusSecret,
    );
  });
});