import { describe, expect, it } from "vitest";
import { deriveSlip10, deriveEd25519 } from "../slip10.js";
import { SLIP10_VECTOR } from "./vectors.js";

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

describe("slip10", () => {
  const seed = hexToBytes(SLIP10_VECTOR.seed);

  for (const vector of SLIP10_VECTOR.paths) {
    it(`derives the SLIP-10 vector for m/${vector.path.join("/")}'`, () => {
      const { chainCode } = deriveSlip10(seed, vector.path);
      expect(bytesToHex(chainCode)).toBe(vector.chainCode);

      const { public: pub } = deriveEd25519(seed, vector.path);
      expect(bytesToHex(pub)).toBe(vector.publicKey);
    });
  }

  it("rejects a non-hardened-looking path component", () => {
    //  Path components are always treated as hardened, so a
    //  component of -1 or above 2^31 is the only structural error.
    expect(() => deriveSlip10(seed, [-1])).toThrow();
    expect(() => deriveSlip10(seed, [0x80000000])).toThrow();
  });

  it("rejects a seed of invalid length", () => {
    expect(() => deriveSlip10(new Uint8Array(8), [0])).toThrow();
    expect(() => deriveSlip10(new Uint8Array(65), [0])).toThrow();
  });
});