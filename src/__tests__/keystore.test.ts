import { describe, expect, it } from "vitest";
import { encodeKeystore } from "../keystore/encode.js";
import { decodeKeystore, validateKeystoreShape } from "../keystore/decode.js";
import { mnemonicToSeed } from "../bip39.js";
import { KEYSTORE_VECTOR } from "./vectors.js";

describe("keystore round-trip", () => {
  it("encrypts and decrypts a seed with argon2id", async () => {
    const seed = mnemonicToSeed(KEYSTORE_VECTOR.mnemonic);
    const file = await encodeKeystore(seed, KEYSTORE_VECTOR.password);
    expect(file.kdf).toBe("argon2id");
    expect(file.version).toBe(1);
    expect(file.fingerprint.length).toBe(8);

    const decrypted = await decodeKeystore(file, KEYSTORE_VECTOR.password);
    expect(decrypted).toEqual(seed);
  });

  it("encrypts and decrypts a seed with pbkdf2", async () => {
    const seed = mnemonicToSeed(KEYSTORE_VECTOR.mnemonic);
    const file = await encodeKeystore(seed, KEYSTORE_VECTOR.password, {
      kdf: "pbkdf2",
      pbkdf2: { iterations: 10_000 }, // fast for tests
    });
    expect(file.kdf).toBe("pbkdf2");

    const decrypted = await decodeKeystore(file, KEYSTORE_VECTOR.password);
    expect(decrypted).toEqual(seed);
  });

  it("rejects a wrong password", async () => {
    const seed = mnemonicToSeed(KEYSTORE_VECTOR.mnemonic);
    const file = await encodeKeystore(seed, KEYSTORE_VECTOR.password, {
      kdf: "pbkdf2",
      pbkdf2: { iterations: 10_000 },
    });
    await expect(decodeKeystore(file, "wrong password")).rejects.toThrow();
  });

  it("rejects a tampered ciphertext", async () => {
    const seed = mnemonicToSeed(KEYSTORE_VECTOR.mnemonic);
    const file = await encodeKeystore(seed, KEYSTORE_VECTOR.password, {
      kdf: "pbkdf2",
      pbkdf2: { iterations: 10_000 },
    });

    //  Flip a byte in the ciphertext.
    const tampered = { ...file };
    const ct = tampered.ciphertext;
    tampered.ciphertext = ct[0] + ((parseInt(ct[1]!, 16) ^ 1).toString(16)) + ct.slice(2);

    await expect(
      decodeKeystore(tampered, KEYSTORE_VECTOR.password),
    ).rejects.toThrow();
  });

  it("rejects a tampered header (AAD mismatch)", async () => {
    const seed = mnemonicToSeed(KEYSTORE_VECTOR.mnemonic);
    const file = await encodeKeystore(seed, KEYSTORE_VECTOR.password, {
      kdf: "pbkdf2",
      pbkdf2: { iterations: 10_000 },
    });

    //  Change the iteration count. The AAD includes it, so the
    //  MAC should fail.
    const tampered = {
      ...file,
      kdf_params: { ...file.kdf_params, iterations: 20_000 },
    };

    await expect(
      decodeKeystore(tampered as any, KEYSTORE_VECTOR.password),
    ).rejects.toThrow();
  });

  it("validates the file shape", () => {
    expect(() => validateKeystoreShape(null)).toThrow();
    expect(() => validateKeystoreShape({})).toThrow();
    expect(() => validateKeystoreShape({ version: 2 })).toThrow();
    expect(() => validateKeystoreShape({ version: 1, kdf: "bogus" })).toThrow();
  });

  it("includes an optional label", async () => {
    const seed = mnemonicToSeed(KEYSTORE_VECTOR.mnemonic);
    const file = await encodeKeystore(seed, KEYSTORE_VECTOR.password, {
      kdf: "pbkdf2",
      pbkdf2: { iterations: 10_000 },
      label: "My test wallet",
    });
    expect(file.label).toBe("My test wallet");
  });
});