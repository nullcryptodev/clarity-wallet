/**
 * Test vectors for the wallet package.
 *
 * These are cross-implementation checks. The expected values are
 * the ones the C++ side produces, taken from the CLI's own test
 * suite. If the JS side produces the same output, the two
 * implementations agree.
 *
 * Any failure here means a user's keystore or signature would be
 * incompatible between the browser and the CLI.
 */

/**
 * BIP-39 test vector. The mnemonic and expected seed are from the
 * BIP-39 specification (Trezor's test vectors).
 */
export const BIP39_VECTOR = {
  mnemonic:
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  seed: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
};

/**
 * SLIP-10 Ed25519 test vector. From the SLIP-0010 spec, test 1.
 *
 * Seed: 000102030405060708090a0b0c0d0e0f
 *
 * Note: the spec lists several test vectors for Ed25519. This is
 * test 1. Test 2 uses the same paths with a different seed, so it
 * produces different keys — mixing values from the two is the
 * classic way to get a failing but valid-looking test.
 */
export const SLIP10_VECTOR = {
  seed: "000102030405060708090a0b0c0d0e0f",
  paths: [
    {
      path: [], // master
      chainCode:
        "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
      publicKey:
        "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
    },
    {
      path: [0], // m/0'
      chainCode:
        "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
      publicKey:
        "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
    },
    {
      path: [0, 1], // m/0'/1'
      chainCode:
        "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
      publicKey:
        "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
    },
    {
      path: [0, 1, 2], // m/0'/1'/2'
      chainCode:
        "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
      publicKey:
        "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
    },
  ],
};

/**
 * A fixed mnemonic and password used for round-trip keystore
 * tests. The encrypted form isn't checked (Argon2id and the AEAD
 * nonce are randomized), but the decrypted seed is.
 */
export const KEYSTORE_VECTOR = {
  mnemonic:
    "stock equal skill catalog reduce divorce abuse bachelor abuse actor doll pear option tired save rich shrimp census grass stock help ozone scout raccoon",
  password: "test-password-do-not-use",
};

/**
 * The derived keys for KEYSTORE_VECTOR.mnemonic at the chain's
 * derivation paths. The expected values are what the CLI produces.
 *
 * If the JS side produces different values, the derivation has
 * diverged.
 */
export const DERIVATION_VECTOR = {
  rewardPublic:
    "f06644de27eaf075cde0ea5ef07c26a68b76db05b20d5b087dc3eafd76d44427",
  rewardSecret:
    "5aa3cd83b2effed042c270299a2a263fc7284a8c42633cbc57ebc5bd32c499f6",
  consensusPublic:
    "819e73fb3824110623a96473c734150777c9c7ed54f236bc593aba46064d0ef6",
  consensusSecret:
    "1f2ffb188fe20fec1932d0ae427ff4dc3947251616ae26a09d677f1a57848af6",
};