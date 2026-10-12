/**
 * Chain-specific derivation paths.
 *
 * These match the C++ `HdPath.h` exactly. Any divergence produces
 * keys the chain won't recognize, so they're defined once here and
 * used everywhere.
 */

import { deriveEd25519 } from "./slip10.js";
import type { WalletKeys } from "./types.js";

/**
 * BIP-44 coin type for CLRTY. Registered values are assigned by
 * SLIP-0044; 9000 is in the "unregistered / testing" range, which
 * is what the CLI uses.
 */
export const CLRTY_COIN_TYPE = 9000;

/** The reward key branch (BIP-44 receive). */
export const REWARD_BRANCH = 0;

/** The validator consensus key branch. */
export const CONSENSUS_BRANCH = 2;

/**
 * Build a derivation path for a reward address.
 *
 *   m/44'/9000'/account'/0'/index'
 */
export function rewardPath(account: number, index: number): number[] {
  return [44, CLRTY_COIN_TYPE, account, REWARD_BRANCH, index];
}

/**
 * Build a derivation path for a consensus key.
 *
 *   m/44'/9000'/account'/2'/index'
 */
export function consensusPath(account: number, index: number): number[] {
  return [44, CLRTY_COIN_TYPE, account, CONSENSUS_BRANCH, index];
}

/**
 * Derive the two keys the wallet manages: the reward key at
 * account 0, index 0, and the consensus key at the same account
 * and index. This is the derivation the CLI performs for
 * `address --new`.
 */
export function deriveWalletKeys(seed: Uint8Array): WalletKeys {
  const reward = deriveEd25519(seed, rewardPath(0, 0));
  const consensus = deriveEd25519(seed, consensusPath(0, 0));
  return {
    rewardPublic: reward.public,
    rewardSecret: reward.secret,
    consensusPublic: consensus.public,
    consensusSecret: consensus.secret,
  };
}