import { bech32m } from "@scure/base";
import type { Bech32mAddress, Network } from "./types.js";
import { NETWORK_HRP } from "./types.js";

/**
 * Encode a 32-byte public key as a bech32m address for the given
 * network.
 */
export function encodeAddress(
  publicKey: Uint8Array,
  network: Network,
): Bech32mAddress {
  if (publicKey.length !== 32) {
    throw new Error(`public key must be 32 bytes, got ${publicKey.length}`);
  }
  const hrp = NETWORK_HRP[network];
  return bech32m.encode(hrp, publicKey, false);
}

/**
 * Decode a bech32m address to its 32-byte public key. Throws on
 * a bad checksum, wrong HRP, or wrong length.
 */
export function decodeAddress(
  address: Bech32mAddress,
  network?: Network,
): Uint8Array {
  //  @scure/base types the input as a template literal that
  //  contains a "1", because a bech32m string without a separator
  //  is not a valid address. Checking here gives a clearer error
  //  than the runtime one, and narrows the type for the call.
  const sep = address.lastIndexOf("1");
  if (sep < 0) {
    throw new Error(`not a bech32m address (no separator): ${address}`);
  }

  const result = bech32m.decode(address as `${string}1${string}`);

  if (network !== undefined && result.prefix !== NETWORK_HRP[network]) {
    throw new Error(
      `expected HRP ${NETWORK_HRP[network]}, got ${result.prefix}`,
    );
  }

  const bytes = bech32m.fromWords(result.words);
  if (bytes.length !== 32) {
    throw new Error(`address decodes to ${bytes.length} bytes, expected 32`);
  }
  return bytes;
}