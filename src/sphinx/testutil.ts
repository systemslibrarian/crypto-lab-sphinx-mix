/**
 * Helpers shared by the unit tests. Not part of the shipped app; kept out of
 * `src/ui` so nothing in the page can import it by accident.
 */
import type { SphinxPacket } from './packet';
import { clonePacket } from './packet';

/** Flip one bit of one byte, returning a fresh array. */
export function flipBit(source: Uint8Array, index: number, mask = 0x01): Uint8Array {
  const out = Uint8Array.from(source);
  out[index] = (out[index] ?? 0) ^ mask;
  return out;
}

/** A copy of `packet` with one byte of `beta` flipped. */
export function tamperBeta(packet: SphinxPacket, index: number, mask = 0x01): SphinxPacket {
  const copy = clonePacket(packet);
  copy.header.beta = flipBit(copy.header.beta, index, mask);
  return copy;
}

/** A copy of `packet` with one byte of the payload flipped. */
export function tamperPayload(packet: SphinxPacket, index: number, mask = 0x01): SphinxPacket {
  const copy = clonePacket(packet);
  copy.payload = flipBit(copy.payload, index, mask);
  return copy;
}

/** A copy of `packet` with one byte of `gamma` flipped. */
export function tamperGamma(packet: SphinxPacket, index: number, mask = 0xff): SphinxPacket {
  const copy = clonePacket(packet);
  copy.header.gamma = flipBit(copy.header.gamma, index, mask);
  return copy;
}

/** A copy of `packet` with one byte of `alpha` flipped. */
export function tamperAlpha(packet: SphinxPacket, index: number, mask = 0x01): SphinxPacket {
  const copy = clonePacket(packet);
  copy.header.alpha = flipBit(copy.header.alpha, index, mask);
  return copy;
}
