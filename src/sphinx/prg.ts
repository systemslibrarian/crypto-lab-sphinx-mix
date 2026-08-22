/**
 * rho -- the pseudorandom generator that blinds the routing block.
 *
 * ChaCha20 (RFC 8439) run over zeros with an all-zero nonce and counter, which
 * yields the raw keystream. Nonce reuse is not a defect here and is worth
 * being explicit about, because "zero nonce" is normally an alarm: the key
 * itself is h_rho(s), a fresh 32-byte value derived from a Diffie-Hellman
 * secret that is unique per (packet, hop). One key, one stream, ever. There is
 * no second message under this key for the nonce to collide with.
 */
import { chacha20 } from '@noble/ciphers/chacha.js';

const ZERO_NONCE = new Uint8Array(12);

export function rho(key: Uint8Array, length: number): Uint8Array {
  if (key.length !== 32) throw new RangeError(`rho key must be 32 bytes, got ${key.length}`);
  return chacha20(key, ZERO_NONCE, new Uint8Array(length));
}
