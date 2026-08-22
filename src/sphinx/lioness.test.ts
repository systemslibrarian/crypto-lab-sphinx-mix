import { describe, expect, it } from 'vitest';
import { lionessDecrypt, lionessEncrypt, lionessKeys } from './lioness';
import { hammingDistance, randomBytes, toHex, xor } from './bytes';
import { rho } from './prg';
import { LIONESS_LEFT_LEN, PAYLOAD_LEN } from './params';

const key = (): Uint8Array => randomBytes(32);

describe('LIONESS — the unbalanced four-round Feistel', () => {
  it('decrypt undoes encrypt', () => {
    const k = key();
    const m = randomBytes(PAYLOAD_LEN);
    expect(toHex(lionessDecrypt(k, lionessEncrypt(k, m)))).toBe(toHex(m));
  });

  it('encrypt undoes decrypt — it is a permutation in both directions', () => {
    const k = key();
    const c = randomBytes(PAYLOAD_LEN);
    expect(toHex(lionessEncrypt(k, lionessDecrypt(k, c)))).toBe(toHex(c));
  });

  it('a wrong key gives a wrong plaintext', () => {
    const m = randomBytes(PAYLOAD_LEN);
    const c = lionessEncrypt(key(), m);
    expect(toHex(lionessDecrypt(key(), c))).not.toBe(toHex(m));
  });

  it('the four round keys are independent', () => {
    const { k1, k2, k3, k4 } = lionessKeys(key());
    const hexes = new Set([k1, k2, k3, k4].map(toHex));
    expect(hexes.size).toBe(4);
  });

  it('it does not mutate its input', () => {
    const k = key();
    const m = randomBytes(PAYLOAD_LEN);
    const before = toHex(m);
    lionessEncrypt(k, m);
    lionessDecrypt(k, m);
    expect(toHex(m)).toBe(before);
  });

  it('it refuses a block no wider than its left half', () => {
    expect(() => lionessEncrypt(key(), randomBytes(LIONESS_LEFT_LEN))).toThrow(/wider/);
  });

  /**
   * THE PROPERTY THE WHOLE PAYLOAD DESIGN RESTS ON.
   *
   * One flipped ciphertext bit must randomise the ENTIRE plaintext, not one
   * bit of it. The expected Hamming distance is half of all 8192 bits; the
   * bound below is ~11 standard deviations either side (sigma = sqrt(8192)/2
   * = 45.25), so it is a real measurement of avalanche rather than a
   * threshold chosen to be easy.
   */
  it('one flipped ciphertext bit randomises the whole 1024-byte block', () => {
    const k = key();
    const m = randomBytes(PAYLOAD_LEN);
    const c = lionessEncrypt(k, m);
    const bits = PAYLOAD_LEN * 8;
    for (const position of [0, 31, 32, 512, PAYLOAD_LEN - 1]) {
      const c2 = Uint8Array.from(c);
      c2[position]! ^= 0x01;
      const d = hammingDistance(lionessDecrypt(k, c), lionessDecrypt(k, c2));
      expect(d, `flip at byte ${position}`).toBeGreaterThan(bits / 2 - 500);
      expect(d, `flip at byte ${position}`).toBeLessThan(bits / 2 + 500);
    }
  });

  it('one flipped PLAINTEXT bit randomises the whole ciphertext too', () => {
    const k = key();
    const m = randomBytes(PAYLOAD_LEN);
    const m2 = Uint8Array.from(m);
    m2[700]! ^= 0x40;
    const d = hammingDistance(lionessEncrypt(k, m), lionessEncrypt(k, m2));
    expect(d).toBeGreaterThan(PAYLOAD_LEN * 8 * 0.4);
  });

  /**
   * The contrast that justifies the choice, measured rather than asserted.
   *
   * Revision 2 of this lab's brief specified "stream cipher over the payload".
   * This is what that would have shipped: a flipped ciphertext bit moves
   * exactly one plaintext bit, which is a clean, recognisable mark an adversary
   * can look for on the far side of the network. That is the tagging attack.
   */
  it('a stream cipher, by contrast, moves exactly one bit — which is the attack', () => {
    const k = key();
    const m = randomBytes(PAYLOAD_LEN);
    const stream = rho(k, PAYLOAD_LEN);
    const c = xor(m, stream);
    const c2 = Uint8Array.from(c);
    c2[700]! ^= 0x40;
    expect(hammingDistance(xor(c, stream), xor(c2, stream))).toBe(1);
  });
});
