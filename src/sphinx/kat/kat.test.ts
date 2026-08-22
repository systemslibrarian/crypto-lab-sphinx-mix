import { describe, expect, it } from 'vitest';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { chacha20 } from '@noble/ciphers/chacha.js';
import {
  CHACHA20_BLOCK0_ZERO,
  CHACHA20_BLOCK1_ZERO,
  CHACHA20_SUNSCREEN,
  HMAC_SHA256_VECTORS,
  RISTRETTO_BAD_ENCODINGS,
  RISTRETTO_BASE_MULTIPLES,
  SHA256_ABC,
  SHA512_ABC,
} from './vectors';
import { fromHex, toHex, xor } from '../bytes';
import { BASE_POINT, mulBase, pointFromBytes } from '../group';
import { rho } from '../prg';
import { truncatedMac } from '../mac';
import { GAMMA_LEN } from '../params';

const ascii = (s: string): Uint8Array => new TextEncoder().encode(s);

/**
 * KATs run through THIS LAB'S wrappers, not through the library directly.
 *
 * That is the point of the exercise: `mulBase`, `rho` and `truncatedMac` are
 * the functions the packet format actually calls, and a KAT that bypassed them
 * to test the library would still pass if this lab wired the library up wrong.
 */
describe('KAT — ristretto255 (RFC 9496 Appendix A.1)', () => {
  it('encodes all sixteen small multiples of the base point', () => {
    expect(RISTRETTO_BASE_MULTIPLES).toHaveLength(16);
    for (let k = 0; k < RISTRETTO_BASE_MULTIPLES.length; k++) {
      const encoded = k === 0 ? new Uint8Array(32) : mulBase(BigInt(k)).toBytes();
      expect(toHex(encoded), `${k}B`).toBe(RISTRETTO_BASE_MULTIPLES[k]);
    }
  });

  it('the generator this lab uses is RFC 9496’s generator', () => {
    expect(toHex(BASE_POINT.toBytes())).toBe(RISTRETTO_BASE_MULTIPLES[1]);
  });

  it('decoding round-trips every one of them', () => {
    for (let k = 1; k < RISTRETTO_BASE_MULTIPLES.length; k++) {
      const hex = RISTRETTO_BASE_MULTIPLES[k]!;
      expect(toHex(pointFromBytes(fromHex(hex)).toBytes())).toBe(hex);
    }
  });
});

describe('KAT — ristretto255 rejected encodings (RFC 9496 Appendix A.3)', () => {
  it('every listed bad encoding is refused as MALFORMED_HEADER', () => {
    expect(RISTRETTO_BAD_ENCODINGS.length).toBeGreaterThan(0);
    for (const { hex, why } of RISTRETTO_BAD_ENCODINGS) {
      expect(() => pointFromBytes(fromHex(hex)), `${why}: ${hex}`).toThrow(/MALFORMED_HEADER/);
    }
  });
});

describe('KAT — ChaCha20 (RFC 8439)', () => {
  it('Appendix A.1 test vector 1 — block 0 under an all-zero key and nonce', () => {
    expect(toHex(rho(new Uint8Array(32), 64))).toBe(CHACHA20_BLOCK0_ZERO);
  });

  it('Appendix A.1 test vector 2 — block 1 of the same stream', () => {
    expect(toHex(rho(new Uint8Array(32), 128).subarray(64, 128))).toBe(CHACHA20_BLOCK1_ZERO);
  });

  it('§2.4.2 — the sunscreen encryption vector', () => {
    // This vector uses a non-zero nonce and starts at counter 1. `rho` pins the
    // nonce to zero by design (see prg.ts), so this one test drives ChaCha20
    // directly with the RFC's nonce and skips the counter-0 block, rather than
    // widening `rho`'s signature for a test.
    const plaintext = ascii(CHACHA20_SUNSCREEN.plaintext);
    const stream = chacha20(
      fromHex(CHACHA20_SUNSCREEN.keyHex),
      fromHex(CHACHA20_SUNSCREEN.nonceHex),
      new Uint8Array(64 + plaintext.length)
    );
    const ciphertext = xor(plaintext, stream.subarray(64, 64 + plaintext.length));
    expect(toHex(ciphertext)).toBe(CHACHA20_SUNSCREEN.ciphertextHex);
  });

  it('rho really is ChaCha20 under the all-zero nonce it documents', () => {
    const key = fromHex('ab'.repeat(32));
    const direct = chacha20(key, new Uint8Array(12), new Uint8Array(96));
    expect(toHex(direct)).toBe(toHex(rho(key, 96)));
  });
});

describe('KAT — HMAC-SHA-256 (RFC 4231)', () => {
  it('all seven test cases', () => {
    expect(HMAC_SHA256_VECTORS).toHaveLength(7);
    for (const v of HMAC_SHA256_VECTORS) {
      const key = fromHex(v.keyHex);
      const data = v.dataHex ? fromHex(v.dataHex) : ascii(v.dataText ?? '');
      const full = hmac(sha256, key, data);
      const got = v.truncate ? full.subarray(0, v.truncate) : full;
      expect(toHex(got), v.name).toBe(v.macHex);
    }
  });

  it('this lab’s gamma is exactly RFC 4231 case 5’s 128-bit truncation', () => {
    const c5 = HMAC_SHA256_VECTORS.find((v) => v.truncate === GAMMA_LEN);
    expect(c5).toBeDefined();
    const got = truncatedMac(fromHex(c5!.keyHex), ascii('Test With Truncation'));
    expect(got).toHaveLength(GAMMA_LEN);
    expect(toHex(got)).toBe(c5!.macHex);
  });
});

describe('KAT — SHA-2 (FIPS 180-4)', () => {
  it('SHA-256("abc")', () => {
    expect(toHex(sha256(ascii('abc')))).toBe(SHA256_ABC);
  });
  it('SHA-512("abc")', () => {
    expect(toHex(sha512(ascii('abc')))).toBe(SHA512_ABC);
  });
});
