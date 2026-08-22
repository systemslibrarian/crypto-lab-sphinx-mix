/**
 * Byte plumbing, plus the two measurements the Peel act reports.
 *
 * The Hamming distance and the byte histogram live here rather than in the UI
 * because they are claims about the cryptography and are unit-tested as such.
 */

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new RangeError(`xor length mismatch: ${a.length} vs ${b.length}`);
  }
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

/** XOR `src` into `dst` in place. */
export function xorInto(dst: Uint8Array, src: Uint8Array): void {
  if (dst.length !== src.length) {
    throw new RangeError(`xorInto length mismatch: ${dst.length} vs ${src.length}`);
  }
  for (let i = 0; i < dst.length; i++) dst[i]! ^= src[i]!;
}

export function zeros(n: number): Uint8Array {
  return new Uint8Array(n);
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

export function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.trim().replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new RangeError('hex string has an odd length');
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new RangeError('hex string has a non-hex character');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Length-independent equality with no early exit.
 *
 * The header MAC comparison runs through this. A byte-at-a-time comparison
 * that returns on the first mismatch leaks, through timing, how many leading
 * bytes of a forged tag were right -- which is a forgery oracle, one byte per
 * query. JavaScript offers no timing guarantees at all, so this is a statement
 * of intent and a correct-by-construction habit rather than a proof; the demo
 * says exactly that on the page rather than claiming constant time.
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Bit-level Hamming distance between two equal-length strings.
 *
 * This is the honest measurement for "the mix's output does not resemble its
 * input". The tempting assertion -- "they share zero bytes" -- is BOTH false
 * as a claim and flaky as a test: two independent pseudorandom strings agree
 * at any given byte position with probability 1/256, so over a 176-byte
 * routing block you expect about 0.69 coincidental matches and see one or more
 * roughly half the time. What actually holds is that the bit-flip count is
 * distributed Binomial(8n, 1/2).
 */
export function hammingDistance(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) {
    throw new RangeError(`hamming length mismatch: ${a.length} vs ${b.length}`);
  }
  let bits = 0;
  for (let i = 0; i < a.length; i++) {
    let v = a[i]! ^ b[i]!;
    while (v) {
      v &= v - 1;
      bits++;
    }
  }
  return bits;
}

/** Number of positions where two equal-length strings hold the same byte. */
export function sharedByteCount(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) {
    throw new RangeError(`sharedByteCount length mismatch: ${a.length} vs ${b.length}`);
  }
  let n = 0;
  for (let i = 0; i < a.length; i++) if (a[i] === b[i]) n++;
  return n;
}

/**
 * Counts of each byte value, bucketed into 16 bins of 16 values.
 *
 * Sixteen bins rather than 256 because the panel has to be readable at 380px
 * and because 176 samples over 256 buckets is too sparse to look like anything
 * at all -- with 16 bins the expected count per bin is 11, which is enough for
 * "flat, no structure" to be visible rather than asserted.
 */
export function byteHistogram(b: Uint8Array, bins = 16): number[] {
  const width = 256 / bins;
  const out = new Array<number>(bins).fill(0);
  for (const v of b) out[Math.min(bins - 1, Math.floor(v / width))]! += 1;
  return out;
}

/**
 * Chi-squared statistic of a histogram against the uniform expectation.
 *
 * Reported next to the histogram so the "looks flat" impression has a number
 * behind it. With 16 bins there are 15 degrees of freedom, so the 95th
 * percentile is 25.0 -- a value above that on a single sample is unremarkable
 * one time in twenty and is NOT evidence of a defect. The page says so; a demo
 * that turned this into a pass/fail light would be teaching a falsehood about
 * what a single chi-squared sample means.
 */
export function chiSquaredUniform(counts: number[]): number {
  const n = counts.reduce((a, b) => a + b, 0);
  if (n === 0) return 0;
  const expected = n / counts.length;
  return counts.reduce((acc, c) => acc + ((c - expected) * (c - expected)) / expected, 0);
}
