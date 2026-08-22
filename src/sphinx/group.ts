/**
 * The group Sphinx's blinding chain runs in: ristretto255 (RFC 9496).
 *
 * WHY NOT X25519, WHICH IS THE THING EVERYONE REACHES FOR.
 *
 * Sphinx does not do one Diffie-Hellman. It does a CHAIN of them, and the
 * chain is built by repeatedly re-blinding the same group element:
 *
 *     alpha_0 = g^x                  s_0 = y_0^x
 *     alpha_1 = alpha_0^{b_0}        s_1 = y_1^{x b_0}
 *     alpha_2 = alpha_1^{b_1}        s_2 = y_2^{x b_0 b_1}
 *
 * Every mix must be able to recompute s_i = alpha_i^{x_i} from the element it
 * receives, and the sender must be able to predict all of them in advance.
 * That requires the exponents to compose as plain integers modulo the group
 * order: b_1 * b_0 * x has to mean what it says.
 *
 * RFC 7748's X25519 breaks exactly that. It CLAMPS its scalar -- clears the
 * three low bits, clears bit 255, sets bit 254 -- before every scalar
 * multiplication. So X25519(b, X25519(a, G)) is not X25519(clamp(b)*clamp(a),
 * G): the second clamp is applied to `b` itself, not to the product, and the
 * product of two clamped scalars is not clamped. Iterated blinding therefore
 * does not compose, and a Sphinx built on the clamped API silently derives a
 * different secret at the mix than the sender predicted. On top of that,
 * Curve25519 has cofactor 8, so a small-order alpha is a live degeneracy the
 * format has to handle rather than a case that cannot arise.
 *
 * ristretto255 removes both problems by construction: it is a prime-order
 * group (no cofactor, no small-order elements, no torsion), its encoding is
 * canonical and validated on decode, and its scalar multiplication is honest
 * scalar multiplication with no clamping. The blinding chain is then just
 * arithmetic in Z_ell.
 *
 * This module is the only place that touches the curve library.
 */
import { ristretto255 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { concat, randomBytes } from './bytes';
import { SphinxError } from './errors';
import { ALPHA_LEN } from './params';

const Point = ristretto255.Point;
export type GroupPoint = InstanceType<typeof Point>;

/** ell -- the prime order of the ristretto255 group. */
export const GROUP_ORDER: bigint = Point.Fn.ORDER;

/** The standard generator, `g` in the paper's notation. */
export const BASE_POINT: GroupPoint = Point.BASE;

/** Canonical 32-byte encoding of the generator (RFC 9496 test vector 1). */
export function basePointBytes(): Uint8Array {
  return BASE_POINT.toBytes();
}

/**
 * Decode a group element, rejecting anything non-canonical.
 *
 * RFC 9496 decoding is strict: it rejects non-canonical field encodings and
 * any string that is not the image of a valid point. A mix that skipped this
 * would be deriving a shared secret from an attacker-chosen bit pattern.
 */
export function pointFromBytes(b: Uint8Array): GroupPoint {
  if (b.length !== ALPHA_LEN) {
    throw new SphinxError('MALFORMED_HEADER', `alpha is ${b.length} bytes, expected ${ALPHA_LEN}`);
  }
  try {
    return Point.fromBytes(b);
  } catch (e) {
    throw new SphinxError('MALFORMED_HEADER', `alpha is not a canonical ristretto255 element (${String(e)})`);
  }
}

/** Reduce a little-endian byte string modulo ell. */
export function scalarFromBytesLE(b: Uint8Array): bigint {
  let acc = 0n;
  for (let i = b.length - 1; i >= 0; i--) acc = (acc << 8n) | BigInt(b[i]!);
  return acc % GROUP_ORDER;
}

/**
 * A uniform non-zero scalar.
 *
 * 64 bytes reduced modulo ell, not 32: reducing a 32-byte value mod ell biases
 * the low scalars, and while the bias is around 2^-124 and of no practical
 * consequence, wide reduction costs nothing and this is a lab where someone
 * will read the code to learn how it is done.
 */
export function randomScalar(): bigint {
  for (;;) {
    const s = scalarFromBytesLE(randomBytes(64));
    if (s !== 0n) return s;
  }
}

export function mulBase(k: bigint): GroupPoint {
  return BASE_POINT.multiply(k);
}

export function mulPoint(p: GroupPoint, k: bigint): GroupPoint {
  return p.multiply(k);
}

/** Multiply modulo ell -- how the sender walks the blinding chain forward. */
export function mulScalars(a: bigint, b: bigint): bigint {
  return (a * b) % GROUP_ORDER;
}

/**
 * h_b(alpha, s) -- the blinding factor for the next hop.
 *
 * Domain-separated and bound to BOTH the group element the mix saw and the
 * secret only the mix can derive. Binding to alpha as well as s is the
 * paper's choice and it matters: it ties the blinding to the exact element in
 * flight, so a mix cannot be tricked into blinding a substituted element with
 * a factor derived from a secret computed against a different one.
 *
 * SHA-512 reduced modulo ell, i.e. the same wide reduction as `randomScalar`.
 */
export function deriveBlinding(alphaBytes: Uint8Array, secret: Uint8Array): bigint {
  const tag = new TextEncoder().encode('sphinx-mix/v1/h_b');
  const h = sha512(concat(tag, alphaBytes, secret));
  const s = scalarFromBytesLE(h);
  // A zero blinding factor would send alpha to the identity and collapse the
  // chain. It cannot happen (probability ~2^-252) but a mix that assumed so
  // without saying so would be trusting an unstated invariant.
  return s === 0n ? 1n : s;
}

/** A fresh mix key pair. Private material is a bigint held only in memory. */
export function generateKeyPair(): { priv: bigint; pub: Uint8Array } {
  const priv = randomScalar();
  return { priv, pub: mulBase(priv).toBytes() };
}
