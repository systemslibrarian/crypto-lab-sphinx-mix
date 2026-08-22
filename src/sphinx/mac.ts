/**
 * mu -- the per-hop header MAC.
 *
 * HMAC-SHA256 keyed by h_mu(s), truncated to kappa = 16 bytes. Truncation is
 * the paper's; 128 bits is a forgery probability of 2^-128 per attempt against
 * a mix that gives no oracle beyond accept/reject.
 *
 * WHAT IT COVERS, AND WHAT IT DOES NOT. gamma authenticates BETA -- the
 * routing block -- and nothing else. Not the payload, not alpha directly
 * (alpha is bound in through the key: h_mu(s) depends on s = alpha^x). So a
 * mix can prove to itself that the routing instructions it is about to follow
 * are the ones the sender wrote, and can prove nothing whatever about the
 * bytes it is forwarding. That asymmetry is deliberate, it is the design, and
 * it is what the Tagging act exists to make visible.
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { GAMMA_LEN } from './params';

export function truncatedMac(key: Uint8Array, message: Uint8Array): Uint8Array {
  return hmac(sha256, key, message).subarray(0, GAMMA_LEN);
}
