/**
 * The five per-hop key derivations, all from one shared secret.
 *
 * The paper names them h_mu, h_rho, h_pi and h_b; h_tau is the replay tag,
 * which the paper leaves to the implementation. Each is HMAC-SHA256 keyed by a
 * distinct ASCII domain string, so no two of them can ever return the same
 * bytes for the same secret -- the property that lets one Diffie-Hellman
 * result key a MAC, a stream cipher and a wide-block permutation at once
 * without any of them being able to say anything about the others.
 *
 * h_b lives in `group.ts` because it returns a scalar rather than a key.
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

const enc = new TextEncoder();

function derive(domain: string, secret: Uint8Array): Uint8Array {
  return hmac(sha256, enc.encode(domain), secret);
}

/** h_mu(s) -- key for the HMAC over the routing block. */
export function hMu(secret: Uint8Array): Uint8Array {
  return derive('sphinx-mix/v1/h_mu', secret);
}

/** h_rho(s) -- key for the PRG that blinds the routing block. */
export function hRho(secret: Uint8Array): Uint8Array {
  return derive('sphinx-mix/v1/h_rho', secret);
}

/** h_pi(s) -- master key for the LIONESS wide-block permutation. */
export function hPi(secret: Uint8Array): Uint8Array {
  return derive('sphinx-mix/v1/h_pi', secret);
}

/**
 * h_tau(s) -- the replay tag a mix remembers.
 *
 * Derived from the shared secret rather than from the packet bytes, and that
 * is the entire point. An attacker who re-sends a captured packet cannot
 * change the secret the mix derives, so the tag is identical no matter how the
 * bytes are dressed up. A tag over the header bytes instead would be defeated
 * by any re-randomisation of the packet, which is precisely what a mix format
 * makes easy.
 */
export function hTau(secret: Uint8Array): Uint8Array {
  return derive('sphinx-mix/v1/h_tau', secret);
}
