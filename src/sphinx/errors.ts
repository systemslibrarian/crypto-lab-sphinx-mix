/**
 * The five ways a Sphinx packet dies in this lab.
 *
 * They are separate codes because they are separate failures with separate
 * lessons, and collapsing them into one "invalid packet" is how a mix design
 * loses the distinction between "an attacker touched the routing block" and
 * "an attacker replayed a packet it captured an hour ago".
 */
export const FAILURE_CODES = [
  /** gamma did not match HMAC(h_mu(s), beta). The header was modified. */
  'HMAC_FAIL',
  /** h_tau(s) is already in this mix's seen-tag set. */
  'REPLAY_DETECTED',
  /** The requested path is longer than r, so no header can encode it. */
  'PATH_TOO_LONG',
  /** alpha is not a canonical ristretto255 element, or a field is mis-sized. */
  'MALFORMED_HEADER',
  /** The decrypted routing block names neither a known mix nor the end marker. */
  'UNKNOWN_ROUTING_BLOCK',
] as const;

export type FailureCode = (typeof FAILURE_CODES)[number];

/** One-line explanations, shown beside the code wherever a packet dies. */
export const FAILURE_TEXT: Record<FailureCode, string> = {
  HMAC_FAIL:
    'The per-hop HMAC over the routing block did not verify. This mix refuses to route a header it cannot authenticate, so the packet stops here.',
  REPLAY_DETECTED:
    'This mix has already processed a packet with this shared-secret tag. Forwarding it again would let an observer send the same bytes twice and watch where they go.',
  PATH_TOO_LONG:
    'The header is sized for a fixed maximum path length. A longer path cannot be encoded, and silently truncating it would leak the real length.',
  MALFORMED_HEADER:
    'A header field is the wrong size, or the group element is not a canonical ristretto255 encoding. Parsing stops before any secret is derived.',
  UNKNOWN_ROUTING_BLOCK:
    'The decrypted routing block names neither a mix this node knows nor the end-of-path marker. There is nowhere to forward it.',
};

/** Thrown by the packet/mix layer; carries the code the UI prints. */
export class SphinxError extends Error {
  readonly code: FailureCode;
  constructor(code: FailureCode, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'SphinxError';
    this.code = code;
  }
}
