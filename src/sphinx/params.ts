/**
 * Sphinx parameters.
 *
 * Sphinx: A Compact and Provably Secure Mix Format — George Danezis and Ian
 * Goldberg, IEEE Symposium on Security and Privacy 2009 (ePrint 2008/475).
 *
 * The paper's §3 notation is kept verbatim so the code can be read beside it:
 * `r` is the maximum path length, `kappa` the security parameter, and the
 * header is the triple (alpha, beta, gamma). Every length below is derived
 * from those two numbers exactly as the paper derives them, which is what
 * makes the header the same size for a one-hop path and a five-hop path.
 *
 *   |beta| = (2r + 1) * kappa      the routing block
 *   |rho|  = (2r + 3) * kappa      the PRG stream a hop draws
 *   |phi_i| = 2 * i * kappa        the filler after i hops
 *
 * The (2r+3) vs (2r+1) gap of 2*kappa is the whole trick: a hop appends
 * 2*kappa bytes of keystream to the tail of the routing block as it strips
 * 2*kappa bytes off the front, so the block neither grows nor shrinks and the
 * tail is indistinguishable from the routing instructions it replaces.
 *
 * TWO DELIBERATE, DOCUMENTED DEVIATIONS FROM THE PAPER'S LETTER, neither of
 * which changes the construction:
 *
 *  1. The paper writes every derived key as kappa bits. We derive full-width
 *     32-byte keys for ChaCha20, HMAC-SHA256 and LIONESS and truncate only the
 *     header MAC to kappa. A 16-byte ChaCha20 key does not exist, so the
 *     literal reading is not implementable; truncating the tag to 128 bits is
 *     what every deployed Sphinx does.
 *
 *  2. The paper's final routing block is (Delta || I || pad), where Delta is a
 *     variable-length destination encoding. This lab has one recipient, so
 *     Delta is the fixed kappa-byte marker `END_MARKER` and `I` is the
 *     kappa-byte packet identifier. The lengths and the parsing rule are
 *     unchanged; only the alphabet of legal first blocks is smaller.
 */

/** Security parameter, in bytes. MAC length, node-id length, filler quantum. */
export const KAPPA = 16;

/** `r` — the maximum path length the format is sized for. */
export const MAX_HOPS = 5;

/** Encoded ristretto255 group element. */
export const ALPHA_LEN = 32;

/** |beta| = (2r + 1) * kappa. Constant for every path length up to r. */
export const BETA_LEN = (2 * MAX_HOPS + 1) * KAPPA;

/** |rho| = (2r + 3) * kappa — the PRG output a single hop consumes. */
export const RHO_LEN = (2 * MAX_HOPS + 3) * KAPPA;

/** |gamma| — the per-hop HMAC over beta, truncated to kappa. */
export const GAMMA_LEN = KAPPA;

/** Every packet carries exactly this many payload bytes, always. */
export const PAYLOAD_LEN = 1024;

/**
 * LIONESS splits its block into a left half the width of the hash and a right
 * half that is everything else. 32 bytes is SHA-256's output width.
 */
export const LIONESS_LEFT_LEN = 32;

/**
 * The kappa-byte marker that tells the last mix it is the last mix, and tells
 * the recipient the wide-block permutation was unwound correctly.
 *
 * All zero, on purpose, and the reason is worth stating: under a PRP the
 * probability that a corrupted payload decrypts to a block whose first kappa
 * bytes are zero is 2^-128. That is a CORRUPTION DETECTOR, not an
 * authenticator -- see `lioness.ts`.
 */
export const END_MARKER = new Uint8Array(KAPPA);

/** Header total size on the wire, for the "it never changes" panel. */
export const HEADER_LEN = ALPHA_LEN + BETA_LEN + GAMMA_LEN;

/** Whole packet size on the wire. */
export const PACKET_LEN = HEADER_LEN + PAYLOAD_LEN;
