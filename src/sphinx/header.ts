/**
 * Header construction -- the paper's §3.2, in order.
 *
 * The header is built FROM THE INSIDE OUT: the innermost routing block, the
 * one only the last mix can read, is written first, and each earlier hop's
 * block is wrapped around it. That is why the Build act plays in reverse --
 * it is not a presentational choice, it is the order the construction runs in.
 *
 * Every intermediate value is returned rather than discarded. This is a
 * teaching lab; the whole point is that the learner can see s_i, b_i, phi_i
 * and each beta_i, which a production implementation would keep to itself.
 */
import { concat, xor, zeros } from './bytes';
import { SphinxError } from './errors';
import {
  deriveBlinding,
  mulBase,
  mulPoint,
  mulScalars,
  pointFromBytes,
  randomScalar,
} from './group';
import { hMu, hRho } from './kdf';
import {
  ALPHA_LEN,
  BETA_LEN,
  END_MARKER,
  GAMMA_LEN,
  KAPPA,
  MAX_HOPS,
  RHO_LEN,
} from './params';
import { rho } from './prg';
import { truncatedMac } from './mac';

/** A mix as the sender sees it: a public id and a public key. */
export interface NodeRef {
  /** kappa-byte routing identifier, the value that appears in a routing block. */
  id: Uint8Array;
  /** 32-byte ristretto255 public key. */
  pub: Uint8Array;
  /** Display name. Never on the wire. */
  name: string;
}

export interface SphinxHeader {
  alpha: Uint8Array;
  beta: Uint8Array;
  gamma: Uint8Array;
}

/** Everything the sender computed, kept for the UI and the tests. */
export interface HeaderBuild {
  header: SphinxHeader;
  /** s_0 .. s_{nu-1} -- the per-hop shared secrets, in path order. */
  sharedSecrets: Uint8Array[];
  /** alpha_0 .. alpha_{nu-1} -- the group element as each hop will see it. */
  alphas: Uint8Array[];
  /** b_0 .. b_{nu-1} -- blinding factors. */
  blindings: bigint[];
  /** phi_0 .. phi_{nu-1} -- fillers; |phi_i| = 2*i*kappa. */
  fillers: Uint8Array[];
  /** beta_{nu-1} .. beta_0, reindexed to path order. */
  betas: Uint8Array[];
  /** gamma_{nu-1} .. gamma_0, reindexed to path order. */
  gammas: Uint8Array[];
}

/**
 * The Diffie-Hellman chain: alpha_i, s_i and b_i for every hop.
 *
 * `running` is x * b_0 * b_1 * ... * b_{i-1} modulo ell. The sender knows
 * every one of these because it knows x and can derive each b_i itself; each
 * mix learns only its own s_i, from alpha_i and its private key. Nothing in
 * alpha_i reveals i, which is why a mix cannot tell its position on the path.
 */
export function deriveChain(path: NodeRef[]): {
  alphas: Uint8Array[];
  secrets: Uint8Array[];
  blindings: bigint[];
} {
  if (path.length === 0) throw new SphinxError('MALFORMED_HEADER', 'a path needs at least one hop');
  if (path.length > MAX_HOPS) {
    throw new SphinxError(
      'PATH_TOO_LONG',
      `${path.length} hops requested but the header is sized for r = ${MAX_HOPS}`
    );
  }
  const alphas: Uint8Array[] = [];
  const secrets: Uint8Array[] = [];
  const blindings: bigint[] = [];
  let running = randomScalar();
  for (const node of path) {
    const alpha = mulBase(running);
    const secret = mulPoint(pointFromBytes(node.pub), running);
    const alphaBytes = alpha.toBytes();
    const secretBytes = secret.toBytes();
    const b = deriveBlinding(alphaBytes, secretBytes);
    alphas.push(alphaBytes);
    secrets.push(secretBytes);
    blindings.push(b);
    running = mulScalars(running, b);
  }
  return { alphas, secrets, blindings };
}

/**
 * The filler strings, phi_0 .. phi_{nu-1}.
 *
 * This is the mechanism that makes the header a fixed size. As each mix strips
 * 2*kappa bytes off the front of the routing block, it appends 2*kappa bytes
 * of its own keystream to the back. The filler is the sender computing, in
 * advance, exactly what those appended bytes will be at every hop, so it can
 * lay them into the innermost block. The last mix therefore sees a full-length
 * routing block of which most is keystream it generated itself several hops
 * earlier -- indistinguishable, to it, from instructions for hops that do not
 * exist.
 *
 *   phi_0 = empty
 *   phi_i = (phi_{i-1} || 0_{2*kappa}) XOR rho(h_rho(s_{i-1}))[(2(r-i)+3)k .. (2r+3)k]
 */
export function buildFillers(secrets: Uint8Array[]): Uint8Array[] {
  const fillers: Uint8Array[] = [new Uint8Array(0)];
  for (let i = 1; i < secrets.length; i++) {
    const previous = fillers[i - 1]!;
    const padded = concat(previous, zeros(2 * KAPPA));
    const stream = rho(hRho(secrets[i - 1]!), RHO_LEN);
    const slice = stream.subarray((2 * (MAX_HOPS - i) + 3) * KAPPA, RHO_LEN);
    if (slice.length !== padded.length) {
      throw new SphinxError(
        'MALFORMED_HEADER',
        `filler ${i}: keystream slice is ${slice.length} bytes, padded filler is ${padded.length}`
      );
    }
    fillers.push(xor(padded, slice));
  }
  return fillers;
}

/**
 * Build (alpha_0, beta_0, gamma_0) for `path`, carrying `identifier`.
 *
 * `identifier` is the paper's `I`: kappa bytes the exit hands to the recipient
 * alongside the payload. It never leaves the innermost routing block, so no
 * mix but the last one ever sees it.
 */
export function createHeader(path: NodeRef[], identifier: Uint8Array): HeaderBuild {
  if (identifier.length !== KAPPA) {
    throw new SphinxError('MALFORMED_HEADER', `identifier must be ${KAPPA} bytes`);
  }
  for (const node of path) {
    if (node.id.length !== KAPPA) {
      throw new SphinxError('MALFORMED_HEADER', `node id must be ${KAPPA} bytes (${node.name})`);
    }
  }
  const nu = path.length;
  const { alphas, secrets, blindings } = deriveChain(path);
  const fillers = buildFillers(secrets);

  // --- the innermost block, for the last mix -----------------------------
  // (END || I || zero pad) XOR the head of the last hop's keystream, then the
  // filler, which is already exactly what the earlier hops will have appended.
  const tailPad = zeros((2 * (MAX_HOPS - nu) + 1) * KAPPA);
  const inner = concat(END_MARKER, identifier, tailPad);
  const innerStream = rho(hRho(secrets[nu - 1]!), RHO_LEN).subarray(
    0,
    (2 * (MAX_HOPS - nu) + 3) * KAPPA
  );
  const betas: Uint8Array[] = new Array<Uint8Array>(nu);
  const gammas: Uint8Array[] = new Array<Uint8Array>(nu);
  betas[nu - 1] = concat(xor(inner, innerStream), fillers[nu - 1]!);
  gammas[nu - 1] = truncatedMac(hMu(secrets[nu - 1]!), betas[nu - 1]!);

  // --- wrap outward: hop nu-2 down to hop 0 ------------------------------
  for (let i = nu - 2; i >= 0; i--) {
    const plain = concat(
      path[i + 1]!.id,
      gammas[i + 1]!,
      betas[i + 1]!.subarray(0, BETA_LEN - 2 * KAPPA)
    );
    betas[i] = xor(plain, rho(hRho(secrets[i]!), RHO_LEN).subarray(0, BETA_LEN));
    gammas[i] = truncatedMac(hMu(secrets[i]!), betas[i]!);
  }

  for (const b of betas) {
    if (b.length !== BETA_LEN) {
      throw new SphinxError('MALFORMED_HEADER', `beta is ${b.length} bytes, expected ${BETA_LEN}`);
    }
  }

  return {
    header: { alpha: alphas[0]!, beta: betas[0]!, gamma: gammas[0]! },
    sharedSecrets: secrets,
    alphas,
    blindings,
    fillers,
    betas,
    gammas,
  };
}

/** Reject a header whose fields are the wrong size before touching any key. */
export function assertHeaderShape(h: SphinxHeader): void {
  if (h.alpha.length !== ALPHA_LEN) {
    throw new SphinxError('MALFORMED_HEADER', `alpha is ${h.alpha.length} bytes, expected ${ALPHA_LEN}`);
  }
  if (h.beta.length !== BETA_LEN) {
    throw new SphinxError('MALFORMED_HEADER', `beta is ${h.beta.length} bytes, expected ${BETA_LEN}`);
  }
  if (h.gamma.length !== GAMMA_LEN) {
    throw new SphinxError('MALFORMED_HEADER', `gamma is ${h.gamma.length} bytes, expected ${GAMMA_LEN}`);
  }
}
