/**
 * A mix node: the receiving half of the protocol.
 *
 * Every check a mix performs is here, in the order it performs them, and the
 * ORDER IS PART OF THE DESIGN:
 *
 *   1. shape          -- reject a mis-sized field before touching a key
 *   2. s = alpha^x    -- the one private-key operation
 *   3. gamma          -- authenticate the routing block
 *   4. replay tag     -- only now, and see below for why
 *   5. unwrap beta    -- one PRG stream over (beta || 0_2k)
 *   6. blind alpha    -- alpha' = alpha^{h_b(alpha, s)}
 *   7. peel delta     -- pi^-1 over the payload
 *
 * WHY THE REPLAY CHECK COMES AFTER THE MAC. The tag is h_tau(s), and s depends
 * only on alpha, so an adversary can take a legitimate packet in flight,
 * corrupt one byte of beta and race it to the mix. If the mix recorded the tag
 * before checking gamma, that forged packet would poison the seen-set and the
 * REAL packet would be dropped behind it as a replay -- a one-byte
 * denial-of-service against any packet an adversary can see. Authenticate
 * first; remember only what you accepted.
 */
import { concat, equalBytes, toHex, xor, zeros } from './bytes';
import { SphinxError, type FailureCode } from './errors';
import { assertHeaderShape, type SphinxHeader } from './header';
import { deriveBlinding, mulPoint, pointFromBytes } from './group';
import { hMu, hPi, hRho, hTau } from './kdf';
import { lionessDecrypt } from './lioness';
import { truncatedMac } from './mac';
import { BETA_LEN, END_MARKER, KAPPA, RHO_LEN } from './params';
import { clonePacket, type SphinxPacket } from './packet';
import { rho } from './prg';

export interface MixNode {
  name: string;
  /** kappa-byte routing identifier. */
  id: Uint8Array;
  priv: bigint;
  pub: Uint8Array;
  /** h_tau(s) values this mix has already accepted, hex-encoded. */
  seen: Set<string>;
}

/** Everything one hop did, for the trace panels. */
export interface HopTrace {
  mixName: string;
  /** alpha as it arrived. */
  alphaIn: Uint8Array;
  /** beta as it arrived. */
  betaIn: Uint8Array;
  gammaIn: Uint8Array;
  payloadIn: Uint8Array;
  /** s_i -- derived, never transmitted. */
  secret: Uint8Array;
  /** The gamma this mix recomputed from beta. */
  gammaComputed: Uint8Array;
  macOk: boolean;
  replayTag: Uint8Array;
  replayed: boolean;
  /** b_i, as a decimal string -- bigint does not survive structured clone in a log. */
  blinding: string | null;
  alphaOut: Uint8Array | null;
  betaOut: Uint8Array | null;
  gammaOut: Uint8Array | null;
  payloadOut: Uint8Array | null;
  /** The kappa bytes the routing block named: a mix id, or the end marker. */
  routedTo: Uint8Array | null;
}

export type MixResult =
  | { kind: 'forward'; nextHopId: Uint8Array; packet: SphinxPacket; trace: HopTrace }
  | { kind: 'deliver'; identifier: Uint8Array; payload: Uint8Array; trace: HopTrace }
  | { kind: 'drop'; code: FailureCode; detail: string; trace: HopTrace | null };

export function createMix(name: string, id: Uint8Array, priv: bigint, pub: Uint8Array): MixNode {
  return { name, id, priv, pub, seen: new Set<string>() };
}

/**
 * Process one packet.
 *
 * `known` is this mix's view of the directory: the routing ids it is willing
 * to forward to. A routing block naming anything else is UNKNOWN_ROUTING_BLOCK
 * -- which is a real operational state, not a contrivance, because mixes leave
 * the network while packets built for them are still in flight.
 *
 * `record` false runs the identical checks WITHOUT adding to the seen-set,
 * which is how the Replay act can show the same packet accepted once and
 * refused the second time without the peel walkthrough having consumed it.
 */
export function processPacket(
  mix: MixNode,
  packet: SphinxPacket,
  known: ReadonlyArray<Uint8Array>,
  record = true
): MixResult {
  const header: SphinxHeader = packet.header;
  try {
    assertHeaderShape(header);
  } catch (e) {
    const err = e as SphinxError;
    return { kind: 'drop', code: err.code, detail: err.message, trace: null };
  }

  let secretBytes: Uint8Array;
  try {
    secretBytes = mulPoint(pointFromBytes(header.alpha), mix.priv).toBytes();
  } catch (e) {
    const err = e as SphinxError;
    return { kind: 'drop', code: err.code ?? 'MALFORMED_HEADER', detail: err.message, trace: null };
  }

  const gammaComputed = truncatedMac(hMu(secretBytes), header.beta);
  const macOk = equalBytes(gammaComputed, header.gamma);
  const replayTag = hTau(secretBytes);
  const tagHex = toHex(replayTag);
  const replayed = macOk && mix.seen.has(tagHex);

  const trace: HopTrace = {
    mixName: mix.name,
    alphaIn: Uint8Array.from(header.alpha),
    betaIn: Uint8Array.from(header.beta),
    gammaIn: Uint8Array.from(header.gamma),
    payloadIn: Uint8Array.from(packet.payload),
    secret: secretBytes,
    gammaComputed,
    macOk,
    replayTag,
    replayed,
    blinding: null,
    alphaOut: null,
    betaOut: null,
    gammaOut: null,
    payloadOut: null,
    routedTo: null,
  };

  if (!macOk) {
    return {
      kind: 'drop',
      code: 'HMAC_FAIL',
      detail: `recomputed ${toHex(gammaComputed)}, header carried ${toHex(header.gamma)}`,
      trace,
    };
  }
  if (replayed) {
    return {
      kind: 'drop',
      code: 'REPLAY_DETECTED',
      detail: `tag ${tagHex.slice(0, 16)} is already in ${mix.name}'s seen set`,
      trace,
    };
  }

  // beta padded to the PRG width, then blinded. The 2*kappa of zeros is where
  // this hop's contribution to the next hop's filler comes from.
  const stream = rho(hRho(secretBytes), RHO_LEN);
  const unwrapped = xor(concat(header.beta, zeros(2 * KAPPA)), stream);
  const routedTo = unwrapped.subarray(0, KAPPA);
  trace.routedTo = Uint8Array.from(routedTo);

  const payloadOut = lionessDecrypt(hPi(secretBytes), packet.payload);
  trace.payloadOut = payloadOut;

  if (record) mix.seen.add(tagHex);

  if (equalBytes(routedTo, END_MARKER)) {
    const identifier = Uint8Array.from(unwrapped.subarray(KAPPA, 2 * KAPPA));
    return { kind: 'deliver', identifier, payload: payloadOut, trace };
  }

  if (!known.some((id) => equalBytes(id, routedTo))) {
    return {
      kind: 'drop',
      code: 'UNKNOWN_ROUTING_BLOCK',
      detail: `routing block names ${toHex(routedTo)}, which is not in ${mix.name}'s directory`,
      trace,
    };
  }

  const blinding = deriveBlinding(header.alpha, secretBytes);
  const alphaOut = mulPoint(pointFromBytes(header.alpha), blinding).toBytes();
  const gammaOut = Uint8Array.from(unwrapped.subarray(KAPPA, 2 * KAPPA));
  const betaOut = Uint8Array.from(unwrapped.subarray(2 * KAPPA, 2 * KAPPA + BETA_LEN));

  trace.blinding = blinding.toString();
  trace.alphaOut = alphaOut;
  trace.betaOut = betaOut;
  trace.gammaOut = gammaOut;

  const next = clonePacket({
    header: { alpha: alphaOut, beta: betaOut, gamma: gammaOut },
    payload: payloadOut,
  });
  return { kind: 'forward', nextHopId: Uint8Array.from(routedTo), packet: next, trace };
}
