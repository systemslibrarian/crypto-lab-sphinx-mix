/**
 * The act the packet format cannot win: traffic analysis.
 *
 * WHAT IS REAL HERE AND WHAT IS NOT, stated first because it is the thing a
 * reader most needs to know. Every packet in this simulation is a REAL Sphinx
 * packet, built with real ristretto255 blinding and peeled by real mixes
 * running the real checks in `mix.ts`. The CLOCK is simulated: arrivals happen
 * at integer ticks rather than in wall time, because a browser tab cannot
 * demonstrate a mixnet in real seconds. Nothing cryptographic is faked; the
 * scheduling is.
 *
 * THE ADVERSARY. A global passive observer. It sees every packet on every
 * link, with a timestamp, including the sender-to-first-mix and
 * last-mix-to-recipient links. It knows each mix's flushing rule and
 * parameters. It does NOT hold any mix's private key, so -- because Sphinx
 * works -- it cannot link a mix's input bytes to its output bytes. Timing and
 * counting are all it has.
 *
 * THE METRIC. For each packet the adversary sees leave the network, it holds a
 * probability distribution over which sender emitted it. The anonymity-set
 * entropy is Shannon entropy of that distribution, H = -sum p log2 p, and the
 * effective anonymity set is 2^H. This is Serjantov and Danezis's measure
 * ("Towards an Information Theoretic Metric for Anonymity", PET 2002) and
 * Diaz et al.'s, from the same year.
 *
 * HOW IT IS COMPUTED -- exactly, not estimated. A threshold mix that holds t
 * packets and releases them in a uniformly random order gives every output the
 * same posterior: the uniform mixture of the t inputs' own distributions. So
 * the distributions can be propagated forward through the network in closed
 * form. No sampling, no Monte Carlo, no error bars.
 *
 * WHAT IT DOES NOT MODEL, because pretending otherwise would be the exact
 * dishonesty this lab is about: long-term intersection attacks across many
 * rounds, statistical disclosure, active attacks (n-1 flooding), packet-size
 * or protocol fingerprints outside the mixnet, and any adversary that can
 * inject or delay. This is a single-round lower bound on what a passive
 * observer learns; a real adversary learns at least this much.
 */
import { createNetwork, nodeRef, type MixNetwork } from './network';
import { processPacket, type MixNode } from './mix';
import { createPacket } from './packet';
import type { SphinxPacket } from './packet';
import { randomBytes } from './bytes';
import { KAPPA } from './params';

export type MixStrategy = 'immediate' | 'pool';

export interface TrafficConfig {
  /** How many distinct senders are on the network. */
  senders: number;
  /** Real messages each sender emits. */
  packetsPerSender: number;
  /** Indistinguishable loop packets each sender emits per real packet. */
  coverPerReal: number;
  strategy: MixStrategy;
  /** Packets a pool mix holds before it flushes. Ignored when immediate. */
  poolThreshold: number;
  /** Mixes on every path. Kept at 3 by the UI. */
  pathLength: number;
}

export const DEFAULT_TRAFFIC: TrafficConfig = {
  senders: 1,
  packetsPerSender: 3,
  coverPerReal: 0,
  strategy: 'immediate',
  poolThreshold: 4,
  pathLength: 3,
};

export interface ObservedPacket {
  /** Index into the sender list; cover packets carry their emitter's index. */
  senderIndex: number;
  isCover: boolean;
  /** The adversary's posterior over senders for this packet, right now. */
  posterior: Float64Array;
  /** Tick it entered the network. */
  emittedAt: number;
  /** Tick it left the last mix, once it has. */
  deliveredAt: number | null;
  packet: SphinxPacket;
  /** The mixes this packet was routed through, by name. */
  route: string[];
  /** True if every cryptographic check passed at every hop. */
  allChecksPassed: boolean;
}

export interface TrafficResult {
  config: TrafficConfig;
  senderNames: string[];
  delivered: ObservedPacket[];
  /** Packets still sitting in a pool when the round ended. */
  stranded: number;
  /** How many scheduling rounds the network needed. */
  rounds: number;
  /** Mean H over delivered packets, in bits. */
  meanEntropyBits: number;
  /** The worst case -- the packet the adversary is most certain about. */
  minEntropyBits: number;
  /** 2^meanEntropy: how many senders the observer effectively cannot rule out. */
  effectiveSetSize: number;
  /** Delivered packets whose posterior is a point mass. */
  fullyTraced: number;
  /** Every hop of every packet passed its HMAC and replay checks. */
  cryptoAllGreen: boolean;
  /** Total real + cover packets injected. */
  injected: number;
}

/**
 * A seeded PRNG for the SCHEDULE only.
 *
 * Deliberately not `crypto.getRandomValues`: the arrival jitter and the flush
 * order have to be reproducible so the tests can assert exact entropies. Every
 * value that matters cryptographically -- mix keys, the per-packet scalar x,
 * the identifier -- comes from `crypto.getRandomValues` via `bytes.ts`, and
 * never from here.
 */
export function makeRng(seed: number): () => number {
  let s = seed >>> 0 || 0x9e3779b9;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 0x100000000;
  };
}

function shuffle<T>(items: T[], rng: () => number): T[] {
  const out = items.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const a = out[i]!;
    out[i] = out[j]!;
    out[j] = a;
  }
  return out;
}

function pointMass(size: number, index: number): Float64Array {
  const p = new Float64Array(size);
  p[index] = 1;
  return p;
}

/** The uniform mixture of a pool's posteriors: what a threshold flush does. */
export function mixPosteriors(pool: Float64Array[]): Float64Array {
  const size = pool[0]?.length ?? 0;
  const out = new Float64Array(size);
  for (const p of pool) for (let i = 0; i < size; i++) out[i]! += p[i]! / pool.length;
  return out;
}

export function entropyBits(p: Float64Array): number {
  let h = 0;
  for (const v of p) if (v > 0) h -= v * Math.log2(v);
  // Floating-point mixtures can land a hair below zero on a point mass.
  return Math.abs(h) < 1e-12 ? 0 : h;
}

interface Held {
  observed: ObservedPacket;
  packet: SphinxPacket;
  /** Which hop of its own path it is about to enter. */
  hop: number;
  /** Indices into `net.mixes`. Each packet picks its own route. */
  route: number[];
}

/** Let the browser paint between chunks of a long build. */
const yieldToPage = (): Promise<void> => new Promise<void>((resolve) => setTimeout(resolve, 0));

/**
 * Run one round of the network and return what the adversary learns.
 *
 * Each packet picks its OWN route through the available mixes. That is not
 * decoration: if every packet took the same three mixes, a batch flushed
 * together at the first mix would arrive together at the second, be flushed
 * together again, and the second and third hops would add no entropy at all.
 * Route diversity is what makes layered mixing worth anything, and running the
 * fixed-route version is how you find that out.
 *
 * `net` is reused across calls so the mix keys stay stable for a session, but
 * a fresh seen-tag set is installed per run: without it, re-running an
 * identical configuration would trip every replay detector and the act would
 * look broken. That is a property of running the same simulation twice, not of
 * the protocol.
 */
export async function runTraffic(
  config: TrafficConfig,
  net: MixNetwork = createNetwork(),
  seed = (crypto.getRandomValues(new Uint32Array(1))[0] ?? 1) >>> 0,
  onProgress?: (built: number, total: number) => void
): Promise<TrafficResult> {
  const rng = makeRng(seed);
  const senderNames = Array.from({ length: config.senders }, (_, i) => `S-${String.fromCharCode(65 + i)}`);
  for (const m of net.mixes) m.seen = new Set<string>();

  const available = net.mixes.length;
  const hops = Math.min(config.pathLength, available);
  if (hops < 1) throw new RangeError('a path needs at least one mix');
  const directory = net.mixes.map((m) => m.id);
  const threshold = config.strategy === 'immediate' ? 1 : Math.max(1, config.poolThreshold);

  /** A uniformly random route of `hops` distinct mixes. */
  const pickRoute = (): number[] => {
    const pool = shuffle(
      Array.from({ length: available }, (_, i) => i),
      rng
    );
    return pool.slice(0, hops);
  };

  // --- inject: every packet here is a real Sphinx packet -----------------
  const total = config.senders * config.packetsPerSender * (1 + config.coverPerReal);
  const held: Held[] = [];
  for (let s = 0; s < config.senders; s++) {
    for (let k = 0; k < config.packetsPerSender; k++) {
      for (let c = 0; c <= config.coverPerReal; c++) {
        const route = pickRoute();
        const path = route.map((i) => nodeRef(net.mixes[i]!));
        const built = createPacket(
          path,
          new TextEncoder().encode(`sender ${s} message ${k}${c ? ` cover ${c}` : ''}`),
          randomBytes(KAPPA)
        );
        held.push({
          observed: {
            senderIndex: s,
            isCover: c > 0,
            posterior: pointMass(config.senders, s),
            emittedAt: Math.floor(rng() * 4),
            deliveredAt: null,
            route: route.map((i) => net.mixes[i]!.name),
            packet: built.packet,
            allChecksPassed: true,
          },
          packet: built.packet,
          hop: 0,
          route,
        });
        onProgress?.(held.length, total);
        if (held.length % 6 === 0) await yieldToPage();
      }
    }
  }

  // --- the round-based schedule -----------------------------------------
  const pools: Held[][] = Array.from({ length: available }, () => []);
  let inbox: Held[][] = Array.from({ length: available }, () => []);
  for (const h of shuffle(held, rng).sort((a, b) => a.observed.emittedAt - b.observed.emittedAt)) {
    inbox[h.route[0]!]!.push(h);
  }

  const delivered: ObservedPacket[] = [];
  let cryptoAllGreen = true;
  const MAX_ROUNDS = 24;
  let rounds = 0;

  for (let round = 1; round <= MAX_ROUNDS; round++) {
    const arriving = inbox;
    inbox = Array.from({ length: available }, () => []);
    let moved = 0;

    for (let m = 0; m < available; m++) {
      const mix: MixNode = net.mixes[m]!;
      const pool = pools[m]!;

      const flush = (): void => {
        if (pool.length === 0) return;
        const mixed = mixPosteriors(pool.map((x) => x.observed.posterior));
        for (const x of shuffle(pool, rng)) {
          x.observed.posterior = mixed;
          x.observed.deliveredAt = round;
          if (x.hop >= x.route.length) delivered.push(x.observed);
          else inbox[x.route[x.hop]!]!.push(x);
          moved++;
        }
        pool.length = 0;
      };

      for (const x of arriving[m]!) {
        const result = processPacket(mix, x.packet, directory, true);
        if (result.kind === 'drop') {
          cryptoAllGreen = false;
          x.observed.allChecksPassed = false;
          continue;
        }
        if (result.kind === 'forward') x.packet = result.packet;
        x.hop += 1;
        pool.push(x);
        if (pool.length >= threshold) flush();
      }
    }
    rounds = round;
    if (moved === 0 && inbox.every((q) => q.length === 0)) break;
    await yieldToPage();
  }

  // A threshold mix does NOT release a partial pool. Whatever is still held
  // when the round ends stays held -- a real cost of the strategy, reported
  // rather than quietly drained to make the numbers look better.
  const stranded = pools.reduce((n, p) => n + p.length, 0);

  const entropies = delivered.map((d) => entropyBits(d.posterior));
  const meanEntropyBits = entropies.length ? entropies.reduce((a, b) => a + b, 0) / entropies.length : 0;
  const minEntropyBits = entropies.length ? Math.min(...entropies) : 0;

  return {
    config,
    senderNames,
    delivered,
    stranded,
    rounds,
    meanEntropyBits,
    minEntropyBits,
    effectiveSetSize: Math.pow(2, meanEntropyBits),
    fullyTraced: entropies.filter((h) => h === 0).length,
    cryptoAllGreen,
    injected: held.length,
  };
}
