/**
 * What the last mix can count.
 *
 * Kuhn, Beck and Strufe, "Breaking and (Partially) Fixing Provably Secure
 * Onion Routing" (arXiv:1910.13772), on the original Sphinx header: the
 * innermost routing block is (destination || identifier || 0-padding), the
 * exit decrypts it, and "The exit node hence can learn the length of the
 * chosen path".
 *
 * The arithmetic, with this lab's lengths. For a nu-hop path the sender writes
 *
 *     END (kappa) || I (kappa) || pad ((2(r - nu) + 1) * kappa) || filler (2(nu - 1) * kappa)
 *
 * under the last hop's keystream. The exit XORs the same keystream back off,
 * so END, I and the pad come out in the clear. The filler does not: it was
 * built from the EARLIER hops' keystreams, which the exit does not hold, so
 * after the exit's own keystream is XORed over it it is still pseudorandom.
 *
 * With a zero pad the exit therefore sees a run of zero bytes that starts
 * right after the identifier and stops where the filler starts. Count it,
 * divide by kappa, and nu falls out:
 *
 *     run = (2(r - nu) + 1) * kappa      =>      nu = r - (run / kappa - 1) / 2
 *
 * With a random pad there is no run. Pad and filler are both uniform-looking
 * bytes, the boundary between them is not marked by anything, and the exit is
 * left guessing among the r possible lengths.
 *
 * Nothing in here uses a key the exit would not have. `readPathLength` takes
 * the decrypted block and nothing else -- not the path, not the sender's
 * build record -- which is what makes it an attack rather than a readout.
 */
import { BETA_LEN, KAPPA, MAX_HOPS } from './params';
import { directory, MIX_NAMES, pathOf, type MixNetwork } from './network';
import { processPacket } from './mix';
import { createPacket } from './packet';
import { tailPadLength, type TailPad } from './header';
import { unpadMessage } from './payload';
import { equalBytes, randomBytes } from './bytes';

/** Where the pad starts in the exit's decrypted block: after END and I. */
export const PAD_OFFSET = 2 * KAPPA;

/** The mix every packet in this exhibit leaves through, whatever its path length. */
export const EXIT_MIX = MIX_NAMES[MIX_NAMES.length - 1]!;

/**
 * A nu-hop path that always ends at the same exit.
 *
 * The exit has to be the same mix for every length, or the experiment hands
 * the answer over for free: if a three-hop path always ended at Mix C, "I am
 * Mix C" would already say nu = 3 and the padding would have nothing to add.
 */
export function pathEndingAtExit(nu: number): string[] {
  if (!Number.isInteger(nu) || nu < 1 || nu > MAX_HOPS) {
    throw new RangeError(`path length must be 1..${MAX_HOPS}, got ${nu}`);
  }
  return [...MIX_NAMES.slice(0, nu - 1), EXIT_MIX];
}

/** Number of consecutive zero bytes starting at `from`. */
export function zeroRunLength(block: Uint8Array, from: number = PAD_OFFSET): number {
  let n = 0;
  while (from + n < block.length && block[from + n] === 0) n++;
  return n;
}

export interface ExitReading {
  /** Zero bytes counted from the end of the identifier. */
  run: number;
  /** Whole kappa-byte blocks in that run, after the parity correction below. */
  blocks: number;
  /** The path length the run implies, or null when there is no run to read. */
  nu: number | null;
}

/**
 * The exit's estimate of the path length, from its decrypted block alone.
 *
 * The pad is always an ODD number of kappa-blocks, (2(r - nu) + 1), so:
 *
 *  - fewer than one whole block of zeros is no pad at all -- `nu` is null;
 *  - the first filler byte is zero by coincidence one time in 256, which
 *    lengthens the run by a byte or two but never by a whole block (that
 *    would take kappa zero bytes in a row, 2^-128), so the block count is
 *    floored;
 *  - an even block count cannot be a pad and is rounded down to the odd one
 *    below it, for the same reason.
 */
export function readPathLength(betaPlain: Uint8Array): ExitReading {
  if (betaPlain.length !== BETA_LEN) {
    throw new RangeError(`expected a ${BETA_LEN}-byte routing block, got ${betaPlain.length}`);
  }
  const run = zeroRunLength(betaPlain, PAD_OFFSET);
  let blocks = Math.floor(run / KAPPA);
  if (blocks >= 1 && blocks % 2 === 0) blocks -= 1;
  if (blocks < 1) return { run, blocks: 0, nu: null };
  const nu = MAX_HOPS - (blocks - 1) / 2;
  return { run, blocks, nu };
}

/** The four regions of the exit's decrypted block for a nu-hop path, as [from, to). */
export function exitBlockLayout(nu: number): {
  end: [number, number];
  identifier: [number, number];
  pad: [number, number];
  filler: [number, number];
} {
  const padEnd = PAD_OFFSET + tailPadLength(nu);
  return {
    end: [0, KAPPA],
    identifier: [KAPPA, 2 * KAPPA],
    pad: [PAD_OFFSET, padEnd],
    filler: [padEnd, BETA_LEN],
  };
}

/** A uniform draw from 1..MAX_HOPS, by rejection so there is no modulo bias. */
export function uniformPathLength(): number {
  const limit = 256 - (256 % MAX_HOPS);
  for (;;) {
    const b = randomBytes(1)[0]!;
    if (b < limit) return 1 + (b % MAX_HOPS);
  }
}

export interface LeakTrial {
  /** The true path length. */
  nu: number;
  pad: TailPad;
  /** The exit's decrypted routing block. */
  betaPlain: Uint8Array;
  reading: ExitReading;
  /** What the exit commits to: its reading, or a uniform guess when it has none. */
  guess: number;
  /** True when `guess` came from the padding rather than from the coin. */
  fromPadding: boolean;
  correct: boolean;
  /** The exit accepted the packet, found END, and the payload unpacked intact. */
  delivered: boolean;
}

/**
 * One packet, as the exit sees it.
 *
 * The packet is built for a nu-hop path ending at `EXIT_MIX` and handed to the
 * exit in the form the last hop receives -- (alpha, beta, gamma, delta) at
 * index nu-1 of the sender's build record, which `roundtrip` and `pathleak`
 * tests confirm is byte-for-byte what routing through the earlier hops
 * produces. Skipping the earlier hops is what makes a few hundred trials
 * affordable in a browser tab; it changes nothing about what the exit holds.
 *
 * `pick` supplies the exit's fallback guess, so a test can seed it.
 */
export function runLeakTrial(
  net: MixNetwork,
  nu: number,
  pad: TailPad,
  pick: () => number = uniformPathLength
): LeakTrial {
  const names = pathEndingAtExit(nu);
  const message = new TextEncoder().encode('how long was the path?');
  const identifier = randomBytes(KAPPA);
  const built = createPacket(pathOf(net, names), message, identifier, { tailPad: pad });
  const exit = net.mixes.find((m) => m.name === EXIT_MIX);
  if (!exit) throw new Error(`no mix named ${EXIT_MIX}`);

  const last = nu - 1;
  const result = processPacket(
    exit,
    {
      header: {
        alpha: built.build.alphas[last]!,
        beta: built.build.betas[last]!,
        gamma: built.build.gammas[last]!,
      },
      payload: built.payloads[last]!,
    },
    directory(net),
    false
  );
  if (result.kind !== 'deliver' || !result.trace.betaPlain) {
    throw new Error(`the exit did not deliver a ${nu}-hop packet: ${result.kind}`);
  }
  const unpacked = unpadMessage(result.payload);
  const delivered =
    unpacked.intact &&
    unpacked.message !== null &&
    equalBytes(unpacked.message, message) &&
    equalBytes(result.identifier, identifier);

  const reading = readPathLength(result.trace.betaPlain);
  const fromPadding = reading.nu !== null;
  const guess = reading.nu ?? pick();
  return {
    nu,
    pad,
    betaPlain: result.trace.betaPlain,
    reading,
    guess,
    fromPadding,
    correct: guess === nu,
    delivered,
  };
}

// ---------------------------------------------------------------------------
// The same paper's second finding: a destroyed payload is still a mark.
// ---------------------------------------------------------------------------

export interface TagArrival {
  sender: string;
  /** True for the one packet the first mix flipped a payload bit in. */
  marked: boolean;
  /** Every hop's header MAC verified. */
  macsOk: boolean;
  hops: number;
  /** The packet reached the exit and was handed over. */
  delivered: boolean;
  /** The payload's leading zero marker survived -- the far end's integrity check. */
  intact: boolean;
}

/**
 * Kuhn, Beck and Strufe, section on the payload attack, in Sphinx's terms:
 * the header is untouched so every mix forwards the packet, the wide-block
 * payload is destroyed, and whoever sits at the far end "just has to notice
 * that Sphinx's integrity check at the receiver failed".
 *
 * One packet per sender, all on the same three-hop path. The adversary holds
 * the FIRST mix, which sees who each packet came from, and flips one payload
 * bit in the packet from `markedSender`. It also holds the far end, and looks
 * for the arrival whose integrity check fails. Nothing here needs a key.
 */
export function runTagExperiment(
  net: MixNetwork,
  senders: readonly string[],
  markedSender: string,
  payloadByte = 500
): TagArrival[] {
  const names = pathEndingAtExit(3);
  const out: TagArrival[] = [];
  for (const sender of senders) {
    const message = new TextEncoder().encode(`a message from ${sender}`);
    const built = createPacket(pathOf(net, names), message, randomBytes(KAPPA));
    const first = net.mixes.find((m) => m.name === names[0]);
    if (!first) throw new Error(`no mix named ${names[0]}`);
    const marked = sender === markedSender;

    // Hop by hop, so the mark can go on between the first mix and the second.
    let current = first;
    let packet = built.packet;
    let hops = 0;
    let macsOk = true;
    let delivered = false;
    let intact = false;
    for (let guard = 0; guard <= MAX_HOPS; guard++) {
      const result = processPacket(current, packet, directory(net), false);
      hops++;
      if (result.kind === 'drop') {
        macsOk = false;
        break;
      }
      if (result.kind === 'deliver') {
        delivered = true;
        intact = unpadMessage(result.payload).intact;
        break;
      }
      packet = result.packet;
      if (marked && hops === 1) {
        // The adversarial first mix: one bit of the payload it is forwarding.
        const payload = Uint8Array.from(packet.payload);
        const at = Math.max(0, Math.min(payload.length - 1, Math.floor(payloadByte)));
        payload[at] = payload[at]! ^ 0x01;
        packet = { header: packet.header, payload };
      }
      const next = net.mixes.find((m) => equalBytes(m.id, result.nextHopId));
      if (!next) {
        macsOk = false;
        break;
      }
      current = next;
    }
    out.push({ sender, marked, macsOk, hops, delivered, intact });
  }
  return out;
}
