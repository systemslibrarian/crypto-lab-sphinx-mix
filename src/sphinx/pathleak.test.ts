/**
 * The path-length leak: Kuhn, Beck and Strufe (arXiv:1910.13772) against the
 * original Sphinx zero padding, and the random-padding fix.
 *
 * Three claims, each stated the way the page states it:
 *
 *  1. with ZERO padding the exit recovers nu exactly, for every nu;
 *  2. with RANDOM padding it does no better than a uniform guess;
 *  3. the packet is delivered in both modes.
 *
 * The exit's fallback guess is seeded here (a small LCG) so the chance-level
 * test is reproducible; the packets themselves are built from fresh random
 * keys every run, as they are on the page.
 */
import { describe, expect, it } from 'vitest';
import { createNetwork, pathOf, routePacket } from './network';
import { createPacket } from './packet';
import { createHeader, tailPadLength } from './header';
import { randomBytes, equalBytes } from './bytes';
import { BETA_LEN, KAPPA, MAX_HOPS } from './params';
import {
  EXIT_MIX,
  exitBlockLayout,
  PAD_OFFSET,
  pathEndingAtExit,
  readPathLength,
  runLeakTrial,
  runTagExperiment,
  zeroRunLength,
} from './pathleak';

const ALL_NU = Array.from({ length: MAX_HOPS }, (_, i) => i + 1);

/** Deterministic uniform pick from 1..MAX_HOPS for the exit's fallback guess. */
function seededPick(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    // Numerical Recipes LCG; the high bits are the usable ones.
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return 1 + Math.floor((s / 2 ** 32) * MAX_HOPS);
  };
}

describe('the layout the attack relies on', () => {
  it('pad and filler tile the block exactly, for every path length', () => {
    for (const nu of ALL_NU) {
      const layout = exitBlockLayout(nu);
      expect(layout.end).toEqual([0, KAPPA]);
      expect(layout.identifier).toEqual([KAPPA, 2 * KAPPA]);
      expect(layout.pad[0]).toBe(PAD_OFFSET);
      expect(layout.pad[1] - layout.pad[0]).toBe(tailPadLength(nu));
      // The filler is 2(nu-1)kappa -- the paper's figure, not the layout's own.
      expect(layout.filler[1] - layout.filler[0]).toBe(2 * (nu - 1) * KAPPA);
      expect(layout.filler[1]).toBe(BETA_LEN);
    }
  });

  it('every path ends at the same exit, so the exit’s identity says nothing about nu', () => {
    for (const nu of ALL_NU) {
      const names = pathEndingAtExit(nu);
      expect(names).toHaveLength(nu);
      expect(names[names.length - 1]).toBe(EXIT_MIX);
      expect(new Set(names).size).toBe(nu);
    }
    expect(() => pathEndingAtExit(0)).toThrow(RangeError);
    expect(() => pathEndingAtExit(MAX_HOPS + 1)).toThrow(RangeError);
  });
});

describe('original Sphinx: zero padding', () => {
  it('the exit recovers nu exactly, for every nu, on every one of many packets', () => {
    const net = createNetwork();
    for (const nu of ALL_NU) {
      for (let i = 0; i < 12; i++) {
        const t = runLeakTrial(net, nu, 'zero', () => {
          throw new Error('the exit should never need to guess under zero padding');
        });
        expect(t.reading.nu, `nu=${nu}, run=${t.reading.run}`).toBe(nu);
        expect(t.fromPadding).toBe(true);
        expect(t.correct).toBe(true);
        expect(t.delivered).toBe(true);
        // The run is the pad, give or take a coincidental zero at the head of
        // the filler -- never short, and never a whole block long.
        expect(t.reading.run).toBeGreaterThanOrEqual(tailPadLength(nu));
        expect(t.reading.run).toBeLessThan(tailPadLength(nu) + KAPPA);
      }
    }
  });

  it('the pad region of the decrypted block really is all zero, and the filler is not', () => {
    const net = createNetwork();
    for (const nu of ALL_NU) {
      const t = runLeakTrial(net, nu, 'zero');
      const { pad, filler } = exitBlockLayout(nu);
      expect(t.betaPlain.subarray(pad[0], pad[1]).every((b) => b === 0)).toBe(true);
      if (filler[1] > filler[0]) {
        // 2(nu-1)*16 >= 32 pseudorandom bytes all being zero is 2^-256.
        expect(t.betaPlain.subarray(filler[0], filler[1]).some((b) => b !== 0)).toBe(true);
      }
    }
  });
});

describe('the fix: random padding', () => {
  it('there is no run to read', () => {
    const net = createNetwork();
    let readings = 0;
    const trials = 60;
    for (let i = 0; i < trials; i++) {
      const nu = 1 + (i % MAX_HOPS);
      const t = runLeakTrial(net, nu, 'random', seededPick(i + 1));
      // A reading needs kappa = 16 consecutive zero bytes of random pad: 2^-128.
      if (t.fromPadding) readings++;
      expect(t.reading.run).toBeLessThan(KAPPA);
      expect(t.delivered).toBe(true);
    }
    expect(readings).toBe(0);
  });

  it('the exit recovers nu no better than a uniform guess over many trials', () => {
    const net = createNetwork();
    const pick = seededPick(0x5eed);
    const perNu = 80;
    const n = perNu * MAX_HOPS;
    let correct = 0;
    for (const nu of ALL_NU) {
      for (let i = 0; i < perNu; i++) {
        const t = runLeakTrial(net, nu, 'random', pick);
        if (t.correct) correct++;
      }
    }
    // Chance is 1/r. The band is five binomial standard deviations: for
    // n = 400, p = 0.2 that is 0.2 +/- 0.1, which a real leak (rate 1.0 under
    // zero padding) misses by forty sigma and an honest coin stays inside
    // with probability > 0.999999.
    const p = 1 / MAX_HOPS;
    const sigma = Math.sqrt((p * (1 - p)) / n);
    const rate = correct / n;
    expect(rate, `recovered ${correct} of ${n}`).toBeGreaterThan(p - 5 * sigma);
    expect(rate, `recovered ${correct} of ${n}`).toBeLessThan(p + 5 * sigma);
  });
});

describe('delivery, through every hop, in both modes', () => {
  it('a packet with either padding routes end to end and arrives intact', () => {
    const net = createNetwork();
    for (const pad of ['zero', 'random'] as const) {
      for (const nu of ALL_NU) {
        const names = pathEndingAtExit(nu);
        const message = new TextEncoder().encode(`pad=${pad} nu=${nu}`);
        const id = randomBytes(KAPPA);
        const built = createPacket(pathOf(net, names), message, id, { tailPad: pad });
        const out = routePacket(net, names[0]!, built.packet, { record: false });
        expect(out.failure, `${pad}/${nu}`).toBeNull();
        expect(out.traces).toHaveLength(nu);
        expect(out.traces.every((t) => t.macOk)).toBe(true);
        expect(out.delivered?.unpacked.intact).toBe(true);
        expect(equalBytes(out.delivered!.unpacked.message!, message)).toBe(true);
        expect(equalBytes(out.delivered!.identifier, id)).toBe(true);

        // What the exit decrypted after the real route is what the shortcut in
        // `runLeakTrial` hands it: same block, same reading.
        const exitTrace = out.traces[nu - 1]!;
        expect(exitTrace.mixName).toBe(EXIT_MIX);
        expect(equalBytes(exitTrace.betaIn, built.build.betas[nu - 1]!)).toBe(true);
        const reading = readPathLength(exitTrace.betaPlain!);
        expect(reading.nu).toBe(pad === 'zero' ? nu : null);
      }
    }
  });

  it('zero padding is the default, so every other act still runs the original design', () => {
    const net = createNetwork();
    const names = pathEndingAtExit(3);
    // No options at all, at both entry points.
    const build = createHeader(pathOf(net, names), randomBytes(KAPPA));
    expect(build.betas).toHaveLength(3);
    const withDefault = createPacket(pathOf(net, names), new Uint8Array(0), randomBytes(KAPPA));
    const out = routePacket(net, names[0]!, withDefault.packet, { record: false });
    expect(readPathLength(out.traces[2]!.betaPlain!).nu).toBe(3);
  });
});

describe('the estimator on its own', () => {
  it('counts zeros from the end of the identifier and nowhere else', () => {
    const block = new Uint8Array(BETA_LEN).fill(0xa5);
    expect(zeroRunLength(block)).toBe(0);
    expect(readPathLength(block).nu).toBeNull();
    // Zeros in END / I (before PAD_OFFSET) are not part of the run.
    block.fill(0, 0, PAD_OFFSET);
    expect(readPathLength(block).nu).toBeNull();
    for (const nu of ALL_NU) {
      const b = new Uint8Array(BETA_LEN).fill(0xa5);
      b.fill(0, PAD_OFFSET, PAD_OFFSET + tailPadLength(nu));
      expect(readPathLength(b).nu).toBe(nu);
      // A coincidental zero or two at the head of the filler does not move it.
      if (PAD_OFFSET + tailPadLength(nu) + 2 <= BETA_LEN) {
        b.fill(0, PAD_OFFSET, PAD_OFFSET + tailPadLength(nu) + 2);
        expect(readPathLength(b).nu).toBe(nu);
      }
    }
  });

  it('rejects a block of the wrong size rather than reading garbage', () => {
    expect(() => readPathLength(new Uint8Array(BETA_LEN - 1))).toThrow(RangeError);
  });
});

describe('a destroyed payload is still a mark', () => {
  it('exactly the marked sender’s packet fails the far end’s check, with every MAC green', () => {
    const net = createNetwork();
    const senders = ['Sender 1', 'Sender 2', 'Sender 3'];
    for (const marked of senders) {
      const arrivals = runTagExperiment(net, senders, marked);
      expect(arrivals).toHaveLength(3);
      for (const a of arrivals) {
        expect(a.macsOk).toBe(true);
        expect(a.hops).toBe(3);
        expect(a.delivered).toBe(true);
        expect(a.marked).toBe(a.sender === marked);
        expect(a.intact).toBe(a.sender !== marked);
      }
    }
  });

  it('with nobody marked, every packet passes — the failure is the mark, not noise', () => {
    const net = createNetwork();
    const arrivals = runTagExperiment(net, ['Sender 1', 'Sender 2'], 'nobody');
    expect(arrivals.every((a) => a.intact && a.delivered && !a.marked)).toBe(true);
  });
});
