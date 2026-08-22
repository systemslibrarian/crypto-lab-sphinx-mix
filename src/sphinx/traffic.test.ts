import { describe, expect, it } from 'vitest';
import {
  DEFAULT_TRAFFIC,
  entropyBits,
  makeRng,
  mixPosteriors,
  runTraffic,
  type TrafficConfig,
} from './traffic';
import { createNetwork } from './network';

const cfg = (over: Partial<TrafficConfig>): TrafficConfig => ({ ...DEFAULT_TRAFFIC, ...over });

describe('anonymity metric arithmetic', () => {
  it('entropy of a point mass is zero', async () => {
    expect(entropyBits(Float64Array.from([1, 0, 0, 0]))).toBe(0);
  });
  it('entropy of the uniform distribution on n is log2 n', async () => {
    for (const n of [2, 4, 8]) {
      const p = Float64Array.from(new Array<number>(n).fill(1 / n));
      expect(entropyBits(p)).toBeCloseTo(Math.log2(n), 12);
    }
  });
  it('mixing point masses from distinct senders gives the uniform mixture', async () => {
    const a = Float64Array.from([1, 0, 0]);
    const b = Float64Array.from([0, 1, 0]);
    const m = mixPosteriors([a, b]);
    expect(Array.from(m)).toEqual([0.5, 0.5, 0]);
    expect(entropyBits(m)).toBeCloseTo(1, 12);
  });
  it('mixing a packet with another from the SAME sender adds nothing', async () => {
    const a = Float64Array.from([1, 0]);
    expect(entropyBits(mixPosteriors([a, a]))).toBe(0);
  });
  it('the schedule RNG is deterministic for a seed and varies across seeds', async () => {
    const a = Array.from({ length: 5 }, makeRng(7));
    const r1 = makeRng(7);
    const r2 = makeRng(8);
    expect(a).toHaveLength(5);
    expect(r1()).toBe(makeRng(7)());
    expect(r1()).not.toBe(r2());
  });
});

describe('NEG-1 — every cryptographic check passes and the packet is still traced', () => {
  /**
   * The negative claim, as an executable fixture. This is the evidence the
   * page's NEG-1 statement points at: one sender, immediate forwarding, an
   * all-green run, and an anonymity set of exactly one.
   */
  it('one sender, immediate forwarding: all green, anonymity set 1', async () => {
    const net = createNetwork();
    const r = await runTraffic(cfg({ senders: 1, packetsPerSender: 4, strategy: 'immediate' }), net, 12345);
    expect(r.cryptoAllGreen).toBe(true);
    expect(r.delivered.length).toBe(4);
    expect(r.meanEntropyBits).toBe(0);
    expect(r.effectiveSetSize).toBe(1);
    expect(r.fullyTraced).toBe(r.delivered.length);
  });

  it('one sender WITH cover traffic and a full pool is still anonymity set 1', async () => {
    // The lesson cover traffic cannot teach: you cannot hide in a crowd of one,
    // however much of the crowd you generate yourself.
    const net = createNetwork();
    const r = await runTraffic(
      cfg({ senders: 1, packetsPerSender: 4, coverPerReal: 3, strategy: 'pool', poolThreshold: 4 }),
      net,
      999
    );
    expect(r.cryptoAllGreen).toBe(true);
    expect(r.meanEntropyBits).toBe(0);
    expect(r.effectiveSetSize).toBe(1);
  });

  it('immediate forwarding gives away everything even with eight senders', async () => {
    const net = createNetwork();
    const r = await runTraffic(cfg({ senders: 8, packetsPerSender: 2, strategy: 'immediate' }), net, 4242);
    expect(r.cryptoAllGreen).toBe(true);
    expect(r.meanEntropyBits).toBe(0);
    expect(r.fullyTraced).toBe(r.delivered.length);
  });
});

describe('mixing is what produces anonymity', () => {
  it('a pool mix over many senders raises the entropy above zero', async () => {
    const net = createNetwork();
    const r = await runTraffic(
      cfg({ senders: 6, packetsPerSender: 4, strategy: 'pool', poolThreshold: 6 }),
      net,
      31337
    );
    expect(r.cryptoAllGreen).toBe(true);
    expect(r.delivered.length).toBeGreaterThan(0);
    expect(r.meanEntropyBits).toBeGreaterThan(1);
  });

  it('entropy can never exceed log2(number of senders)', async () => {
    const net = createNetwork();
    for (const senders of [2, 4, 8]) {
      const r = await runTraffic(
        cfg({ senders, packetsPerSender: 4, coverPerReal: 1, strategy: 'pool', poolThreshold: 8 }),
        net,
        77
      );
      expect(r.meanEntropyBits).toBeLessThanOrEqual(Math.log2(senders) + 1e-9);
      expect(r.effectiveSetSize).toBeLessThanOrEqual(senders + 1e-9);
    }
  });

  it('a bigger pool never lowers the mean entropy for the same traffic', async () => {
    const net = createNetwork();
    const small = await runTraffic(
      cfg({ senders: 6, packetsPerSender: 6, strategy: 'pool', poolThreshold: 2 }),
      net,
      555
    );
    const large = await runTraffic(
      cfg({ senders: 6, packetsPerSender: 6, strategy: 'pool', poolThreshold: 6 }),
      net,
      555
    );
    expect(large.meanEntropyBits).toBeGreaterThan(small.meanEntropyBits);
  });

  it('cover traffic fills pools that would otherwise strand real packets', async () => {
    const net = createNetwork();
    const bare = await runTraffic(
      cfg({ senders: 4, packetsPerSender: 1, strategy: 'pool', poolThreshold: 6 }),
      net,
      2024
    );
    const covered = await runTraffic(
      cfg({ senders: 4, packetsPerSender: 1, coverPerReal: 3, strategy: 'pool', poolThreshold: 6 }),
      net,
      2024
    );
    expect(bare.delivered.length).toBeLessThan(covered.delivered.length);
    expect(covered.meanEntropyBits).toBeGreaterThan(0);
  });

  it('the cryptography is green in every configuration — that is the point', async () => {
    const net = createNetwork();
    for (const strategy of ['immediate', 'pool'] as const) {
      for (const senders of [1, 3, 8]) {
        const r = await runTraffic(cfg({ senders, packetsPerSender: 2, strategy }), net, 8);
        expect(r.cryptoAllGreen, `${strategy}/${senders}`).toBe(true);
        for (const d of r.delivered) expect(d.allChecksPassed).toBe(true);
      }
    }
  });

  it('running the same configuration twice does not trip replay detection', async () => {
    const net = createNetwork();
    const a = await runTraffic(cfg({ senders: 3, packetsPerSender: 2 }), net, 5);
    const b = await runTraffic(cfg({ senders: 3, packetsPerSender: 2 }), net, 5);
    expect(a.cryptoAllGreen).toBe(true);
    expect(b.cryptoAllGreen).toBe(true);
  });
});
