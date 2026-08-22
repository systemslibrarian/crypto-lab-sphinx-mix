import { describe, expect, it } from 'vitest';
import { createNetwork, routePacket, send, directory } from './network';
import { processPacket } from './mix';
import { byteHistogram, hammingDistance, sharedByteCount, toHex } from './bytes';
import { BETA_LEN, ALPHA_LEN, PAYLOAD_LEN } from './params';
import { clonePacket } from './packet';

/**
 * Bitwise unlinkability, measured the honest way.
 *
 * The claim is NOT "the input and output share no bytes". Two independent
 * pseudorandom 176-byte strings agree at about 0.69 positions on average, and
 * a test asserting zero shared bytes would fail roughly half the time while
 * also teaching something false. The claim that holds is that the bit-flip
 * count is Binomial(8n, 1/2): no correlation an adversary can use.
 */
describe('bitwise unlinkability at a mix', () => {
  const window = (bits: number): [number, number] => {
    const sigma = Math.sqrt(bits) / 2;
    return [bits / 2 - 6 * sigma, bits / 2 + 6 * sigma];
  };

  it('the routing block a mix emits differs from the one it received in ~half its bits', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    const out = routePacket(net, 'Mix A', built.packet);
    const [lo, hi] = window(BETA_LEN * 8);
    for (const t of out.traces) {
      if (!t.betaOut) continue;
      const d = hammingDistance(t.betaIn, t.betaOut);
      expect(d, `${t.mixName} beta hamming=${d}`).toBeGreaterThan(lo);
      expect(d, `${t.mixName} beta hamming=${d}`).toBeLessThan(hi);
    }
  });

  it('the group element is re-randomised too', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    const out = routePacket(net, 'Mix A', built.packet);
    const [lo, hi] = window(ALPHA_LEN * 8);
    for (const t of out.traces) {
      if (!t.alphaOut) continue;
      expect(toHex(t.alphaOut)).not.toBe(toHex(t.alphaIn));
      const d = hammingDistance(t.alphaIn, t.alphaOut);
      expect(d).toBeGreaterThan(lo);
      expect(d).toBeLessThan(hi);
    }
  });

  it('the payload is re-randomised at every hop', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    const out = routePacket(net, 'Mix A', built.packet);
    const [lo, hi] = window(PAYLOAD_LEN * 8);
    for (const t of out.traces) {
      if (!t.payloadOut) continue;
      const d = hammingDistance(t.payloadIn, t.payloadOut);
      expect(d).toBeGreaterThan(lo);
      expect(d).toBeLessThan(hi);
    }
  });

  it('a handful of coincidentally-equal bytes is EXPECTED, not a defect', () => {
    // Documenting the reason the zero-shared-bytes assertion was rejected: over
    // 40 independent hops the total shared-byte count should sit near n/256 per
    // hop, and observing a nonzero total is the normal case.
    const net = createNetwork();
    let totalShared = 0;
    let hops = 0;
    for (let i = 0; i < 12; i++) {
      const built = send(net, ['Mix A', 'Mix B', 'Mix C'], `msg ${i}`);
      for (const t of routePacket(net, 'Mix A', built.packet).traces) {
        if (!t.betaOut) continue;
        totalShared += sharedByteCount(t.betaIn, t.betaOut);
        hops++;
      }
    }
    const expected = (hops * BETA_LEN) / 256;
    expect(hops).toBeGreaterThan(20);
    // Poisson around `expected`; a wide but real interval.
    expect(totalShared).toBeGreaterThan(expected - 5 * Math.sqrt(expected));
    expect(totalShared).toBeLessThan(expected + 5 * Math.sqrt(expected));
  });

  it('the output byte distribution is flat — no structure survives the hop', () => {
    const net = createNetwork();
    const counts = new Array<number>(16).fill(0);
    for (let i = 0; i < 40; i++) {
      const built = send(net, ['Mix A', 'Mix B'], `m${i}`);
      const step = processPacket(net.mixes[0]!, built.packet, directory(net), false);
      if (step.kind !== 'forward') throw new Error('expected a forward');
      byteHistogram(step.packet.header.beta).forEach((c, b) => (counts[b]! += c));
    }
    const total = counts.reduce((a, b) => a + b, 0);
    const expected = total / 16;
    const chi = counts.reduce((a, c) => a + ((c - expected) ** 2) / expected, 0);
    // 15 degrees of freedom; the 0.9999 quantile is ~46.8.
    expect(chi).toBeLessThan(46.8);
  });

  it('two mixes on the same path derive unrelated secrets', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    const s = built.build.sharedSecrets.map(toHex);
    expect(new Set(s).size).toBe(3);
  });

  it('nothing a mix sees reveals its position on the path', () => {
    // The only length signal would be the header, and it is the same size at
    // every hop; the only position signal would be alpha, and it is a fresh
    // uniform group element at every hop.
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    const out = routePacket(net, 'Mix A', built.packet);
    const shapes = new Set(
      out.traces.map((t) => `${t.alphaIn.length}/${t.betaIn.length}/${t.gammaIn.length}/${t.payloadIn.length}`)
    );
    expect(shapes.size).toBe(1);
  });

  it('re-sending the same packet from a clone still yields identical wire bytes', () => {
    // Guards the Replay act: the packet an attacker captures really is the
    // packet it re-sends, so REPLAY_DETECTED is about the tag, not about
    // accidental re-encoding.
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B'], 'x');
    const copy = clonePacket(built.packet);
    expect(toHex(copy.header.beta)).toBe(toHex(built.packet.header.beta));
    expect(toHex(copy.payload)).toBe(toHex(built.packet.payload));
  });
});
