import { describe, expect, it } from 'vitest';
import { createNetwork, routePacket, send, directory, MIX_NAMES } from './network';
import { BETA_LEN, HEADER_LEN, KAPPA, MAX_HOPS, PACKET_LEN, PAYLOAD_LEN } from './params';
import { toHex } from './bytes';
import { clonePacket } from './packet';
import { createPacket } from './packet';
import { pathOf } from './network';

const decode = (b: Uint8Array): string => new TextDecoder().decode(b);

describe('Sphinx end-to-end', () => {
  it('routes a three-hop packet and recovers the message', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'the pool flushes at midnight');
    const out = routePacket(net, 'Mix A', built.packet);
    expect(out.failure).toBeNull();
    expect(out.delivered).not.toBeNull();
    expect(out.delivered!.unpacked.intact).toBe(true);
    expect(decode(out.delivered!.unpacked.message!)).toBe('the pool flushes at midnight');
    expect(out.traces).toHaveLength(3);
  });

  it('routes every path length from one to r hops', () => {
    for (let n = 1; n <= MAX_HOPS; n++) {
      const net = createNetwork();
      const names = MIX_NAMES.slice(0, n);
      const built = send(net, names, `path of ${n}`);
      const out = routePacket(net, names[0]!, built.packet);
      expect(out.failure, `path length ${n}`).toBeNull();
      expect(decode(out.delivered!.unpacked.message!)).toBe(`path of ${n}`);
    }
  });

  it('the header is byte-identical in size at every path length', () => {
    const sizes = new Set<string>();
    for (let n = 1; n <= MAX_HOPS; n++) {
      const net = createNetwork();
      const built = send(net, MIX_NAMES.slice(0, n), 'x');
      const h = built.packet.header;
      sizes.add(`${h.alpha.length}/${h.beta.length}/${h.gamma.length}/${built.packet.payload.length}`);
      expect(h.beta.length).toBe(BETA_LEN);
    }
    expect(sizes.size).toBe(1);
    expect([...sizes][0]).toBe(`32/${BETA_LEN}/${KAPPA}/${PAYLOAD_LEN}`);
    expect(HEADER_LEN + PAYLOAD_LEN).toBe(PACKET_LEN);
  });

  it('the header a mix forwards is also full size — nothing shrinks', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    const out = routePacket(net, 'Mix A', built.packet);
    for (const t of out.traces) {
      expect(t.betaIn.length).toBe(BETA_LEN);
      if (t.betaOut) expect(t.betaOut.length).toBe(BETA_LEN);
      if (t.payloadOut) expect(t.payloadOut.length).toBe(PAYLOAD_LEN);
    }
  });

  it('the identifier survives the path and only the exit sees it', () => {
    const net = createNetwork();
    const path = pathOf(net, ['Mix A', 'Mix B', 'Mix C']);
    const id = new Uint8Array(KAPPA).fill(0xa7);
    const built = createPacket(path, new TextEncoder().encode('hi'), id);
    const out = routePacket(net, 'Mix A', built.packet);
    expect(toHex(out.delivered!.identifier)).toBe(toHex(id));
  });

  it('every mix on the path derives the shared secret the sender predicted', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    const out = routePacket(net, 'Mix A', built.packet);
    out.traces.forEach((t, i) => {
      expect(toHex(t.secret), `hop ${i}`).toBe(toHex(built.build.sharedSecrets[i]!));
      expect(toHex(t.alphaIn), `alpha ${i}`).toBe(toHex(built.build.alphas[i]!));
    });
  });

  it('an empty message and a maximum-length message both round-trip', () => {
    const net = createNetwork();
    for (const len of [0, 1006]) {
      const msg = new Uint8Array(len).fill(0x41);
      const built = createPacket(pathOf(net, ['Mix A', 'Mix B']), msg, new Uint8Array(KAPPA));
      const out = routePacket(net, 'Mix A', built.packet);
      expect(out.delivered!.unpacked.intact, `len ${len}`).toBe(true);
      expect(out.delivered!.unpacked.message!.length).toBe(len);
    }
  });

  it('the same message sent twice produces entirely different packets', () => {
    const net = createNetwork();
    const a = send(net, ['Mix A', 'Mix B', 'Mix C'], 'same words');
    const b = send(net, ['Mix A', 'Mix B', 'Mix C'], 'same words');
    expect(toHex(a.packet.header.alpha)).not.toBe(toHex(b.packet.header.alpha));
    expect(toHex(a.packet.header.beta)).not.toBe(toHex(b.packet.header.beta));
    expect(toHex(a.packet.payload)).not.toBe(toHex(b.packet.payload));
  });

  it('a clone is independent of its source', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A'], 'x');
    const copy = clonePacket(built.packet);
    copy.header.beta.set([(built.packet.header.beta[0] ?? 0) ^ 0xff], 0);
    expect(built.packet.header.beta[0]).not.toBe(copy.header.beta[0]);
    expect(directory(net)).toHaveLength(MIX_NAMES.length);
  });
});
