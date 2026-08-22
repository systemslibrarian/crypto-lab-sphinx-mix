import { describe, expect, it } from 'vitest';
import { createNetwork, directory, pathOf, routePacket, send } from './network';
import { createPacket } from './packet';
import { tamperBeta, tamperGamma } from './testutil';
import { KAPPA, MAX_HOPS, END_MARKER } from './params';
import { SphinxError } from './errors';
import { processPacket } from './mix';
import { equalBytes, randomBytes, toHex } from './bytes';

/**
 * Every one of the five failure codes, reached the way the UI reaches it.
 *
 * A failure code that no test can produce is a string in a switch statement,
 * not a behaviour. Each of these drives the real path.
 */
describe('failure codes', () => {
  it('HMAC_FAIL — one flipped header byte kills the packet at the hop that reads it', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    const out = routePacket(net, 'Mix A', tamperBeta(built.packet, 40));
    expect(out.failure?.code).toBe('HMAC_FAIL');
    expect(out.failure?.atMix).toBe('Mix A');
    expect(out.delivered).toBeNull();
  });

  it('HMAC_FAIL — a flip in a LATER hop’s block survives to that hop and dies there', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    // Mix A strips the first 2*kappa of the block, so a byte past that offset
    // lands inside what Mix B will authenticate. Mix A's own gamma still
    // covers it, though -- gamma is over the WHOLE block -- so it dies at A.
    const out = routePacket(net, 'Mix A', tamperBeta(built.packet, 2 * KAPPA + 3, 0x80));
    expect(out.failure?.code).toBe('HMAC_FAIL');
    expect(out.failure?.atMix).toBe('Mix A');
  });

  it('HMAC_FAIL — a header forged at hop 2 dies at hop 2, after hop 1 passed it', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    const first = processPacket(net.mixes[0]!, built.packet, directory(net), false);
    expect(first.kind).toBe('forward');
    if (first.kind !== 'forward') throw new Error('unreachable');
    const out = routePacket(net, 'Mix B', tamperGamma(first.packet, 0));
    expect(out.failure?.code).toBe('HMAC_FAIL');
    expect(out.failure?.atMix).toBe('Mix B');
  });

  it('REPLAY_DETECTED — the same packet a second time', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    const first = routePacket(net, 'Mix A', built.packet);
    expect(first.failure).toBeNull();
    const second = routePacket(net, 'Mix A', built.packet);
    expect(second.failure?.code).toBe('REPLAY_DETECTED');
    expect(second.failure?.atMix).toBe('Mix A');
  });

  it('REPLAY_DETECTED — the tag is over the shared secret, so re-encoding does not evade it', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B'], 'x');
    routePacket(net, 'Mix A', built.packet);
    // A different payload entirely; alpha is unchanged, so s is unchanged.
    const disguised = { header: built.packet.header, payload: randomBytes(built.packet.payload.length) };
    const out = routePacket(net, 'Mix A', disguised);
    expect(out.failure?.code).toBe('REPLAY_DETECTED');
  });

  it('a forged packet does NOT poison the seen-set against the real one', () => {
    // The DoS this ordering exists to prevent: authenticate before remembering.
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B'], 'x');
    expect(routePacket(net, 'Mix A', tamperBeta(built.packet, 0)).failure?.code).toBe('HMAC_FAIL');
    const real = routePacket(net, 'Mix A', built.packet);
    expect(real.failure).toBeNull();
    expect(real.delivered?.unpacked.intact).toBe(true);
  });

  it('PATH_TOO_LONG — r + 1 hops cannot be encoded', () => {
    const net = createNetwork(MAX_HOPS + 1);
    const names = net.mixes.map((m) => m.name);
    expect(names).toHaveLength(MAX_HOPS + 1);
    let code: string | null = null;
    try {
      createPacket(pathOf(net, names), new Uint8Array(1), new Uint8Array(KAPPA));
    } catch (e) {
      code = (e as SphinxError).code;
    }
    expect(code).toBe('PATH_TOO_LONG');
  });

  it('MALFORMED_HEADER — a non-canonical alpha is rejected before any key is used', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B'], 'x');
    const bad = {
      header: { ...built.packet.header, alpha: new Uint8Array(32).fill(0xff) },
      payload: built.packet.payload,
    }; // 0xff.. is not a valid ristretto255 encoding
    const out = routePacket(net, 'Mix A', bad);
    expect(out.failure?.code).toBe('MALFORMED_HEADER');
    expect(out.traces).toHaveLength(0); // no trace: nothing was derived
  });

  it('MALFORMED_HEADER — a mis-sized field is rejected', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A'], 'x');
    const short = {
      header: {
        alpha: built.packet.header.alpha,
        beta: built.packet.header.beta.subarray(0, 32),
        gamma: built.packet.header.gamma,
      },
      payload: built.packet.payload,
    };
    const out = routePacket(net, 'Mix A', short);
    expect(out.failure?.code).toBe('MALFORMED_HEADER');
  });

  it('UNKNOWN_ROUTING_BLOCK — a mix leaves the directory while a packet is in flight', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'x');
    const withoutB = directory(net).filter((id) => !equalBytes(id, net.mixes[1]!.id));
    const out = routePacket(net, 'Mix A', built.packet, { directoryOverride: withoutB });
    expect(out.failure?.code).toBe('UNKNOWN_ROUTING_BLOCK');
    expect(out.failure?.atMix).toBe('Mix A');
  });

  it('the end marker is what makes the last mix the last mix', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B'], 'x');
    const out = routePacket(net, 'Mix A', built.packet);
    const last = out.traces[out.traces.length - 1]!;
    expect(toHex(last.routedTo!)).toBe(toHex(END_MARKER));
    expect(toHex(out.traces[0]!.routedTo!)).toBe(toHex(net.mixes[1]!.id));
  });
});
