import { describe, expect, it } from 'vitest';
import { createNetwork, routePacket, send } from './network';
import { tamperAlpha, tamperBeta, tamperPayload } from './testutil';
import { hammingDistance, toHex } from './bytes';
import { PAYLOAD_LEN } from './params';

/**
 * The two tagging failures, side by side. The difference IS the lesson.
 *
 * Header: verified hop by hop. The network catches it and the packet dies.
 * Payload: not verified by anyone on the path. Every mix forwards it happily,
 * and the damage lands on the recipient as unrecoverable corruption.
 */
describe('tagging — header versus payload', () => {
  it('a header byte flip is caught by the network, at the very next hop', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'meet at the docks');
    const out = routePacket(net, 'Mix A', tamperBeta(built.packet, 77, 0x08));
    expect(out.failure?.code).toBe('HMAC_FAIL');
    expect(out.traces).toHaveLength(1); // it never reached Mix B
    expect(out.traces[0]!.macOk).toBe(false);
  });

  it('a payload byte flip is caught by NOBODY on the path', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'meet at the docks');
    const out = routePacket(net, 'Mix A', tamperPayload(built.packet, 500));
    expect(out.failure).toBeNull();
    expect(out.traces).toHaveLength(3);
    for (const hop of out.traces) expect(hop.macOk).toBe(true);
    expect(out.delivered).not.toBeNull();
  });

  it('…and arrives irrecoverable: the marker is gone and the message is lost', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'meet at the docks');
    const out = routePacket(net, 'Mix A', tamperPayload(built.packet, 500));
    expect(out.delivered!.unpacked.intact).toBe(false);
    expect(out.delivered!.unpacked.message).toBeNull();
    expect(out.delivered!.unpacked.detail).toMatch(/marker/);
  });

  it('the corruption is total, not local — a PRP, not a stream cipher', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'meet at the docks');
    const clean = routePacket(net, 'Mix A', built.packet);
    // A fresh network is not needed: replay protection keys on the shared
    // secret, and this is a distinct packet only in its payload -- so route
    // the tampered copy through its own network built the same way.
    const net2 = createNetwork();
    const built2 = send(net2, ['Mix A', 'Mix B', 'Mix C'], 'meet at the docks');
    const dirty = routePacket(net2, 'Mix A', tamperPayload(built2.packet, 500));

    const cleanPlain = clean.delivered!.unpacked;
    expect(cleanPlain.intact).toBe(true);
    expect(dirty.delivered!.unpacked.intact).toBe(false);

    // Compare the exit's raw plaintext block against the sender's framing:
    // the flip should have moved about half of all 8192 bits.
    const exitTrace = dirty.traces[dirty.traces.length - 1]!;
    const d = hammingDistance(exitTrace.payloadOut!, built2.plaintext);
    expect(d).toBeGreaterThan(PAYLOAD_LEN * 8 * 0.4);
    expect(d).toBeLessThan(PAYLOAD_LEN * 8 * 0.6);
  });

  it('the untampered packet delivers the exact message, so the contrast is real', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B', 'Mix C'], 'meet at the docks');
    const out = routePacket(net, 'Mix A', built.packet);
    expect(new TextDecoder().decode(out.delivered!.unpacked.message!)).toBe('meet at the docks');
  });

  it('gamma covers beta and NOT the payload — shown by recomputing it', () => {
    const net = createNetwork();
    const built = send(net, ['Mix A', 'Mix B'], 'x');
    const out = routePacket(net, 'Mix A', tamperPayload(built.packet, 0, 0xff));
    const hop = out.traces[0]!;
    // The MAC the mix recomputed is bit-identical to the one in the header,
    // even though a payload byte changed. That is the asymmetry, measured.
    expect(toHex(hop.gammaComputed)).toBe(toHex(hop.gammaIn));
    expect(hop.macOk).toBe(true);
  });

  it('a flipped alpha is a MALFORMED_HEADER or an HMAC_FAIL — never silent', () => {
    const net = createNetwork();
    let malformed = 0;
    let hmacFail = 0;
    for (let i = 0; i < 12; i++) {
      const built = send(net, ['Mix A', 'Mix B'], `m${i}`);
      const code = routePacket(net, 'Mix A', tamperAlpha(built.packet, i % 32)).failure?.code;
      expect(code === 'MALFORMED_HEADER' || code === 'HMAC_FAIL').toBe(true);
      if (code === 'MALFORMED_HEADER') malformed++;
      else hmacFail++;
    }
    expect(malformed + hmacFail).toBe(12);
  });
});
