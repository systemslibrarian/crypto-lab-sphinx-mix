/**
 * A whole Sphinx packet, and the sender side of the protocol.
 *
 * The payload is wrapped in the SAME reverse order as the header: the
 * innermost hop's permutation is applied first, then each earlier hop's around
 * it, so that a mix applying pi^-1 once peels exactly one layer. The header
 * and the payload therefore travel through the same chain of shared secrets,
 * derived once, used for four different jobs.
 */
import { PACKET_LEN, PAYLOAD_LEN } from './params';
import { createHeader, type HeaderBuild, type NodeRef, type SphinxHeader } from './header';
import { hPi } from './kdf';
import { lionessEncrypt } from './lioness';
import { padMessage } from './payload';
import { SphinxError } from './errors';

export interface SphinxPacket {
  header: SphinxHeader;
  /** delta -- always exactly PAYLOAD_LEN bytes. */
  payload: Uint8Array;
}

export interface PacketBuild {
  packet: SphinxPacket;
  build: HeaderBuild;
  /** delta_{nu-1} .. delta_0 in path order: the payload as each hop will see it. */
  payloads: Uint8Array[];
  /** The framed plaintext before any permutation was applied. */
  plaintext: Uint8Array;
}

export function createPacket(
  path: NodeRef[],
  message: Uint8Array,
  identifier: Uint8Array
): PacketBuild {
  const build = createHeader(path, identifier);
  const plaintext = padMessage(message);

  // delta_{nu-1} = pi(h_pi(s_{nu-1}), plaintext), then wrap outward.
  const payloads: Uint8Array[] = new Array<Uint8Array>(path.length);
  let delta = plaintext;
  for (let i = path.length - 1; i >= 0; i--) {
    delta = lionessEncrypt(hPi(build.sharedSecrets[i]!), delta);
    payloads[i] = delta;
  }
  if (delta.length !== PAYLOAD_LEN) {
    throw new SphinxError('MALFORMED_HEADER', `payload is ${delta.length} bytes, expected ${PAYLOAD_LEN}`);
  }
  return { packet: { header: build.header, payload: delta }, build, payloads, plaintext };
}

/** The bytes as they go on the wire, for the size panel. */
export function serialize(p: SphinxPacket): Uint8Array {
  const out = new Uint8Array(PACKET_LEN);
  out.set(p.header.alpha, 0);
  out.set(p.header.beta, p.header.alpha.length);
  out.set(p.header.gamma, p.header.alpha.length + p.header.beta.length);
  out.set(p.payload, p.header.alpha.length + p.header.beta.length + p.header.gamma.length);
  return out;
}

/** Deep copy, so a mutation in one act cannot leak into another. */
export function clonePacket(p: SphinxPacket): SphinxPacket {
  return {
    header: {
      alpha: Uint8Array.from(p.header.alpha),
      beta: Uint8Array.from(p.header.beta),
      gamma: Uint8Array.from(p.header.gamma),
    },
    payload: Uint8Array.from(p.payload),
  };
}
