/**
 * A small mix network, and the route a packet takes through it.
 *
 * This is the layer the UI drives. It holds the directory (every mix's public
 * key and routing id), builds packets, and walks them hop by hop, collecting a
 * trace of everything each mix did.
 */
import { randomBytes } from './bytes';
import { createMix, processPacket, type HopTrace, type MixNode, type MixResult } from './mix';
import { generateKeyPair } from './group';
import type { NodeRef } from './header';
import { KAPPA } from './params';
import { clonePacket, createPacket, type PacketBuild, type SphinxPacket } from './packet';
import { unpadMessage, type UnpackResult } from './payload';
import type { FailureCode } from './errors';

export interface MixNetwork {
  mixes: MixNode[];
}

/** Names are stable across a session so a trace can be read; keys are not. */
export const MIX_NAMES = ['Mix A', 'Mix B', 'Mix C', 'Mix D', 'Mix E'] as const;

export function createNetwork(count: number = MIX_NAMES.length): MixNetwork {
  const mixes: MixNode[] = [];
  for (let i = 0; i < count; i++) {
    const { priv, pub } = generateKeyPair();
    mixes.push(createMix(MIX_NAMES[i] ?? `Mix ${i + 1}`, randomBytes(KAPPA), priv, pub));
  }
  return { mixes };
}

export function nodeRef(m: MixNode): NodeRef {
  return { id: m.id, pub: m.pub, name: m.name };
}

export function directory(net: MixNetwork): Uint8Array[] {
  return net.mixes.map((m) => m.id);
}

export function pathOf(net: MixNetwork, names: readonly string[]): NodeRef[] {
  return names.map((n) => {
    const m = net.mixes.find((x) => x.name === n);
    if (!m) throw new Error(`no mix named ${n}`);
    return nodeRef(m);
  });
}

export interface RouteStep {
  mixName: string;
  result: MixResult;
}

export interface RouteOutcome {
  steps: RouteStep[];
  /** Set when the packet reached an exit. */
  delivered: { identifier: Uint8Array; unpacked: UnpackResult } | null;
  /** Set when a mix refused it. */
  failure: { code: FailureCode; detail: string; atMix: string } | null;
  /** Every hop trace, in order, for the panels. */
  traces: HopTrace[];
}

/**
 * Walk a packet through the network.
 *
 * The next hop is chosen by the ROUTING BLOCK, not by a list the caller holds
 * -- which is the point of the format. `directoryOverride` lets an act take a
 * mix out of the directory mid-flight so UNKNOWN_ROUTING_BLOCK is a real
 * routing outcome rather than a message string.
 */
export function routePacket(
  net: MixNetwork,
  first: string,
  packet: SphinxPacket,
  options: { record?: boolean; directoryOverride?: Uint8Array[] } = {}
): RouteOutcome {
  const record = options.record ?? true;
  const known = options.directoryOverride ?? directory(net);
  const steps: RouteStep[] = [];
  const traces: HopTrace[] = [];

  let current = net.mixes.find((m) => m.name === first);
  let inFlight = clonePacket(packet);
  const budget = net.mixes.length + 1;

  for (let hop = 0; hop < budget; hop++) {
    if (!current) {
      return {
        steps,
        delivered: null,
        failure: { code: 'UNKNOWN_ROUTING_BLOCK', detail: 'no mix in the directory holds that id', atMix: '(network)' },
        traces,
      };
    }
    const result = processPacket(current, inFlight, known, record);
    steps.push({ mixName: current.name, result });
    if (result.trace) traces.push(result.trace);

    if (result.kind === 'drop') {
      return {
        steps,
        delivered: null,
        failure: { code: result.code, detail: result.detail, atMix: current.name },
        traces,
      };
    }
    if (result.kind === 'deliver') {
      return {
        steps,
        delivered: { identifier: result.identifier, unpacked: unpadMessage(result.payload) },
        failure: null,
        traces,
      };
    }
    inFlight = result.packet;
    current = net.mixes.find((m) => m.id.every((b, i) => b === result.nextHopId[i]));
  }

  return {
    steps,
    delivered: null,
    failure: { code: 'PATH_TOO_LONG', detail: `still routing after ${budget} hops`, atMix: '(network)' },
    traces,
  };
}

export function send(net: MixNetwork, names: readonly string[], message: string): PacketBuild {
  return createPacket(pathOf(net, names), new TextEncoder().encode(message), randomBytes(KAPPA));
}
