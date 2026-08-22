/**
 * Deliberate corruption, in one place.
 *
 * Every "break it yourself" control in this lab routes through here, so the
 * page has exactly one way to damage a packet and it is always a copy. The
 * original is never mutated: an act that corrupted the packet in place would
 * quietly poison the next act.
 */
import { clonePacket, type SphinxPacket } from '../sphinx/packet';

export type TamperTarget = 'alpha' | 'beta' | 'gamma' | 'payload';

export function tamperedCopy(
  packet: SphinxPacket,
  target: TamperTarget,
  index: number,
  mask = 0x01
): SphinxPacket {
  const copy = clonePacket(packet);
  const field =
    target === 'payload'
      ? copy.payload
      : target === 'alpha'
        ? copy.header.alpha
        : target === 'gamma'
          ? copy.header.gamma
          : copy.header.beta;
  const at = Math.max(0, Math.min(field.length - 1, Math.floor(index)));
  field[at] = (field[at] ?? 0) ^ mask;
  return copy;
}
