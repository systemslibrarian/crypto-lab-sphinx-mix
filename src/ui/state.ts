/**
 * Session state.
 *
 * One mix network per page load. Mix private keys are bigints held in memory
 * and never persisted, never sent anywhere -- there is no backend to send them
 * to. Reloading the page destroys them and builds a new network.
 */
import { createNetwork, type MixNetwork } from '../sphinx/network';

export const network: MixNetwork = createNetwork();

/** Reset every mix's replay memory. Used by the acts that re-send packets. */
export function forgetSeenTags(): void {
  for (const m of network.mixes) m.seen = new Set<string>();
}
