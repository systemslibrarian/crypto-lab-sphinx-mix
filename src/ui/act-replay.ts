/**
 * Act 4 — Replay.
 *
 * Send a packet, watch it arrive. Send the same bytes again and watch the
 * first mix refuse them. The interesting part is WHY the tag works: it is
 * derived from the shared secret, not from the packet bytes, so re-dressing
 * the packet does not evade it.
 */
import { button, clear, disclosure, el, kv, liveRegion, pill, verdict } from './dom';
import { network, forgetSeenTags } from './state';
import { pathOf, routePacket } from '../sphinx/network';
import { createPacket, clonePacket, type SphinxPacket } from '../sphinx/packet';
import { tamperedCopy } from './tamper';
import { randomBytes, toHex } from '../sphinx/bytes';
import { FAILURE_TEXT } from '../sphinx/errors';
import { KAPPA } from '../sphinx/params';

const PATH = ['Mix A', 'Mix B', 'Mix C'] as const;

export function renderReplay(root: HTMLElement): void {
  clear(root);
  let packet: SphinxPacket | null = null;
  let attempts = 0;
  const log: HTMLElement[] = [];

  root.append(
    el('h2', { text: 'Replay' }),
    el('p', {
      text:
        'Every cryptographic check in Sphinx is stateless except one. A mix that forgot the packets it had already seen could be fed the same bytes twice by an observer, who would then watch where the copy went and learn the path — no key required. So each mix remembers a tag for every packet it accepts.',
    })
  );

  const controls = el('div', { class: 'controls' });
  controls.append(
    button('New packet', () => reset(), { class: 'btn', id: 'replay-new' }),
    button('Send it', () => sendOnce(), { class: 'btn btn-primary', id: 'replay-send' }),
    button('Forge a copy, then send the real one', () => forgeThenSend(), {
      class: 'btn',
      id: 'replay-forge',
    }),
    button('Clear every mix’s memory', () => forget(), { class: 'btn btn-danger', id: 'replay-forget' })
  );
  const out = liveRegion('replay-out');
  const seen = el('p', { class: 'status-line', id: 'replay-seen' });
  root.append(controls, seen, out);

  function reset(): void {
    const built = createPacket(
      pathOf(network, PATH),
      new TextEncoder().encode('the same bytes, twice'),
      randomBytes(KAPPA)
    );
    packet = clonePacket(built.packet);
    attempts = 0;
    log.length = 0;
    render(el('div', {}, [verdict('info', ['A fresh packet is ready. Send it once, then send it again.'])]));
  }

  function forget(): void {
    forgetSeenTags();
    attempts = 0;
    log.length = 0;
    render(
      el('div', {}, [
        verdict('alarm', [
          'Every mix has forgotten every tag it ever saw. The next replay will be accepted — which is exactly the failure this state exists to make visible, not a feature.',
        ]),
      ])
    );
  }

  function sendOnce(): void {
    if (!packet) return;
    attempts += 1;
    const outcome = routePacket(network, PATH[0], packet);
    const card = el('div', { class: 'card card-tight reveal' });
    card.append(el('h4', { text: `Transmission ${attempts}` }));

    if (outcome.failure) {
      card.append(
        el('p', {}, [
          pill('bad', outcome.failure.code),
          ` at ${outcome.failure.atMix}`,
        ])
      );
      card.append(verdict('fail', [FAILURE_TEXT[outcome.failure.code]]));
      card.append(el('p', { class: 'status-line', text: outcome.failure.detail }));
    } else {
      const message = outcome.delivered!.unpacked.message;
      card.append(
        verdict('pass', [
          'Delivered through all three mixes. Payload: ',
          el('code', { text: message ? new TextDecoder().decode(message) : '(unreadable)' }),
        ])
      );
    }
    log.unshift(card);
    render(null);
  }

  /**
   * The ordering attack, performed.
   *
   * An adversary takes a legitimate packet in flight, corrupts one byte of the
   * routing block, and races the corrupted copy to the first mix. The copy has
   * the SAME alpha, so the mix derives the same shared secret and therefore the
   * same replay tag. A mix that recorded the tag before checking the MAC would
   * now refuse the genuine packet behind it as a replay -- a one-byte denial of
   * service against any packet an adversary can see.
   *
   * This lab authenticates first and remembers only what it accepted, so the
   * forged copy dies with HMAC_FAIL leaving no trace, and the real packet
   * arrives normally. Both results are rendered so the pair is the lesson.
   */
  function forgeThenSend(): void {
    // A FRESH packet, always. Running this against a packet the learner has
    // already sent would report REPLAY_DETECTED for the genuine half -- true,
    // but about the previous transmission rather than about the forgery, and
    // the two lessons would be indistinguishable on screen.
    const built = createPacket(
      pathOf(network, PATH),
      new TextEncoder().encode('the same bytes, twice'),
      randomBytes(KAPPA)
    );
    packet = clonePacket(built.packet);
    attempts += 1;
    const forged = routePacket(network, PATH[0], tamperedCopy(packet, 'beta', 9));
    const genuine = routePacket(network, PATH[0], packet);

    const card = el('div', { class: 'card card-tight reveal', id: 'replay-forge-out' });
    card.append(el('h4', { text: `Transmission ${attempts}: a forged copy, then the genuine packet` }));
    card.append(
      el('p', {}, [
        'Forged copy: ',
        pill('bad', forged.failure?.code ?? 'DELIVERED'),
        ` at ${forged.failure?.atMix ?? 'the exit'}`,
      ])
    );
    card.append(
      genuine.failure
        ? verdict('fail', [
            'The genuine packet was then refused with ',
            el('strong', { text: genuine.failure.code }),
            '. That is the denial of service: one corrupted byte, and a packet the adversary could merely SEE never arrives.',
          ])
        : verdict('pass', [
            'The genuine packet was then delivered normally. The forged copy left no trace, because a mix remembers only what it has already authenticated — the MAC is checked before the replay tag is recorded.',
          ])
    );
    log.unshift(card);
    render(null);
  }

  function render(banner: HTMLElement | null): void {
    clear(out);
    if (banner) out.append(banner);
    const first = network.mixes.find((m) => m.name === PATH[0])!;
    seen.textContent = `${PATH[0]} is currently remembering ${first.seen.size} shared-secret tag${first.seen.size === 1 ? '' : 's'}.`;
    for (const entry of log) out.append(entry);
    if (packet) {
      out.append(
        disclosure('What exactly does a mix remember?', [
          el('p', {
            text: 'The tag is h_τ(s) — a domain-separated HMAC of the shared secret the mix derived, not of the packet bytes. That choice is load-bearing.',
          }),
          el('p', {
            text: 'A tag over the bytes would be defeated by any re-randomisation: an attacker could change a byte the MAC does not cover, or re-encode a field, and the packet would look new. The shared secret depends only on α and the mix\'s private key, so an attacker who wants a different tag has to produce a different α — and then the MAC fails and the packet dies anyway.',
          }),
          el('p', {
            text: 'The cost is real and worth naming: a mix\'s memory grows without bound unless tags are expired, and expiring them re-opens the replay window. Production designs bound it with an epoch — mix keys rotate, and tags older than the current epoch are discarded along with the key that could have derived them.',
          }),
          kv([
            ['Header α of the current packet', `${toHex(packet.header.alpha).slice(0, 32)}…`],
            ['Tags held by Mix A', String(first.seen.size)],
          ]),
        ])
      );
    }
  }

  reset();
}
