/**
 * Act 2 — Peel.
 *
 * One hop at a time: derive the shared secret, check the header MAC, unwrap
 * the routing block, blind the group element, forward. The measurement panel
 * is the point of the act — input versus output as a Hamming distance and a
 * byte distribution, NOT as "they share no bytes", which is both false and
 * flaky (two pseudorandom 176-byte strings coincide at ~0.69 positions).
 */
import { button, clear, disclosure, el, hexDump, histogram, kv, liveRegion, verdict } from './dom';
import { network, forgetSeenTags } from './state';
import { pathOf, directory } from '../sphinx/network';
import { processPacket, type HopTrace } from '../sphinx/mix';
import { clonePacket, createPacket, type SphinxPacket } from '../sphinx/packet';
import {
  byteHistogram,
  chiSquaredUniform,
  hammingDistance,
  randomBytes,
  sharedByteCount,
  toHex,
} from '../sphinx/bytes';
import { BETA_LEN, KAPPA } from '../sphinx/params';

const PATH = ['Mix A', 'Mix B', 'Mix C'] as const;

export function renderPeel(root: HTMLElement): void {
  clear(root);
  let packet: SphinxPacket | null = null;
  let traces: HopTrace[] = [];
  let hop = -1;

  root.append(
    el('h2', { text: 'Peel' }),
    el('p', {
      text:
        'Each mix does the same four things and learns nothing beyond them: it derives a shared secret from the group element in the header and its own private key, checks the MAC over the routing block, strips its own instruction, and re-randomises the group element for the next hop. It never learns the path, its own position on it, or who sent the packet.',
    })
  );

  const controls = el('div', { class: 'controls' });
  controls.append(
    button('New packet', () => reset(), { class: 'btn btn-primary', id: 'peel-new' }),
    button('Peel one hop', () => advance(), { class: 'btn', id: 'peel-step' })
  );
  const progress = el('p', { class: 'status-line', id: 'peel-progress' });
  const out = liveRegion('peel-out');
  root.append(controls, progress, out);
  const stepBtn = controls.querySelector<HTMLButtonElement>('#peel-step')!;

  function reset(): void {
    forgetSeenTags();
    const built = createPacket(
      pathOf(network, PATH),
      new TextEncoder().encode('meet at the docks'),
      randomBytes(KAPPA)
    );
    packet = clonePacket(built.packet);
    traces = [];
    hop = -1;
    render();
  }

  function advance(): void {
    if (!packet || hop >= PATH.length - 1) return;
    const mix = network.mixes.find((m) => m.name === PATH[hop + 1])!;
    const result = processPacket(mix, packet, directory(network), false);
    if (result.trace) traces.push(result.trace);
    hop += 1;
    if (result.kind === 'forward') packet = result.packet;
    render();
  }

  function render(): void {
    clear(out);
    progress.textContent = hop < 0 ? 'At the sender — no hop taken yet' : `Hop ${hop + 1} / ${PATH.length}`;
    stepBtn.disabled = hop >= PATH.length - 1;

    const row = el('div', { class: 'hoprow' });
    PATH.forEach((name, i) => {
      const done = i <= hop;
      row.append(
        el('div', { class: `hopnode${i === hop ? ' hopnode-active' : done ? ' hopnode-done' : ''}` }, [
          el('span', { class: 'hopnode-title', text: name }),
          el('span', { class: 'hopnode-meta', text: done ? 'peeled' : 'not reached' }),
        ])
      );
    });
    out.append(row);

    if (hop < 0) {
      out.append(
        verdict('info', ['Press ', el('strong', { text: 'Peel one hop' }), ' to run the first mix.'])
      );
      return;
    }

    const t = traces[hop]!;
    const card = el('div', { class: 'card reveal' });
    card.append(el('h3', { text: `${t.mixName} processes the packet` }));
    card.append(
      kv([
        ['1. Derive s = α^x', `${toHex(t.secret).slice(0, 40)}…`],
        ['2. Recompute γ over β', toHex(t.gammaComputed)],
        ['   γ carried in the header', toHex(t.gammaIn)],
        [
          '3. Replay tag h_τ(s)',
          `${toHex(t.replayTag).slice(0, 24)}… (${t.replayed ? 'already seen' : 'not seen before'})`,
        ],
        [
          '4. Blinding factor b',
          t.blinding ? `${t.blinding.slice(0, 24)}… (mod ℓ)` : 'not computed — this is the exit',
        ],
      ])
    );
    card.append(
      t.macOk
        ? verdict('pass', ['MAC verified — this routing block is the one the sender wrote.'])
        : verdict('fail', ['HMAC_FAIL — the routing block was modified in flight.'])
    );
    card.append(
      el('p', { class: 'status-line' }, [
        'Next hop: ',
        el('code', {
          text:
            t.routedTo && toHex(t.routedTo) === '0'.repeat(2 * KAPPA)
              ? 'END — this mix is the exit'
              : t.routedTo
                ? toHex(t.routedTo)
                : '(none)',
        }),
      ])
    );
    out.append(card);

    if (!t.betaOut) {
      out.append(
        verdict('pass', [
          'This was the exit. The routing block named the END marker rather than another mix, so there is nothing left to forward.',
        ])
      );
      return;
    }

    // ---- the measurement panel ------------------------------------------
    const bits = BETA_LEN * 8;
    const distance = hammingDistance(t.betaIn, t.betaOut);
    const shared = sharedByteCount(t.betaIn, t.betaOut);
    const expectedShared = BETA_LEN / 256;
    const counts = byteHistogram(t.betaOut);
    const chi = chiSquaredUniform(counts);

    const panel = el('div', { class: 'card reveal' });
    panel.append(
      el('h3', { text: 'What an observer sees: input block versus output block' }),
      el('div', { class: 'grid2' }, [
        el('div', {}, [
          el('h4', { text: 'β going in (first 96 bytes)' }),
          hexDump(t.betaIn, { label: `${t.mixName} input routing block` }),
        ]),
        el('div', {}, [
          el('h4', { text: 'β coming out, diffed against it' }),
          hexDump(t.betaOut, { against: t.betaIn, label: `${t.mixName} output routing block` }),
        ]),
      ]),
      el('p', { class: 'legend' }, [
        el('span', { class: 'legend-item' }, [
          el('span', { class: 'legend-swatch', style: 'background:var(--accent)', 'aria-hidden': 'true' }),
          'byte changed',
        ]),
        el('span', { class: 'legend-item' }, [
          el('span', { class: 'legend-swatch', style: 'background:var(--bad)', 'aria-hidden': 'true' }),
          'byte unchanged (underlined) — coincidence, not structure',
        ]),
      ])
    );

    panel.append(
      kv([
        [
          'Hamming distance',
          `${distance} of ${bits} bits (${((distance / bits) * 100).toFixed(1)}%) — expected ${bits / 2}`,
        ],
        [
          'Bytes that happen to match',
          `${shared} of ${BETA_LEN} — expected about ${expectedShared.toFixed(2)}`,
        ],
        ['χ² of the output byte distribution', `${chi.toFixed(1)} on 15 d.f.`],
      ])
    );
    panel.append(el('h4', { text: 'Byte-value distribution of the output block' }));
    panel.append(histogram(counts, 'output routing block byte distribution, 16 bins'));
    panel.append(
      el('p', {
        class: 'status-line',
        text: `Every bin holds about ${(BETA_LEN / 16).toFixed(0)} bytes. A single χ² sample above 25.0 happens one time in twenty by chance, so this number is context, not a pass/fail light — the claim it supports is "no exploitable correlation", which is a statement about distributions, not about one draw.`,
      })
    );
    panel.append(
      disclosure('Why not just say "they share no bytes"?', [
        el('p', {
          text: `Because it is false. Two independent pseudorandom strings agree at any given byte position with probability 1/256, so over ${BETA_LEN} bytes you expect ${expectedShared.toFixed(2)} coincidental matches and see at least one about half the time. A demo that asserted zero shared bytes would be teaching a claim that is wrong, and a test that asserted it would fail roughly every other run.`,
        }),
        el('p', {
          text: 'Bitwise unlinkability means an adversary gains no advantage in linking the input to the output — the two are computationally indistinguishable from independent uniform strings. It does not mean they differ everywhere.',
        }),
      ])
    );
    out.append(panel);

    if (hop === PATH.length - 1) {
      out.append(verdict('info', ['Path complete. Every check passed at every hop.']));
    }
  }

  reset();
}
