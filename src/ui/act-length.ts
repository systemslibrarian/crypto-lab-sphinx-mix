/**
 * Act 3 — Fixed length.
 *
 * Add a fourth hop, add a fifth. Nothing about the packet changes size. The
 * panel shows WHY: the routing block is partly real instructions and partly
 * filler, and the filler grows by exactly as much as the instructions shrink.
 */
import { button, clear, disclosure, el, hexDump, kv, liveRegion, pill, verdict } from './dom';
import { network } from './state';
import { pathOf, MIX_NAMES } from '../sphinx/network';
import { createHeader } from '../sphinx/header';
import { randomBytes } from '../sphinx/bytes';
import { BETA_LEN, GAMMA_LEN, HEADER_LEN, KAPPA, MAX_HOPS, PACKET_LEN, PAYLOAD_LEN } from '../sphinx/params';

export function renderLength(root: HTMLElement): void {
  clear(root);
  let hops = 3;

  root.append(
    el('h2', { text: 'Fixed length' }),
    el('p', {
      text:
        'If a packet got shorter at every hop, a mix could read its own position off the length and the last mix would know it was last. Sphinx sizes every header for the maximum path length and fills the unused space with keystream the sender generated in advance. A three-hop packet and a five-hop packet are the same size, byte for byte.',
    })
  );

  const controls = el('div', { class: 'controls' });
  const select = el('select', { id: 'len-hops', 'aria-describedby': 'len-hops-help' }) as HTMLSelectElement;
  for (let n = 1; n <= MAX_HOPS; n++) {
    select.append(el('option', { value: n, text: `${n} hop${n === 1 ? '' : 's'}`, selected: n === 3 }));
  }
  select.addEventListener('change', () => {
    hops = Number(select.value);
    render();
  });
  controls.append(
    el('div', { class: 'field' }, [el('label', { for: 'len-hops', text: 'Path length' }), select]),
    button('Rebuild with fresh keys', () => render(), { class: 'btn', id: 'len-rebuild' })
  );
  root.append(
    controls,
    el('p', {
      class: 'status-line',
      id: 'len-hops-help',
      text: `The header is sized for r = ${MAX_HOPS}, the maximum this lab's parameters allow. Ask for six and the sender refuses with PATH_TOO_LONG rather than silently truncating, because a truncated path would leak the real length.`,
    })
  );

  const out = liveRegion('len-out');
  root.append(out);

  function render(): void {
    clear(out);
    const names = MIX_NAMES.slice(0, hops);
    const build = createHeader(pathOf(network, names), randomBytes(KAPPA));
    const innerBeta = build.betas[hops - 1]!;
    const filler = build.fillers[hops - 1]!;
    const instructionBytes = BETA_LEN - filler.length;

    const row = el('div', { class: 'hoprow' });
    names.forEach((name) =>
      row.append(
        el('div', { class: 'hopnode' }, [
          el('span', { class: 'hopnode-title', text: name }),
          el('span', { class: 'hopnode-meta', text: 'β = ' + BETA_LEN + ' B' }),
        ])
      )
    );
    out.append(row);

    out.append(
      verdict('pass', [
        `Header ${HEADER_LEN} bytes · payload ${PAYLOAD_LEN} bytes · packet ${PACKET_LEN} bytes — for `,
        el('strong', { text: `${hops} hop${hops === 1 ? '' : 's'}` }),
        ', and for every other path length on this control.',
      ])
    );

    const card = el('div', { class: 'card reveal' });
    card.append(
      el('h3', { text: 'Inside the innermost routing block' }),
      el('p', {
        text: `The last mix on the path receives a full ${BETA_LEN}-byte block. Only the first ${2 * KAPPA} bytes of it are real — the END marker and the packet identifier. The rest is padding and filler, and the mix has no way to tell which is which.`,
      })
    );

    // A proportional bar: real instructions versus filler.
    const bar = el('div', {
      class: 'meter',
      role: 'img',
      'aria-label': `Routing block composition at the last hop: ${instructionBytes} bytes of instructions and padding, ${filler.length} bytes of filler, of ${BETA_LEN} total`,
    });
    bar.append(
      el('div', {
        class: 'meter-fill',
        style: `width:${(instructionBytes / BETA_LEN) * 100}%`,
      })
    );
    card.append(bar);
    card.append(
      el('p', { class: 'legend' }, [
        el('span', { class: 'legend-item' }, [
          el('span', { class: 'legend-swatch', style: 'background:var(--accent)', 'aria-hidden': 'true' }),
          `instructions + padding: ${instructionBytes} B`,
        ]),
        el('span', { class: 'legend-item' }, [
          el('span', { class: 'legend-swatch', style: 'background:var(--bg)', 'aria-hidden': 'true' }),
          `filler φ: ${filler.length} B`,
        ]),
      ])
    );

    card.append(
      kv([
        ['Path length ν', String(hops)],
        ['Maximum r', String(MAX_HOPS)],
        ['Routing block β', `${BETA_LEN} bytes = (2r + 1)·κ`],
        ['Filler φ (2·(ν−1)·κ)', `${filler.length} bytes`],
        ['MAC γ', `${GAMMA_LEN} bytes`],
        ['Group element α', '32 bytes'],
      ])
    );

    if (filler.length > 0) {
      card.append(el('h4', { text: 'The filler, as it sits in the innermost block' }));
      card.append(hexDump(filler, { label: 'filler bytes at the last hop' }));
      card.append(
        el('p', { class: 'status-line' }, [
          'These bytes were computed by the SENDER, ',
          pill('neutral', `${hops - 1} hop${hops === 2 ? '' : 's'} in advance`),
          ', from the shared secrets of the earlier mixes — because those mixes are each going to append exactly this keystream as they strip their own instructions off the front.',
        ])
      );
    } else {
      card.append(
        el('p', {
          class: 'status-line',
          text: 'A one-hop path needs no filler: no earlier mix has appended anything yet. The block is instructions and padding only — and it is still the full length.',
        })
      );
    }
    out.append(card);

    out.append(
      disclosure('The filler recurrence, and why it has to be the sender that computes it', [
        el('p', {
          text: 'φ₀ is empty. φᵢ = (φᵢ₋₁ ‖ 0₂κ) ⊕ ρ(h_ρ(sᵢ₋₁))[(2(r−i)+3)κ … (2r+3)κ]. Each step appends 2κ zero bytes and XORs the tail of the previous hop\'s keystream over the whole thing.',
        }),
        el('p', {
          text: 'Only the sender can do this, because only the sender knows every sᵢ at once. A mix knows one secret; it appends its 2κ bytes of keystream to the tail without ever seeing what the earlier hops appended, and the result matches the sender\'s prediction exactly. That agreement is what the MAC at the next hop confirms.',
        }),
        el('p', { text: 'The innermost block as it goes on the wire — instructions and filler alike, all of it already encrypted:' }),
        hexDump(innerBeta, { limit: 48, label: 'innermost routing block, encrypted' }),
      ])
    );
  }

  render();
}
