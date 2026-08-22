/**
 * Act 1 — Build a path.
 *
 * The headline mechanism, shown rather than asserted: the header is
 * constructed FROM THE INSIDE OUT. Each step wraps one more layer around the
 * block only the last mix can read, and the total length does not move.
 */
import { el, button, clear, hexDump, kv, liveRegion, pill, verdict, disclosure } from './dom';
import { network } from './state';
import { pathOf } from '../sphinx/network';
import { createPacket, type PacketBuild } from '../sphinx/packet';
import { randomBytes, toHex } from '../sphinx/bytes';
import { BETA_LEN, GAMMA_LEN, HEADER_LEN, KAPPA, MAX_HOPS, PAYLOAD_LEN } from '../sphinx/params';

const PATH = ['Mix A', 'Mix B', 'Mix C'] as const;

export function renderBuild(root: HTMLElement): void {
  clear(root);
  let build: PacketBuild | null = null;
  let step = 0;

  root.append(
    el('h2', { text: 'Build a path' }),
    el('p', {
      text:
        'A sender picks three mixes and writes one routing instruction for each. The instruction for the LAST mix is written first, and every earlier one is wrapped around it — so watch this play in reverse. Nothing here is animation for its own sake: this is the order the construction actually runs in, because each layer encrypts the layer inside it.',
    })
  );

  const controls = el('div', { class: 'controls' });
  const msgInput = el('input', {
    type: 'text',
    id: 'build-msg',
    value: 'the pool flushes at midnight',
    maxlength: 64,
  }) as HTMLInputElement;
  controls.append(
    el('div', { class: 'field' }, [
      el('label', { for: 'build-msg', text: 'Message' }),
      msgInput,
    ]),
    button('Build the packet', () => rebuild(), { class: 'btn btn-primary', id: 'build-run' }),
    button('‹ Back', () => setStep(step - 1), { class: 'btn', id: 'build-back' }),
    button('Next ›', () => setStep(step + 1), { class: 'btn', id: 'build-next' })
  );
  const progress = el('p', { class: 'status-line', id: 'build-progress' });
  const out = liveRegion('build-out');
  root.append(controls, progress, out);

  const backBtn = controls.querySelector<HTMLButtonElement>('#build-back')!;
  const nextBtn = controls.querySelector<HTMLButtonElement>('#build-next')!;

  function rebuild(): void {
    const path = pathOf(network, PATH);
    build = createPacket(path, new TextEncoder().encode(msgInput.value), randomBytes(KAPPA));
    step = 0;
    render();
  }

  function setStep(next: number): void {
    if (!build) return;
    step = Math.max(0, Math.min(PATH.length, next));
    render();
  }

  function render(): void {
    clear(out);
    if (!build) return;
    const b = build;
    const nu = PATH.length;
    progress.textContent = `Step ${step} / ${nu}`;
    backBtn.disabled = step === 0;
    nextBtn.disabled = step === nu;

    // The path, with the layer being written highlighted.
    const row = el('div', { class: 'hoprow' });
    PATH.forEach((name, i) => {
      // Step 1 writes the innermost block (hop nu-1); step k writes hop nu-k.
      const writing = step > 0 && i === nu - step;
      const written = step > 0 && i > nu - step;
      row.append(
        el(
          'div',
          {
            class: `hopnode${writing ? ' hopnode-active' : written ? ' hopnode-done' : ''}`,
          },
          [
            el('span', { class: 'hopnode-title', text: name }),
            el('span', {
              class: 'hopnode-meta',
              text: `id ${toHex(pathOf(network, [name])[0]!.id).slice(0, 8)}…`,
            }),
            writing ? el('span', { class: 'hopnode-meta', text: 'writing this layer' }) : null,
            written && !writing ? el('span', { class: 'hopnode-meta', text: 'layer sealed' }) : null,
          ]
        )
      );
    });
    out.append(row);

    if (step === 0) {
      out.append(
        verdict('info', [
          'Nothing is wrapped yet. Press ',
          el('strong', { text: 'Next' }),
          ` to write the innermost layer — the one only ${PATH[nu - 1]} can read.`,
        ])
      );
      out.append(
        el('p', {
          class: 'stack-note',
          text: `The sender has already done the one thing it cannot do later: it derived a shared secret with every mix on the path in advance, from a single random scalar. Mix A's secret is s₀, Mix B's is s₁, Mix C's is s₂ — and no mix can compute another mix's.`,
        })
      );
      return;
    }

    const hop = nu - step; // which hop's layer this step writes
    const card = el('div', { class: 'card reveal' });
    card.append(
      el('h3', { text: `Layer ${step}: the routing block for ${PATH[hop]}` }),
      el('p', {
        text:
          hop === nu - 1
            ? `The innermost block. It carries the END marker (so ${PATH[hop]} knows it is last) and the packet identifier, then zero padding, then the filler — pre-computed keystream standing in for hops that do not exist. All of it is XORed with ρ(h_ρ(s${sub(hop)})).`
            : `Wrapped around the block above: ${PATH[hop + 1]}'s routing id, the MAC γ${sub(hop + 1)} that ${PATH[hop + 1]} will check, and the first ${BETA_LEN - 2 * KAPPA} bytes of the inner block — then XORed with ρ(h_ρ(s${sub(hop)})).`,
      })
    );

    const beta = b.build.betas[hop]!;
    const gamma = b.build.gammas[hop]!;
    const filler = b.build.fillers[hop]!;
    card.append(
      kv([
        [`Shared secret s${sub(hop)}`, `${toHex(b.build.sharedSecrets[hop]!).slice(0, 32)}…`],
        [`Routing block β${sub(hop)}`, `${beta.length} bytes`],
        [`MAC γ${sub(hop)}`, `${toHex(gamma)} (${gamma.length} bytes)`],
        [
          `Filler φ${sub(hop)}`,
          filler.length === 0 ? '0 bytes (the innermost hop needs none of its own)' : `${filler.length} bytes`,
        ],
      ])
    );
    card.append(el('h4', { text: `β${sub(hop)} — first 96 bytes` }));
    card.append(hexDump(beta, { label: `routing block for ${PATH[hop]}` }));
    card.append(
      el('p', { class: 'status-line' }, [
        'Length after this layer: ',
        pill('ok', `β = ${beta.length} B`),
        ' ',
        pill('neutral', `header = ${HEADER_LEN} B`),
        ' — unchanged, and it will stay unchanged for the rest of the build.',
      ])
    );
    out.append(card);

    if (step === nu) {
      out.append(
        verdict('pass', [
          'Header complete. The sender transmits ',
          el('code', { text: `(α₀, β₀, γ₀)` }),
          ` — ${HEADER_LEN} bytes — plus a ${PAYLOAD_LEN}-byte payload, to ${PATH[0]}.`,
        ])
      );
      out.append(
        kv([
          ['α₀ (group element)', toHex(b.packet.header.alpha)],
          ['γ₀ (MAC, 16 B)', toHex(b.packet.header.gamma)],
          ['Total on the wire', `${HEADER_LEN + PAYLOAD_LEN} bytes`],
        ])
      );
      out.append(
        disclosure('Why the header is exactly (2r + 1)·κ bytes', [
          el('p', {
            text: `r is the maximum path length — ${MAX_HOPS} here — and κ is the security parameter, ${KAPPA} bytes. The routing block is (2r + 1)·κ = ${BETA_LEN} bytes, the MAC is κ = ${GAMMA_LEN} bytes, and the group element is 32.`,
          }),
          el('p', {
            text: `Each hop consumes exactly 2κ bytes: the next mix's id, and the MAC that mix will check. A mix strips those 2κ bytes off the front and appends 2κ bytes of its own keystream to the back, so the block is the same size going out as coming in. Act 3 shows the filler that makes the appended bytes indistinguishable from real instructions.`,
          }),
        ])
      );
    }
  }

  rebuild();
}

/** Unicode subscript digits, so s₀/β₁/γ₂ read as they do in the paper. */
function sub(n: number): string {
  return String(n)
    .split('')
    .map((d) => '₀₁₂₃₄₅₆₇₈₉'[Number(d)] ?? d)
    .join('');
}
