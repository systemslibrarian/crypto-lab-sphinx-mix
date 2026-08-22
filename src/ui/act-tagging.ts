/**
 * Act 5 — Tagging: two different failures, and the difference is the lesson.
 *
 * Flip a byte in the header and the next mix refuses the packet: header
 * integrity is verified hop by hop, and it protects the NETWORK. Flip a byte
 * in the payload and nothing on the path notices: payload protection is
 * anti-tagging only, and what it protects is the adversary's ability to
 * RECOGNISE its own mark, not the recipient's ability to trust the bytes.
 */
import { button, clear, disclosure, el, hexDump, kv, liveRegion, pill, verdict } from './dom';
import { forgetSeenTags, network } from './state';
import { pathOf, routePacket, type RouteOutcome } from '../sphinx/network';
import { createPacket, type PacketBuild } from '../sphinx/packet';
import { tamperedCopy } from './tamper';
import { hammingDistance, randomBytes } from '../sphinx/bytes';
import { FAILURE_TEXT } from '../sphinx/errors';
import { BETA_LEN, KAPPA, PAYLOAD_LEN } from '../sphinx/params';

const PATH = ['Mix A', 'Mix B', 'Mix C'] as const;
const MESSAGE = 'meet at the docks at nine';

export function renderTagging(root: HTMLElement): void {
  clear(root);

  root.append(
    el('h2', { text: 'Tagging' }),
    el('p', {
      text:
        'A tagging attack is an adversary who controls the first mix marking a packet on the way in, and an adversary who controls the last mix looking for that mark on the way out. If the mark survives recognisably, the two observations link and the path is exposed. Sphinx answers the header and the payload with two completely different mechanisms — try both.',
    })
  );

  const controls = el('div', { class: 'controls' });
  const headerIdx = numberField('tag-header-idx', 'Header byte to flip', 0, BETA_LEN - 1, 77);
  const payloadIdx = numberField('tag-payload-idx', 'Payload byte to flip', 0, PAYLOAD_LEN - 1, 500);
  controls.append(
    headerIdx.field,
    payloadIdx.field,
    button('Flip both and send', () => run(), { class: 'btn btn-primary', id: 'tag-run' })
  );
  const out = liveRegion('tag-out');
  root.append(controls, out);

  // Runs once at mount so the panel a reader arrives at already shows the
  // comparison rather than an empty region. An empty region is exactly what an
  // accessibility scan reports as perfectly accessible.

  function run(): void {
    forgetSeenTags();
    const path = pathOf(network, PATH);
    const clean = createPacket(path, new TextEncoder().encode(MESSAGE), randomBytes(KAPPA));

    // Each variant is routed on its own freshly built packet so the replay
    // detector never fires: this act is about tagging, and a REPLAY_DETECTED
    // here would be an artefact of the harness rather than a result.
    const headerCase = createPacket(path, new TextEncoder().encode(MESSAGE), randomBytes(KAPPA));
    const payloadCase = createPacket(path, new TextEncoder().encode(MESSAGE), randomBytes(KAPPA));

    const baseline = routePacket(network, PATH[0], clean.packet);
    const headerOut = routePacket(
      network,
      PATH[0],
      tamperedCopy(headerCase.packet, 'beta', Number(headerIdx.input.value))
    );
    const payloadOut = routePacket(
      network,
      PATH[0],
      tamperedCopy(payloadCase.packet, 'payload', Number(payloadIdx.input.value))
    );

    clear(out);
    out.append(
      el('div', { class: 'grid2 reveal' }, [
        headerColumn(headerOut),
        payloadColumn(payloadOut, payloadCase),
      ])
    );
    out.append(comparison(baseline, headerOut, payloadOut));
  }

  function headerColumn(outcome: RouteOutcome): HTMLElement {
    const card = el('div', { class: 'card' });
    card.append(
      el('h3', { text: 'Header byte flipped' }),
      el('p', { class: 'status-line', text: 'The routing block is covered by a per-hop MAC.' })
    );
    card.append(hopTrail(outcome));
    if (outcome.failure) {
      card.append(el('p', {}, [pill('bad', outcome.failure.code), ` at ${outcome.failure.atMix}`]));
      card.append(verdict('fail', [FAILURE_TEXT[outcome.failure.code]]));
      card.append(
        el('p', {
          class: 'status-line',
          text: `Reached ${outcome.traces.length} of ${PATH.length} mixes — ${outcome.failure.detail}`,
        })
      );
    } else {
      card.append(verdict('alarm', ['The packet was delivered. That should not happen — please report it.']));
    }
    card.append(
      verdict('info', [
        el('strong', { text: 'Header integrity. ' }),
        'Verified hop by hop, by the network, for the network. It stops a modified packet from being routed anywhere.',
      ])
    );
    return card;
  }

  function payloadColumn(outcome: RouteOutcome, built: PacketBuild): HTMLElement {
    const card = el('div', { class: 'card' });
    card.append(
      el('h3', { text: 'Payload byte flipped' }),
      el('p', { class: 'status-line', text: 'The payload is covered by a wide-block permutation, and by no MAC at all.' })
    );
    card.append(hopTrail(outcome));
    const allGreen = outcome.traces.every((t) => t.macOk) && !outcome.failure;
    card.append(
      allGreen
        ? verdict('alarm', [
            'Every mix accepted it. Every MAC verified. The packet was forwarded normally through all ',
            el('strong', { text: String(PATH.length) }),
            ' hops and nothing on the path detected anything.',
          ])
        : verdict('fail', [`Unexpected: ${outcome.failure?.code ?? 'unknown'}`])
    );

    const arrived = outcome.delivered;
    if (arrived) {
      const exit = outcome.traces[outcome.traces.length - 1]!;
      const damage = hammingDistance(exit.payloadOut!, built.plaintext);
      card.append(
        arrived.unpacked.intact
          ? verdict('pass', ['The payload arrived intact.'])
          : verdict('fail', [
              el('strong', { text: 'The payload arrived irrecoverable. ' }),
              arrived.unpacked.detail,
            ])
      );
      card.append(
        kv([
          [
            'Plaintext bits changed',
            `${damage} of ${PAYLOAD_LEN * 8} (${((damage / (PAYLOAD_LEN * 8)) * 100).toFixed(1)}%)`,
          ],
          ['Bits the attacker flipped', '1'],
          ['Message recovered', arrived.unpacked.message ? 'yes' : 'no'],
        ])
      );
      card.append(el('h4', { text: 'What the recipient unwrapped (first 96 bytes)' }));
      card.append(hexDump(exit.payloadOut!, { against: built.plaintext, label: 'recovered payload block' }));
    }
    card.append(
      verdict('info', [
        el('strong', { text: 'Anti-tagging, not integrity. ' }),
        'LIONESS is a permutation, not an authentication code. It converts a targeted one-bit change into unpredictable corruption of all ',
        String(PAYLOAD_LEN),
        ' bytes, so the adversary cannot recognise its own mark. It hands nobody an authenticity verdict.',
      ])
    );
    return card;
  }

  function comparison(base: RouteOutcome, headerOut: RouteOutcome, payloadOut: RouteOutcome): HTMLElement {
    const card = el('div', { class: 'card' });
    card.append(el('h3', { text: 'Side by side' }));
    const table = el('table');
    table.append(
      el('caption', { text: 'The same one-bit change, in two places, with two entirely different outcomes.' })
    );
    const head = el('tr');
    for (const h of ['', 'Untouched', 'Header byte flipped', 'Payload byte flipped']) {
      head.append(el('th', { scope: 'col', text: h }));
    }
    table.append(el('thead', {}, [head]));
    const body = el('tbody');
    const rows: [string, (o: RouteOutcome) => string][] = [
      ['Mixes that accepted it', (o) => `${o.traces.filter((t) => t.macOk).length} of ${PATH.length}`],
      ['Detected on the path', (o) => (o.failure ? `yes — ${o.failure.code}` : 'no')],
      ['Delivered to the recipient', (o) => (o.delivered ? 'yes' : 'no')],
      [
        'Payload usable',
        (o) => (o.delivered ? (o.delivered.unpacked.intact ? 'yes' : 'no — corrupted') : 'n/a'),
      ],
      ['Who caught it', (o) => (o.failure ? 'the network' : o.delivered?.unpacked.intact ? 'nothing to catch' : 'the recipient, and only as corruption')],
    ];
    for (const [label, get] of rows) {
      const tr = el('tr');
      tr.append(el('th', { scope: 'row', text: label }));
      for (const o of [base, headerOut, payloadOut]) tr.append(el('td', { text: get(o) }));
      body.append(tr);
    }
    table.append(body);
    card.append(el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Tagging outcomes compared' }, [table]));
    card.append(
      verdict('info', [
        'Header integrity is verified hop by hop and protects the network; payload protection is anti-tagging only and leaves authenticity to the recipient\'s own layer.',
      ])
    );
    card.append(
      disclosure('So how does the recipient know the payload is genuine?', [
        el('p', {
          text: `This lab chose the paper's route: recognisable payload structure. The plaintext begins with ${KAPPA} zero bytes, and the recipient checks for them. Under a permutation, corruption survives that check with probability 2⁻¹²⁸, which makes it a reliable CORRUPTION detector.`,
        }),
        el('p', {
          text: 'It is not an authenticator. It says the bytes did not arrive intact; it never says who sent them, and it gives no guarantee against anyone who can predict or influence the plaintext structure. Explicit end-to-end authenticity needs a separate authenticator the sender and recipient share — a signature or a MAC under a key no mix holds — and Sphinx deliberately leaves that to the layer above, because a mix format that demanded it would have to know something about the recipient.',
        }),
        el('p', {
          text: 'The alternative route, which this lab did not take, is an end-to-end MAC inside the payload. It gives a real authenticity verdict; it costs payload space, and it requires the sender and recipient to have already established a key, which a single-shot mix packet may not have.',
        }),
      ])
    );
    return card;
  }

  run();
}

function hopTrail(outcome: RouteOutcome): HTMLElement {
  const row = el('div', { class: 'hoprow' });
  PATH.forEach((name, i) => {
    const trace = outcome.traces[i];
    const died = outcome.failure && outcome.failure.atMix === name;
    const cls = died ? ' hopnode-dead' : trace ? ' hopnode-done' : '';
    row.append(
      el('div', { class: `hopnode${cls}` }, [
        el('span', { class: 'hopnode-title', text: name }),
        el('span', {
          class: 'hopnode-meta',
          text: died ? 'packet dies here' : trace ? 'MAC ok, forwarded' : 'never reached',
        }),
      ])
    );
  });
  return row;
}

function numberField(
  id: string,
  label: string,
  min: number,
  max: number,
  value: number
): { field: HTMLElement; input: HTMLInputElement } {
  const input = el('input', { type: 'number', id, min, max, value, step: 1 }) as HTMLInputElement;
  input.style.width = '7rem';
  return {
    field: el('div', { class: 'field' }, [el('label', { for: id, text: `${label} (0–${max})` }), input]),
    input,
  };
}
