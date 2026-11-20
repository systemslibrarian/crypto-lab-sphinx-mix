/**
 * Act 7 — What the last mix can count.
 *
 * Act 3 shows that the header never changes size. This act shows what that
 * does NOT hide. In the original Sphinx design the unused tail of the
 * innermost routing block is padded with zeros; the last mix decrypts the
 * block, sees the zeros, counts them, and has the path length.
 *
 * Kuhn, Beck and Strufe, "Breaking and (Partially) Fixing Provably Secure
 * Onion Routing" (arXiv:1910.13772), §IV-A: "The exit node hence can learn
 * the length of the chosen path". Their fix is to fill the pad with random
 * bits instead, and the toggle here builds real packets both ways.
 *
 * Everything on this panel is computed from packets built in the tab: the
 * zero run is counted off the block the exit actually decrypted, by
 * `readPathLength`, which is handed that block and nothing else.
 */
import { button, clear, disclosure, el, hexDump, kv, liveRegion, verdict } from './dom';
import { network } from './state';
import { pathOf, routePacket } from '../sphinx/network';
import { createPacket } from '../sphinx/packet';
import { tailPadLength, type TailPad } from '../sphinx/header';
import { randomBytes, zeros } from '../sphinx/bytes';
import { BETA_LEN, KAPPA, MAX_HOPS } from '../sphinx/params';
import {
  EXIT_MIX,
  pathEndingAtExit,
  readPathLength,
  runLeakTrial,
  runTagExperiment,
} from '../sphinx/pathleak';

const MESSAGE = 'how long was the path?';
const TRIALS_PER_LENGTH = 20;
const SENDERS = ['Sender 1', 'Sender 2', 'Sender 3'] as const;

const PAD_LABEL: Record<TailPad, string> = {
  zero: 'zeros',
  random: 'random bytes',
};

export function renderLeak(root: HTMLElement): void {
  clear(root);
  let hops = 3;
  let pad: TailPad = 'zero';

  root.append(
    el('h2', { text: 'What the last mix can count' }),
    el('p', {
      text: `Act 3 showed that a packet is the same size at every path length. That keeps the length from anyone watching the wire. It does not keep it from the last mix. The innermost routing block is END, then the identifier, then padding, then filler — and in the original Sphinx design the padding is ${tailPadLength(1) / KAPPA} to 1 blocks of zero bytes, depending on the path. The last mix decrypts its block and the zeros are simply there to be counted.`,
    }),
    el('p', {
      text: `Every packet on this panel leaves through ${EXIT_MIX}, whatever its length, so that being the exit says nothing by itself. The attack and the fix are from Kuhn, Beck and Strufe, “Breaking and (Partially) Fixing Provably Secure Onion Routing” (arXiv:1910.13772, §IV-A): “The exit node hence can learn the length of the chosen path”.`,
    })
  );

  // ---- one packet -------------------------------------------------------
  const controls = el('div', { class: 'controls' });
  const hopSelect = el('select', { id: 'leak-hops' }) as HTMLSelectElement;
  for (let n = 1; n <= MAX_HOPS; n++) {
    hopSelect.append(el('option', { value: n, text: `${n} hop${n === 1 ? '' : 's'}`, selected: n === hops }));
  }
  hopSelect.addEventListener('change', () => {
    hops = Number(hopSelect.value);
    sendOne();
  });
  const padSelect = el('select', { id: 'leak-pad' }) as HTMLSelectElement;
  padSelect.append(
    el('option', { value: 'zero', text: 'Zeros (original Sphinx)', selected: true }),
    el('option', { value: 'random', text: 'Random bytes (the fix)' })
  );
  padSelect.addEventListener('change', () => {
    pad = padSelect.value as TailPad;
    sendOne();
  });
  controls.append(
    el('div', { class: 'field' }, [el('label', { for: 'leak-hops', text: 'Path length' }), hopSelect]),
    el('div', { class: 'field' }, [el('label', { for: 'leak-pad', text: 'Padding in the innermost block' }), padSelect]),
    button('Send one packet', () => sendOne(), { class: 'btn btn-primary', id: 'leak-send' })
  );
  const out = liveRegion('leak-out');
  root.append(controls, out);

  function sendOne(): void {
    clear(out);
    const names = pathEndingAtExit(hops);
    const built = createPacket(
      pathOf(network, names),
      new TextEncoder().encode(MESSAGE),
      randomBytes(KAPPA),
      { tailPad: pad }
    );
    // record:false -- this act re-sends on every control change and must not
    // leave replay tags behind for act 4 to trip over.
    const outcome = routePacket(network, names[0]!, built.packet, { record: false });
    const exitTrace = outcome.traces[outcome.traces.length - 1];

    const row = el('div', { class: 'hoprow' });
    names.forEach((name, i) =>
      row.append(
        el('div', { class: `hopnode${outcome.traces[i] ? ' hopnode-done' : ''}` }, [
          el('span', { class: 'hopnode-title', text: name }),
          el('span', { class: 'hopnode-meta', text: i === names.length - 1 ? 'exit' : `hop ${i + 1}` }),
        ])
      )
    );
    out.append(row);

    if (!outcome.delivered || !exitTrace?.betaPlain) {
      out.append(
        verdict('fail', [`Unexpected: the packet was not delivered (${outcome.failure?.code ?? 'unknown'}).`])
      );
      return;
    }
    const arrived = outcome.delivered.unpacked;
    const text = arrived.message ? new TextDecoder().decode(arrived.message) : '';
    out.append(
      arrived.intact && text === MESSAGE
        ? verdict('pass', [
            el('strong', { text: 'Delivered. ' }),
            `All ${outcome.traces.length} header MAC${outcome.traces.length === 1 ? '' : 's'} verified and the message arrived intact with ${PAD_LABEL[pad]} as padding.`,
          ])
        : verdict('fail', ['The message did not arrive intact.'])
    );

    const block = exitTrace.betaPlain;
    const reading = readPathLength(block);
    const padLen = tailPadLength(hops);
    const fillerLen = BETA_LEN - 2 * KAPPA - padLen;

    const card = el('div', { class: 'card reveal' });
    card.append(
      el('h3', { text: `The routing block as ${EXIT_MIX} decrypted it` }),
      el('p', {
        class: 'status-line',
        text: `All ${BETA_LEN} bytes, after ${EXIT_MIX} XORed its own keystream off. Bytes 0–${KAPPA - 1} are the END marker (zero by definition), bytes ${KAPPA}–${2 * KAPPA - 1} the identifier, and everything from byte ${2 * KAPPA} on is padding and then filler. Every 00 byte is underlined.`,
      }),
      hexDump(block, {
        against: zeros(BETA_LEN),
        limit: BETA_LEN,
        label: `routing block as decrypted by ${EXIT_MIX}`,
      })
    );
    card.append(
      kv([
        ['Zero run', `${reading.run} bytes, counted from byte ${2 * KAPPA}`],
        ['Whole blocks', `${reading.blocks} of ${KAPPA} bytes`],
        [
          'Exit computes',
          reading.nu === null ? 'no run to read' : `ν = r − (blocks − 1)/2 = ${reading.nu}`,
        ],
        ['Sender chose', `ν = ${hops}`],
        ['Padding', `${padLen} bytes of ${PAD_LABEL[pad]} = (2(r − ν) + 1)·κ`],
        ['Filler', `${fillerLen} bytes = 2(ν − 1)·κ`],
      ])
    );
    if (reading.nu !== null) {
      card.append(
        verdict(reading.nu === hops ? 'alarm' : 'fail', [
          el('strong', { text: `${EXIT_MIX} read the path length off the padding: ${reading.nu}. ` }),
          `It counted ${reading.run} zero bytes after the identifier and used no key but its own. The packet was the same size as every other packet on the wire, and that did not help.`,
        ])
      );
    } else {
      card.append(
        verdict('pass', [
          el('strong', { text: 'No run to count. ' }),
          `After the identifier ${EXIT_MIX} holds ${BETA_LEN - 2 * KAPPA} bytes with nothing marking where padding stops and filler starts. Any of the ${MAX_HOPS} path lengths would look like this, so its best guess is 1 in ${MAX_HOPS}.`,
        ])
      );
    }
    out.append(card);
  }

  // ---- many packets -----------------------------------------------------
  const trialCard = el('div', { class: 'card' });
  const total = TRIALS_PER_LENGTH * MAX_HOPS;
  const trialBtn = button(`Run ${total} packets in each mode`, () => void runTrials(), {
    class: 'btn',
    id: 'leak-trials',
  });
  const trialStatus = el('p', { class: 'status-line', id: 'leak-trials-status' });
  const trialOut = liveRegion('leak-trials-out');
  trialCard.append(
    el('h3', { text: 'One packet is an anecdote' }),
    el('p', {
      text: `Build ${TRIALS_PER_LENGTH} real packets at each path length from 1 to ${MAX_HOPS}, with each kind of padding, and let ${EXIT_MIX} commit to a path length for every one. Where the padding gives it a run of zeros it uses the run; where it does not, it has nothing better than a uniform guess, and makes one.`,
    }),
    el('div', { class: 'controls' }, [trialBtn]),
    trialStatus,
    trialOut
  );
  root.append(trialCard);

  let busy = false;
  async function runTrials(): Promise<void> {
    if (busy) return;
    busy = true;
    trialBtn.disabled = true;
    clear(trialOut);
    const modes: TailPad[] = ['zero', 'random'];
    const correct: Record<TailPad, number[]> = {
      zero: new Array<number>(MAX_HOPS + 1).fill(0),
      random: new Array<number>(MAX_HOPS + 1).fill(0),
    };
    const delivered: Record<TailPad, number> = { zero: 0, random: 0 };
    let done = 0;
    try {
      for (let nu = 1; nu <= MAX_HOPS; nu++) {
        for (const mode of modes) {
          for (let i = 0; i < TRIALS_PER_LENGTH; i++) {
            const t = runLeakTrial(network, nu, mode);
            if (t.correct) correct[mode][nu]!++;
            if (t.delivered) delivered[mode]++;
            done++;
          }
          trialStatus.textContent = `Building and decrypting real packets… ${done} of ${2 * total}`;
          // Yield so the status line paints and the tab stays responsive.
          await new Promise<void>((resolve) => setTimeout(resolve, 0));
        }
      }
      trialStatus.textContent = `${2 * total} real packets built, each decrypted by ${EXIT_MIX}.`;
      renderTrials(correct, delivered);
    } finally {
      busy = false;
      trialBtn.disabled = false;
    }
  }

  function renderTrials(correct: Record<TailPad, number[]>, delivered: Record<TailPad, number>): void {
    clear(trialOut);
    const sum = (a: number[]): number => a.reduce((x, y) => x + y, 0);
    const zeroHits = sum(correct.zero);
    const randomHits = sum(correct.random);

    const table = el('table', { id: 'leak-trials-table' });
    table.append(
      el('caption', {
        text: `Path lengths ${EXIT_MIX} got right, out of ${TRIALS_PER_LENGTH} packets per row and padding.`,
      })
    );
    const head = el('tr');
    for (const h of ['True path length', 'Zero padding', 'Random padding']) {
      head.append(el('th', { scope: 'col', text: h }));
    }
    table.append(el('thead', {}, [head]));
    const body = el('tbody');
    for (let nu = 1; nu <= MAX_HOPS; nu++) {
      body.append(
        el('tr', {}, [
          el('th', { scope: 'row', text: `${nu} hop${nu === 1 ? '' : 's'}` }),
          el('td', { class: 'num', text: `${correct.zero[nu]} of ${TRIALS_PER_LENGTH}` }),
          el('td', { class: 'num', text: `${correct.random[nu]} of ${TRIALS_PER_LENGTH}` }),
        ])
      );
    }
    body.append(
      el('tr', {}, [
        el('th', { scope: 'row', text: 'All lengths' }),
        el('td', { class: 'num', text: `${zeroHits} of ${total}` }),
        el('td', { class: 'num', text: `${randomHits} of ${total}` }),
      ])
    );
    table.append(body);
    trialOut.append(
      el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Path lengths recovered by the exit' }, [table])
    );

    // What a fair 1-in-r guess gives, and how far from it this run landed.
    const p = 1 / MAX_HOPS;
    const expected = total * p;
    const sigma = Math.sqrt(total * p * (1 - p));
    const z = (randomHits - expected) / sigma;
    trialOut.append(
      kv([
        ['Delivered, zeros', `${delivered.zero} of ${total} intact`],
        ['Delivered, random', `${delivered.random} of ${total} intact`],
        ['Recovered, zeros', `${zeroHits} of ${total} (${((zeroHits / total) * 100).toFixed(1)}%)`],
        ['Recovered, random', `${randomHits} of ${total} (${((randomHits / total) * 100).toFixed(1)}%)`],
        [`A 1-in-${MAX_HOPS} guess`, `expects ${expected.toFixed(1)} of ${total} (${(p * 100).toFixed(1)}%), standard deviation ${sigma.toFixed(2)}`],
        ['Random vs. guess', `${z >= 0 ? '+' : '−'}${Math.abs(z).toFixed(2)} standard deviations`],
      ])
    );
    trialOut.append(
      verdict(zeroHits === total ? 'alarm' : 'fail', [
        el('strong', { text: 'Zero padding: ' }),
        `${EXIT_MIX} named the path length of ${zeroHits} of ${total} packets, every one of them delivered normally.`,
      ])
    );
    trialOut.append(
      Math.abs(z) <= 4
        ? verdict('pass', [
            el('strong', { text: 'Random padding: ' }),
            `${randomHits} of ${total}, which is what guessing gives. The same packets, the same size, the same delivery — and the count is gone.`,
          ])
        : verdict('fail', [
            `Random padding: ${randomHits} of ${total} is more than four standard deviations from a 1-in-${MAX_HOPS} guess. That should happen about once in sixteen thousand runs — run it again, and report it if it repeats.`,
          ])
    );
  }

  // ---- the paper's second finding --------------------------------------
  const tagCard = el('div', { class: 'card' });
  const tagSelect = el('select', { id: 'leak-tag-sender' }) as HTMLSelectElement;
  SENDERS.forEach((s, i) => tagSelect.append(el('option', { value: s, text: s, selected: i === 1 })));
  const tagOut = liveRegion('leak-tag-out');
  tagCard.append(
    el('h3', { text: 'The same paper’s second finding: a destroyed payload is still a mark' }),
    el('p', {
      text: 'Act 5 flips a payload bit and shows the far end receiving 1024 bytes of noise, so the adversary cannot recognise the bit it flipped. The paper’s point is that it does not need to. No mix checks the payload, so the packet still arrives — and it is the one arrival whose integrity check fails.',
    }),
    el('div', { class: 'controls' }, [
      el('div', { class: 'field' }, [
        el('label', { for: 'leak-tag-sender', text: 'Packet the first mix marks' }),
        tagSelect,
      ]),
      button('Mark it and deliver all three', () => runTag(), { class: 'btn', id: 'leak-tag-run' }),
    ]),
    tagOut
  );
  root.append(tagCard);

  function runTag(): void {
    clear(tagOut);
    const arrivals = runTagExperiment(network, SENDERS, tagSelect.value);
    const table = el('table', { id: 'leak-tag-table' });
    table.append(
      el('caption', {
        text: `Three senders, one packet each, all through Mix A and out through ${EXIT_MIX}.`,
      })
    );
    const head = el('tr');
    for (const h of ['Sender', 'First mix flipped a payload bit', 'Header MACs verified', 'Integrity check at the far end']) {
      head.append(el('th', { scope: 'col', text: h }));
    }
    table.append(el('thead', {}, [head]));
    const body = el('tbody');
    for (const a of arrivals) {
      body.append(
        el('tr', {}, [
          el('th', { scope: 'row', text: a.sender }),
          el('td', { text: a.marked ? 'yes — 1 bit' : 'no' }),
          el('td', { text: a.macsOk ? `all ${a.hops}` : 'no' }),
          el('td', { text: !a.delivered ? 'not delivered' : a.intact ? 'passed' : 'FAILED' }),
        ])
      );
    }
    table.append(body);
    tagOut.append(
      el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Marked and unmarked packets at the far end' }, [table])
    );
    const failed = arrivals.filter((a) => a.delivered && !a.intact);
    const marked = arrivals.find((a) => a.marked);
    if (failed.length === 1 && marked && failed[0]!.sender === marked.sender && arrivals.every((a) => a.macsOk)) {
      tagOut.append(
        verdict('alarm', [
          el('strong', { text: `Exactly one arrival failed its check, and it is ${marked.sender}’s. ` }),
          `Every header MAC verified on all three. Whoever holds the first mix and the far end has linked ${marked.sender} to this exit without a key and without reading a byte of plaintext.`,
        ])
      );
    } else {
      tagOut.append(verdict('fail', ['Unexpected: the marked packet was not the only one to fail its check.']));
    }
    tagOut.append(
      verdict('info', [
        el('strong', { text: 'How far the link reaches. ' }),
        'In Sphinx as designed the recipient’s address travels inside the payload, which this attack destroys, so the paper’s wording is that “the sender can only be linked to the exit node”. Where the recipient is itself the last relay — HORNET’s setup phase uses Sphinx that way — a corrupt recipient learns who tried to reach it: it “just has to notice that Sphinx’s integrity check at the receiver failed”.',
      ])
    );
  }

  root.append(
    disclosure('What the fix costs, and what “partially” means', [
      el('p', {
        text: `Nothing reads the padding. The exit takes END and the identifier from the first ${2 * KAPPA} bytes and ignores the rest, and the header MAC is computed over the block whatever it holds, so swapping zeros for random bytes changes no length, no check and no key. The paper’s corrected construction is the original “except that we consider the 0-bit string for padding β[ν−1] replaced by random bits to prevent the known attack”.`,
      }),
      el('p', {
        text: 'The paper states the attack as a lower bound — the exit “observes (after XORing) where the first 1 bit after the identifier is” and “knows that the filler string starts there or earlier” — because the filler could begin with a zero by coincidence. This panel counts in whole κ-byte blocks, so a stray zero byte at the head of the filler never moves the answer; being wrong would take sixteen of them in a row.',
      }),
      el('p', {
        text: 'Random padding closes this one leak — the exit mix can no longer read the path length. That is a different concern from payload tagging, which Sphinx answers separately with its wide-block payload (act 5). And the paper’s title says “partially” for a different reason still: Kuhn, Beck and Strufe re-prove their corrected security properties for only one protocol, as a demonstration, leaving the rest of the provably-secure onion-routing family unproven — the abstract’s “showing our improved properties for one protocol, thus partially fixing the family”. The original design is still what the other six acts build, because it is the paper this lab implements.',
      }),
    ])
  );

  sendOne();
}
