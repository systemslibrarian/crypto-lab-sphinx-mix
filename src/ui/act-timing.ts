/**
 * Act 6 — Timing correlation. The climax, and the negative claim.
 *
 * Every packet here is a real Sphinx packet and every cryptographic check
 * really runs. The clock is simulated. With one sender and immediate
 * forwarding, an observer who cannot decrypt a single byte still traces every
 * packet end to end — because the anonymity set is one, and the packet format
 * has nothing whatever to say about that.
 */
import { button, clear, disclosure, el, kv, liveRegion, pill, slider, verdict } from './dom';
import { network } from './state';
import { DEFAULT_TRAFFIC, entropyBits, runTraffic, type TrafficConfig, type TrafficResult } from '../sphinx/traffic';

export function renderTiming(root: HTMLElement): void {
  clear(root);
  const config: TrafficConfig = { ...DEFAULT_TRAFFIC };
  let busy = false;

  root.append(
    el('h2', { text: 'Timing correlation' }),
    el('p', {
      text:
        'Everything so far has been about the packet: unlinkable bytes, a header that never changes length, a payload an adversary cannot mark. None of it says anything about WHEN packets move. An observer who sees every link, holds no key, and breaks no cryptography can still count and time — and counting is often enough.',
    })
  );

  const controls = el('div', { class: 'controls' });
  const senders = slider('tc-senders', 'Senders', { min: 1, max: 8, value: config.senders }, (v) => {
    config.senders = v;
  });
  const perSender = slider(
    'tc-packets',
    'Real messages each',
    { min: 1, max: 2, value: config.packetsPerSender },
    (v) => {
      config.packetsPerSender = v;
    }
  );
  const cover = slider('tc-cover', 'Cover packets each', { min: 0, max: 2, value: config.coverPerReal }, (v) => {
    config.coverPerReal = v;
  });
  const strategy = el('select', { id: 'tc-strategy' }) as HTMLSelectElement;
  strategy.append(
    el('option', { value: 'immediate', text: 'Forward immediately', selected: true }),
    el('option', { value: 'pool', text: 'Pool mix (hold, then flush)' })
  );
  strategy.addEventListener('change', () => {
    config.strategy = strategy.value as TrafficConfig['strategy'];
    threshold.input.disabled = config.strategy === 'immediate';
  });
  const threshold = slider(
    'tc-threshold',
    'Pool size before flush',
    { min: 2, max: 8, value: config.poolThreshold },
    (v) => {
      config.poolThreshold = v;
    }
  );
  threshold.input.disabled = true;

  controls.append(
    senders.field,
    perSender.field,
    cover.field,
    el('div', { class: 'field' }, [el('label', { for: 'tc-strategy', text: 'Mix strategy' }), strategy]),
    threshold.field
  );

  const runBtn = button('Run the network', () => void run(), { class: 'btn btn-primary', id: 'tc-run' });
  const presetA = button(
    'Preset: one sender, immediate',
    () => {
      applyPreset({ senders: 1, packetsPerSender: 2, coverPerReal: 0, strategy: 'immediate', poolThreshold: 4 });
    },
    { class: 'btn', id: 'tc-preset-neg' }
  );
  const presetB = button(
    'Preset: eight senders, pool of 6',
    () => {
      applyPreset({ senders: 8, packetsPerSender: 2, coverPerReal: 1, strategy: 'pool', poolThreshold: 6 });
    },
    { class: 'btn', id: 'tc-preset-crowd' }
  );
  const actions = el('div', { class: 'controls' }, [runBtn, presetA, presetB]);
  const status = el('p', { class: 'status-line', id: 'tc-status' });
  const out = liveRegion('tc-out');
  root.append(controls, actions, status, out);

  function applyPreset(p: Partial<TrafficConfig>): void {
    Object.assign(config, p);
    senders.setValue(config.senders);
    perSender.setValue(config.packetsPerSender);
    cover.setValue(config.coverPerReal);
    threshold.setValue(config.poolThreshold);
    strategy.value = config.strategy;
    threshold.input.disabled = config.strategy === 'immediate';
    void run();
  }

  async function run(): Promise<void> {
    if (busy) return;
    busy = true;
    runBtn.disabled = true;
    clear(out);
    status.textContent = 'Building real Sphinx packets…';
    try {
      const result = await runTraffic({ ...config }, network, undefined, (built, total) => {
        status.textContent = `Building real Sphinx packets… ${built} of ${total}`;
      });
      status.textContent = `${result.injected} real packets built and routed through ${result.rounds} scheduling rounds.`;
      render(result);
    } finally {
      busy = false;
      runBtn.disabled = false;
    }
  }

  function render(r: TrafficResult): void {
    clear(out);
    const ceiling = Math.log2(r.config.senders);
    const traced = r.fullyTraced === r.delivered.length && r.delivered.length > 0;

    // --- the meter -------------------------------------------------------
    const meterCard = el('div', { class: 'card reveal' });
    meterCard.append(el('h3', { text: 'Anonymity-set entropy' }));
    const fill = el('div', {
      class: `meter-fill${r.meanEntropyBits === 0 ? ' meter-fill-zero' : ''}`,
      style: `width:${ceiling > 0 ? Math.max(1.5, (r.meanEntropyBits / ceiling) * 100) : 1.5}%`,
    });
    meterCard.append(
      el(
        'div',
        {
          class: 'meter',
          role: 'img',
          'aria-label': `Anonymity-set entropy ${r.meanEntropyBits.toFixed(2)} bits of a possible ${ceiling.toFixed(2)} bits`,
        },
        [fill]
      )
    );
    meterCard.append(
      kv([
        ['Mean entropy H', `${r.meanEntropyBits.toFixed(3)} bits (ceiling for ${r.config.senders} sender${r.config.senders === 1 ? '' : 's'}: ${ceiling.toFixed(3)})`],
        ['Effective anonymity set 2^H', `${r.effectiveSetSize.toFixed(2)} of ${r.config.senders}`],
        ['Worst packet', `${r.minEntropyBits.toFixed(3)} bits`],
        ['Delivered', `${r.delivered.length} of ${r.injected} packets`],
        ['Still held in a pool', String(r.stranded)],
      ])
    );
    meterCard.append(
      el('p', {}, [
        r.cryptoAllGreen
          ? pill('ok', 'ALL CRYPTOGRAPHIC CHECKS PASSED')
          : pill('bad', 'A CRYPTOGRAPHIC CHECK FAILED'),
        ' ',
        traced ? pill('bad', 'EVERY PACKET TRACED') : pill('ok', `${r.delivered.length - r.fullyTraced} PACKETS AMBIGUOUS`),
      ])
    );

    // The tone tracks system integrity, not the return value: an all-green
    // run that an observer traced end to end is an ALARM, not a success.
    meterCard.append(
      traced
        ? verdict('alarm', [
            el('strong', { text: 'Every packet was traced end to end. ' }),
            'Not one cryptographic check failed. The header was unlinkable at every hop, the payload was unmarkable, the MACs all verified — and the observer still knows exactly who sent what, because ',
            r.config.senders === 1
              ? 'there was only one sender to choose from.'
              : 'each mix released each packet in the order it arrived, so the observer only had to count.',
          ])
        : verdict('pass', [
            `An observer cannot narrow a delivered packet below ${r.effectiveSetSize.toFixed(2)} candidate senders on average. The cryptography did not change; the traffic did.`,
          ])
    );
    out.append(meterCard);

    // --- what the observer wrote down ------------------------------------
    const traceCard = el('div', { class: 'card' });
    traceCard.append(el('h3', { text: 'The observer’s notebook' }));
    const table = el('table');
    table.append(
      el('caption', {
        text: 'One row per delivered packet, with the observer’s posterior over senders. It holds no keys and decrypted nothing.',
      })
    );
    const head = el('tr');
    for (const h of ['Packet', 'Actually sent by', 'Route', 'H (bits)', 'Candidates', 'Traced?']) {
      head.append(el('th', { scope: 'col', text: h }));
    }
    table.append(el('thead', {}, [head]));
    const body = el('tbody');
    r.delivered.slice(0, 14).forEach((d, i) => {
      const h = entropyBits(d.posterior);
      const tr = el('tr');
      tr.append(el('th', { scope: 'row', text: `#${i + 1}${d.isCover ? ' (cover)' : ''}` }));
      tr.append(el('td', { text: r.senderNames[d.senderIndex] ?? '?' }));
      tr.append(el('td', { text: d.route.join(' → ') }));
      tr.append(el('td', { class: 'num', text: h.toFixed(2) }));
      tr.append(el('td', { class: 'num', text: Math.pow(2, h).toFixed(2) }));
      tr.append(el('td', {}, [h === 0 ? pill('bad', 'TRACED') : pill('ok', 'AMBIGUOUS')]));
      body.append(tr);
    });
    table.append(body);
    traceCard.append(
      el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Delivered packets and the observer’s certainty' }, [table])
    );
    if (r.delivered.length > 14) {
      traceCard.append(el('p', { class: 'status-line', text: `Showing the first 14 of ${r.delivered.length} delivered packets.` }));
    }
    if (r.delivered.length === 0) {
      traceCard.append(
        verdict('alarm', [
          'Nothing was delivered at all. A threshold mix does not flush a partial pool, and there was never enough traffic to fill one. That is a real cost of the strategy, not a bug — raise the number of senders, or add cover traffic to fill the pools.',
        ])
      );
    }
    out.append(traceCard);

    out.append(
      disclosure('How the entropy is computed, and what it does not model', [
        el('p', {
          text: 'The adversary is a global passive observer: it sees every packet on every link with a timestamp, including the sender-to-first-mix and last-mix-onward links, and it knows each mix’s flushing rule. It holds no mix private key, so — because Sphinx works — it cannot link a mix’s input bytes to its output bytes. Timing and counting are all it has.',
        }),
        el('p', {
          text: 'A threshold mix holding t packets releases them in a uniformly random order, so every output has the same posterior: the uniform mixture of those t inputs’ own distributions. That propagates forward in closed form, so H = −Σ p log₂ p is computed exactly rather than sampled. This is the Serjantov–Danezis / Díaz et al. entropy measure (PET 2002).',
        }),
        el('p', {
          text: 'What it does NOT model, because pretending otherwise would be the dishonesty this lab is about: long-term intersection and statistical disclosure attacks across many rounds, active attacks such as n−1 flooding, fingerprinting outside the mixnet, and any adversary able to inject or delay. This is a single-round LOWER bound on what a passive observer learns — a real adversary learns at least this much.',
        }),
        el('p', {
          text: 'Cover traffic in this model does one measurable thing: it fills pools that would otherwise strand real packets, so more of them are delivered and delivered with a full anonymity set. It does not raise the entropy of a packet that was already delivered. Its other job — defeating long-term intersection attacks by making a sender’s output rate independent of whether it has anything to say — needs the many-round model this single round cannot show.',
        }),
      ])
    );
  }

  // The arrival state is the negative claim's own fixture: one sender,
  // immediate forwarding. It renders as an ALARM on purpose.
  void run();
}
