/**
 * Sphinx Mix — page shell.
 *
 * Builds the hero, the plain-language on-ramp, the honest-scoping notice, the
 * six acts, the negative claim and the failure-code reference. Panels render
 * LAZILY on first activation; a tab that has never been clicked holds an empty
 * container, which is deliberate — it keeps first paint cheap and it is what
 * the accessibility gate drives through.
 */
import './style.css';
import { el, clear, disclosure, pill } from './ui/dom';
import { renderBuild } from './ui/act-build';
import { renderPeel } from './ui/act-peel';
import { renderLength } from './ui/act-length';
import { renderReplay } from './ui/act-replay';
import { renderTagging } from './ui/act-tagging';
import { renderTiming } from './ui/act-timing';
import { FAILURE_CODES, FAILURE_TEXT } from './sphinx/errors';
import { HEADER_LEN, KAPPA, MAX_HOPS, PACKET_LEN, PAYLOAD_LEN } from './sphinx/params';

interface Act {
  id: string;
  num: string;
  label: string;
  render: (root: HTMLElement) => void;
}

// [extension] point -- a seventh act (an active n-1 flooding attack, or a
// Loopix-style multi-round intersection attack) is one entry here plus one
// module in src/ui/. The tab machinery, the lazy render and the a11y drive all
// key off this array, so nothing else needs to change.
const ACTS: Act[] = [
  { id: 'build', num: '1', label: 'Build a path', render: renderBuild },
  { id: 'peel', num: '2', label: 'Peel', render: renderPeel },
  { id: 'length', num: '3', label: 'Fixed length', render: renderLength },
  { id: 'replay', num: '4', label: 'Replay', render: renderReplay },
  { id: 'tagging', num: '5', label: 'Tagging', render: renderTagging },
  { id: 'timing', num: '6', label: 'Timing correlation', render: renderTiming },
];

function hero(): HTMLElement {
  return el('header', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('h1', { class: 'cl-hero-title', text: 'Sphinx Mix' }),
      el('p', { class: 'cl-hero-sub', text: 'Mix-network packet format · Danezis & Goldberg, IEEE S&P 2009' }),
      el('p', {
        class: 'cl-hero-desc',
        text:
          'Peel a real Sphinx packet across three mixes — per-hop ristretto255 blinding, a header that never changes length, a LIONESS-protected payload — then watch one sender on a quiet network get traced end to end with every cryptographic check green.',
      }),
    ]),
    el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
      el('span', { class: 'cl-hero-why-label', text: 'WHY IT MATTERS' }),
      el('p', {
        class: 'cl-hero-why-text',
        text:
          'Anonymity systems fail in a way encryption does not: every check can pass and the system can still expose you. Sphinx is the packet format Nym, Katzenpost and Loopix are built on, and knowing exactly where its guarantee stops is the difference between using it and trusting it.',
      }),
    ]),
  ]);
}

function intro(): HTMLElement {
  const wrap = el('section', { class: 'intro', 'aria-label': 'What this is' });
  wrap.append(
    el('div', { class: 'card' }, [
      el('h2', { text: 'What is a mix network?' }),
      el('p', {
        text:
          'Encryption hides what you said. It does not hide that you said it, or to whom. Anyone watching the wire sees your address on every packet — and for most of the things people need privacy for, that metadata is the sensitive part.',
      }),
      el('p', {
        text:
          'A mix network answers that by routing each message through several relays, called mixes, each of which peels off one layer of encryption and forwards the result. No single mix knows both the sender and the recipient. Sphinx is the packet FORMAT that makes this work: a fixed-size header, one shared secret per hop, and a payload nobody in the middle can mark.',
      }),
      el('p', {
        text:
          'The whole lab exists to separate two things that sound the same and are not. Bitwise unlinkability is a property of the packet — an observer cannot match a mix’s input bytes to its output bytes. Anonymity is a property of the traffic — an observer cannot work out who is talking to whom. The first does not produce the second, and act 6 shows you exactly how it fails to.',
      }),
    ])
  );
  return wrap;
}

function scopeNotice(): HTMLElement {
  return el('div', { class: 'callout callout-scope' }, [
    el('span', { class: 'callout-label', text: 'NOT PRODUCTION CRYPTO — A TEACHING DEMO' }),
    el('p', {
      text:
        'What is real: the ristretto255 group operations, the per-hop blinding chain, the HMAC-SHA256 header MACs, the ChaCha20 filler and routing-block keystream, the LIONESS wide-block permutation, every failure check, and every packet built or peeled anywhere on this page. All of it runs in your browser; no key material leaves the tab, and there is no backend to send it to.',
    }),
    el('p', {
      text:
        'What is simulated: the clock. Act 6 schedules arrivals in integer rounds rather than wall-clock time, because a browser tab cannot demonstrate a mixnet in real seconds. The packets in it are real; the timing is a model, and the disclosure inside that act names exactly which attacks the model leaves out.',
    }),
    el('p', {
      text:
        'What this is not: a deployable mix. Nothing here is constant-time — JavaScript offers no timing guarantees at all — there is no directory authority, no key rotation, no epoch handling, no packet-size negotiation, and the mix keys are regenerated on every page load.',
    }),
  ]);
}

function negativeClaim(): HTMLElement {
  return el('section', { class: 'callout callout-neg', 'aria-label': 'What this does not prove' }, [
    el('span', { class: 'callout-label', text: 'WHAT SPHINX DOES NOT PROVE' }),
    el('p', {
      text:
        'Sphinx provides bitwise unlinkability between a mix’s input and its output, hidden path position, and tagging resistance. It does not provide anonymity. Anonymity comes from mixing and from traffic conditions the packet format cannot supply.',
    }),
    el('p', {
      text:
        'The evidence is act 6’s first preset: one sender, immediate forwarding. Every MAC verifies, every header is unlinkable, every payload is unmarkable — and the anonymity-set entropy is exactly 0 bits, so an observer holding no keys traces every packet from end to end. A correct implementation of a correct format, offering no anonymity at all.',
    }),
  ]);
}

function failureReference(): HTMLElement {
  const list = el('div', { role: 'list' });
  for (const code of FAILURE_CODES) {
    list.append(
      el('div', { role: 'listitem', class: 'card card-tight' }, [
        el('p', {}, [pill('bad', code)]),
        el('p', { class: 'status-line', text: FAILURE_TEXT[code] }),
      ])
    );
  }
  return disclosure(`The ${FAILURE_CODES.length} ways a packet dies here`, [
    el('p', {
      text: 'Each of these is a real code returned by the mix layer, not a message the page writes. Every one is reachable from a control on this page, and every one is covered by a test.',
    }),
    list,
  ]);
}

function learnerCheck(): HTMLElement {
  const result = el('p', { class: 'status-line', role: 'status', 'aria-live': 'polite' });
  const opts = el('div', { class: 'check-opts' });
  const answers: [string, boolean, string][] = [
    [
      'The next mix rejects it — the payload is MACed like the header',
      false,
      'Not quite. γ covers the routing block and nothing else. Act 5 recomputes the MAC after a payload flip and it still matches.',
    ],
    [
      'Nothing on the path notices, and the payload arrives destroyed',
      true,
      'Correct. No mix authenticates the payload, so it is forwarded normally through every remaining hop — and because LIONESS is a wide-block permutation, one flipped bit randomises all 1024 bytes.',
    ],
    [
      'Nothing notices, and the payload arrives with that one bit flipped',
      false,
      'That is what a STREAM CIPHER over the payload would do, and it is exactly the tagging channel Sphinx’s payload construction exists to close. Act 5 measures the difference.',
    ],
  ];
  for (const [label, ok, why] of answers) {
    const b = el('button', { type: 'button', class: 'check-opt', text: label });
    b.addEventListener('click', () => {
      clear(result);
      result.append(ok ? pill('ok', 'Correct') : pill('bad', 'Not quite'), ' ', why);
    });
    opts.append(b);
  }
  return disclosure('Check yourself: an attacker flips one bit of the payload. What happens?', [
    opts,
    result,
  ]);
}

function parameters(): HTMLElement {
  return disclosure('The parameters this lab runs at', [
    el('p', {
      text: `κ = ${KAPPA} bytes (the security parameter: MAC length, routing-id length, filler quantum). r = ${MAX_HOPS} (maximum path length). Routing block β = (2r + 1)·κ bytes. Header = ${HEADER_LEN} bytes. Payload = ${PAYLOAD_LEN} bytes. Whole packet = ${PACKET_LEN} bytes, for every path length.`,
    }),
    el('p', {
      text:
        'The group is ristretto255 (RFC 9496), not X25519, and that is a correctness requirement rather than a preference. Sphinx does not do one Diffie-Hellman; it does a chain, built by re-blinding the same group element at each hop, and that only works if exponents compose as plain integers modulo the group order. RFC 7748’s X25519 clamps its scalar before every multiplication — clearing the three low bits, clearing bit 255, setting bit 254 — so X25519(b, X25519(a, G)) is not X25519(b·a, G): the second clamp lands on b itself, not on the product, and the product of two clamped scalars is not clamped. Iterated blinding therefore does not compose, and a Sphinx built on the clamped API silently derives a different secret at the mix than the sender predicted. Curve25519’s cofactor of 8 adds a second problem: small-order elements are a live degeneracy the format would have to handle. ristretto255 removes both — prime order, no cofactor, canonical validated encodings, and scalar multiplication that is just scalar multiplication.',
    }),
    el('p', {
      text:
        'Two documented departures from the paper’s letter, neither of which changes the construction: derived keys are full-width 32 bytes for ChaCha20, HMAC and LIONESS (a 16-byte ChaCha20 key does not exist), with only the header MAC truncated to κ; and the final routing block carries a fixed κ-byte END marker instead of the paper’s variable-length destination encoding, because this lab has one recipient.',
    }),
  ]);
}

function tabs(): HTMLElement {
  const nav = el('nav', { class: 'tabs-nav', 'aria-label': 'Acts' });
  const tablist = el('div', { class: 'tablist', role: 'tablist', 'aria-label': 'Acts' });
  const main = el('main');
  const rendered = new Set<string>();

  const panels = ACTS.map((act) => {
    const panel = el('div', {
      class: 'tab-panel',
      id: `panel-${act.id}`,
      role: 'tabpanel',
      'aria-labelledby': `tab-${act.id}`,
      tabindex: '0',
      hidden: true,
    });
    main.append(panel);
    return panel;
  });

  const buttons = ACTS.map((act, i) => {
    const b = el('button', {
      type: 'button',
      class: 'tab-btn',
      id: `tab-${act.id}`,
      role: 'tab',
      'aria-controls': `panel-${act.id}`,
      'aria-selected': i === 0 ? 'true' : 'false',
      tabindex: i === 0 ? '0' : '-1',
    });
    b.append(el('span', { class: 'tab-num', 'aria-hidden': 'true', text: act.num }), act.label);
    b.addEventListener('click', () => select(i));
    b.addEventListener('keydown', (e) => {
      const k = (e as KeyboardEvent).key;
      if (k !== 'ArrowLeft' && k !== 'ArrowRight' && k !== 'Home' && k !== 'End') return;
      e.preventDefault();
      const next =
        k === 'Home' ? 0 : k === 'End' ? ACTS.length - 1 : (i + (k === 'ArrowRight' ? 1 : ACTS.length - 1)) % ACTS.length;
      select(next);
      buttons[next]!.focus();
    });
    tablist.append(b);
    return b;
  });

  function select(index: number): void {
    ACTS.forEach((act, i) => {
      const on = i === index;
      buttons[i]!.setAttribute('aria-selected', on ? 'true' : 'false');
      buttons[i]!.tabIndex = on ? 0 : -1;
      panels[i]!.hidden = !on;
      if (on && !rendered.has(act.id)) {
        rendered.add(act.id);
        act.render(panels[i]!);
      }
    });
  }

  nav.append(tablist);
  select(0);
  const frag = document.createDocumentFragment();
  frag.append(nav, main);
  return el('div', {}, [frag]);
}

function footer(): HTMLElement {
  return el('footer', { class: 'scripture-footer' }, [
    el('p', {
      text:
        'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    }),
  ]);
}

function mount(): void {
  const app = document.getElementById('app');
  if (!app) throw new Error('#app is missing');
  clear(app);
  app.append(hero(), intro(), scopeNotice(), learnerCheck(), tabs(), negativeClaim(), failureReference(), parameters(), footer());
}

mount();
