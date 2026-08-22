/**
 * Small DOM helpers. No framework; every element the page builds goes through
 * here so accessible names, roles and live regions are set in one place rather
 * than remembered at forty call sites.
 */
import { toHex } from '../sphinx/bytes';

type Attrs = Record<string, string | number | boolean | undefined>;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: (Node | string | null | undefined)[] = []
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === 'class') node.className = String(v);
    else if (k === 'text') node.textContent = String(v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** A key/value list. Values are monospaced; keys are the visible labels. */
export function kv(pairs: [string, string | Node][]): HTMLElement {
  const dl = el('dl', { class: 'kv' });
  for (const [k, v] of pairs) {
    dl.append(el('dt', { text: k }));
    dl.append(el('dd', {}, [typeof v === 'string' ? v : v]));
  }
  return dl;
}

/**
 * A hex dump, optionally diffed against a reference.
 *
 * Bytes that DIFFER are tinted with the accent; bytes that happen to MATCH are
 * underlined and tinted red, because those are the interesting ones -- the
 * coincidental collisions that make "zero shared bytes" the wrong claim. Colour
 * is never the only channel: the matches also carry an underline, and the count
 * is printed as text beside the dump.
 */
export function hexDump(
  bytes: Uint8Array,
  options: { against?: Uint8Array; limit?: number; label?: string } = {}
): HTMLElement {
  const limit = options.limit ?? 96;
  const shown = bytes.subarray(0, limit);
  const box = el('p', { class: 'hexblock' });
  if (options.against) {
    const ref = options.against;
    for (let i = 0; i < shown.length; i++) {
      const same = ref[i] === shown[i];
      box.append(
        el('span', {
          class: same ? 'hx-same' : 'hx-diff',
          text: toHex(shown.subarray(i, i + 1)),
        })
      );
      if (i % 2 === 1) box.append(document.createTextNode(' '));
    }
  } else {
    box.textContent = toHex(shown).replace(/(.{4})/g, '$1 ').trim();
  }
  if (bytes.length > limit) box.append(document.createTextNode(` … (${bytes.length} bytes total)`));
  if (!options.label) return box;
  // The label goes on a wrapper with an explicit `role`, never on the <p>.
  // `aria-label` is PROHIBITED on a role-less element, and axe files that
  // finding under `incomplete` rather than `violations` -- so a gate that only
  // reads `violations` never sees it and the label is silently discarded by
  // every screen reader. `group` is the right role here: a named block of
  // content that should not appear in a page summary.
  return el('div', { class: 'hexwrap', role: 'group', 'aria-label': options.label }, [box]);
}

export type VerdictTone = 'pass' | 'fail' | 'alarm' | 'info';

const VERDICT_ICON: Record<VerdictTone, string> = {
  pass: 'OK',
  fail: 'X',
  alarm: '!',
  info: 'i',
};

/**
 * A verdict line. Icon + text + colour, never colour alone (WCAG 1.4.1).
 *
 * The tone tracks SYSTEM INTEGRITY, not the raw return value: a packet that
 * every mix accepted and that an observer then traced end to end is an ALARM,
 * not a success, however green the cryptography was.
 */
export function verdict(tone: VerdictTone, children: (Node | string)[]): HTMLElement {
  return el('div', { class: `verdict verdict-${tone}` }, [
    el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: VERDICT_ICON[tone] }),
    el('span', {}, children),
  ]);
}

export function pill(kind: 'ok' | 'bad' | 'neutral', text: string): HTMLElement {
  const cls = kind === 'neutral' ? 'pill' : `pill pill-${kind}`;
  return el('span', { class: cls, text });
}

/** A `<details>` disclosure. Ships SHUT; that is the state readers arrive at. */
export function disclosure(
  summaryText: string,
  body: (Node | string)[],
  cls = ''
): HTMLDetailsElement {
  const d = el('details', { class: cls });
  d.append(el('summary', { text: summaryText }));
  d.append(el('div', { class: 'detail-body' }, body));
  return d;
}

/** A labelled range input with a live numeric readout. */
export function slider(
  id: string,
  label: string,
  opts: { min: number; max: number; value: number; step?: number; suffix?: string },
  onChange: (v: number) => void
): { field: HTMLElement; input: HTMLInputElement; setValue: (v: number) => void } {
  const out = el('output', { class: 'slider-value', for: id });
  const input = el('input', {
    type: 'range',
    id,
    min: opts.min,
    max: opts.max,
    step: opts.step ?? 1,
    value: opts.value,
  }) as HTMLInputElement;
  const render = (v: number): void => {
    out.textContent = `${v}${opts.suffix ?? ''}`;
  };
  render(opts.value);
  input.addEventListener('input', () => {
    render(Number(input.value));
    onChange(Number(input.value));
  });
  const field = el('div', { class: 'field' }, [
    el('label', { for: id, text: label }),
    el('div', { style: 'display:flex;align-items:center;gap:.5rem' }, [input, out]),
  ]);
  return { field, input, setValue: (v) => { input.value = String(v); render(v); } };
}

export function button(
  text: string,
  onClick: () => void,
  opts: { class?: string; id?: string } = {}
): HTMLButtonElement {
  const b = el('button', {
    type: 'button',
    class: opts.class ?? 'btn',
    id: opts.id,
    text,
  }) as HTMLButtonElement;
  b.addEventListener('click', onClick);
  return b;
}

/**
 * A live region for asynchronous output.
 *
 * `role="status"` + `aria-live="polite"` so a screen reader is told when a
 * result lands, without interrupting whatever it is currently reading.
 */
export function liveRegion(id: string, cls = ''): HTMLElement {
  return el('div', { id, class: cls, role: 'status', 'aria-live': 'polite' });
}

/** A histogram of 16 byte-value bins, with the uniform expectation drawn in. */
export function histogram(counts: number[], label: string): HTMLElement {
  const max = Math.max(1, ...counts);
  const wrap = el('div', {
    class: 'histo',
    role: 'img',
    'aria-label': `${label}: ${counts.map((c, i) => `bin ${i} ${c}`).join(', ')}`,
  });
  for (const c of counts) {
    wrap.append(el('div', { class: 'histo-bar', style: `height:${Math.max(2, (c / max) * 100)}%` }));
  }
  return wrap;
}
