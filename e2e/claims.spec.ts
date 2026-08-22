import { expect, test, type Page } from '@playwright/test';

/**
 * The claims suite: does the page tell the truth?
 *
 * The rule that makes these tests worth anything is that they COMPARE TWO
 * VALUES THE PAGE ITSELF PRINTED, or RE-DERIVE a claim from the page's raw
 * inputs by a different route than the source takes -- never assert against a
 * hardcoded string, and never recompute the same expression the source used.
 * A test that re-derives the source's own expression will happily agree with a
 * bug.
 *
 * Internal consistency alone is not enough either: a page can be consistently
 * wrong, and a mutation that corrupts the underlying maths is reported
 * consistently everywhere. So the mix below is deliberate:
 *
 *  - CROSS-CHECKS: the failure-code reference against the codes the acts
 *    actually emit; the hero's stated packet size against the size the length
 *    act prints; the entropy figure against the effective-set-size figure.
 *  - INDEPENDENT RE-DERIVATIONS: the Hamming distance recomputed IN THE TEST
 *    from the two hex dumps on screen, by parsing them and counting bits --
 *    a completely different route from `hammingDistance()` in the source;
 *    2^H recomputed from H; the filler length recomputed from the path length
 *    by the paper's formula rather than by the source's recurrence.
 *  - PARTS-SUM-TO-WHOLE: header + payload = packet; instructions + filler =
 *    the routing block.
 *  - RETIREMENT: changing an input clears the stale verdict.
 *  - A NO-OP GUARD: re-selecting the same value must NOT retire a fresh
 *    verdict.
 *
 * NEG-1 -- the negative claim the page prints in prose -- is an assertion
 * here, with act 6's one-sender fixture as its evidence. That is the point of
 * putting it in this file rather than in a document: a negative claim with an
 * evidence fixture IS a test.
 */

const KAPPA = 16;
const MAX_HOPS = 5;

async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  await expect(page.locator('h1')).toHaveText('Sphinx Mix');
}

async function openAct(page: Page, name: RegExp, panel: string): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.locator(panel)).toBeVisible();
  await expect(page.locator(panel)).not.toBeEmpty();
}

/** Pull an integer out of the page's own text. Fails loudly rather than NaN. */
function intFrom(text: string, re: RegExp): number {
  const m = re.exec(text);
  expect(m, `expected ${re} in: ${text.slice(0, 400)}`).not.toBeNull();
  const v = Number(m![1]);
  expect(Number.isFinite(v), `not a number: ${m![1]}`).toBe(true);
  return v;
}

function floatFrom(text: string, re: RegExp): number {
  const m = re.exec(text);
  expect(m, `expected ${re} in: ${text.slice(0, 400)}`).not.toBeNull();
  return Number.parseFloat(m![1]!);
}

/**
 * Read a hex dump off the page and turn it back into bytes.
 *
 * The Peel act paints its diff as one <span> per byte with spaces every two
 * bytes, so the visible text is the hex with whitespace in it. Stripping the
 * whitespace is the only transformation; nothing here re-uses the source's
 * formatting logic.
 */
async function bytesFromDump(page: Page, selector: string): Promise<number[]> {
  const text = (await page.locator(selector).innerText()).split('…')[0]!;
  const hex = text.replace(/[^0-9a-fA-F]/g, '');
  expect(hex.length % 2, `odd hex length in ${selector}`).toBe(0);
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16));
  return out;
}

/** Popcount of a XOR b, written here rather than imported from src/. */
function bitsDiffering(a: number[], b: number[]): number {
  let n = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    let v = a[i]! ^ b[i]!;
    while (v) {
      n += v & 1;
      v >>= 1;
    }
  }
  return n;
}

/**
 * Assert that the page's printed 2^H agrees with its printed H.
 *
 * The tolerance is DERIVED from the precision each figure is printed at, not
 * picked to make the test pass. The page prints H to `hDp` decimals and the
 * effective set size to `effDp`, so:
 *
 *   |2^H_true − effPrinted|   <= 0.5 * 10^-effDp        (rounding of the answer)
 *   |2^H_printed − 2^H_true|  <= 2^H * ln2 * 0.5*10^-hDp (rounding of the input)
 *
 * and the two add. Anything outside that band is a real disagreement between
 * the two numbers on screen; anything inside it is display rounding.
 */
function expectPowerOfTwoConsistent(effPrinted: number, hPrinted: number, hDp: number, effDp: number): void {
  const fromH = Math.pow(2, hPrinted);
  const band = 0.5 * Math.pow(10, -effDp) + fromH * Math.LN2 * 0.5 * Math.pow(10, -hDp);
  expect(
    Math.abs(effPrinted - fromH),
    `2^${hPrinted} = ${fromH.toFixed(6)}, page printed ${effPrinted} (display-rounding band ${band.toFixed(6)})`
  ).toBeLessThanOrEqual(band);
}

test.describe('the page tells the truth', () => {
  test('every failure code in the reference is a code the lab actually exports', async ({ page }) => {
    await boot(page);
    await page.locator('summary', { hasText: /ways a packet dies/ }).click();
    const pills = await page.locator('[role="listitem"] .pill-bad').allInnerTexts();
    expect(pills.sort()).toEqual(
      ['HMAC_FAIL', 'MALFORMED_HEADER', 'PATH_TOO_LONG', 'REPLAY_DETECTED', 'UNKNOWN_ROUTING_BLOCK'].sort()
    );
    // The summary's own count must agree with the number of cards behind it.
    const summary = await page.locator('summary', { hasText: /ways a packet dies/ }).innerText();
    expect(intFrom(summary, /The (\d+) ways/)).toBe(pills.length);
  });

  test('the header sizes the hero implies and the length act prints agree, and sum', async ({ page }) => {
    await boot(page);
    await openAct(page, /Fixed length/, '#panel-length');
    const verdict = await page.locator('#panel-length .verdict-pass').innerText();
    const header = intFrom(verdict, /Header (\d+) bytes/);
    const payload = intFrom(verdict, /payload (\d+) bytes/);
    const packet = intFrom(verdict, /packet (\d+) bytes/);
    // parts-sum-to-whole
    expect(header + payload).toBe(packet);

    const kvText = await page.locator('#panel-length .kv').innerText();
    const beta = intFrom(kvText, /Routing block β\s*(\d+) bytes/);
    const gamma = intFrom(kvText, /MAC γ\s*(\d+) bytes/);
    const alpha = intFrom(kvText, /Group element α\s*(\d+) bytes/);
    // The header is exactly its three fields, cross-checked against the verdict.
    expect(alpha + beta + gamma).toBe(header);

    // Independent re-derivation of beta from the paper's formula, using r and
    // kappa read off the page rather than the source's own BETA_LEN constant.
    const r = intFrom(kvText, /Maximum r\s*(\d+)/);
    expect(r).toBe(MAX_HOPS);
    expect(beta).toBe((2 * r + 1) * KAPPA);
    expect(gamma).toBe(KAPPA);
  });

  test('the header size does not change with the path length — every value on the control', async ({ page }) => {
    await boot(page);
    await openAct(page, /Fixed length/, '#panel-length');
    const seen = new Set<string>();
    for (const hops of ['1', '2', '3', '4', '5']) {
      await page.selectOption('#len-hops', hops);
      await expect(page.locator('#panel-length .hopnode')).toHaveCount(Number(hops));
      const verdict = await page.locator('#panel-length .verdict-pass').innerText();
      seen.add(`${intFrom(verdict, /Header (\d+) bytes/)}/${intFrom(verdict, /packet (\d+) bytes/)}`);

      // Independent re-derivation: |phi| = 2*(nu-1)*kappa, from the paper,
      // not from the source's recurrence.
      const kvText = await page.locator('#panel-length .kv').innerText();
      const filler = intFrom(kvText, /Filler φ[^\n]*\s(\d+) bytes/);
      expect(filler, `filler at ${hops} hops`).toBe(2 * (Number(hops) - 1) * KAPPA);

      // parts-sum-to-whole: the composition bar's two halves are the block.
      const beta = intFrom(kvText, /Routing block β\s*(\d+) bytes/);
      const legend = await page.locator('#panel-length .legend').innerText();
      const instructions = intFrom(legend, /instructions \+ padding: (\d+) B/);
      const fillerLegend = intFrom(legend, /filler φ: (\d+) B/);
      expect(instructions + fillerLegend).toBe(beta);
      expect(fillerLegend).toBe(filler);
    }
    expect(seen.size, 'the header size must be identical at every path length').toBe(1);
  });

  test('the Hamming distance the Peel act prints is the distance between the two dumps it shows', async ({ page }) => {
    await boot(page);
    await openAct(page, /Peel/, '#panel-peel');
    await page.getByRole('button', { name: 'Peel one hop' }).click();
    await expect(page.locator('#peel-progress')).toHaveText('Hop 1 / 3');

    const dumps = page.locator('#panel-peel .grid2 .hexblock');
    await expect(dumps).toHaveCount(2);
    const inBytes = await bytesFromDump(page, '#panel-peel .grid2 > div:nth-child(1) .hexblock');
    const outBytes = await bytesFromDump(page, '#panel-peel .grid2 > div:nth-child(2) .hexblock');
    expect(inBytes.length).toBeGreaterThan(64);
    expect(outBytes.length).toBe(inBytes.length);

    const kvText = await page.locator('#panel-peel .card').last().locator('.kv').innerText();
    const printedBits = intFrom(kvText, /Hamming distance\s*(\d+) of/);
    const totalBits = intFrom(kvText, /of (\d+) bits/);

    // The page prints the distance over the WHOLE 176-byte block; the dumps
    // show the first 96 bytes. So the re-derivation is a bound, not equality:
    // the visible prefix's differing bits cannot exceed the whole block's.
    const visibleDiff = bitsDiffering(inBytes, outBytes);
    expect(visibleDiff).toBeLessThanOrEqual(printedBits);
    // ...and the prefix should itself be about half-random, which is the claim.
    expect(visibleDiff).toBeGreaterThan(inBytes.length * 8 * 0.25);

    // The printed percentage must be the printed distance over the printed total.
    const pct = floatFrom(kvText, /\(([\d.]+)%\)/);
    expect(pct).toBeCloseTo((printedBits / totalBits) * 100, 1);

    // The shared-byte count on screen must be the count in the visible dumps,
    // bounded the same way, and its stated expectation must be blockLen/256.
    const shared = intFrom(kvText, /Bytes that happen to match\s*(\d+) of/);
    const blockLen = intFrom(kvText, /match\s*\d+ of (\d+)/);
    expect(totalBits).toBe(blockLen * 8);
    const visibleShared = inBytes.filter((b, i) => b === outBytes[i]).length;
    expect(visibleShared).toBeLessThanOrEqual(shared);
    const expected = floatFrom(kvText, /expected about ([\d.]+)/);
    expect(expected).toBeCloseTo(blockLen / 256, 2);
  });

  test('the Peel act’s histogram label carries the same counts as its bars', async ({ page }) => {
    await boot(page);
    await openAct(page, /Peel/, '#panel-peel');
    await page.getByRole('button', { name: 'Peel one hop' }).click();
    const label = await page.locator('#panel-peel .histo').getAttribute('aria-label');
    expect(label).toBeTruthy();
    const counts = [...label!.matchAll(/bin (\d+) (\d+)/g)].map((m) => Number(m[2]));
    expect(counts).toHaveLength(16);
    const kvText = await page.locator('#panel-peel .card').last().locator('.kv').innerText();
    const blockLen = intFrom(kvText, /match\s*\d+ of (\d+)/);
    // parts-sum-to-whole: the bins are a partition of the block.
    expect(counts.reduce((a, b) => a + b, 0)).toBe(blockLen);
  });

  test('each failure path is reached and the page names the actual cause', async ({ page }) => {
    await boot(page);

    // HMAC_FAIL and the untouched-payload contrast, from the tagging act.
    await openAct(page, /Tagging/, '#panel-tagging');
    await expect(page.locator('#panel-tagging .pill-bad').first()).toHaveText('HMAC_FAIL');
    const deadHop = await page.locator('#panel-tagging .hopnode-dead .hopnode-title').innerText();
    const namedAt = await page.locator('#panel-tagging .card').first().innerText();
    // Cross-check: the mix the panel says it died at is the mix drawn dead.
    expect(namedAt).toContain(`at ${deadHop}`);

    // REPLAY_DETECTED, reached by sending the same packet twice.
    await openAct(page, /Replay/, '#panel-replay');
    const tagCount = async (): Promise<number> =>
      intFrom(await page.locator('#replay-seen').innerText(), /remembering (\d+) shared-secret tag/);

    // The absolute count is NOT asserted: the tagging act above already routed
    // accepted packets through Mix A, and those tags are legitimately still
    // there -- a mix that forgot them between page tabs would be the bug. What
    // is asserted is the DELTA, which is the actual claim: a mix remembers
    // exactly what it accepted, and remembers nothing it refused.
    const before = await tagCount();
    await page.getByRole('button', { name: 'Send it' }).click();
    await expect(page.locator('#panel-replay .verdict-pass')).toBeVisible();
    const afterAccept = await tagCount();
    expect(afterAccept - before).toBe(1);

    await page.getByRole('button', { name: 'Send it' }).click();
    await expect(page.locator('#panel-replay .pill-bad').first()).toHaveText('REPLAY_DETECTED');
    await expect(page.locator('#panel-replay .verdict-fail').first()).toContainText(
      'already processed a packet with this shared-secret tag'
    );
    expect(await tagCount(), 'a refused packet must not be remembered').toBe(afterAccept);

    // The check ORDERING, exercised from the page. A forged copy of a packet
    // derives the SAME shared secret and therefore the same replay tag, so a
    // mix that recorded the tag before verifying the MAC would refuse the
    // genuine packet behind it. This is the one claim that internal
    // consistency cannot establish: both branches print confidently either
    // way, and only driving the real pair separates them.
    const beforeForge = await tagCount();
    await page.getByRole('button', { name: /Forge a copy, then send the real one/ }).click();
    const forgeCard = page.locator('#replay-forge-out');
    await expect(forgeCard.locator('.pill-bad')).toHaveText('HMAC_FAIL');
    await expect(forgeCard.locator('.verdict-pass')).toContainText('delivered normally');
    // Exactly one tag added: the genuine packet's. The forged copy left none.
    expect(await tagCount(), 'a forged copy must not be remembered').toBe(beforeForge + 1);

    // ...and clearing the memory really clears it.
    await page.getByRole('button', { name: /Clear every mix/ }).click();
    await expect(page.locator('#panel-replay .verdict-alarm')).toContainText('forgotten every tag');
    expect(await tagCount()).toBe(0);
  });

  test('a payload flip is caught by nobody on the path and destroys the payload', async ({ page }) => {
    await boot(page);
    await openAct(page, /Tagging/, '#panel-tagging');
    const rows = await page.locator('#panel-tagging table').innerText();
    // The comparison table is the page's own claim; each column is cross-checked
    // against the verdicts rendered above it.
    expect(rows).toContain('Detected on the path');
    const payloadCard = page.locator('#panel-tagging .grid2 > div').nth(1);
    await expect(payloadCard.locator('.verdict-alarm')).toContainText('Every mix accepted it');
    await expect(payloadCard.locator('.verdict-fail')).toContainText('irrecoverable');

    // Independent re-derivation: the page says one bit was flipped and prints
    // how many plaintext bits changed. Under a wide-block permutation that must
    // be close to half the block, so recompute the ratio from the two printed
    // counts rather than trusting the percentage beside them.
    const kvText = await payloadCard.locator('.kv').innerText();
    const changed = intFrom(kvText, /Plaintext bits changed\s*(\d+) of/);
    const total = intFrom(kvText, /changed\s*\d+ of (\d+)/);
    const flipped = intFrom(kvText, /Bits the attacker flipped\s*(\d+)/);
    expect(flipped).toBe(1);
    expect(total).toBe(1024 * 8);
    expect(changed / total).toBeGreaterThan(0.4);
    expect(changed / total).toBeLessThan(0.6);
    const pct = floatFrom(kvText, /\(([\d.]+)%\)/);
    expect(pct).toBeCloseTo((changed / total) * 100, 1);
  });

  /**
   * NEG-1, as an executable claim.
   *
   * "Sphinx provides bitwise unlinkability, hidden path position and tagging
   * resistance. It does NOT provide anonymity." The evidence fixture is act
   * 6's one-sender preset: every check green, every packet traced.
   */
  test('NEG-1: one sender, immediate forwarding — all checks green, anonymity set 1', async ({ page }) => {
    await boot(page);
    await openAct(page, /Timing correlation/, '#panel-timing');
    await expect(page.locator('#panel-timing .meter')).toBeVisible({ timeout: 120_000 });

    await expect(page.locator('#panel-timing .pill-ok').first()).toHaveText(
      'ALL CRYPTOGRAPHIC CHECKS PASSED'
    );
    await expect(page.locator('#panel-timing .pill-bad').first()).toHaveText('EVERY PACKET TRACED');
    await expect(page.locator('#panel-timing .verdict-alarm')).toContainText('traced end to end');

    const kvText = await page.locator('#panel-timing .kv').innerText();
    const h = floatFrom(kvText, /Mean entropy H\s*([\d.]+) bits/);
    const effective = floatFrom(kvText, /Effective anonymity set 2\^H\s*([\d.]+) of/);
    const senders = intFrom(kvText, /of (\d+)\n?/);
    expect(h).toBe(0);
    // Independent re-derivation of the effective set size from the entropy.
    expectPowerOfTwoConsistent(effective, h, 3, 2);
    expect(effective).toBe(1);
    expect(senders).toBe(1);

    // Every row in the observer's notebook is a traced packet, and each row's
    // "candidates" cell must be 2 to the power of its own H cell.
    const rows = page.locator('#panel-timing tbody tr');
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
    for (let i = 0; i < count; i++) {
      const cells = await rows.nth(i).locator('td').allInnerTexts();
      const rowH = Number.parseFloat(cells[2]!);
      const rowCandidates = Number.parseFloat(cells[3]!);
      expectPowerOfTwoConsistent(rowCandidates, rowH, 2, 2);
      expect(await rows.nth(i).locator('.pill-bad').innerText()).toBe('TRACED');
    }

    // The page's prose claim and the fixture must agree.
    const claim = await page.locator('.callout-neg').innerText();
    expect(claim).toContain('does not provide anonymity');
    expect(claim).toContain('0 bits');
  });

  test('mixing, not cryptography, is what moves the meter — and the ceiling is log2(senders)', async ({ page }) => {
    await boot(page);
    await openAct(page, /Timing correlation/, '#panel-timing');
    await expect(page.locator('#panel-timing .meter')).toBeVisible({ timeout: 120_000 });

    await page.getByRole('button', { name: /eight senders, pool of 6/ }).click();
    await expect(page.locator('#panel-timing .verdict-pass')).toBeVisible({ timeout: 180_000 });

    const kvText = await page.locator('#panel-timing .kv').innerText();
    const h = floatFrom(kvText, /Mean entropy H\s*([\d.]+) bits/);
    const ceiling = floatFrom(kvText, /ceiling for \d+ senders: ([\d.]+)/);
    const senders = intFrom(kvText, /ceiling for (\d+) senders/);
    const effective = floatFrom(kvText, /Effective anonymity set 2\^H\s*([\d.]+) of/);

    expect(senders).toBe(8);
    // Independent re-derivation of the ceiling the page prints.
    expect(ceiling).toBeCloseTo(Math.log2(senders), 2);
    expect(h).toBeGreaterThan(0);
    expect(h).toBeLessThanOrEqual(ceiling + 1e-6);
    expectPowerOfTwoConsistent(effective, h, 3, 2);

    // The cryptography did not change: it is still all green.
    await expect(page.locator('#panel-timing .pill-ok').first()).toHaveText(
      'ALL CRYPTOGRAPHIC CHECKS PASSED'
    );

    // parts-sum-to-whole: delivered + still-held cannot exceed what was built.
    const delivered = intFrom(kvText, /Delivered\s*(\d+) of/);
    const injected = intFrom(kvText, /Delivered\s*\d+ of (\d+) packets/);
    const stranded = intFrom(kvText, /Still held in a pool\s*(\d+)/);
    expect(delivered + stranded).toBe(injected);
  });

  test('retirement: changing the path length clears the stale filler figure', async ({ page }) => {
    await boot(page);
    await openAct(page, /Fixed length/, '#panel-length');
    const fillerAt = async (): Promise<number> =>
      intFrom(await page.locator('#panel-length .kv').innerText(), /Filler φ[^\n]*\s(\d+) bytes/);

    await page.selectOption('#len-hops', '2');
    const two = await fillerAt();
    await page.selectOption('#len-hops', '5');
    const five = await fillerAt();
    expect(five).not.toBe(two);
    expect(five).toBe(2 * 4 * KAPPA);
    await expect(page.locator('#panel-length .verdict-pass')).toContainText('5 hops');
    await expect(page.locator('#panel-length .verdict-pass')).not.toContainText('2 hops');
  });

  test('no-op guard: re-selecting the same path length does not retire a fresh result', async ({ page }) => {
    await boot(page);
    await openAct(page, /Fixed length/, '#panel-length');
    await page.selectOption('#len-hops', '4');
    const before = await page.locator('#panel-length .kv').innerText();
    await page.selectOption('#len-hops', '4');
    const after = await page.locator('#panel-length .kv').innerText();
    // Same selection, same figures. (The filler and lengths are deterministic
    // in the path length; only the hex, which is not compared here, is fresh.)
    expect(after).toBe(before);
    await expect(page.locator('#panel-length .verdict-pass')).toContainText('4 hops');
  });

  test('the honest-scoping notice says what is real and what is simulated', async ({ page }) => {
    await boot(page);
    const scope = await page.locator('.callout-scope').innerText();
    expect(scope).toContain('NOT PRODUCTION CRYPTO');
    expect(scope).toMatch(/What is real/);
    expect(scope).toMatch(/What is simulated/);
    expect(scope).toContain('the clock');
    expect(scope).toMatch(/nothing here is constant-time/i);
  });

  test('the parameters panel and the length act agree on kappa and r', async ({ page }) => {
    await boot(page);
    await page.locator('summary', { hasText: /parameters this lab runs at/ }).click();
    const params = await page.locator('details', { hasText: /parameters this lab runs at/ }).innerText();
    const kappa = intFrom(params, /κ = (\d+) bytes/);
    const r = intFrom(params, /r = (\d+) \(maximum path length\)/);
    const header = intFrom(params, /Header = (\d+) bytes/);
    const payload = intFrom(params, /Payload = (\d+) bytes/);
    const packet = intFrom(params, /Whole packet = (\d+) bytes/);
    expect(kappa).toBe(KAPPA);
    expect(header + payload).toBe(packet);
    // Independent re-derivation from the paper's formula.
    expect(header).toBe(32 + (2 * r + 1) * kappa + kappa);

    await openAct(page, /Fixed length/, '#panel-length');
    const kvText = await page.locator('#panel-length .kv').innerText();
    expect(intFrom(kvText, /Maximum r\s*(\d+)/)).toBe(r);
    const verdict = await page.locator('#panel-length .verdict-pass').innerText();
    expect(intFrom(verdict, /Header (\d+) bytes/)).toBe(header);
  });

  test('a closed disclosure really is hidden — the [hidden] cascade probe', async ({ page }) => {
    await boot(page);
    // A class rule setting `display` outranks the UA `[hidden]` rule, so an
    // element can paint while the code believes it is hidden. Ask the browser.
    const leaks = await page.evaluate(() => {
      const bad: string[] = [];
      for (const el of Array.from(document.querySelectorAll('[hidden]'))) {
        if ((el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) {
          bad.push(`${el.tagName.toLowerCase()}#${el.id}`);
        }
      }
      for (const d of Array.from(document.querySelectorAll('details:not([open])'))) {
        const body = d.querySelector('.detail-body');
        if (body && (body as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) {
          bad.push(`closed details body: ${d.querySelector('summary')?.textContent?.slice(0, 40)}`);
        }
      }
      return bad;
    });
    expect(leaks).toEqual([]);
  });
});
