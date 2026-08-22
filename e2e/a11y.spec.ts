import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where act
 * 1 has built a real packet and parked its stepper at zero while the other
 * five acts are hidden and UNRENDERED; the shared skip link focused; the
 * learner check and both page-level disclosures opened through their
 * summaries, answered wrong and then right; the header builder stepped to its
 * end and back; the Peel act's measurement panel with its per-byte hex diff
 * and byte histogram, at each of three hops including the END-marker exit;
 * the path length driven to five and down to one, which is the only state that
 * renders the no-filler branch; a packet delivered and then replayed into a
 * REPLAY_DETECTED refusal, and the alarm state after every mix's memory is
 * cleared; the tagging act's dead hop beside its all-green-but-corrupted
 * counterpart, at two different byte offsets; act 6 in both of its presets --
 * the all-green fully-traced ALARM and the ambiguous pool-mix state -- each
 * built from real Sphinx packets; three hover states; and three focus rings.
 * Every one of those states is scanned, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page (the retired
 * template gate's `addStyleTag` motion kill bypassed the stylesheet's own
 * reduced-motion block, so the rendering reduced-motion readers get was never
 * the one scanned), why no panel is revealed from script (that gate stripped
 * every `[hidden]` and opened every `<details>` by JS before its only scan),
 * why the lab's defaults are asserted rather than assumed, and why
 * `violations` is not the whole oracle.
 */

test('no WCAG A/AA violations', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await boot(page, 'dark');
  await driveAllStates(page, 'dark');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});

test('no WCAG A/AA violations at 380px', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await page.setViewportSize(NARROW);
  await boot(page, 'dark');
  await driveAllStates(page, 'dark @380px');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});
