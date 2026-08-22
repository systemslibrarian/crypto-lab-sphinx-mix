# Sphinx Mix

**Mix-network packet format · Danezis & Goldberg, IEEE S&P 2009**

Peel a real Sphinx packet across three mixes — per-hop ristretto255 blinding, a header
that never changes length, a LIONESS-protected payload — then watch one sender on a quiet
network get traced end to end with every cryptographic check green.

---

## What It Is

A browser demo of the **Sphinx mix-network packet format**, built to teach one distinction
that most explanations of anonymity systems blur:

> **Bitwise unlinkability is a property of the packet format. Anonymity is a property of
> the traffic. The first does not produce the second.**

**The primitives, exactly.**

| Role | Primitive | Specification |
|---|---|---|
| Group, per-hop blinding chain | **ristretto255** | RFC 9496 (December 2023) |
| Header MAC `μ` | **HMAC-SHA-256**, truncated to κ = 16 bytes | RFC 2104; RFC 4231 test vectors; FIPS 180-4 |
| Routing-block PRG `ρ`, filler | **ChaCha20** keystream | RFC 8439 (June 2018) |
| Payload PRP `π` | **LIONESS**, from ChaCha20 + HMAC-SHA-256 | Anderson & Biham, *Two Practical and Provably Secure Block Ciphers: BEAR and LION*, FSE 1996 |
| Blinding-factor derivation `h_b` | **SHA-512**, reduced mod ℓ | FIPS 180-4 |
| Packet format | **Sphinx** | Danezis & Goldberg, IEEE S&P 2009; [ePrint 2008/475](https://eprint.iacr.org/2008/475) |

The Sphinx paper is a construction and a security proof, not a standards document; there is
no RFC for it and no published KAT file. It is nevertheless the live packet format behind
**Nym**, **Katzenpost** and the **Loopix** design, all of which specify their own
instantiation of the same construction.

**Why ristretto255, and why not X25519.** Sphinx does not perform one Diffie–Hellman; it
performs a chain, built by re-blinding the same group element at each hop:

```
alpha_0 = g^x            s_0 = y_0^x            b_0 = h_b(alpha_0, s_0)
alpha_1 = alpha_0^{b_0}  s_1 = y_1^{x b_0}      b_1 = h_b(alpha_1, s_1)
alpha_2 = alpha_1^{b_1}  s_2 = y_2^{x b_0 b_1}
```

Each mix recomputes its own `s_i = alpha_i^{x_i}`; the sender predicts all of them from `x`
alone. That only works if exponents compose as plain integers modulo the group order.
**RFC 7748's X25519 clamps its scalar before every multiplication** — clearing the three
low bits, clearing bit 255, setting bit 254 — so `X25519(b, X25519(a, G))` is *not*
`X25519(b·a, G)`: the second clamp lands on `b` itself, not on the product, and the product
of two clamped scalars is not clamped. Iterated blinding therefore does not compose, and a
Sphinx built on the clamped API silently derives a different secret at the mix than the
sender predicted. Curve25519's cofactor of 8 adds a second problem: small-order elements
become a live degeneracy the format has to handle rather than a case that cannot arise.
ristretto255 removes both — prime order, no cofactor, canonical validated encodings, and
scalar multiplication that is just scalar multiplication. The in-page **parameters**
disclosure carries this same derivation for readers who never open the README.

**Why LIONESS and not a stream cipher over the payload.** Under a stream cipher a payload is
malleable bit for bit: flip bit 37 of the ciphertext and bit 37 of the plaintext flips,
everything else survives. An adversary controlling the first and last hop can therefore *tag*
a packet — mark it on the way in, recognise the mark on the way out, link the two
observations. LIONESS is an **unbalanced four-round Feistel network** whose rounds alternate
a stream cipher keyed by the narrow left half with a keyed hash of the wide right half:

```
R ^= S(L ^ k1)      L ^= H(k2, R)      R ^= S(L ^ k3)      L ^= H(k4, R)
```

One flipped ciphertext bit randomises all 1024 bytes. The change is still invisible to the
mixes — but it is no longer a *signal*, because the adversary cannot recognise its own mark
on the far side. `src/sphinx/lioness.test.ts` measures both behaviours side by side.

**Parameters.** κ = 16 bytes, r = 5 (maximum path length), routing block β = (2r+1)·κ = 176
bytes, header = 224 bytes, payload = 1024 bytes, whole packet = 1248 bytes — for *every*
path length from one hop to five.

**Honest scoping.** **Not production crypto — a teaching demo.**

* **Real:** the ristretto255 group operations, the per-hop blinding chain, the HMAC-SHA-256
  header MACs, the ChaCha20 filler and routing-block keystream, the LIONESS permutation,
  every failure check, and every packet built or peeled anywhere on the page. Everything runs
  in the browser; no key material leaves the tab and there is no backend to send it to.
* **Simulated:** the clock, and only the clock. Exhibit 6 schedules arrivals in integer
  rounds rather than wall-clock time, because a browser tab cannot demonstrate a mixnet in
  real seconds. The packets in it are real Sphinx packets and every cryptographic check
  really runs.
* **Not present:** constant-time execution (JavaScript offers no timing guarantees at all),
  a directory authority, key rotation, epoch handling, packet-size negotiation, or any
  persistence — mix keys are regenerated on every page load.

**What this does NOT prove.** Sphinx provides bitwise unlinkability between a mix's input and
its output, hidden path position, and tagging resistance. **It does not provide anonymity.**
That comes from mixing and from traffic conditions the packet format cannot supply. The
evidence is exhibit 6's first preset — one sender, immediate forwarding, every check green,
anonymity-set entropy exactly 0 bits — and it is asserted as a test, not merely stated:
`e2e/claims.spec.ts`.

---

## Exhibits

1. **Build a path** — Pick a message; watch the header construct in reverse, innermost layer
   first, because that is the order the construction runs in. Each step shows the routing
   block for one hop, its MAC, its filler, and the length staying put.
2. **Peel** — Step a packet through three mixes one hop at a time. Each hop derives its
   shared secret, checks the header MAC, unwraps the routing block, blinds the group element
   and forwards. The measurement panel shows input against output as a **Hamming distance**
   and a **byte-distribution histogram**, with the coincidentally-matching bytes highlighted —
   not as "zero shared bytes", which is false and which a disclosure explains at length.
3. **Fixed length** — Drive the path from one hop to five. The header, the payload and the
   whole packet are byte-identical in size at every setting. A proportional bar shows how much
   of the innermost routing block is real instructions and how much is filler, and the filler
   grows by exactly as much as the instructions shrink.
4. **Replay** — Send a packet, watch it arrive; send the same bytes again and watch the first
   mix refuse them with `REPLAY_DETECTED`. A control clears every mix's memory so you can see
   what a stateless mix would allow. The disclosure explains why the tag is over the shared
   secret rather than over the packet bytes.
5. **Tagging** — Flip one byte of the header and one byte of the payload, side by side.
   The header flip dies at the next hop with `HMAC_FAIL`; the payload flip is caught by
   nobody, forwarded normally through every remaining hop, and arrives irrecoverable. A
   comparison table puts the two outcomes against an untouched control.
6. **Timing correlation** — Run the whole mixnet. Start with one sender and immediate
   forwarding: every check passes and an observer holding no keys traces every packet from end
   to end. Add senders, add cover traffic, switch to a pool mix, and watch the anonymity-set
   entropy meter climb toward its ceiling of log₂(senders).

Plus, on the page itself: a plain-language "what is a mix network" intro, a break-it-yourself
learner check, the five failure codes with their explanations, and the parameters the lab runs
at.

---

## When to Use It

**Use a Sphinx-style mix format when** you need to hide *who is talking to whom* from an
adversary who can see the network, and you can accept latency measured in seconds to minutes.
Its distinguishing properties are a header whose size is independent of path length, a
per-hop shared secret nobody else can derive, replay resistance, and payload tagging
resistance — all in a single compact format.

**Do NOT use it when:**

* **You need low latency.** Anonymity here comes from *delay and batching*. Exhibit 6 shows
  what a zero-delay mixnet is worth: nothing. Any deployment that forwards immediately to keep
  latency down has spent the packet format and bought no anonymity with it.
* **There is only one plausible sender.** A mix format cannot manufacture an anonymity set.
  A single-user deployment is fully traceable however correct the cryptography is.
* **You need end-to-end authenticity from the format.** Sphinx deliberately does not provide
  it — see *What Can Go Wrong*.
* **You want to build it from `X25519`.** The clamped API does not compose under iterated
  blinding. Use a prime-order group.
* **You want to copy this code.** This is a teaching implementation: not constant-time, no
  key rotation, no directory, no epochs.

---

## Live Demo

**<https://systemslibrarian.github.io/crypto-lab-sphinx-mix/>**

Everything runs client-side. You can build a packet from a message you type, step it hop by
hop and read the shared secret each mix derives, drive the path length from one to five and
watch the header refuse to change size, replay a packet into a `REPLAY_DETECTED`, flip
individual bytes of the header and the payload and compare what happens, and run a mixnet
under six different traffic configurations while an entropy meter reports what a passive
observer learns.

---

## What Can Go Wrong

The threat model, and the places this construction has historically been got wrong.

**The adversary exhibit 6 models.** A global passive observer: it sees every packet on every
link with a timestamp, including the sender-to-first-mix and last-mix-onward links, and it
knows each mix's flushing rule. It holds no mix private key, so — because Sphinx works — it
cannot link a mix's input bytes to its output bytes. Timing and counting are all it has, and
they are usually enough.

**Payload tagging is a subtle correlation channel with a long history in mix design.** It is
the reason the payload gets a wide-block permutation rather than a stream cipher, and it is
the specific mistake this lab was nearly built with. A stream-cipher payload lets an adversary
who controls the entry and exit points flip a chosen bit on the way in and look for the
corresponding flip on the way out: a low-noise, targeted link between two observations, costing
one bit. Because the mixes do not authenticate the payload, nothing on the path stops it. The
answer is not to add a MAC — a MAC the mixes could check would have to be re-computable at every
hop, which hands the mixes a linking oracle of their own — but to make the mark unrecognisable.
LIONESS does that. Exhibit 5 lets you perform the attack and watch it fail to produce a signal.

**Anti-tagging is not integrity, and this lab says which one it chose.** LIONESS is a PRP, not
an authentication code. It converts targeted modification into unpredictable corruption; it
hands nobody an authenticity verdict. This lab uses the paper's route to a corruption check —
**recognisable payload structure**: the plaintext begins with κ zero bytes and the recipient
checks for them, so corruption survives with probability 2⁻¹²⁸. That detects damage. It does not
authenticate a sender, and it offers nothing against an adversary who can predict or influence
the plaintext structure. Explicit end-to-end authenticity requires a separate authenticator the
sender and recipient share, under a key no mix holds, and Sphinx leaves that to the layer above
on purpose: a mix format that demanded it would have to know something about the recipient.

**Check ordering is load-bearing.** A mix verifies the header MAC *before* recording the replay
tag. Reversed, an adversary could take a legitimate packet in flight, corrupt one byte of the
routing block and race it to the mix; the forged packet would poison the seen-set and the real
packet would be dropped behind it as a replay. That is a one-byte denial of service against any
packet an adversary can see. `src/sphinx/failures.test.ts` has a test named for exactly that.

**The replay set grows without bound.** A mix that remembers every tag forever eventually
cannot. A mix that expires tags re-opens the replay window for anything older than the cutoff.
Production designs bound it with an epoch: mix keys rotate, and tags older than the current
epoch are discarded along with the key that could have derived them. This lab does not implement
epochs, and says so in-page.

**A threshold mix does not flush a partial pool.** Raise the threshold above the traffic and
real packets sit in pools indefinitely. Exhibit 6 reports the stranded count rather than
quietly draining the pools to make the delivery figures look better; that trade is the actual
cost of the strategy.

**What exhibit 6's entropy figure does not model,** stated because pretending otherwise would be
the exact dishonesty this lab is about: long-term intersection and statistical disclosure attacks
across many rounds; active attacks such as n−1 flooding, where an adversary fills a pool with its
own packets so the one real packet is the only unknown; fingerprinting outside the mixnet; and any
adversary able to inject or delay. It is a **single-round lower bound** on what a passive observer
learns. A real adversary learns at least this much. Cover traffic's measurable effect in this model
is on delivery and latency rather than on the entropy of an already-delivered packet; its other
job — defeating long-term intersection attacks by making a sender's output rate independent of
whether it has anything to say — needs a multi-round model this one cannot show.

**"Zero shared bytes" is not the unlinkability claim.** Two independent pseudorandom 176-byte
strings agree at about 0.69 byte positions on average, and see at least one coincidence roughly
half the time. A demo asserting zero shared bytes would teach something false, and a test
asserting it would fail every other run. The claim that holds is that the bit-flip count is
Binomial(8n, ½) — no correlation an adversary can exploit — and that is what is measured and
tested.

---

## Real-World Usage

Sphinx is not a historical curiosity; it is the packet format currently in production use for
mixnets.

* **Nym** — the Nym mixnet uses a Sphinx-derived packet format over a Loopix-style stratified
  topology with Poisson mixing and cover traffic.
* **Katzenpost** — a mixnet framework whose wire format is Sphinx, with an explicit
  specification of the instantiation (group, KDFs, payload PRP) that the paper leaves open.
* **Loopix** (Piotrowska, Hayes, Elahi, Meiser, Danezis, USENIX Security 2017) — the design that
  pairs Sphinx packets with Poisson mixing and loop cover traffic, and the source of the
  argument that the packet format alone is not the anonymity story.
* **Lightning Network onion routing** — BOLT #4 specifies a Sphinx-derived format for HTLC
  routing, with a 1300-byte routing packet and per-hop shared secrets derived exactly this way.
  It is the widest deployment of the construction by packet count.

LIONESS itself shows up wherever a wide-block PRP is needed on a budget: Sphinx payloads, and
historically in disk-encryption proposals where a sector must behave as a single block.

---

## How to Run Locally

```bash
npm install
npm run dev          # http://localhost:5173/crypto-lab-sphinx-mix/

npm test             # unit, failure-path and spec-KAT suites (Vitest)
npm run build        # typechecks src/ and e2e/, then builds

npx playwright install chromium   # NOT --with-deps
npm run test:a11y    # axe WCAG 2.1 A/AA gate against the production build
npm run test:claims  # the page-tells-the-truth suite
```

`npm run test:a11y` and `npm run test:claims` both build first and serve the result on port
4646, so what they judge is what ships.

---

## Related Demos

* **Feistel Forge** — DES: a *balanced* sixteen-round Feistel network. **LIONESS, the wide-block
  permutation protecting this lab's payload, is an unbalanced four-round Feistel network: the same
  construction doing a different job.** Feistel Forge's first exhibit shows why the round function
  `F` need not be invertible and the structure is still reversible — which is exactly the property
  LIONESS relies on to use a stream cipher and a hash as its rounds. Read them together.
* **Format Ward** — format-preserving encryption (SP 800-38G), the fleet's other Feistel, where
  the round structure is the whole point.
* **Blind Relay** — Oblivious HTTP. The other way to split metadata: two non-colluding parties,
  no mixing, low latency. The complement to this lab's trade.
* **ORAM Vault** and **Patron Shield** — hiding access patterns rather than routes.
* **Ring Sign**, **Credential Veil**, **Traitor Trace** — anonymity and unlinkability at the
  signature and credential layer rather than the network layer.
* **ChaCha20 Stream** — the stream cipher this lab uses for `ρ` and inside LIONESS.
* **Curve Lens** and **Point Arithmetic** — the elliptic-curve groundwork under ristretto255.

---

## Build & Verify

**70 unit tests across 7 files, all passing**, plus **14 claims tests** and **2 accessibility
tests** driving the production build in Chromium.

| Suite | File | Covers |
|---|---|---|
| Spec KATs | `src/sphinx/kat/kat.test.ts` (12 tests) | RFC 9496 App. A.1 — all 16 ristretto255 base-point multiples; RFC 9496 App. A.3 — 6 encodings a conforming decoder must reject; RFC 8439 App. A.1 blocks 0 and 1 and §2.4.2 encryption; RFC 4231 — all 7 HMAC-SHA-256 cases including the 128-bit truncation this lab's `γ` uses; FIPS 180-4 SHA-256/512 |
| End-to-end | `src/sphinx/roundtrip.test.ts` | round-trip at every path length 1–5; the header identical in size at all of them; the identifier reaching only the exit; every mix deriving the secret the sender predicted; empty and maximum-length messages |
| Failure paths | `src/sphinx/failures.test.ts` | all five failure codes reached through the real path, plus the MAC-before-replay ordering that stops a one-byte denial of service |
| Unlinkability | `src/sphinx/unlinkability.test.ts` | Hamming distance within 6σ of `8n/2` for header, group element and payload; a χ² test on the output byte distribution; coincidental byte matches asserted as *expected*, not as a defect |
| LIONESS | `src/sphinx/lioness.test.ts` | permutation in both directions; one flipped bit randomising the whole 1024-byte block, at five positions; the stream-cipher contrast measured at exactly one bit |
| Tagging | `src/sphinx/tagging.test.ts` | header flip caught at the next hop; payload flip caught by nobody and arriving destroyed; `γ` recomputed identically after a payload flip, which is the asymmetry made measurable |
| Traffic | `src/sphinx/traffic.test.ts` | the entropy arithmetic; NEG-1 as an executable fixture; the log₂(senders) ceiling; a bigger pool never lowering entropy; cover traffic filling pools that would otherwise strand packets |
| Claims | `e2e/claims.spec.ts` (14 tests) | NEG-1 against the live page; the Hamming distance re-derived *in the test* from the two hex dumps on screen; the filler length re-derived from the paper's formula; parts-sum-to-whole on header/payload/packet and instructions/filler; every failure path named on screen; retirement and no-op guards; the `[hidden]` cascade probe |
| Accessibility | `e2e/a11y.spec.ts` (2 tests) | WCAG 2.1 A/AA, zero violations and zero unexplained `incomplete` results, over ~40 driven states at 1280px and 380px |

Sphinx has no published test vectors, so the KATs pin every **primitive** the construction is
assembled from, at the exact call sites this lab uses — through `mulBase`, `rho` and
`truncatedMac`, not through the library directly, because a KAT that bypassed this lab's own
wrappers would still pass if the library were wired up wrong. The Sphinx layer above them is
covered by round-trip, failure-path and statistical property tests. Calling those KATs would be
claiming external validation this construction does not have.

The accessibility gate is not the retired fleet template: it sets `reducedMotion` through
`emulateMedia` and asserts from inside the page that it took effect, injects nothing, opens every
disclosure through its own `<summary>`, drives every panel through its real tab button, and
asserts axe's `incomplete` bucket alongside `violations` — with an arithmetic composite-aware
contrast walk, a per-side non-text-contrast oracle, a reflow check and a keyboard-reachability
check for scrolling regions, none of which axe has a rule for.

---

## Performance

Every figure is real cryptography in the browser, single-threaded.

| Operation | Cost |
|---|---|
| Build a 3-hop packet | 6 ristretto255 scalar multiplications + 3 LIONESS passes over 1024 bytes |
| Process one hop | 2 scalar multiplications (shared secret, blinding) + 1 LIONESS pass |
| Exhibit 6, largest configuration | 48 real packets over 3 hops each — roughly 1 second, built in chunks that yield to the event loop so the page keeps painting |

The dominant cost is the scalar multiplication, at roughly 2 ms per operation. Exhibit 6's
controls are capped at 8 senders × 2 messages × 2 cover packets deliberately: the ceiling is a
responsiveness budget, not a limit of the construction.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
