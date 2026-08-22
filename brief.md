6. Sphinx Mix

crypto-lab-sphinx-mix · PRIVACY

Thesis. Bitwise unlinkability is a property of the packet format. Anonymity is a property of the traffic. The first does not produce the second.

Construction. Sphinx (Danezis & Goldberg, IEEE S&P 2009; eprint 2008/475). Fixed-size header regardless of path length, per-hop shared secret with the group element blinded at each hop, filler generation so header length never varies.

Header and payload are protected by different mechanisms, and Revision 2 got this wrong. The per-hop HMAC covers the header — the routing block — not the payload. The payload is protected by a wide-block pseudorandom permutation (LIONESS), so any modification randomizes the whole payload rather than producing a targeted change. Revision 2 specified "stream cipher over the payload," which is malleable bit-for-bit and would have built a lab vulnerable to precisely the tagging attack Sphinx's payload construction exists to defeat. Build LIONESS properly from a stream cipher and a hash.

Free cross-link: LIONESS is an unbalanced four-round Feistel network. Sphinx's payload protection and §10's subject are the same construction doing different jobs — say so in both READMEs.

Use ristretto255, and do not call it X25519. RFC 7748's X25519 clamps scalars and operates on Montgomery x-coordinates in a fixed format; iterated blinding does not compose as plain scalar multiplication under clamping, which is exactly the algebra Sphinx's per-hop blinding chain requires. ristretto255 gives a prime-order group with no cofactor or clamping complications and is already vendored for DKG Gate, PSI Gate, Frozen Heart, Bulletproofs, and Icy DVRF. MATH.md states the group, the blinding-factor derivation, and why the clamped API is the wrong instantiation — that last paragraph is worth writing because the mistake is common in the wild.

Acts
Build a path. Three mixes. Watch the header construct in reverse, innermost layer first.
Peel. Each mix derives its shared secret, checks its header HMAC, decrypts its routing block, blinds the group element, forwards. Show input versus output as Hamming distance and a byte-distribution panel, not as "zero shared bytes" — two pseudorandom strings coincide at roughly one position in 256 by chance, so a zero-shared-bytes assertion is both false as a claim and flaky as a test. Bitwise unlinkability means no correlation an adversary can exploit, not literal byte inequality.
Fixed length. Add a fourth and fifth hop. The header stays exactly the same size. Show the filler that makes this work.
Replay. Resend a packet. The mix's seen-tag set catches it. REPLAY_DETECTED.
Tagging — two different failures, and the difference is the lesson.
Mutate a header byte: the next hop's HMAC fails and the packet dies there. HMAC_FAIL. Hop-by-hop integrity, checked by the network.
Mutate a payload byte: no mix detects anything. The packet is forwarded normally through every remaining hop and the payload arrives irrecoverable, because the wide-block permutation propagated the change across all of it. Call this anti-tagging, not integrity — LIONESS is a PRP, not an authentication code. It converts targeted modification into unpredictable corruption; it does not by itself hand the recipient an authenticity verdict. Explicit authentication requires recognizable payload structure or a separate end-to-end authenticator, and the lab should show which one it chose.
Put those side by side in one panel. Header integrity is verified hop by hop and protects the network; payload protection is anti-tagging only and leaves authenticity to the recipient's own layer. Payload tagging has a long history as a subtle correlation channel in mix designs — that belongs in THREAT-MODEL.md rather than glossed.
Timing correlation — the climax. Run the mixnet with one sender. Input and output correlate trivially; the anonymity set is 1 and every packet is traceable end to end despite every cryptographic check passing. Add senders, add cover traffic, switch from immediate forwarding to a pool mix with delays, and watch an anonymity-set entropy meter climb.

Negative claim (NEG-1). Sphinx provides bitwise unlinkability between a mix's input and output, hidden path position, and tagging resistance. It does not provide anonymity. That comes from mixing and traffic conditions the packet format cannot supply. Evidence: act 6's single-sender fixture, all-green and fully traced.

Failure codes. HMAC_FAIL · REPLAY_DETECTED · PATH_TOO_LONG · MALFORMED_HEADER · UNKNOWN_ROUTING_BLOCK

Repo description.

Browser demo: a Sphinx packet peeled across three mixes with real per-hop blinding and a header that never changes length — then one sender on a quiet network gets traced end to end with every cryptographic check green.