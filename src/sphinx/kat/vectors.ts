/**
 * Known-answer vectors, copied from the specifications.
 *
 * Sphinx itself has no published test vectors -- the 2009 paper gives a
 * construction and a proof, not a KAT file, and no later RFC standardised it.
 * So the KATs here pin every PRIMITIVE the construction is assembled from, at
 * the exact call sites this lab uses, and the Sphinx layer above them is
 * covered by round-trip, failure-path and statistical property tests.
 *
 * Saying which is which matters: a lab that called its own round-trip a "KAT"
 * would be claiming external validation it does not have.
 *
 * Sources:
 *   RFC 9496 App. A.1  -- ristretto255 encodings of small base-point multiples
 *   RFC 9496 App. A.3  -- encodings that MUST be rejected
 *   RFC 8439 App. A.1  -- ChaCha20 block function
 *   RFC 8439 §2.4.2    -- ChaCha20 encryption
 *   RFC 4231 §4        -- HMAC-SHA-256
 *   FIPS 180-4         -- SHA-256 / SHA-512 short messages
 */

/** RFC 9496 Appendix A.1 — encodings of kB for k = 0 .. 15. */
export const RISTRETTO_BASE_MULTIPLES: string[] = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76',
  '6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919',
  '94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259',
  'da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57',
  'e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e',
  'f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403',
  '44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d',
  '903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c',
  '02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031',
  '20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f',
  'bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42',
  'e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460',
  'aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f',
  '46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e',
  'e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e',
];

/**
 * RFC 9496 Appendix A.3 — a subset of the encodings a conforming decoder MUST
 * reject. This lab decodes `alpha` on every hop, so these are the exact
 * strings an adversary would try.
 */
export const RISTRETTO_BAD_ENCODINGS: { hex: string; why: string }[] = [
  { hex: '00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', why: 'non-canonical field encoding' },
  { hex: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', why: 'non-canonical field encoding' },
  { hex: 'f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', why: 'non-canonical field encoding' },
  { hex: 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', why: 'non-canonical field encoding' },
  { hex: '0100000000000000000000000000000000000000000000000000000000000000', why: 'negative field element' },
  { hex: '01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', why: 'negative field element' },
];

/** RFC 8439 Appendix A.1, Test Vector #1 — key 0, nonce 0, counter 0. */
export const CHACHA20_BLOCK0_ZERO =
  '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7' +
  'da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586';

/** RFC 8439 Appendix A.1, Test Vector #2 — same key/nonce, counter 1. */
export const CHACHA20_BLOCK1_ZERO =
  '9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed' +
  '29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f';

/** RFC 8439 §2.4.2 — the "sunscreen" encryption vector (counter starts at 1). */
export const CHACHA20_SUNSCREEN = {
  keyHex: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  nonceHex: '000000000000004a00000000',
  plaintext:
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  ciphertextHex:
    '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b' +
    'f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8' +
    '07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736' +
    '5af90bbf74a35be6b40b8eedf2785e42874d',
};

/** RFC 4231 §4 — HMAC-SHA-256 test cases. `truncate` marks case 5. */
export const HMAC_SHA256_VECTORS: {
  name: string;
  keyHex: string;
  dataHex?: string;
  dataText?: string;
  macHex: string;
  truncate?: number;
}[] = [
  {
    name: 'RFC 4231 case 1',
    keyHex: '0b'.repeat(20),
    dataHex: '4869205468657265',
    macHex: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
  },
  {
    name: 'RFC 4231 case 2',
    keyHex: '4a656665',
    dataHex: '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
    macHex: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  },
  {
    name: 'RFC 4231 case 3',
    keyHex: 'aa'.repeat(20),
    dataHex: 'dd'.repeat(50),
    macHex: '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
  },
  {
    name: 'RFC 4231 case 4',
    keyHex: '0102030405060708090a0b0c0d0e0f10111213141516171819',
    dataHex: 'cd'.repeat(50),
    macHex: '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
  },
  {
    // 128-bit truncation — the same truncation this lab applies to gamma.
    name: 'RFC 4231 case 5 (truncated to 128 bits)',
    keyHex: '0c'.repeat(20),
    dataHex: '546573742057697468205472756e636174696f6e',
    macHex: 'a3b6167473100ee06e0c796c2955552b',
    truncate: 16,
  },
  {
    name: 'RFC 4231 case 6',
    keyHex: 'aa'.repeat(131),
    dataText: 'Test Using Larger Than Block-Size Key - Hash Key First',
    macHex: '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
  },
  {
    name: 'RFC 4231 case 7',
    keyHex: 'aa'.repeat(131),
    dataText:
      'This is a test using a larger than block-size key and a larger than block-size data. ' +
      'The key needs to be hashed before being used by the HMAC algorithm.',
    macHex: '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
  },
];

/** FIPS 180-4 short-message digests. */
export const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
export const SHA512_ABC =
  'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
  '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';
