/**
 * LIONESS -- the wide-block pseudorandom permutation that protects the payload.
 *
 * Ross Anderson and Eli Biham, "Two Practical and Provably Secure Block
 * Ciphers: BEAR and LION", FSE 1996; LIONESS is the four-round variant.
 *
 * WHAT IT IS. An UNBALANCED FOUR-ROUND FEISTEL NETWORK. The block is split
 * into a narrow left half L (32 bytes, the width of the hash) and a wide right
 * half R (everything else -- 992 bytes here). The rounds alternate between a
 * stream cipher keyed by L and a keyed hash of R:
 *
 *     R ^= S(L ^ k1)          stream cipher, keyed by the left half
 *     L ^= H(k2, R)           keyed hash of the right half
 *     R ^= S(L ^ k3)
 *     L ^= H(k4, R)
 *
 * Decryption is the same four lines read upwards. This is the same shape as
 * any Feistel cipher -- the round function need not be invertible because the
 * XOR structure supplies the inverse -- with the halves deliberately lopsided
 * so one hash call and one stream call cover a kilobyte.
 *
 * WHY SPHINX USES A PRP AND NOT A STREAM CIPHER. Under a stream cipher a
 * payload is malleable bit for bit: flip bit 37 of the ciphertext and bit 37
 * of the plaintext flips, everything else survives. An adversary who controls
 * the first and last hop can therefore TAG a packet -- flip a chosen bit on
 * the way in, look for the corresponding flip on the way out, and link the two
 * observations. That is a targeted, low-noise correlation channel, and it is
 * the attack Sphinx's payload construction exists to defeat. Under a wide-block
 * PRP the same flip randomises all 1024 bytes: the change is still
 * undetectable to the mixes, but it is no longer a SIGNAL, because the
 * adversary cannot recognise its own mark on the far side.
 *
 * WHAT THIS DOES *NOT* GIVE YOU, stated plainly because the distinction is the
 * lesson: a PRP is not a MAC. LIONESS converts targeted modification into
 * unpredictable corruption. It hands nobody an authenticity verdict. This lab
 * chooses the paper's route to a corruption check -- RECOGNISABLE PAYLOAD
 * STRUCTURE: the plaintext begins with kappa zero bytes, so a recipient who
 * unwinds the permutation and does not find them knows the payload was
 * mangled. Under a PRP, corruption survives that check with probability
 * 2^-128. It is a corruption detector and nothing more: it says the bytes did
 * not arrive intact, never who sent them. End-to-end authenticity needs a
 * separate authenticator the sender and recipient share, which Sphinx
 * deliberately leaves to the layer above.
 */
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { xor, xorInto } from './bytes';
import { LIONESS_LEFT_LEN } from './params';
import { rho } from './prg';

const enc = new TextEncoder();

/**
 * The four round keys, from one master key.
 *
 * k1 and k3 are XORed into the 32-byte left half before it keys the stream
 * cipher; k2 and k4 key the HMAC. All four are independent, so recovering one
 * round key says nothing about the others.
 */
export interface LionessKeys {
  k1: Uint8Array;
  k2: Uint8Array;
  k3: Uint8Array;
  k4: Uint8Array;
}

export function lionessKeys(master: Uint8Array): LionessKeys {
  const sub = (i: number): Uint8Array => hmac(sha256, master, enc.encode(`sphinx-mix/v1/lioness/k${i}`));
  return { k1: sub(1), k2: sub(2), k3: sub(3), k4: sub(4) };
}

function split(block: Uint8Array): { L: Uint8Array; R: Uint8Array } {
  if (block.length <= LIONESS_LEFT_LEN) {
    throw new RangeError(
      `LIONESS needs a block wider than its ${LIONESS_LEFT_LEN}-byte left half, got ${block.length}`
    );
  }
  const copy = Uint8Array.from(block);
  return { L: copy.subarray(0, LIONESS_LEFT_LEN), R: copy.subarray(LIONESS_LEFT_LEN) };
}

function join(L: Uint8Array, R: Uint8Array): Uint8Array {
  const out = new Uint8Array(L.length + R.length);
  out.set(L, 0);
  out.set(R, L.length);
  return out;
}

/** pi(k, .) -- the forward permutation. The sender applies it once per hop. */
export function lionessEncrypt(master: Uint8Array, block: Uint8Array): Uint8Array {
  const { k1, k2, k3, k4 } = lionessKeys(master);
  const { L, R } = split(block);
  xorInto(R, rho(xor(L, k1), R.length));
  xorInto(L, hmac(sha256, k2, R));
  xorInto(R, rho(xor(L, k3), R.length));
  xorInto(L, hmac(sha256, k4, R));
  return join(L, R);
}

/** pi^-1(k, .) -- the inverse. Each mix applies it once as it forwards. */
export function lionessDecrypt(master: Uint8Array, block: Uint8Array): Uint8Array {
  const { k1, k2, k3, k4 } = lionessKeys(master);
  const { L, R } = split(block);
  xorInto(L, hmac(sha256, k4, R));
  xorInto(R, rho(xor(L, k3), R.length));
  xorInto(L, hmac(sha256, k2, R));
  xorInto(R, rho(xor(L, k1), R.length));
  return join(L, R);
}
