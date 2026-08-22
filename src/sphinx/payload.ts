/**
 * The payload: fixed-length framing under the wide-block permutation.
 *
 * Plaintext layout, exactly PAYLOAD_LEN bytes:
 *
 *   [ 0 .. kappa )        zero marker -- the recipient's corruption check
 *   [ kappa .. kappa+2 )  message length, big-endian uint16
 *   [ kappa+2 .. )        the message, then zero padding to the fixed length
 *
 * The padding is what makes every packet the same size no matter how long the
 * message is, which is as much a part of the unlinkability story as the
 * header's filler. The marker is the paper's structural check; see
 * `lioness.ts` for why a structural check is not authentication.
 */
import { concat, equalBytes, zeros } from './bytes';
import { END_MARKER, KAPPA, PAYLOAD_LEN } from './params';

/** Longest message a packet can carry: 1024 - 16 - 2 = 1006 bytes. */
export const MAX_MESSAGE_LEN = PAYLOAD_LEN - KAPPA - 2;

export function padMessage(message: Uint8Array): Uint8Array {
  if (message.length > MAX_MESSAGE_LEN) {
    throw new RangeError(
      `message is ${message.length} bytes; a packet carries at most ${MAX_MESSAGE_LEN}`
    );
  }
  const lengthField = new Uint8Array([message.length >>> 8, message.length & 0xff]);
  return concat(
    zeros(KAPPA),
    lengthField,
    message,
    zeros(MAX_MESSAGE_LEN - message.length)
  );
}

export interface UnpackResult {
  /** True only if the kappa-byte marker survived and the length field is sane. */
  intact: boolean;
  /** The recovered message, or null when the marker check failed. */
  message: Uint8Array | null;
  /** Why it failed, for the UI. */
  detail: string;
}

export function unpadMessage(plain: Uint8Array): UnpackResult {
  if (plain.length !== PAYLOAD_LEN) {
    return { intact: false, message: null, detail: `payload is ${plain.length} bytes, expected ${PAYLOAD_LEN}` };
  }
  if (!equalBytes(plain.subarray(0, KAPPA), END_MARKER)) {
    return {
      intact: false,
      message: null,
      detail:
        'the leading zero marker is gone, so the wide-block permutation did not unwind to the plaintext the sender wrote',
    };
  }
  const length = (plain[KAPPA]! << 8) | plain[KAPPA + 1]!;
  if (length > MAX_MESSAGE_LEN) {
    return { intact: false, message: null, detail: `length field says ${length}, which cannot fit` };
  }
  return {
    intact: true,
    message: plain.subarray(KAPPA + 2, KAPPA + 2 + length),
    detail: 'the zero marker survived and the length field parses',
  };
}
