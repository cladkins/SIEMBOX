/**
 * The CT collector's certificate source: crt.sh first, Cert Spotter when
 * crt.sh can't answer for a name.
 *
 * Fallback decision, per name:
 *  - crt.sh answers: its answer is used.
 *  - crt.sh fails transiently (timeouts, 5xx, 429, non-JSON — it is often
 *    overloaded): Cert Spotter is asked. crt.sh is not asked again for the rest
 *    of the run (one source per run, and no 45-second timeout per lookalike);
 *    the next run starts with crt.sh again.
 *  - crt.sh refuses the name as too large to monitor (CtTooLargeError: it
 *    reached crt.sh's result limit, an arbitrary subset): Cert Spotter is asked
 *    too, because it pages through everything in a fixed order and so can
 *    answer completely for a name crt.sh can't. If it can't either, the
 *    refusal stays a CtTooLargeError (a warning that rules out one name, as
 *    before), now naming both reasons.
 *  - crt.sh refuses us otherwise (e.g. HTTP 403 from a proxy): no fallback;
 *    the collector fails as before, so a blocked egress is not papered over.
 * When Cert Spotter fails too, the failure is transient whatever its kind
 * (crt.sh will be back): the baseline is kept and the run is retried, with
 * both reasons in the message (e.g. Cert Spotter's rate limit and its advice
 * to add an API key).
 */
import {
  CtClient,
  CtTooLargeError,
  asAnswer,
  type CertificateSource,
  type CtAnswer,
} from './ct';
import { CertSpotterClient } from './certSpotter';
import { CollectorError, errorMessage } from './types';
import { getCertSpotterApiKey } from '../settings';

const withoutRetryTail = (message: string) => message.replace(/;\s*will retry\.?$/i, '');

export class FallbackCertificateSource implements CertificateSource {
  /** Why crt.sh failed transiently earlier in this run; null while it hasn't. */
  private primaryDown: string | null = null;

  constructor(
    private readonly primary: CertificateSource,
    private readonly fallback: CertificateSource
  ) {}

  async certificatesFor(name: string): Promise<CtAnswer> {
    let reason: string;
    let tooLarge: CtTooLargeError | null = null;
    if (this.primaryDown !== null) {
      reason = this.primaryDown;
    } else {
      try {
        return { ...asAnswer(await this.primary.certificatesFor(name)), source: 'crtsh' };
      } catch (err) {
        if (err instanceof CtTooLargeError) {
          tooLarge = err;
          reason = err.message;
        } else if (err instanceof CollectorError && err.transient) {
          reason = err.message;
          this.primaryDown = err.message;
        } else {
          throw err;
        }
      }
    }
    try {
      const answer = asAnswer(await this.fallback.certificatesFor(name));
      return { certs: answer.certs, source: 'certspotter', fallbackReason: reason };
    } catch (err) {
      const fallbackMessage = withoutRetryTail(errorMessage(err));
      if (tooLarge) {
        throw new CtTooLargeError(`${tooLarge.message}; Cert Spotter: ${fallbackMessage}`);
      }
      throw new CollectorError(
        `${withoutRetryTail(reason)}; Cert Spotter fallback failed too: ${fallbackMessage}; will retry`,
        true
      );
    }
  }
}

/** crt.sh with the Cert Spotter fallback, using the saved Cert Spotter API key if there is one. */
export async function createDefaultCtSource(): Promise<CertificateSource> {
  const apiKey = await getCertSpotterApiKey();
  return new FallbackCertificateSource(new CtClient(), new CertSpotterClient({ apiKey }));
}
