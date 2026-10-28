/**
 * The only xAI call in this repo.
 *
 * What Grok decides: nothing about the case. This function returns JSON that
 * passed `validate`, or a typed failure.
 * What code decides: whether those facts are usable, and whether any fix runs.
 * On a failure, do not fill in a value. Do not act on the call.
 *
 * Temperature is 0. The timeout is 15 seconds. The API key is `XAI_API_KEY`.
 * The model is `XAI_MODEL`, or grok-4.7 when that variable is unset.
 * This function does not log the key, the prompt, or the reply.
 */

/** A JSON Schema object. We send it as given. `validate` is the check we trust. */
export type JsonSchema = Record<string, unknown>;

/**
 * Why there are no facts. Every reason means the same thing to a caller:
 * do not act on this call.
 */
export type ExtractFailureReason =
  | 'timeout'
  | 'http_error'
  | 'bad_json'
  | 'schema_mismatch'
  | 'no_key';

export type ExtractResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: ExtractFailureReason };

/** OpenAI-compatible chat completions endpoint. No SDK. */
const CHAT_COMPLETIONS_URL = 'https://api.x.ai/v1/chat/completions';

/** Used when XAI_MODEL is unset or blank. grok-4.7 is the current text model. */
const DEFAULT_MODEL = 'grok-4.7';

/** Hard stop. A slow reply is a failure, not a value we invent. */
const TIMEOUT_MS = 15_000;

export async function extract<T>(opts: {
  system: string;
  input: string;
  schemaName: string;
  schema: JsonSchema;
  /** Returns true only when `value` is a complete T. Anything else is a mismatch. */
  validate: (value: unknown) => value is T;
}): Promise<ExtractResult<T>> {
  const apiKey = process.env.XAI_API_KEY?.trim();
  if (!apiKey) {
    return { ok: false, reason: 'no_key' };
  }

  const model = process.env.XAI_MODEL?.trim() || DEFAULT_MODEL;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(CHAT_COMPLETIONS_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        temperature: 0,
        messages: [
          { role: 'system', content: opts.system },
          { role: 'user', content: opts.input },
        ],
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: opts.schemaName,
            schema: opts.schema,
            strict: true,
          },
        },
      }),
      signal: controller.signal,
    });
  } catch (err) {
    if (isAbortError(err)) {
      return { ok: false, reason: 'timeout' };
    }
    return { ok: false, reason: 'http_error' };
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    return { ok: false, reason: 'http_error' };
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return { ok: false, reason: 'bad_json' };
  }

  const content = readMessageContent(payload);
  if (content === undefined) {
    return { ok: false, reason: 'bad_json' };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return { ok: false, reason: 'bad_json' };
  }

  try {
    if (!opts.validate(parsed)) {
      return { ok: false, reason: 'schema_mismatch' };
    }
  } catch {
    return { ok: false, reason: 'schema_mismatch' };
  }

  return { ok: true, value: parsed };
}

function readMessageContent(payload: unknown): string | undefined {
  if (typeof payload !== 'object' || payload === null) {
    return undefined;
  }

  const choices = (payload as { choices?: unknown }).choices;
  if (!Array.isArray(choices)) {
    return undefined;
  }

  const first = choices[0] as { message?: unknown } | undefined;
  if (typeof first?.message !== 'object' || first.message === null) {
    return undefined;
  }

  const content = (first.message as { content?: unknown }).content;
  if (typeof content !== 'string') {
    return undefined;
  }

  return content;
}

function isAbortError(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'name' in err &&
    (err as { name: unknown }).name === 'AbortError'
  );
}
