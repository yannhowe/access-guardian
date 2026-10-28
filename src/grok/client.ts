/**
 * Every xAI call in this repo goes through this file.
 *
 * `extract()` returns JSON that passed `validate`, or a typed failure.
 * What Grok decides: the JSON object when `validate` returns true.
 * What code decides: whether those facts are usable, and whether any fix runs.
 * On a failure, do not fill in a value. Do not act on the call.
 *
 * Temperature is 0. The model call times out after 15 seconds.
 * The model is `XAI_MODEL`, or grok-4.7 when that variable is unset.
 * The API key is `XAI_API_KEY` from the environment when `secretId` is omitted.
 * When `secretId` is set, the key is read from that Secrets Manager secret.
 * The daily report passes `XAI_SECRET_ID`. The secret read times out after 10 seconds.
 * A missing secret, an empty value, or a timeout is `no_key`. The model is not called.
 * This function does not write the key into the environment.
 * This function does not log the key, the prompt, or the reply.
 */
import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';

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

/** Hard stop for the model call. A slow reply is a failure, not a value we invent. */
const TIMEOUT_MS = 15_000;

/** Hard stop for the Secrets Manager read. The model is not called after this. */
const SECRET_TIMEOUT_MS = 10_000;

export async function extract<T>(opts: {
  system: string;
  input: string;
  schemaName: string;
  schema: JsonSchema;
  /** Returns true only when `value` is a complete T. Anything else is a mismatch. */
  validate: (value: unknown) => value is T;
  /**
   * Secrets Manager secret id. When set, the key comes from that secret.
   * When omitted, the key is `XAI_API_KEY` from the environment.
   */
  secretId?: string;
}): Promise<ExtractResult<T>> {
  const apiKey = await readApiKey(opts.secretId);
  if (apiKey === undefined) {
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

/**
 * `secretId` selects Secrets Manager. Omitting it selects `XAI_API_KEY`.
 * A failed secret read does not fall back to the environment.
 */
async function readApiKey(secretId: string | undefined): Promise<string | undefined> {
  if (secretId !== undefined) {
    return readKeyFromSecret(secretId);
  }
  const fromEnv = process.env.XAI_API_KEY?.trim();
  if (fromEnv === undefined || fromEnv.length === 0) {
    return undefined;
  }
  return fromEnv;
}

async function readKeyFromSecret(secretId: string): Promise<string | undefined> {
  const trimmedId = secretId.trim();
  if (trimmedId.length === 0) {
    return undefined;
  }

  const client = new SecretsManagerClient({});
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SECRET_TIMEOUT_MS);
  try {
    const response = await client.send(new GetSecretValueCommand({ SecretId: trimmedId }), {
      abortSignal: controller.signal,
    });
    return secretString(response);
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
    try {
      client.destroy();
    } catch {
      // Closing the client is local cleanup.
    }
  }
}

function secretString(response: unknown): string | undefined {
  if (typeof response !== 'object' || response === null) {
    return undefined;
  }
  const value = (response as { SecretString?: unknown }).SecretString;
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return undefined;
  }
  return trimmed;
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
