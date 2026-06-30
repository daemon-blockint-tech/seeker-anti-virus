import { ChatOpenAI } from "@langchain/openai";

export interface OpenRouterOptions {
  /** OpenRouter API key. Defaults to `process.env.OPENROUTER_API_KEY`. */
  apiKey?: string;
  /** Model slug, e.g. "anthropic/claude-3.5-sonnet". Defaults to `OPENROUTER_MODEL`. */
  model?: string;
  /** Sampling temperature (default 0 for deterministic classification). */
  temperature?: number;
  /** Override the OpenRouter base URL. */
  baseURL?: string;
}

/** Default model used when neither option nor env var is set. */
export const DEFAULT_OPENROUTER_MODEL = "anthropic/claude-3.5-sonnet";

const OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1";

/**
 * Build a {@link ChatOpenAI} client pointed at OpenRouter (PRD §8).
 *
 * OpenRouter is OpenAI-API compatible, so we reuse `@langchain/openai` with a
 * custom `baseURL`. The model is read from `OPENROUTER_MODEL` so it can be
 * swapped (e.g. to a Claude model) without code changes.
 */
export function createOpenRouterModel(options: OpenRouterOptions = {}): ChatOpenAI {
  const apiKey = options.apiKey ?? process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    throw new Error(
      "OpenRouter API key missing: set OPENROUTER_API_KEY or pass { apiKey }.",
    );
  }
  const model =
    options.model ?? (process.env.OPENROUTER_MODEL?.trim() || DEFAULT_OPENROUTER_MODEL);

  return new ChatOpenAI({
    apiKey,
    model,
    temperature: options.temperature ?? 0,
    configuration: {
      baseURL: options.baseURL ?? OPENROUTER_BASE_URL,
      defaultHeaders: {
        // Optional attribution headers recognized by OpenRouter.
        "HTTP-Referer": "https://github.com/daemon-blockint-tech/seeker-anti-virus",
        "X-Title": "Sync Anti-Virus",
      },
    },
  });
}
