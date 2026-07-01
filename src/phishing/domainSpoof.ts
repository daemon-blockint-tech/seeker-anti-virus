import { DEFAULT_SIGNATURES } from "../signatures/signatureDatabase.js";

/**
 * Protected Solana-ecosystem wallet / dApp / brand names. A domain (or `.skr`
 * handle) that resembles one of these without being it is a spoofing candidate.
 */
export const PROTECTED_BRANDS = [
  "phantom",
  "solflare",
  "backpack",
  "magiceden",
  "tensor",
  "jupiter",
  "raydium",
  "orca",
  "drift",
  "marginfi",
  "jito",
  "solana",
  "solanamobile",
  "seeker",
  "seedvault",
  "okx",
  "coinbase",
  "metamask",
  "binance",
];

/** Multi-character confusables applied before per-character folding. */
const MULTI_CONFUSABLES: [RegExp, string][] = [
  [/rn/g, "m"],
  [/vv/g, "w"],
  [/cl/g, "d"],
];

/** Per-character confusable map (digits, symbols, Cyrillic/Greek homoglyphs). */
const CHAR_CONFUSABLES: Record<string, string> = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
  "@": "a", $: "s", "!": "i", "|": "l",
  // Cyrillic
  а: "a", е: "e", о: "o", р: "p", с: "c", у: "y", х: "x", і: "i", ѕ: "s", ԁ: "d", ո: "n", м: "m", т: "t", в: "b", к: "k", һ: "h", ӏ: "l", ј: "j", ԛ: "q", ԝ: "w", г: "r",
  // Greek
  ο: "o", α: "a", ν: "v", ρ: "p", τ: "t", ι: "i", κ: "k", ε: "e",
};

/** Fold a label to its ASCII "skeleton" so homoglyphs collapse onto the brand. */
export function skeletonize(input: string): string {
  let s = input.normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase();
  for (const [re, to] of MULTI_CONFUSABLES) s = s.replace(re, to);
  let out = "";
  for (const ch of s) out += CHAR_CONFUSABLES[ch] ?? ch;
  return out.replace(/[^a-z0-9]/g, "");
}

/** Strip a label to plain ASCII alphanumerics without confusable folding. */
function asciiLabel(input: string): string {
  return input.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function hasNonAscii(input: string): boolean {
  return /[^\x00-\x7f]/.test(input);
}

/** Levenshtein edit distance (small strings). */
export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1]! + 1, prev[j]! + 1, prev[j - 1]! + cost);
    }
    prev = cur;
  }
  return prev[n]!;
}

/** Reduce a URL/domain to its registrable label + suffix. */
export function parseHost(input: string): { host: string; sld: string; tld: string } | null {
  const host = input
    .trim()
    .toLowerCase()
    .replace(/^[a-z]+:\/\//, "")
    .replace(/^www\./, "")
    .split("/")[0]!
    .split(":")[0]!;
  if (!host) return null;
  const parts = host.split(".").filter(Boolean);
  if (parts.length === 0) return null;
  const tld = parts.length >= 2 ? parts[parts.length - 1]! : "";
  const sld = parts.length >= 2 ? parts[parts.length - 2]! : parts[0]!;
  return { host, sld, tld };
}

export type SpoofTechnique = "homograph" | "obfuscation" | "typosquat" | "skr_impersonation";

export interface SpoofAnalysis {
  brand: string;
  technique: SpoofTechnique;
  severity: "medium" | "high" | "critical";
  confidence: number;
  isSkr: boolean;
  detail: string;
}

/** Default set of domains already covered by the static phishing signatures. */
const KNOWN_STATIC_DOMAINS = new Set(
  DEFAULT_SIGNATURES.filter((s) => s.category === "phishing")
    .flatMap((s) => s.domains ?? [])
    .map((d) => parseHost(d)?.host ?? d.toLowerCase()),
);

/**
 * Analyze a domain / `.skr` handle for spoofing of a protected brand (FR-7b).
 * Returns the strongest finding, or null if it looks benign / is already
 * covered by the static signature list (to avoid double-counting in scoring).
 */
export function analyzeDomainSpoof(
  input: string,
  skipDomains: Set<string> = KNOWN_STATIC_DOMAINS,
): SpoofAnalysis | null {
  const parsed = parseHost(input);
  if (!parsed) return null;
  if (skipDomains.has(parsed.host)) return null;

  const { sld, tld } = parsed;
  const isSkr = tld === "skr";
  const skel = skeletonize(sld);
  const ascii = asciiLabel(sld);
  if (skel.length < 3) return null;

  let bestTypo: { brand: string; dist: number } | null = null;

  for (const brand of PROTECTED_BRANDS) {
    if (skel === brand) {
      if (hasNonAscii(sld)) {
        return {
          brand,
          technique: "homograph",
          severity: "critical",
          confidence: 0.92,
          isSkr,
          detail: `Unicode homoglyph of "${brand}" (IDN homograph attack)`,
        };
      }
      if (ascii !== brand) {
        return {
          brand,
          technique: "obfuscation",
          severity: "high",
          confidence: 0.9,
          isSkr,
          detail: `Character-substitution look-alike of "${brand}" ("${sld}")`,
        };
      }
      // Exact brand: only actionable as a `.skr` handle we can't attribute.
      if (isSkr) {
        return {
          brand,
          technique: "skr_impersonation",
          severity: "medium",
          confidence: 0.6,
          isSkr,
          detail: `"${brand}.skr" — verify this Solana Mobile handle belongs to the official ${brand} wallet`,
        };
      }
      return null;
    }

    if (brand.length >= 4) {
      const dist = levenshtein(skel, brand);
      if (
        dist >= 1 &&
        dist <= 2 &&
        Math.abs(skel.length - brand.length) <= 2 &&
        (!bestTypo || dist < bestTypo.dist)
      ) {
        bestTypo = { brand, dist };
      }
    }
  }

  if (bestTypo) {
    return {
      brand: bestTypo.brand,
      technique: "typosquat",
      severity: "high",
      confidence: 0.86,
      isSkr,
      detail: `Typosquat of "${bestTypo.brand}" (edit distance ${bestTypo.dist})`,
    };
  }

  return null;
}
