// SPDX-License-Identifier: AGPL-3.0-or-later

export function timingSafeEqual(a: string, b: string) {
  const ea = new TextEncoder().encode(a), eb = new TextEncoder().encode(b);
  if (ea.length !== eb.length) return false;
  let diff = 0;
  for (let i = 0; i < ea.length; i++) diff |= ea[i] ^ eb[i];
  return diff === 0;
}

/** Only same-origin paths survive as a post-sign-in target: no scheme, no host, no "//" or "\". */
export function safeNext(raw: string | null | undefined, fallback = "/account"): string {
  if (!raw || raw.length > 512) return fallback;
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\") || /[\u0000-\u001f]/.test(raw)) return fallback;
  return raw;
}

const AI_TRAINING_BOTS = ["GPTBot", "ClaudeBot", "anthropic-ai", "CCBot", "Google-Extended", "Applebot-Extended", "Bytespider", "Amazonbot", "meta-externalagent", "cohere-ai", "MistralAI-Training", "Diffbot"];

/** Only the start page is for search engines. AI training is not allowed anywhere. */
export const robotsTxt = () =>
  [
    "# Search engines may list the start page. Training AI models on this site is not allowed.",
    "User-agent: *",
    "Content-Signal: search=yes, ai-input=no, ai-train=no",
    "Allow: /$",
    "Allow: /privacy",
    "Allow: /datenschutz",
    "Allow: /imprint",
    "Allow: /impressum",
    "Disallow: /",
    "",
    ...AI_TRAINING_BOTS.map((b) => `User-agent: ${b}`),
    "Disallow: /",
    "",
  ].join("\n");

export type Legal = {
  name: string;
  business?: string;
  street: string;
  city: string;
  country: { en: string; de: string };
  email: string;
  phone?: string;
  vatId?: string;
  authority: string;
};

export function parseLegal(raw?: string): Legal | null {
  if (!raw) return null;
  try {
    const l = JSON.parse(raw) as Legal;
    return l && l.name && l.street && l.city && l.email && l.authority && l.country?.en && l.country?.de ? l : null;
  } catch {
    return null;
  }
}
