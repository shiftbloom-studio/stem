// SPDX-License-Identifier: AGPL-3.0-or-later
// Sealed apps (docs/sealed-apps.md): apps that sign people in through stem without learning who they are
// elsewhere. Each sealed app gets its own `sub` for a person (OpenID Connect pairwise identifiers), never
// gets the email address, and can't read people through the directory API. While sealed apps are on,
// stem also keeps only coarse session data: the network instead of the IP address, browser and system
// instead of the full user agent.
import type { BetterAuthPlugin } from "better-auth";
import type { Env } from "./env";

/** Apps listed in SEALED_APPS, when PAIRWISE_SECRET is long enough. Empty means sealed apps are off. */
export function sealedApps(env: Pick<Env, "SEALED_APPS" | "PAIRWISE_SECRET">): Set<string> {
  if (!pairwiseSecret(env)) return new Set();
  return new Set((env.SEALED_APPS || "").split(",").map((a) => a.trim()).filter(Boolean));
}

export const sealedEnabled = (env: Pick<Env, "SEALED_APPS" | "PAIRWISE_SECRET">) => sealedApps(env).size > 0;

export const isSealedApp = (env: Pick<Env, "SEALED_APPS" | "PAIRWISE_SECRET">, app: unknown) =>
  typeof app === "string" && sealedApps(env).has(app);

/** The secret behind pairwise `sub` values. Better Auth wants 32 characters at least.
 * It stays in use as long as it's set, even with SEALED_APPS empty, so ids already handed out don't change. */
export function pairwiseSecret(env: Pick<Env, "PAIRWISE_SECRET">): string | undefined {
  const s = env.PAIRWISE_SECRET || "";
  return s.length >= 32 ? s : undefined;
}

/** Scopes a sealed app's clients may ask for: everything except the email address. */
export const sealedScopes = (scopes: string[]) => scopes.filter((s) => s !== "email");

/** The network an address belongs to: /24 for IPv4, /48 for IPv6. Enough to tell "my home" from "abroad". */
export function coarseIp(ip: string | null | undefined): string | null {
  if (!ip) return null;
  const v = ip.trim();
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}.0/24`;
  if (v.includes(":")) {
    // Expand "::" far enough to know the first three groups.
    const [head, tail] = v.split("::");
    const left = head ? head.split(":") : [];
    const right = tail !== undefined && tail ? tail.split(":") : [];
    const groups = tail === undefined ? left : [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right];
    if (groups.length < 3 || groups.slice(0, 3).some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
    return `${groups.slice(0, 3).map((g) => g.toLowerCase().replace(/^0+(?=.)/, "")).join(":")}::/48`;
  }
  return null;
}

/** Browser and system only, e.g. "Firefox on Windows". No versions, no device model. */
export function coarseUserAgent(ua: string | null | undefined): string | null {
  if (!ua) return null;
  const b = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${b} on ${os}` : b;
}

type SessionData = { ipAddress?: string | null; userAgent?: string | null };
const coarse = <T extends SessionData>(s: T) => {
  const out: SessionData = {};
  if ("ipAddress" in s) out.ipAddress = coarseIp(s.ipAddress);
  if ("userAgent" in s) out.userAgent = coarseUserAgent(s.userAgent);
  return out;
};

/** Stores sessions with coarse network and browser while sealed apps are on. Off, it does nothing. */
export const coarseSessions = (env: Env) =>
  ({
    id: "stem-coarse-sessions",
    init() {
      if (!sealedEnabled(env)) return;
      return {
        options: {
          databaseHooks: {
            session: {
              create: { async before(session: SessionData) { return { data: { ...session, ...coarse(session) } }; } },
              update: { async before(session: SessionData) { return { data: { ...session, ...coarse(session) } }; } },
            },
          },
        },
      };
    },
  }) as unknown as BetterAuthPlugin;
