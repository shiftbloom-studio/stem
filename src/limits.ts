// SPDX-License-Identifier: AGPL-3.0-or-later
// Per-address limits for email codes. Per-IP limits alone don't stop someone who rotates IPs:
// every fresh code would bring five more guesses. These counters follow the address instead.
import type { BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware, APIError } from "better-auth/api";

/** Codes one address can get: one per minute, ten per day. */
export const SEND_INTERVAL_MS = 60_000;
export const SENDS_PER_DAY = 10;
/** Wrong or right, verification attempts per address per day across all its codes. */
export const VERIFY_PER_DAY = 15;
/** How long a code lives (matches emailOTP's expiresIn). Only attempts while a code may be pending count. */
export const CODE_LIFETIME_MS = 600_000;
const DAY_MS = 24 * 3600 * 1000;

const SEND_PATH = "/email-otp/send-verification-otp";
const VERIFY_PATHS = new Set(["/sign-in/email-otp", "/email-otp/verify-email", "/email-otp/check-verification-otp"]);

type Row = { id: string; key: string; windowStart: Date; sends: number; verifies: number; lastSend: Date | null };

async function keyOf(email: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(email.trim().toLowerCase()));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const tooMany = (message: string) => new APIError("TOO_MANY_REQUESTS", { code: "EMAIL_RATE_LIMITED", message });

export const emailLimits = () =>
  ({
    id: "stem-email-limits",
    schema: {
      emailLimit: {
        fields: {
          // SHA-256 of the lowercased address, so addresses without an account aren't stored in clear.
          key: { type: "string", unique: true, required: true },
          windowStart: { type: "date", required: true },
          sends: { type: "number", required: true },
          verifies: { type: "number", required: true },
          lastSend: { type: "date", required: false },
        },
      },
    },
    hooks: {
      before: [
        {
          matcher: (ctx) => ctx.path === SEND_PATH || VERIFY_PATHS.has(ctx.path || ""),
          handler: createAuthMiddleware(async (ctx) => {
            const email = typeof ctx.body?.email === "string" ? ctx.body.email : "";
            if (!email) return;
            const db = ctx.context.adapter;
            const key = await keyOf(email);
            const now = Date.now();
            let row = await db.findOne<Row>({ model: "emailLimit", where: [{ field: "key", value: key }] });
            if (row && now - new Date(row.windowStart).getTime() > DAY_MS) {
              row = await db.update<Row>({ model: "emailLimit", where: [{ field: "id", value: row.id }], update: { windowStart: new Date(now), sends: 0, verifies: 0 } });
            }
            if (!row) {
              row = await db.create<Omit<Row, "id">, Row>({ model: "emailLimit", data: { key, windowStart: new Date(now), sends: 0, verifies: 0, lastSend: null } });
              // Now and then, forget counters nobody has touched for two days.
              if (Math.random() < 0.02) await db.deleteMany({ model: "emailLimit", where: [{ field: "windowStart", operator: "lt", value: new Date(now - 2 * DAY_MS) }] });
            }
            if (row.verifies >= VERIFY_PER_DAY) throw tooMany("Too many attempts for this address. Try again tomorrow.");
            if (ctx.path === SEND_PATH) {
              if (row.lastSend && now - new Date(row.lastSend).getTime() < SEND_INTERVAL_MS) throw tooMany("We just sent a code. Wait a minute before asking for another.");
              if (row.sends >= SENDS_PER_DAY) throw tooMany("That's a lot of codes for one day. Try again tomorrow.");
              await db.update({ model: "emailLimit", where: [{ field: "id", value: row.id }], update: { sends: row.sends + 1, lastSend: new Date(now) } });
            } else if (row.lastSend && now - new Date(row.lastSend).getTime() <= CODE_LIFETIME_MS) {
              // Guesses with no code out can't succeed, so they don't count. Otherwise anyone could lock an
              // address out for a day with a few requests, without ever passing the bot check on sending.
              await db.update({ model: "emailLimit", where: [{ field: "id", value: row.id }], update: { verifies: row.verifies + 1 } });
            }
          }),
        },
      ],
    },
  }) satisfies BetterAuthPlugin;
