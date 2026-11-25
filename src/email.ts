// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Env } from "./env";
import { esc } from "./ui/html";

export type Mail = { to: string; subject: string; text: string; html: string };

/** "stem <login@example.com>" → { name, email }. A bare address works too. */
export function parseFrom(raw: string): { email: string; name: string } | string {
  const m = /^\s*(.*?)\s*<([^<>\s]+@[^<>\s]+)>\s*$/.exec(raw);
  if (m) return m[1] ? { name: m[1].replace(/^"|"$/g, ""), email: m[2] } : m[2];
  return raw.trim();
}

/** Local development: STEM_URL points at this machine. */
export function isLocal(env: Pick<Env, "STEM_URL">): boolean {
  try {
    return ["localhost", "127.0.0.1", "[::1]"].includes(new URL(env.STEM_URL).hostname);
  } catch {
    return false;
  }
}

export async function sendMail(env: Env, mail: Mail): Promise<void> {
  if (isLocal(env) && (env.DEV_LOG_EMAIL === "true" || !env.EMAIL || !env.EMAIL_FROM)) {
    // Local development only: the code shows up in `wrangler dev` output.
    console.log(`[mail] to=${mail.to} subject=${JSON.stringify(mail.subject)}\n${mail.text}`);
    return;
  }
  // Anywhere else, codes never go to the logs: a deployment without email fails loudly instead.
  if (!env.EMAIL || !env.EMAIL_FROM) throw new Error("email is not configured: set the EMAIL binding and EMAIL_FROM");
  await env.EMAIL.send({ from: parseFrom(env.EMAIL_FROM), to: mail.to, subject: mail.subject, text: mail.text, html: mail.html });
}

const wrap = (title: string, body: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title></head>
<body style="margin:0;background:#ffffff;color:#1A1216;font:16px/1.6 -apple-system,'Segoe UI',Helvetica,Arial,sans-serif">
<div style="max-width:520px;margin:0 auto;padding:40px 24px">
<p style="margin:0 0 28px;font-weight:600;font-size:20px;letter-spacing:-.02em">stem<span style="color:#FF2E52">.</span></p>
${body}
<p style="margin:36px 0 0;font-size:13px;color:#6b6266">stem is the sign-in for shiftbloom studio apps. If you didn't ask for this email, you can ignore it.</p>
</div></body></html>`;

export function codeMail(to: string, code: string, type: string): Mail {
  const purpose = type === "email-verification" ? "confirm your email address" : "sign in";
  return {
    to,
    subject: `${code} is your stem code`,
    text: `Your code to ${purpose}: ${code}\n\nIt works for 10 minutes and only once. If you didn't ask for it, ignore this email. Nobody from shiftbloom studio will ever ask you for this code.`,
    html: wrap("Your stem code", `<p style="margin:0 0 12px">Here's your code to ${purpose}:</p>
<p style="margin:0 0 20px;font:600 32px/1.2 ui-monospace,Menlo,Consolas,monospace;letter-spacing:.18em">${esc(code)}</p>
<p style="margin:0;color:#6b6266">It works for 10 minutes and only once. Nobody from shiftbloom studio will ever ask you for this code.</p>`),
  };
}

export function inviteMail(to: string, orgName: string, inviter: string | null, url: string, days = 7): Mail {
  const who = inviter ? `${inviter} invited you` : "You've been invited";
  return {
    to,
    subject: `Join ${orgName}`,
    text: `${who} to join ${orgName}.\n\nAccept here: ${url}\n\nThe link works for ${days === 1 ? "one day" : `${days} days`}. You sign in with this email address; no password needed.`,
    html: wrap(`Join ${orgName}`, `<p style="margin:0 0 20px">${esc(who)} to join <strong>${esc(orgName)}</strong>.</p>
<p style="margin:0 0 20px"><a href="${esc(url)}" style="display:inline-block;background:#FF2E52;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 20px;border-radius:999px">Accept the invitation</a></p>
<p style="margin:0;color:#6b6266">The link works for ${days === 1 ? "one day" : `${days} days`}. You sign in with this email address; no password needed.</p>`),
  };
}
