// SPDX-License-Identifier: AGPL-3.0-or-later
// The live half of a mandate: one Durable Object per root mandate, shared by every token derived from
// it. It holds what a signature can't: the stop button, the expiry, a budget all branches share, a
// replay check for proofs of possession, and a hash-chained trail of every call.
import { DurableObject } from "cloudflare:workers";
import { createHash } from "node:crypto";
import { canonicalize, sha256b64u, POP_MAX_AGE, type Budget } from "./verify";

export type Outcome = "allowed" | "revoked" | "expired" | "unknown" | "over_budget" | "replayed";
export type UseInput = { holder: string; depth: number; action: string; path?: string; bytes: number; popJti: string; popIat: number; location: string };
export type UseResult = { outcome: Outcome; remaining: Budget };
export type MandateStatus = { status: "active" | "revoked" | "expired" | "unknown"; exp: number | null; remaining: Budget; calls: number };
export type TrailEntry = { seq: number; at: number; holder: string; depth: number; location: string; action: string; path: string | null; bytes: number; outcome: Outcome; hash: string };

/** Storage the object needs. Durable Object SQLite in production; tests pass node:sqlite. */
export type Sql = { exec<T = Record<string, unknown>>(query: string, ...args: unknown[]): { toArray(): T[] } };

/** The object's logic without the runtime, so tests can run it on any SQLite. */
export class MandateState {
  constructor(private sql: Sql, private now: () => number = Date.now) {
    sql.exec("CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT NOT NULL)");
    sql.exec("CREATE TABLE IF NOT EXISTS trail (seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, holder TEXT NOT NULL, depth INTEGER NOT NULL, location TEXT NOT NULL, action TEXT NOT NULL, path TEXT, bytes INTEGER NOT NULL, outcome TEXT NOT NULL, hash TEXT NOT NULL)");
    sql.exec("CREATE TABLE IF NOT EXISTS pop (jti TEXT PRIMARY KEY, until INTEGER NOT NULL)");
  }
  private get(k: string) {
    return this.sql.exec<{ v: string }>("SELECT v FROM state WHERE k = ?", k).toArray()[0]?.v;
  }
  private set(k: string, v: string | number) {
    this.sql.exec("INSERT INTO state (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", k, String(v));
  }
  private num(k: string) {
    const v = this.get(k);
    return v === undefined ? undefined : Number(v);
  }
  private remaining(): Budget {
    const b: Budget = {};
    const bytes = this.num("bytes"), calls = this.num("calls");
    if (bytes !== undefined) b.bytes = bytes;
    if (calls !== undefined) b.calls = calls;
    return b;
  }

  /** Called once by stem when it issues the root. A second call changes nothing. */
  open(exp: number, budget: Budget) {
    if (this.get("status")) return false;
    this.set("status", "active");
    this.set("exp", exp);
    this.set("used", 0);
    if (budget.bytes !== undefined) this.set("bytes", budget.bytes);
    if (budget.calls !== undefined) this.set("calls", budget.calls);
    return true;
  }

  status(): MandateStatus {
    let status = (this.get("status") as MandateStatus["status"]) ?? "unknown";
    const exp = this.num("exp") ?? null;
    if (status === "active" && exp !== null && this.now() / 1000 > exp) status = "expired";
    return { status, exp, remaining: this.remaining(), calls: this.num("used") ?? 0 };
  }

  /** Check and debit in one synchronous step: two calls can't interleave between the check and the write. */
  use(i: UseInput): UseResult {
    const now = this.now();
    const s = this.status();
    let outcome: Outcome = s.status === "active" ? "allowed" : s.status;
    const left = s.remaining;
    if (outcome === "allowed" && ((left.bytes !== undefined && i.bytes > left.bytes) || (left.calls !== undefined && left.calls < 1))) outcome = "over_budget";
    if (outcome === "allowed") {
      // A proof of possession counts once. RETURNING tells "inserted" from "already there".
      this.sql.exec("DELETE FROM pop WHERE until < ?", Math.floor(now / 1000));
      const fresh = this.sql.exec("INSERT INTO pop (jti, until) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING RETURNING jti", i.popJti, i.popIat + POP_MAX_AGE + 60).toArray().length === 1;
      if (!fresh) outcome = "replayed";
    }
    if (outcome === "allowed") {
      if (left.bytes !== undefined) this.set("bytes", (left.bytes = left.bytes - i.bytes));
      if (left.calls !== undefined) this.set("calls", (left.calls = left.calls - 1));
      this.set("used", s.calls + 1);
    }
    this.append(now, i, outcome);
    return { outcome, remaining: left };
  }

  private append(at: number, i: UseInput, outcome: Outcome) {
    const prev = this.sql.exec<{ hash: string }>("SELECT hash FROM trail ORDER BY seq DESC LIMIT 1").toArray()[0]?.hash ?? "";
    const entry = { at, holder: i.holder, depth: i.depth, location: i.location, action: i.action, path: i.path ?? null, bytes: i.bytes, outcome };
    const hash = syncHash(prev + canonicalize(entry));
    this.sql.exec("INSERT INTO trail (at, holder, depth, location, action, path, bytes, outcome, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", at, i.holder, i.depth, i.location, i.action, i.path ?? null, i.bytes, outcome, hash);
  }

  revoke() {
    const s = this.get("status");
    if (!s) return false;
    if (s !== "revoked") this.set("status", "revoked");
    return true;
  }

  expire() {
    if (this.get("status") === "active") this.set("status", "expired");
    this.sql.exec("DELETE FROM pop");
  }

  trail(limit = 50): TrailEntry[] {
    return this.sql.exec<TrailEntry>("SELECT seq, at, holder, depth, location, action, path, bytes, outcome, hash FROM trail ORDER BY seq DESC LIMIT ?", Math.min(Math.max(1, limit), 500)).toArray();
  }
}

/** Recomputes a trail hash, to check a trail someone downloaded: hash(n) = H(hash(n-1) + canonical entry). */
export const trailHash = (prev: string, e: Omit<TrailEntry, "seq" | "hash">) => sha256b64u(prev + canonicalize({ at: e.at, holder: e.holder, depth: e.depth, location: e.location, action: e.action, path: e.path, bytes: e.bytes, outcome: e.outcome }));

/** SHA-256 without await (node:crypto under nodejs_compat), so use() stays one synchronous step. */
const syncHash = (text: string) => createHash("sha256").update(text).digest("base64url");

/** The Durable Object class (binding MANDATE). One instance per root mandate, named by its jti. */
export class Mandate extends DurableObject {
  private state: MandateState;
  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env as never);
    this.state = new MandateState(ctx.storage.sql as unknown as Sql);
  }
  async open(exp: number, budget: Budget) {
    const opened = this.state.open(exp, budget);
    if (opened) await this.ctx.storage.setAlarm(exp * 1000);
    return opened;
  }
  status() {
    return this.state.status();
  }
  use(i: UseInput) {
    return this.state.use(i);
  }
  revoke() {
    return this.state.revoke();
  }
  trail(limit?: number) {
    return this.state.trail(limit);
  }
  alarm() {
    this.state.expire();
  }
}
