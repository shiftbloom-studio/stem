// SPDX-License-Identifier: AGPL-3.0-or-later
// App gateway: a named Workers entrypoint for app Workers on the same Cloudflare account.
//
// An app binds to it with a service binding that names the entrypoint and its app in `props`:
//   "services": [{ "binding": "IDENTITY", "service": "stem", "entrypoint": "AppGateway", "props": { "app": "my-app" } }]
// Cloudflare sets `ctx.props` from the caller's binding, so stem knows which app is calling without a
// shared secret. Only Workers on the same account can bind to this entrypoint.
//
// It adds two things on top of the plain service binding (which keeps working as before):
// - Per-user and per-app rate limits. `fetch` forwards to the normal HTTP app with the end user's IP
//   from the `x-stem-client-ip` header, or, for calls without an end user, a stable per-app address.
// - Typed directory methods. The same directory API as /api/v1, scoped to `props.app`, as plain RPC
//   calls without a client-credentials token.
import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./env";

/** Who is calling through the gateway. Only ever set by the entrypoint, on a copy of env. */
export type Gateway = { app: string; rpc: boolean };

/** Key of the gateway context on env. A symbol, so no config variable or request can set it. */
export const GATEWAY = Symbol("stem.gateway");

export type GatewayEnv = Env & { [GATEWAY]?: Gateway };

export const gatewayOf = (env: Env): Gateway | undefined => (env as GatewayEnv)[GATEWAY];

/** Header an app sets to the IP of the person it is calling for. Read only through the gateway. */
export const CLIENT_IP_HEADER = "x-stem-client-ip";

const APP_ID = /^[a-z][a-z0-9-]{1,39}$/;
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** A plain IPv4 or IPv6 address (no ports, ranges or lists), or null. */
export function cleanIp(value: string | null | undefined): string | null {
  const v = (value || "").trim();
  if (!v || v.length > 45) return null;
  if (IPV4.test(v)) return v;
  if (!v.includes(":") || !/^[0-9a-fA-F:.]+$/.test(v)) return null;
  try {
    return new URL(`http://[${v}]/`).hostname ? v : null;
  } catch {
    return null;
  }
}

/** A stable address in the private fd00::/8 range for an app's calls without an end user.
 * All 64 prefix bits come from the app name, because limits group IPv6 addresses by /64. */
export async function appAddress(app: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`stem-app:${app}`)));
  const g = (i: number) => ((h[i] << 8) | h[i + 1]).toString(16);
  return `fd${h[0].toString(16).padStart(2, "0")}:${g(1)}:${g(3)}:${g(5)}::1`;
}

/** Reads and checks the app named in the caller's binding props. */
export function propsApp(props: unknown): string | null {
  const app = props && typeof props === "object" ? (props as { app?: unknown }).app : undefined;
  return typeof app === "string" && APP_ID.test(app) ? app : null;
}

type Handler = (req: Request, env: Env, ctx: ExecutionContext) => Response | Promise<Response>;

/** Raised by the directory methods: `status` and `code` match the HTTP API's error response. */
export class StemError extends Error {
  constructor(public status: number, public code: string, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "StemError";
  }
}

export type Org = { id: string; name: string; slug: string; logo: string | null; metadata: Record<string, unknown>; app: string | null; created_at: string | null };
export type User = { id: string; email: string; name: string | null; email_verified: boolean };
export type Member = { user_id: string; role: string; created_at: string | null; user: User | null };
export type Invitation = { id: string; organization_id: string; email: string; role: string | null; status: string; expires_at: string | null; created_at: string | null; inviter_id: string; redirect_to: string | null };

/** Builds the entrypoint class around the HTTP app, so both share one code path. */
export function createGateway(handle: Handler) {
  return class AppGateway extends WorkerEntrypoint<Env> {
    private app(): string {
      const app = propsApp(this.ctx.props);
      if (!app) throw new StemError(403, "gateway_needs_app", 'set props: { "app": "<app id>" } on the service binding');
      return app;
    }

    private envFor(app: string, rpc: boolean): GatewayEnv {
      return { ...this.env, [GATEWAY]: { app, rpc } };
    }

    /** HTTP, exactly like the public hostname, with a fair client IP for the rate limits. */
    async fetch(request: Request): Promise<Response> {
      const app = propsApp(this.ctx.props);
      if (!app) return Response.json({ error: "gateway_needs_app" }, { status: 403, headers: { "cache-control": "no-store" } });
      const headers = new Headers(request.headers);
      const ip = cleanIp(headers.get(CLIENT_IP_HEADER)) || (await appAddress(app));
      headers.delete(CLIENT_IP_HEADER);
      headers.set("cf-connecting-ip", ip);
      return handle(new Request(request, { headers }), this.envFor(app, false), this.ctx);
    }

    /** One directory call through the HTTP app, authorized by the props instead of a token. */
    private async call<T>(method: string, path: string, body?: unknown, query?: Record<string, string | number | undefined>): Promise<T> {
      const app = this.app();
      const url = new URL(`/api/v1${path}`, this.env.STEM_URL);
      for (const [k, v] of Object.entries(query || {})) if (v !== undefined) url.searchParams.set(k, String(v));
      const headers = new Headers({ "cf-connecting-ip": await appAddress(app) });
      if (body !== undefined) headers.set("content-type", "application/json");
      const res = await handle(new Request(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), this.envFor(app, true), this.ctx);
      if (res.status === 204) return undefined as T;
      const json = (await res.json().catch(() => ({}))) as { error?: string; detail?: string };
      if (!res.ok) throw new StemError(res.status, json.error || "server_error", json.detail);
      return json as T;
    }

    private async orNull<T>(p: Promise<T>): Promise<T | null> {
      try {
        return await p;
      } catch (e) {
        if (e instanceof StemError && e.status === 404) return null;
        throw e;
      }
    }

    private id(v: string) {
      return encodeURIComponent(String(v));
    }

    /** Role names this stem accepts. */
    async roles(): Promise<string[]> {
      return (await this.call<{ data: string[] }>("GET", "/roles")).data;
    }

    /** The app's organizations. */
    async listOrgs(): Promise<Org[]> {
      return (await this.call<{ data: Org[] }>("GET", "/orgs")).data;
    }

    /** One of the app's organizations, or null. */
    getOrg(orgId: string): Promise<Org | null> {
      return this.orNull(this.call<Org>("GET", `/orgs/${this.id(orgId)}`));
    }

    updateOrg(orgId: string, update: { name?: string; logo?: string | null; metadata?: Record<string, unknown> }): Promise<Org> {
      return this.call<Org>("PATCH", `/orgs/${this.id(orgId)}`, update);
    }

    listMembers(orgId: string, page: { limit?: number; offset?: number } = {}): Promise<{ data: Member[]; total: number; limit: number; offset: number }> {
      return this.call("GET", `/orgs/${this.id(orgId)}/members`, undefined, { limit: page.limit, offset: page.offset });
    }

    addMember(orgId: string, member: { user_id?: string; email?: string; role: string }): Promise<Member> {
      return this.call<Member>("POST", `/orgs/${this.id(orgId)}/members`, member);
    }

    setMemberRole(orgId: string, userId: string, role: string): Promise<{ user_id: string; role: string }> {
      return this.call("PATCH", `/orgs/${this.id(orgId)}/members/${this.id(userId)}`, { role });
    }

    async removeMember(orgId: string, userId: string): Promise<void> {
      await this.call("DELETE", `/orgs/${this.id(orgId)}/members/${this.id(userId)}`);
    }

    async listInvitations(orgId: string, status = "pending"): Promise<Invitation[]> {
      return (await this.call<{ data: Invitation[] }>("GET", `/orgs/${this.id(orgId)}/invitations`, undefined, { status })).data;
    }

    invite(orgId: string, invitation: { email: string; role?: string; inviter_id?: string; redirect_to?: string; expires_in_days?: number }): Promise<Invitation> {
      return this.call<Invitation>("POST", `/orgs/${this.id(orgId)}/invitations`, invitation);
    }

    async cancelInvitation(orgId: string, invitationId: string): Promise<void> {
      await this.call("DELETE", `/orgs/${this.id(orgId)}/invitations/${this.id(invitationId)}`);
    }

    /** A user's public profile, only for members of the app's organizations, or null. */
    getUser(userId: string): Promise<User | null> {
      return this.orNull(this.call<User>("GET", `/users/${this.id(userId)}`));
    }
  };
}
