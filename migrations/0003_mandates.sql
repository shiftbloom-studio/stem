-- Mandates (docs/mandates.md): requests waiting for the person's passkey, and issued root mandates.
-- The live state of each mandate (stop, budget, trail) lives in its Durable Object, not here.
create table "mandateRequest" ("id" text not null primary key, "userCode" text not null, "agentJwk" text not null, "agentThumbprint" text not null, "terms" text not null, "status" text not null, "userId" text references "user" ("id") on delete cascade, "core" text, "token" text, "mandateId" text, "createdAt" date not null, "expiresAt" date not null);
create table "mandate" ("id" text not null primary key, "userId" text not null references "user" ("id") on delete cascade, "purpose" text not null, "rights" text not null, "agentThumbprint" text not null, "passkeyId" text not null, "status" text not null, "createdAt" date not null, "expiresAt" date not null, "revokedAt" date);
create index "mandateRequest_expiresAt_idx" on "mandateRequest" ("expiresAt");
create index "mandate_userId_idx" on "mandate" ("userId");
