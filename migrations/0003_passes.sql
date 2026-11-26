-- Passes (src/passes): one blind-RSA key per statement and UTC day, and how many passes each account took today.
-- Private keys are encrypted with a key derived from BETTER_AUTH_SECRET. Rows older than two days are deleted daily.
create table "passIssuerKey" ("id" text not null primary key, "statement" text not null, "epoch" text not null, "tokenKey" text not null, "privateKey" text not null, "createdAt" integer not null, unique ("statement", "epoch"));
create table "passQuota" ("userId" text not null references "user" ("id") on delete cascade, "day" text not null, "used" integer not null, "granted" integer not null, primary key ("userId", "day"));
