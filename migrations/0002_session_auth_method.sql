-- How each session was signed in ("passkey" or "email_code") and, for passkeys, whether the key is synced.
-- Older sessions keep NULL, which tokens report as auth_method "unknown".
alter table "session" add column "authMethod" text;
alter table "session" add column "passkeySynced" integer;
