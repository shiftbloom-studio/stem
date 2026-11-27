-- Primary team: a person can be in many teams and marks one of them as primary.
-- The column is nullable, so code from before this migration keeps working while it is applied.
-- "isPrimary" is 1 on at most one membership per person; NULL or 0 everywhere else.
alter table "member" add column "isPrimary" integer;
create unique index "member_userId_primary_uidx" on "member" ("userId") where "isPrimary" = 1;
