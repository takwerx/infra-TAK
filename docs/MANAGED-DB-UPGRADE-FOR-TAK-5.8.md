# Upgrading a managed PostgreSQL to 18 for TAK Server 5.8

**TAK Server 5.8 requires PostgreSQL 18.** If your CoT database runs on a managed service —
**AWS RDS** or **Azure Database for PostgreSQL Flexible Server** — the console **cannot** upgrade
it for you. The provider owns the engine, and the upgrade happens in their console or CLI.

So the order is: **upgrade the database first, then install TAK 5.8.** The console refuses a 5.8
install while it can see PostgreSQL 15, precisely so you cannot get halfway.

> **Not sure if this applies to you?** Open the console's **TAK Server** page. If the deployment
> mode is **External database**, this guide is for you. If it says single-server or two-server, the
> console handles the migration itself and you want the in-app **Update** button instead.

---

## 1. Before you touch anything

**Check what you are actually on.** The console's TAK Server page shows the database version it
sees. Confirm it independently from your provider console too — they must agree.

**Take a snapshot you have restored from before.** A provider snapshot is not a backup until you
know you can restore it. Both providers do point-in-time restore; a manual snapshot immediately
before the upgrade is the thing you will reach for if this goes wrong.

**Know your downtime.** A managed major-version upgrade takes the database offline. TAK Server will
be down for the whole window and clients will disconnect. Plan it like any other outage.

**Read your provider's current documentation.** The steps below are the shape of the work, not a
substitute — both providers change their upgrade tooling, and the versions they offer move.

- AWS RDS: *Upgrading the PostgreSQL DB engine for Amazon RDS*
- Azure: *Major version upgrade for Azure Database for PostgreSQL Flexible Server*

---

## 2. Stop TAK Server first

From the console's **TAK Server** page, **Stop**. Do not leave it running into the upgrade — you do
not want TAK reconnecting to a database mid-upgrade, and a clean stop means a clean start after.

---

## 3. Upgrade the instance

### AWS RDS

Two routes, and the choice is about downtime:

- **In-place major version upgrade** — modify the instance and select engine version 18. Simplest,
  and the database is offline for the duration.
- **Blue/green deployment** — RDS builds a PostgreSQL 18 copy alongside, keeps it in sync, and you
  switch over. Much shorter outage, more moving parts, and you must repoint the console at the new
  endpoint afterwards if the name changes.

RDS runs pre-upgrade checks and will refuse if something in the database is incompatible. **Read
what it says rather than retrying** — it is usually specific and actionable.

**The step people miss:** after you pick the new engine version and press Continue, RDS shows a
summary page with a **Scheduling of modifications** choice, and it defaults to *Apply during the
next scheduled maintenance window*. Leave that default and **nothing happens now** — the instance
stays Available, still on the old version, and it looks like the upgrade silently failed. Choose
**Apply immediately** if you intend to upgrade during your planned window.

### Azure Database for PostgreSQL Flexible Server

Flexible Server supports an in-place **major version upgrade** from the portal or CLI: stop the
server, choose the target major version, upgrade. The server is unavailable during it.

### Either way

**PostGIS matters.** TAK's schema uses it. Confirm your upgraded instance has a PostGIS version
available and enabled for PostgreSQL 18 — on managed services PostGIS is an extension the provider
offers per engine version, and the available version changes with the engine. If PostGIS is
missing or too old after the upgrade, TAK's schema work will fail.

In practice the provider handles this for you: on an RDS instance taken from PostgreSQL 15 to 18,
PostGIS moved from 3.4.6 to 3.6.3 as part of the same upgrade, with nothing to do by hand. Confirm
it rather than assume it — the check is in the next section.

---

## 4. Check the database is actually on 18 — and that TAK can still log in

Two separate things, and the second one is easy to skip:

```
SHOW server_version_num;        -- expect 18xxxx
```

```
-- can TAK's user still authenticate?
psql "host=<endpoint> user=martiuser dbname=cot sslmode=require"
```

> ⚠ **This second check is not paranoia.** On self-hosted RHEL upgrades we found that TAK's 5.8
> package installs a `pg_hba.conf` requiring `scram-sha-256`, while the old password had been
> stored as an **md5 hash** — and an md5 hash cannot satisfy a scram challenge. The result was a
> server that came up looking perfectly healthy with its schema never migrated.
>
> Whether a managed provider's engine upgrade re-encodes stored passwords is **provider-specific
> and we have not verified it for either service.** If `martiuser` cannot log in after the
> upgrade, reset its password — which re-stores it under the current encryption — and try again:
>
> ```sql
> ALTER USER martiuser PASSWORD '<the same password already in CoreConfig.xml>';
> ```
>
> Same password. Nothing in the console needs changing.

---

## 5. Install TAK Server 5.8

Back in the console:

1. **TAK Server** page → upload the TAK Server 5.8 package.
2. Click **Update**. With the database on 18, the console stops refusing and installs normally.
3. Wait for it to finish and start TAK Server.

---

## 6. Verify — do not skip this

The important check is **not** that TAK started. It is that the 5.8 schema actually applied:

```sql
select max(version::int) from schema_version where success;   -- expect 106 or higher
```

```sql
-- 5.8 adds these to cot_router
select column_name from information_schema.columns
 where table_name = 'cot_router' and column_name in ('flow_tags','username');
```

If `schema_version` is still 99 and those columns are missing, **TAK Server 5.8 is running against
a 5.7 schema.** It will look healthy and behave incorrectly. Stop TAK, resolve why the schema
update could not run — the authentication check in §4 is the first thing to look at — and re-run
it before putting the server back into service.

Finally, connect a real client and confirm it appears **with its channels**. Channels exercise the
whole identity path, which is the part a database change is most likely to disturb.

---

## If it goes wrong

- **The database upgraded but TAK will not start** — check the console's TAK Server logs first.
  Most often the connection string or credentials no longer match; §4 covers the credential case.
- **The schema did not apply** — see §6. Do not leave the server in service.
- **You need to go back** — restore the snapshot from §1 to a *new* instance, point the console's
  external-database settings at it, and reinstall TAK 5.7. Managed services cannot downgrade an
  engine in place.

---

## What the console does and does not do here

| | |
|---|---|
| Upgrade a managed PostgreSQL engine | **No** — the provider owns it |
| Refuse a 5.8 install while it sees PostgreSQL 15 | **Yes** — so you cannot get halfway |
| Install TAK 5.8 and run its schema updates | **Yes** |
| Verify the schema actually applied | **Yes**, and it fails loudly if not |
| Back up a managed database before the upgrade | **No** — use a provider snapshot (§1) |

On single-server and two-server deployments the console does own the whole migration, backup
included. Managed databases are the exception, and this guide exists because of it.
