import { Type } from '@sinclair/typebox';
import { sql } from 'drizzle-orm';
import { randomUUID } from 'node:crypto';
import Schema from '@openaddresses/batch-schema';
import Err from '@openaddresses/batch-error';
import Auth from '../lib/auth.js';
import Config from '../lib/config.js';

// Server-side store for the standalone Dispatcher: Events (1:1 with a DataSync feed) and the
// Incidents within them. Lives in CloudTAK's own Postgres so every dispatcher on this CloudTAK
// shares the same board — closed incidents persist (findable) until the Event is nuked.
//
// We own two tables via CREATE TABLE IF NOT EXISTS (config.pg is a drizzle PgDatabase, so
// config.pg.execute(sql`...`) runs raw SQL); this does not touch CloudTAK's drizzle migrations,
// and the gis DB survives API image rebuilds. Auto-loaded by schema.load('./routes/') and
// installed alongside the TAK-CAD proxy route by the infra-TAK plugin installer.

interface EventRow {
    id: string;
    name: string;
    prefix: string;
    feed_guid: string;
    feed_name: string;
    status: string;
    seq: number;
    created_at: string;
    created_by: string | null;
}

interface IncidentRow {
    id: string;
    event_id: string;
    number: string;
    type: string | null;
    address: string | null;
    lat: number | null;
    lon: number | null;
    dispatcher: string | null;
    details: string | null;
    status: string;
    assigned: unknown;
    notes: unknown;
    created_at: string;
    closed_at: string | null;
}

// drizzle's execute() returns the driver RowList; cast to the row shape we SELECTed.
async function query<T>(config: Config, statement: ReturnType<typeof sql>): Promise<T[]> {
    const result = await config.pg.execute(statement);
    return result as unknown as T[];
}

// jsonb columns can come back from the driver as a (possibly double-encoded) JSON string.
// Unwrap to a real array so the UI can map/spread it, and so a read-modify-write never
// re-JSON.stringifies an already-stringified value (which double-encodes the column).
function asArray(v: unknown): unknown[] {
    let x: unknown = v;
    for (let i = 0; i < 4 && typeof x === 'string'; i++) {
        try {
            x = JSON.parse(x);
        } catch {
            return [];
        }
    }
    return Array.isArray(x) ? x : [];
}

// Normalize an incident row's jsonb fields to arrays before sending it to the client.
function mapIncident(row: IncidentRow): IncidentRow {
    return { ...row, assigned: asArray(row.assigned), notes: asArray(row.notes) };
}

export default async function router(schema: Schema, config: Config) {
    // Idempotent schema bootstrap. Best-effort so a transient DB hiccup can't block CloudTAK
    // startup; CREATE TABLE IF NOT EXISTS is safe to re-run on every load.
    try {
        await config.pg.execute(sql`
            CREATE TABLE IF NOT EXISTS dispatcher_events (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                prefix      TEXT NOT NULL,
                feed_guid   TEXT NOT NULL,
                feed_name   TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'active',
                seq         INTEGER NOT NULL DEFAULT 0,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
                created_by  TEXT
            )
        `);
        await config.pg.execute(sql`
            CREATE TABLE IF NOT EXISTS dispatcher_incidents (
                id          TEXT PRIMARY KEY,
                event_id    TEXT NOT NULL REFERENCES dispatcher_events(id) ON DELETE CASCADE,
                number      TEXT NOT NULL,
                type        TEXT,
                address     TEXT,
                lat         DOUBLE PRECISION,
                lon         DOUBLE PRECISION,
                dispatcher  TEXT,
                details     TEXT,
                status      TEXT NOT NULL DEFAULT 'active',
                assigned    JSONB NOT NULL DEFAULT '[]'::jsonb,
                notes       JSONB NOT NULL DEFAULT '[]'::jsonb,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
                closed_at   TIMESTAMPTZ
            )
        `);
    } catch (err) {
        console.error('[dispatcher] table bootstrap failed', err);
    }

    // ── Events ──────────────────────────────────────────────────────────────────

    await schema.get('/dispatcher/events', {
        name: 'List Events',
        group: 'Dispatcher',
        description: 'List all dispatcher events (active + archived)',
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);
            const events = await query<EventRow>(config, sql`
                SELECT id, name, prefix, feed_guid, feed_name, status, seq, created_at, created_by
                FROM dispatcher_events ORDER BY created_at DESC
            `);
            res.json({ events });
        } catch (err) {
            Err.respond(err, res);
        }
    });

    await schema.post('/dispatcher/events', {
        name: 'Create Event',
        group: 'Dispatcher',
        description: 'Create a dispatcher event tied to a DataSync feed',
        body: Type.Object({
            name: Type.String(),
            prefix: Type.String(),
            feed_guid: Type.String(),
            feed_name: Type.String(),
        }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            const user = await Auth.as_user(config, req);
            const id = randomUUID();
            const prefix = (req.body.prefix || 'INC').replace(/[^A-Z0-9-]/gi, '').toUpperCase().slice(0, 12) || 'INC';
            const events = await query<EventRow>(config, sql`
                INSERT INTO dispatcher_events (id, name, prefix, feed_guid, feed_name, created_by)
                VALUES (${id}, ${req.body.name}, ${prefix}, ${req.body.feed_guid}, ${req.body.feed_name}, ${user.email})
                RETURNING id, name, prefix, feed_guid, feed_name, status, seq, created_at, created_by
            `);
            res.json({ event: events[0] });
        } catch (err) {
            Err.respond(err, res);
        }
    });

    await schema.patch('/dispatcher/events/:eventid', {
        name: 'Update Event',
        group: 'Dispatcher',
        description: 'Archive or reactivate an event',
        params: Type.Object({ eventid: Type.String() }),
        body: Type.Object({ status: Type.Union([Type.Literal('active'), Type.Literal('archived')]) }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);
            const events = await query<EventRow>(config, sql`
                UPDATE dispatcher_events SET status = ${req.body.status} WHERE id = ${req.params.eventid}
                RETURNING id, name, prefix, feed_guid, feed_name, status, seq, created_at, created_by
            `);
            if (!events.length) throw new Err(404, null, 'Event not found');
            res.json({ event: events[0] });
        } catch (err) {
            Err.respond(err, res);
        }
    });

    await schema.delete('/dispatcher/events/:eventid', {
        name: 'Delete Event',
        group: 'Dispatcher',
        description: 'Nuke an event and all its incidents (permanent)',
        params: Type.Object({ eventid: Type.String() }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);
            await config.pg.execute(sql`DELETE FROM dispatcher_events WHERE id = ${req.params.eventid}`);
            res.json({ status: 200, message: 'deleted' });
        } catch (err) {
            Err.respond(err, res);
        }
    });

    // ── Incidents ───────────────────────────────────────────────────────────────

    await schema.get('/dispatcher/events/:eventid/incidents', {
        name: 'List Incidents',
        group: 'Dispatcher',
        description: 'List incidents in an event (active + closed)',
        params: Type.Object({ eventid: Type.String() }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);
            const incidents = await query<IncidentRow>(config, sql`
                SELECT id, event_id, number, type, address, lat, lon, dispatcher, details,
                       status, assigned, notes, created_at, closed_at
                FROM dispatcher_incidents WHERE event_id = ${req.params.eventid}
                ORDER BY created_at ASC
            `);
            res.json({ incidents: incidents.map(mapIncident) });
        } catch (err) {
            Err.respond(err, res);
        }
    });

    await schema.post('/dispatcher/events/:eventid/incidents', {
        name: 'Create Incident',
        group: 'Dispatcher',
        description: 'Create an incident in an event (number assigned server-side)',
        params: Type.Object({ eventid: Type.String() }),
        body: Type.Object({
            type: Type.Optional(Type.String()),
            address: Type.Optional(Type.String()),
            lat: Type.Number(),
            lon: Type.Number(),
            dispatcher: Type.Optional(Type.String()),
            details: Type.Optional(Type.String()),
        }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);

            // Atomically claim the next sequence number for this event.
            const bumped = await query<{ seq: number; prefix: string }>(config, sql`
                UPDATE dispatcher_events SET seq = seq + 1 WHERE id = ${req.params.eventid}
                RETURNING seq, prefix
            `);
            if (!bumped.length) throw new Err(404, null, 'Event not found');
            const number = `${bumped[0].prefix}-${String(bumped[0].seq).padStart(3, '0')}`;

            const id = randomUUID();
            const incidents = await query<IncidentRow>(config, sql`
                INSERT INTO dispatcher_incidents
                    (id, event_id, number, type, address, lat, lon, dispatcher, details)
                VALUES
                    (${id}, ${req.params.eventid}, ${number}, ${req.body.type ?? null},
                     ${req.body.address ?? null}, ${req.body.lat}, ${req.body.lon},
                     ${req.body.dispatcher ?? null}, ${req.body.details ?? null})
                RETURNING id, event_id, number, type, address, lat, lon, dispatcher, details,
                          status, assigned, notes, created_at, closed_at
            `);
            res.json({ incident: mapIncident(incidents[0]) });
        } catch (err) {
            Err.respond(err, res);
        }
    });

    await schema.patch('/dispatcher/incidents/:incidentid', {
        name: 'Update Incident',
        group: 'Dispatcher',
        description: 'Update an incident (assign / note / close / reopen)',
        params: Type.Object({ incidentid: Type.String() }),
        body: Type.Object({
            type: Type.Optional(Type.String()),
            address: Type.Optional(Type.String()),
            lat: Type.Optional(Type.Number()),
            lon: Type.Optional(Type.Number()),
            dispatcher: Type.Optional(Type.String()),
            details: Type.Optional(Type.String()),
            status: Type.Optional(Type.Union([Type.Literal('active'), Type.Literal('closed')])),
            assigned: Type.Optional(Type.Array(Type.Any())),
            notes: Type.Optional(Type.Array(Type.Any())),
        }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);

            // Read-modify-write: merge the patch over the current row, then write all columns.
            const current = await query<IncidentRow>(config, sql`
                SELECT id, event_id, number, type, address, lat, lon, dispatcher, details,
                       status, assigned, notes, created_at, closed_at
                FROM dispatcher_incidents WHERE id = ${req.params.incidentid}
            `);
            if (!current.length) throw new Err(404, null, 'Incident not found');
            const cur = current[0];
            const b = req.body;

            const next = {
                type: b.type ?? cur.type,
                address: b.address ?? cur.address,
                lat: b.lat ?? cur.lat,
                lon: b.lon ?? cur.lon,
                dispatcher: b.dispatcher ?? cur.dispatcher,
                details: b.details ?? cur.details,
                status: b.status ?? cur.status,
                assigned: b.assigned ?? asArray(cur.assigned),
                notes: b.notes ?? asArray(cur.notes),
            };
            // Closing stamps closed_at; reopening clears it.
            const closedAt = next.status === 'closed'
                ? (cur.closed_at ?? new Date().toISOString())
                : null;

            const incidents = await query<IncidentRow>(config, sql`
                UPDATE dispatcher_incidents SET
                    type       = ${next.type},
                    address    = ${next.address},
                    lat        = ${next.lat},
                    lon        = ${next.lon},
                    dispatcher = ${next.dispatcher},
                    details    = ${next.details},
                    status     = ${next.status},
                    assigned   = ${JSON.stringify(next.assigned)}::jsonb,
                    notes      = ${JSON.stringify(next.notes)}::jsonb,
                    closed_at  = ${closedAt}
                WHERE id = ${req.params.incidentid}
                RETURNING id, event_id, number, type, address, lat, lon, dispatcher, details,
                          status, assigned, notes, created_at, closed_at
            `);
            res.json({ incident: mapIncident(incidents[0]) });
        } catch (err) {
            Err.respond(err, res);
        }
    });
}
