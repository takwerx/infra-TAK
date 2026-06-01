import { Type } from '@sinclair/typebox';
import Schema from '@openaddresses/batch-schema';
import Err from '@openaddresses/batch-error';
import Auth from '../lib/auth.js';
import Config from '../lib/config.js';
import { TAKAPI, APIAuthCertificate } from '@tak-ps/node-tak';

// Server-side proxy for the TAK-CAD TAK Server plugin.
//
// The CloudTAK web plugin (api/web/plugins/takcad) runs in the browser and can
// only reach CloudTAK's own /api routes. CloudTAK has no generic passthrough to
// arbitrary /Marti/api/plugins/* endpoints, so this route forwards TAK-CAD calls
// to TAK Server using the caller's client-certificate auth (via TAKAPI.fetch).
//
// Auto-loaded by CloudTAK's schema.load('./routes/'). Installed and kept in
// place across CloudTAK updates by the infra-TAK plugin installer.

// TAK Server's plugin data API (DistributedPluginManager.requestDataFromPlugin)
// looks the plugin up by its fully-qualified class name, NOT a short alias.
// Path segment 'takcad' → "no plugin with class name takcad is currently installed".
const TAKCAD_BASE = '/Marti/api/plugins/tak.server.plugins.TakCadServerPlugin/submit';

// OpenRouteService geocoding key (from the TAK-CAD alpha release docs). Kept
// server-side so it's not shipped in the browser bundle.
const ORS_KEY = '5b3ce3597851110001cf62488c4f8dccd2cc447aa974115095a2e6e4';

// Map an ORS geocode feature to a TAK-CAD suggestion (label, coords + parsed address).
type OrsFeature = { geometry: { coordinates: number[] }; properties: Record<string, string> };
function orsToSuggestion(f: OrsFeature) {
    const p = f.properties || {};
    const street = [p.housenumber, p.street].filter(Boolean).join(' ');
    return {
        label: p.label || '',
        lon: f.geometry.coordinates[0],
        lat: f.geometry.coordinates[1],
        streetName: street || p.name || '',
        city: p.locality || p.localadmin || p.county || '',
        state: p.region_a || p.region || '',
        zipCode: p.postalcode || '',
        country: p.country || '',
    };
}

export default async function router(schema: Schema, config: Config) {
    // Forward geocode — CloudTAK's CSP (connect-src 'self') blocks the browser from
    // calling openrouteservice.org directly, so proxy it through the API host.
    await schema.get('/takcad/geocode', {
        name: 'TAK-CAD Geocode',
        group: 'TAKCAD',
        description: 'Proxy an address geocode lookup to OpenRouteService',
        query: Type.Object({
            q: Type.String(),
        }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);

            const qs = new URLSearchParams({ api_key: ORS_KEY, text: String(req.query.q), size: '5' });
            const r = await fetch(`https://api.openrouteservice.org/geocode/search?${qs.toString()}`);
            if (!r.ok) {
                res.json({ suggestions: [] });
                return;
            }
            const json = await r.json() as { features?: OrsFeature[] };
            res.json({ suggestions: (json.features ?? []).map(orsToSuggestion) });
        } catch (err) {
            Err.respond(err, res);
        }
    });

    // Reverse geocode — turn a map-clicked lat/lon into an address (for "pick on map").
    await schema.get('/takcad/geocode/reverse', {
        name: 'TAK-CAD Reverse Geocode',
        group: 'TAKCAD',
        description: 'Proxy a reverse geocode (lat/lon → address) to OpenRouteService',
        query: Type.Object({
            lat: Type.Number(),
            lon: Type.Number(),
        }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);

            const qs = new URLSearchParams({
                'api_key': ORS_KEY,
                'point.lat': String(req.query.lat),
                'point.lon': String(req.query.lon),
                'size': '1',
            });
            const r = await fetch(`https://api.openrouteservice.org/geocode/reverse?${qs.toString()}`);
            if (!r.ok) {
                res.json({ suggestion: null });
                return;
            }
            const json = await r.json() as { features?: OrsFeature[] };
            const f = (json.features ?? [])[0];
            res.json({ suggestion: f ? orsToSuggestion(f) : null });
        } catch (err) {
            Err.respond(err, res);
        }
    });

    // POST a CoT event to TAK Server using client-cert auth.
    // The browser plugin can't post XML via raw fetch (no auth) or std() (JSON only),
    // so this proxy accepts JSON, builds CoT XML, and forwards via TAKAPI.fetch().
    await schema.post('/takcad/cot', {
        name: 'Dispatcher CoT',
        group: 'TAKCAD',
        description: 'Post a CoT marker to TAK Server on behalf of the dispatcher plugin',
        body: Type.Object({
            uid: Type.String(),
            name: Type.String(),
            type: Type.String(),
            address: Type.String(),
            lat: Type.Number(),
            lon: Type.Number(),
            remarks: Type.Optional(Type.String()),
            deleteMarker: Type.Optional(Type.Boolean()),
        }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);
            const user = await Auth.as_user(config, req);
            const profile = await config.models.Profile.from(user.email);
            const api = await TAKAPI.init(new URL(String(config.server.api)), new APIAuthCertificate(profile.auth.cert, profile.auth.key));

            const now = new Date().toISOString();
            const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            const b = req.body as { uid: string; name: string; type: string; address: string; lat: number; lon: number; remarks?: string; deleteMarker?: boolean };
            const stale = b.deleteMarker
                ? new Date(Date.now() - 1000).toISOString()
                : new Date(Date.now() + 3600_000).toISOString();
            const remarks = esc(b.remarks ?? `${b.type}${b.address ? ' — ' + b.address : ''}`);
            const xml = [
                `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`,
                `<event version="2.0" uid="${esc(b.uid)}" type="a-u-G" how="h-g-i-g-o"`,
                ` time="${now}" start="${now}" stale="${stale}">`,
                `<point lat="${b.lat}" lon="${b.lon}" hae="0" ce="9999999" le="9999999"/>`,
                `<detail>`,
                `<contact callsign="${esc(b.name)}"/>`,
                `<remarks>${remarks}</remarks>`,
                `</detail>`,
                `</event>`,
            ].join('');

            await api.fetch(new URL('/Marti/api/cot/xml', String(config.server.api)), {
                method: 'POST',
                headers: { 'Content-Type': 'application/xml' },
                body: xml,
            });
            res.json({ status: 200 });
        } catch (err) {
            Err.respond(err, res);
        }
    });

    // GET — getIncidents, getIncidentMetadata, getIncident, getVehicles, etc.
    await schema.get('/marti/plugins/takcad/submit', {
        name: 'TAK-CAD GET',
        group: 'TAKCAD',
        description: 'Proxy a TAK-CAD read (fn) to TAK Server using client-cert auth',
        query: Type.Object({
            fn: Type.String(),
            uid: Type.Optional(Type.String()),
            connection: Type.Optional(Type.Integer()),
        }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);

            let api;
            if (req.query.connection) {
                const connection = await config.models.Connection.from(parseInt(String(req.query.connection)));
                api = await TAKAPI.init(new URL(String(config.server.api)), new APIAuthCertificate(connection.auth.cert, connection.auth.key));
            } else {
                const user = await Auth.as_user(config, req);
                const profile = await config.models.Profile.from(user.email);
                api = await TAKAPI.init(new URL(String(config.server.api)), new APIAuthCertificate(profile.auth.cert, profile.auth.key));
            }

            const params = new URLSearchParams();
            params.set('fn', String(req.query.fn));
            if (req.query.uid) params.set('uid', String(req.query.uid));

            // TAK Server's DistributedPluginManager requires a non-null Accept
            // header ("accept must be specified") — node-tak sends none by default.
            const data = await api.fetch(new URL(`${TAKCAD_BASE}?${params.toString()}`, String(config.server.api)), { method: 'GET', headers: { Accept: 'application/json' } });
            res.json(data);
        } catch (err) {
            Err.respond(err, res);
        }
    });

    // POST — updateIncident, updateVehicle, updatePerson (JSON body).
    // Updates route through TAK Server's updateInPlugin (onUpdateData), which is
    // POST /submit (NOT /submit/result — that's onSubmitDataWithResult, inserts only)
    // and requires the uid as a query param ("Cannot process request, missing uid").
    await schema.post('/marti/plugins/takcad/submit', {
        name: 'TAK-CAD POST (update)',
        group: 'TAKCAD',
        description: 'Proxy a TAK-CAD update (fn + uid) to TAK Server using client-cert auth',
        query: Type.Object({
            fn: Type.String(),
            uid: Type.String(),
            connection: Type.Optional(Type.Integer()),
        }),
        body: Type.Record(Type.String(), Type.Any()),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);

            let api;
            if (req.query.connection) {
                const connection = await config.models.Connection.from(parseInt(String(req.query.connection)));
                api = await TAKAPI.init(new URL(String(config.server.api)), new APIAuthCertificate(connection.auth.cert, connection.auth.key));
            } else {
                const user = await Auth.as_user(config, req);
                const profile = await config.models.Profile.from(user.email);
                api = await TAKAPI.init(new URL(String(config.server.api)), new APIAuthCertificate(profile.auth.cert, profile.auth.key));
            }

            const params = new URLSearchParams();
            params.set('fn', String(req.query.fn));
            params.set('uid', String(req.query.uid));

            const data = await api.fetch(new URL(`${TAKCAD_BASE}?${params.toString()}`, String(config.server.api)), {
                method: 'POST',
                headers: { Accept: 'application/json' },
                body: req.body,
            });
            res.json(data);
        } catch (err) {
            Err.respond(err, res);
        }
    });

    // PUT — insertIncident, insertVehicle, insertPerson, etc. (JSON body)
    await schema.put('/marti/plugins/takcad/submit/result', {
        name: 'TAK-CAD PUT',
        group: 'TAKCAD',
        description: 'Proxy a TAK-CAD insert (fn) to TAK Server using client-cert auth',
        query: Type.Object({
            fn: Type.String(),
            connection: Type.Optional(Type.Integer()),
        }),
        body: Type.Record(Type.String(), Type.Any()),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);

            let api;
            if (req.query.connection) {
                const connection = await config.models.Connection.from(parseInt(String(req.query.connection)));
                api = await TAKAPI.init(new URL(String(config.server.api)), new APIAuthCertificate(connection.auth.cert, connection.auth.key));
            } else {
                const user = await Auth.as_user(config, req);
                const profile = await config.models.Profile.from(user.email);
                api = await TAKAPI.init(new URL(String(config.server.api)), new APIAuthCertificate(profile.auth.cert, profile.auth.key));
            }

            const data = await api.fetch(new URL(`${TAKCAD_BASE}/result?fn=${encodeURIComponent(String(req.query.fn))}`, String(config.server.api)), {
                method: 'PUT',
                headers: { Accept: 'application/json' },
                body: req.body,
            });
            res.json(data);
        } catch (err) {
            Err.respond(err, res);
        }
    });

    // DELETE — deleteIncident, deleteVehicle, deletePerson, etc.
    await schema.delete('/marti/plugins/takcad/submit', {
        name: 'TAK-CAD DELETE',
        group: 'TAKCAD',
        description: 'Proxy a TAK-CAD delete (fn + uid) to TAK Server using client-cert auth',
        query: Type.Object({
            fn: Type.String(),
            uid: Type.String(),
            connection: Type.Optional(Type.Integer()),
        }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);

            let api;
            if (req.query.connection) {
                const connection = await config.models.Connection.from(parseInt(String(req.query.connection)));
                api = await TAKAPI.init(new URL(String(config.server.api)), new APIAuthCertificate(connection.auth.cert, connection.auth.key));
            } else {
                const user = await Auth.as_user(config, req);
                const profile = await config.models.Profile.from(user.email);
                api = await TAKAPI.init(new URL(String(config.server.api)), new APIAuthCertificate(profile.auth.cert, profile.auth.key));
            }

            const params = new URLSearchParams();
            params.set('fn', String(req.query.fn));
            params.set('uid', String(req.query.uid));

            const data = await api.fetch(new URL(`${TAKCAD_BASE}?${params.toString()}`, String(config.server.api)), { method: 'DELETE', headers: { Accept: 'application/json' } });
            res.json(data ?? { status: 200, message: 'deleted' });
        } catch (err) {
            Err.respond(err, res);
        }
    });
}
