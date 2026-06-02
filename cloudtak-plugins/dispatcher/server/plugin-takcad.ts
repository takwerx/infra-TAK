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

// Nominatim (OpenStreetMap) geocoding — no API key required, better US address coverage.
const NOMINATIM_BASE = 'https://nominatim.openstreetmap.org';
const NOMINATIM_HEADERS = { 'User-Agent': 'infra-TAK-dispatcher/1.0 (contact@takwerx.com)' };

type NominatimFeature = {
    display_name: string;
    lat: string;
    lon: string;
    address: Record<string, string>;
};

function nominatimToSuggestion(f: NominatimFeature) {
    const a = f.address || {};
    const street = [a.house_number, a.road || a.pedestrian || a.footway || a.path].filter(Boolean).join(' ');
    return {
        label: f.display_name || '',
        lat: parseFloat(f.lat),
        lon: parseFloat(f.lon),
        streetName: street || '',
        city: a.city || a.town || a.village || a.hamlet || a.county || '',
        state: a.state || '',
        zipCode: a.postcode || '',
        country: a.country || '',
    };
}

export default async function router(schema: Schema, config: Config) {
    // Forward geocode — CloudTAK's CSP (connect-src 'self') blocks the browser from
    // calling openrouteservice.org directly, so proxy it through the API host.
    await schema.get('/takcad/geocode', {
        name: 'TAK-CAD Geocode',
        group: 'TAKCAD',
        description: 'Proxy an address geocode lookup to Nominatim (OpenStreetMap)',
        query: Type.Object({
            q: Type.String(),
        }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);

            const qs = new URLSearchParams({ q: String(req.query.q), format: 'json', addressdetails: '1', limit: '5' });
            const r = await fetch(`${NOMINATIM_BASE}/search?${qs.toString()}`, { headers: NOMINATIM_HEADERS });
            if (!r.ok) {
                res.json({ suggestions: [] });
                return;
            }
            const json = await r.json() as NominatimFeature[];
            res.json({ suggestions: (Array.isArray(json) ? json : []).map(nominatimToSuggestion) });
        } catch (err) {
            Err.respond(err, res);
        }
    });

    // Reverse geocode — turn a map-clicked lat/lon into an address (for "pick on map").
    await schema.get('/takcad/geocode/reverse', {
        name: 'TAK-CAD Reverse Geocode',
        group: 'TAKCAD',
        description: 'Proxy a reverse geocode (lat/lon → address) to Nominatim (OpenStreetMap)',
        query: Type.Object({
            lat: Type.Number(),
            lon: Type.Number(),
        }),
        res: Type.Any(),
    }, async (req, res) => {
        try {
            await Auth.is_auth(config, req);

            const qs = new URLSearchParams({ lat: String(req.query.lat), lon: String(req.query.lon), format: 'json', addressdetails: '1' });
            const r = await fetch(`${NOMINATIM_BASE}/reverse?${qs.toString()}`, { headers: NOMINATIM_HEADERS });
            if (!r.ok) {
                res.json({ suggestion: null });
                return;
            }
            const f = await r.json() as NominatimFeature;
            res.json({ suggestion: f && f.lat ? nominatimToSuggestion(f) : null });
        } catch (err) {
            Err.respond(err, res);
        }
    });

    // NOTE: Incident map markers are NOT posted via this server route. TAK Server has
    // no REST CoT-injection endpoint (POST /Marti/api/cot/xml → 404), and a raw CoT
    // does not persist into a DataSync mission. Instead the plugin draws markers
    // browser-side via mapStore.worker.db.add() with a Mission origin (see
    // plugin/lib/map-marker.ts) — the same supported mechanism the ping plugin uses.

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
