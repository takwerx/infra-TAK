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

const TAKCAD_BASE = '/Marti/api/plugins/takcad/submit';

export default async function router(schema: Schema, config: Config) {
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

            const data = await api.fetch(new URL(`${TAKCAD_BASE}?${params.toString()}`, String(config.server.api)), { method: 'GET' });
            res.json(data);
        } catch (err) {
            Err.respond(err, res);
        }
    });

    // PUT — insertIncident, updateIncident, insertVehicle, etc. (JSON body)
    await schema.put('/marti/plugins/takcad/submit/result', {
        name: 'TAK-CAD PUT',
        group: 'TAKCAD',
        description: 'Proxy a TAK-CAD write (fn) to TAK Server using client-cert auth',
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

            const data = await api.fetch(new URL(`${TAKCAD_BASE}?${params.toString()}`, String(config.server.api)), { method: 'DELETE' });
            res.json(data ?? { status: 200, message: 'deleted' });
        } catch (err) {
            Err.respond(err, res);
        }
    });
}
