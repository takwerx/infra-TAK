// Copy of CloudTAK 13.124.0 dist/stateless/routes/connection-layer-ephemeral.js (ops #969, infra-TAK #589,
// dfpc-coe/CloudTAK#2047). Verbatim except the four imports, which become the stubs below so the file loads
// on its own. The Auth stub copies the logic of CloudTAK's Auth.is_auth, Auth.as_user and
// Auth.is_connection (13.124.0 dist/common/auth.js), including that a resource with id 0 matches any token
// of that kind. This is the text infra-TAK's ETL layer fix edits.
const Type = {
    Object: (o) => o,
    Integer: (o) => ({ kind: 'integer', ...o }),
    Union: (a) => ({ kind: 'union', anyOf: a }),
    Literal: (v) => ({ kind: 'literal', const: v }),
    String: () => ({ kind: 'string' }),
    Record: () => ({ kind: 'record' }),
    Any: () => ({ kind: 'any' }),
};
class Err extends Error {
    constructor(status, _err, message) { super(message); this.status = status; }
    static respond(err, res) { res.status(err.status || 500).json({ message: err.message }); }
}
const AuthResourceAccess = { CONNECTION: 'connection', LAYER: 'layer' };
const Auth = {
    security: () => ({}),
    // req.auth: { kind: 'user', access, email } | { kind: 'resource', access, id } | undefined
    is_auth: async (_config, req, opts = {}) => {
        const auth = req.auth;
        if (!auth) throw new Err(401, null, 'No Auth Present');
        if (auth.kind === 'resource' && opts.resources && !opts.resources.some((r) => {
            if (r.id) return r.access === auth.access && r.id === auth.id;
            else return r.access === auth.access;
        })) throw new Err(403, null, 'Resource token cannot access this resource');
        return auth;
    },
    as_user: async (_config, req, opts = {}) => {
        const auth = req.auth;
        if (!auth) throw new Err(401, null, 'No Auth Present');
        if (auth.kind === 'resource') throw new Err(401, null, 'Only an authenticated user can access this resource');
        if (opts.admin && auth.access !== 'admin') throw new Err(401, null, 'User must be a System Administrator to access this resource');
        return auth;
    },
    is_connection: async (config, req, opts, connectionid) => {
        const auth = await Auth.is_auth(config, req, opts);
        const connection = config.connections[connectionid];
        if (!connection) throw new Err(404, null, 'Item Not Found');
        if (auth.kind === 'user') {
            if (auth.access === 'admin' || connection.owner === auth.email) return { connection, auth };
            throw new Err(401, null, 'Only a System Admin can access this connection');
        }
        else if (auth.access === 'layer') {
            const layer = config.layers[auth.id];
            if (!layer || layer.connection !== connectionid) throw new Err(401, null, 'Layer does not belong to this Connection');
            return { auth, connection, layer };
        }
        return { auth, connection };
    },
};
const sql = () => 'Now()';
export default async function router(schema, config) {
    await schema.put('/connection/:connectionid/layer/:layerid/incoming/ephemeral', {
        name: 'Incoming Ephemeral',
        group: 'LayerEphemeral',
        description: 'Store ephemeral values',
        params: Type.Object({
            connectionid: Type.Integer({ minimum: 1 }),
            layerid: Type.Integer({ minimum: 1 }),
        }),
        body: Type.Record(Type.String(), Type.Any()),
        res: Type.Record(Type.String(), Type.Any()),
        security: Auth.security({ resources: [AuthResourceAccess.CONNECTION, AuthResourceAccess.LAYER] }),
    }, async (req, res) => {
        try {
            const { connection } = await Auth.is_connection(config, req, {
                resources: [
                    { access: AuthResourceAccess.CONNECTION, id: req.params.connectionid },
                    { access: AuthResourceAccess.LAYER, id: req.params.layerid },
                ],
            }, req.params.connectionid);
            if (connection.readonly)
                throw new Err(400, null, 'Connection is Read-Only mode');
            const layer = await config.models.Layer.augmented_from(req.params.layerid);
            if (layer.connection !== connection.id) {
                throw new Err(400, null, 'Layer does not belong to this connection');
            }
            else if (!layer.incoming) {
                throw new Err(400, null, 'Layer does not have incoming config');
            }
            const incoming = await config.models.LayerIncoming.commit(req.params.layerid, {
                updated: sql `Now()`,
                ephemeral: req.body,
            });
            res.json(incoming.ephemeral);
        }
        catch (err) {
            Err.respond(err, res);
        }
    });
    await schema.put('/connection/:connectionid/layer/:layerid/outgoing/ephemeral', {
        name: 'Outgoing Ephemeral',
        group: 'LayerEphemeral',
        description: 'Store ephemeral values',
        params: Type.Object({
            connectionid: Type.Integer({ minimum: 1 }),
            layerid: Type.Integer({ minimum: 1 }),
        }),
        body: Type.Record(Type.String(), Type.Any()),
        res: Type.Record(Type.String(), Type.Any()),
        security: Auth.security({ resources: [AuthResourceAccess.CONNECTION, AuthResourceAccess.LAYER] }),
    }, async (req, res) => {
        try {
            const { connection } = await Auth.is_connection(config, req, {
                resources: [
                    { access: AuthResourceAccess.CONNECTION, id: req.params.connectionid },
                    { access: AuthResourceAccess.LAYER, id: req.params.layerid },
                ],
            }, req.params.connectionid);
            if (connection.readonly)
                throw new Err(400, null, 'Connection is Read-Only mode');
            const layer = await config.models.Layer.augmented_from(req.params.layerid);
            if (layer.connection !== connection.id) {
                throw new Err(400, null, 'Layer does not belong to this connection');
            }
            else if (!layer.outgoing) {
                throw new Err(400, null, 'Layer does not have outgoing config');
            }
            const outgoing = await config.models.LayerOutgoing.commit(req.params.layerid, {
                updated: sql `Now()`,
                ephemeral: req.body,
            });
            res.json(outgoing.ephemeral);
        }
        catch (err) {
            Err.respond(err, res);
        }
    });
}
//# sourceMappingURL=connection-layer-ephemeral.js.map