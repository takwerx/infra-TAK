// Trimmed copy of CloudTAK 13.124.0 dist/stateless/routes/connection-layer.js (ops #969, infra-TAK #589).
// The two "Update ... layer configuration" routes are verbatim down to the layer lookup, because that is
// the text infra-TAK's ETL layer fix edits. Everything before and after is cut or stubbed so the file
// loads on its own: the imports become the stubs below, the handlers end with res.json().
const Type = {
    Integer: (o) => ({ kind: 'integer', ...o }),
    Object: (o) => o,
    Optional: (o) => o,
    Boolean: () => ({ kind: 'boolean' }),
    Union: () => ({ kind: 'union' }),
    Null: () => ({ kind: 'null' }),
    String: () => ({ kind: 'string' }),
    Any: () => ({ kind: 'any' }),
};
class Err extends Error {
    constructor(status, _err, message) { super(message); this.status = status; }
    static respond(err, res) { res.status(err.status || 500).json({ message: err.message }); }
}
const AuthResourceAccess = { CONNECTION: 'connection', LAYER: 'layer' };
const Auth = {
    security: () => ({}),
    // admin only, like CloudTAK's Auth.as_user(config, req, { admin: true })
    as_user: async (_config, req, opts) => {
        if (!req.user) throw new Err(401, null, 'Authentication Required');
        if (opts && opts.admin && req.user.access !== 'admin') throw new Err(403, null, 'Admin Required');
        return req.user;
    },
    // a connection owner, or an admin, like CloudTAK's Auth.is_connection
    is_connection: async (config, req, _opts, id) => {
        if (!req.user) throw new Err(401, null, 'Authentication Required');
        const connection = config.connections[id];
        if (!connection) throw new Err(404, null, 'Item Not Found');
        if (req.user.access !== 'admin' && connection.owner !== req.user.email) throw new Err(403, null, 'Forbidden');
        return { connection };
    },
};
const EmailSenders = {}, StyleContainer = {}, Layer_Config = {}, FilterContainer = {};
const LayerIncomingResponse = {}, LayerOutgoingResponse = {};
export default async function router(schema, config) {
    const layerControl = {
        from: async (connection, id) => {
            const layer = config.layers[id];
            if (!layer) throw new Err(404, null, 'Item Not Found');
            return layer;
        },
    };
    await schema.patch('/connection/:connectionid/layer/:layerid/incoming', {
        name: 'Update Incoming',
        group: 'Layer',
        description: 'Update an incoming layer configuration',
        params: Type.Object({
            connectionid: Type.Integer({ minimum: 1 }),
            layerid: Type.Integer({ minimum: 1 }),
        }),
        body: Type.Object({
            webhooks: Type.Optional(Type.Boolean()),
            email: Type.Optional(Type.Boolean()),
            email_senders: Type.Optional(EmailSenders),
            cron: Type.Optional(Type.Union([Type.Null(), Type.String()])),
            enabled_styles: Type.Optional(Type.Boolean()),
            styles: Type.Optional(StyleContainer),
            stale: Type.Optional(Type.Integer()),
            data: Type.Optional(Type.Union([Type.Null(), Type.Integer()])),
            environment: Type.Optional(Type.Any()),
            config: Type.Optional(Layer_Config),
        }),
        res: LayerIncomingResponse,
        security: Auth.security({ resources: [AuthResourceAccess.CONNECTION, AuthResourceAccess.LAYER] }),
    }, async (req, res) => {
        try {
            const { connection } = await Auth.is_connection(config, req, {
                resources: [
                    { access: AuthResourceAccess.CONNECTION, id: req.params.connectionid },
                    { access: AuthResourceAccess.LAYER, id: req.params.layerid },
                ],
            }, req.params.connectionid);
            const layer = await layerControl.from(connection, req.params.layerid);
            if (layer.connection !== connection.id) {
                throw new Err(400, null, 'Layer does not belong to this connection');
            }
            else if (!layer.incoming) {
                throw new Err(400, null, 'Layer does not have incoming config');
            }
            res.json({ ok: true, layer: layer.id });
        }
        catch (err) {
            Err.respond(err, res);
        }
    });
    await schema.patch('/connection/:connectionid/layer/:layerid/outgoing', {
        name: 'Update Outgoing',
        group: 'Layer',
        description: 'Update an outgoing layer configuration',
        params: Type.Object({
            connectionid: Type.Integer({ minimum: 1 }),
            layerid: Type.Integer({ minimum: 1 }),
        }),
        body: Type.Object({
            environment: Type.Optional(Type.Any()),
            filters: Type.Optional(FilterContainer),
        }),
        res: LayerOutgoingResponse,
        security: Auth.security({ resources: [AuthResourceAccess.CONNECTION, AuthResourceAccess.LAYER] }),
    }, async (req, res) => {
        try {
            const { connection } = await Auth.is_connection(config, req, {
                resources: [
                    { access: AuthResourceAccess.CONNECTION, id: req.params.connectionid },
                    { access: AuthResourceAccess.LAYER, id: req.params.layerid },
                ],
            }, req.params.connectionid);
            const layer = await layerControl.from(connection, req.params.layerid);
            if (!layer.outgoing) {
                throw new Err(400, null, 'Layer does not have outgoing config');
            }
            res.json({ ok: true, layer: layer.id });
        }
        catch (err) {
            Err.respond(err, res);
        }
    });
}
