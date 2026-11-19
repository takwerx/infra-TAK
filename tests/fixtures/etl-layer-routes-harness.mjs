// ops #969 test harness: loads a route file (argv[2]), registers its two PATCH routes on a fake schema
// and calls each handler the way CloudTAK's framework would (params checked against the declared
// minimum first). Prints one JSON object. Run by tests/test_cloudtak_etl_layer_save_ops969.py.
const mod = await import(process.argv[2]);
const routes = {};
const schema = { patch: async (path, def, handler) => { routes[path] = { def, handler }; } };
const config = {
    connections: { 5: { id: 5, owner: 'owner@example.org' } },
    layers: {
        1: { id: 1, connection: null, incoming: {}, outgoing: {} },   // server-wide layer
        2: { id: 2, connection: 5, incoming: {}, outgoing: {} },      // a connection's own layer
    },
};
await mod.default(schema, config);
function call(path, params, user) {
    return new Promise((resolve) => {
        const min = routes[path].def.params.connectionid.minimum;
        if (params.connectionid < min) return resolve({ code: 400, message: 'validation: connectionid must be >= ' + min });
        const res = {
            status(c) { this.code = c; return this; },
            json(b) { resolve({ code: this.code || 200, message: b.message || 'ok' }); },
        };
        routes[path].handler({ params, user, body: {} }, res);
    });
}
const admin = { access: 'admin', email: 'admin@example.org' };
const owner = { access: 'user', email: 'owner@example.org' };
const other = { access: 'user', email: 'other@example.org' };
const results = {};
for (const kind of ['incoming', 'outgoing']) {
    const p = '/connection/:connectionid/layer/:layerid/' + kind;
    results[kind] = {
        minimum: routes[p].def.params.connectionid.minimum,
        admin_server_wide: await call(p, { connectionid: 0, layerid: 1 }, admin),
        user_server_wide: await call(p, { connectionid: 0, layerid: 1 }, owner),
        anonymous_server_wide: await call(p, { connectionid: 0, layerid: 1 }, null),
        admin_other_layer_on_0: await call(p, { connectionid: 0, layerid: 2 }, admin),
        owner_own_layer: await call(p, { connectionid: 5, layerid: 2 }, owner),
        other_user_own_layer: await call(p, { connectionid: 5, layerid: 2 }, other),
        owner_wrong_layer: await call(p, { connectionid: 5, layerid: 1 }, owner),
    };
}
console.log(JSON.stringify(results));
