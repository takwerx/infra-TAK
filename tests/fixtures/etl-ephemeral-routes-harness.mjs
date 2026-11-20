// ops #969 / CloudTAK#2047 test harness: loads the ephemeral route file (argv[2]), registers its two PUT
// routes on a fake schema and calls each handler the way CloudTAK's framework would: the URL parts are
// strings, they are checked against the declared params schema and coerced first (like the api's ajv with
// coerceTypes; checked against the api's own ajv on a real 13.124.0 box), then the handler runs.
// Prints one JSON object. Run by tests/test_cloudtak_etl_layer_save_ops969.py.
const mod = await import(process.argv[2]);
const routes = {};
const schema = { put: async (path, def, handler) => { routes[path] = { def, handler }; } };
const stored = [];
const config = {
    connections: {
        5: { id: 5, owner: 'owner@example.org' },
        7: { id: 7, owner: 'owner@example.org', readonly: true },
    },
    layers: {
        1: { id: 1, connection: null, incoming: {}, outgoing: {} },     // server-wide layer
        2: { id: 2, connection: 5, incoming: {}, outgoing: {} },        // a connection's own layer
        3: { id: 3, connection: null, incoming: {}, outgoing: {} },     // another server-wide layer
        4: { id: 4, connection: 7, incoming: {}, outgoing: {} },        // a layer of a read-only connection
        5: { id: 5, connection: null, incoming: null, outgoing: null }, // server-wide, no incoming or outgoing config
    },
    models: {
        Layer: {
            augmented_from: async (id) => {
                const layer = config.layers[id];
                if (!layer) { const e = new Error('Item Not Found'); e.status = 404; throw Object.assign(e, { status: 404 }); }
                return layer;
            },
        },
        LayerIncoming: { commit: async (id, v) => { stored.push(['incoming', id, v.ephemeral]); return { ephemeral: v.ephemeral }; } },
        LayerOutgoing: { commit: async (id, v) => { stored.push(['outgoing', id, v.ephemeral]); return { ephemeral: v.ephemeral }; } },
    },
};
await mod.default(schema, config);

// what ajv does with one declared param: coerce a numeric string for an integer, compare a literal
function check(def, value) {
    if (def.kind === 'integer') {
        if (typeof value !== 'string' || !/^\d+$/.test(value)) return { ok: false };
        const n = Number(value);
        return n >= (def.minimum ?? -Infinity) ? { ok: true, value: n } : { ok: false };
    }
    if (def.kind === 'literal') return value === def.const ? { ok: true, value } : { ok: false };
    if (def.kind === 'union') {
        for (const b of def.anyOf) { const r = check(b, value); if (r.ok) return r; }
        return { ok: false };
    }
    return { ok: false };
}
function call(path, urlParams, auth) {
    return new Promise((resolve) => {
        const params = {};
        for (const k of Object.keys(urlParams)) {
            const r = check(routes[path].def.params[k], urlParams[k]);
            if (!r.ok) return resolve({ code: 400, message: 'Validation Error ' + k });
            params[k] = r.value;
        }
        const res = {
            status(c) { this.code = c; return this; },
            json(b) { resolve({ code: this.code || 200, message: (b && b.message) || 'ok' }); },
        };
        routes[path].handler({ params, auth, body: { session: 'abc' } }, res);
    });
}
const admin = { kind: 'user', access: 'admin', email: 'admin@example.org' };
const agency = { kind: 'user', access: 'agency', email: 'agency@example.org' };
const owner = { kind: 'user', access: 'user', email: 'owner@example.org' };
const layerTok = (id) => ({ kind: 'resource', access: 'layer', id });
const connTok = (id) => ({ kind: 'resource', access: 'connection', id });
const results = {};
for (const kind of ['incoming', 'outgoing']) {
    const p = '/connection/:connectionid/layer/:layerid/' + kind + '/ephemeral';
    const n0 = stored.length;
    const r = {
        connectionid_schema: routes[p].def.params.connectionid,
        // the ETL library's own call: the word null in the URL, the layer's own ETL token
        etl_token_null: await call(p, { connectionid: 'null', layerid: '1' }, layerTok(1)),
        stored_after_etl_token_null: stored.slice(n0).map((s) => s.slice(0, 2).join(':')),
        etl_token_zero: await call(p, { connectionid: '0', layerid: '1' }, layerTok(1)),
        admin_null: await call(p, { connectionid: 'null', layerid: '1' }, admin),
        // never
        anonymous_null: await call(p, { connectionid: 'null', layerid: '1' }, undefined),
        user_null: await call(p, { connectionid: 'null', layerid: '1' }, owner),
        agency_admin_null: await call(p, { connectionid: 'null', layerid: '1' }, agency),
        other_layer_token_null: await call(p, { connectionid: 'null', layerid: '1' }, layerTok(3)),
        connection_token_null: await call(p, { connectionid: 'null', layerid: '1' }, connTok(5)),
        connection_token_zero: await call(p, { connectionid: '0', layerid: '1' }, connTok(5)),
        admin_connection_layer_null: await call(p, { connectionid: 'null', layerid: '2' }, admin),
        etl_token_connection_layer_null: await call(p, { connectionid: 'null', layerid: '2' }, layerTok(2)),
        no_config_null: await call(p, { connectionid: 'null', layerid: '5' }, admin),
        bad_words: [await call(p, { connectionid: 'NULL', layerid: '1' }, admin),
                    await call(p, { connectionid: 'abc', layerid: '1' }, admin),
                    await call(p, { connectionid: '-1', layerid: '1' }, admin),
                    await call(p, { connectionid: '', layerid: '1' }, admin)],
        // a connection's own layers: as before
        conn_etl_token: await call(p, { connectionid: '5', layerid: '2' }, layerTok(2)),
        conn_owner: await call(p, { connectionid: '5', layerid: '2' }, owner),
        conn_other_user: await call(p, { connectionid: '5', layerid: '2' }, { kind: 'user', access: 'user', email: 'x@example.org' }),
        conn_wrong_layer: await call(p, { connectionid: '5', layerid: '1' }, admin),
        conn_etl_token_other_connection: await call(p, { connectionid: '6', layerid: '2' }, layerTok(2)),
        conn_readonly: await call(p, { connectionid: '7', layerid: '4' }, layerTok(4)),
        conn_connection_token: await call(p, { connectionid: '5', layerid: '2' }, connTok(5)),
    };
    results[kind] = r;
}
console.log(JSON.stringify(results));
