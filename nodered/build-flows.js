#!/usr/bin/env node
const fs   = require('fs');
const path = require('path');

const html    = fs.readFileSync(path.join(__dirname, 'configurator.html'), 'utf8');
const CFG_TAB = 'flow_arcgis_cfg';

// Shared snippet: write a timestamped backup of all config keys to /data/config-backups/
// on the Docker volume immediately after any save operation.
// Coerce any global.get() result into a clean array. Handles three rotten formats:
//   1) localfilesystem REST envelope: { msg: "[]", format: "..." }
//   2) double-serialized strings:     "[]"
//   3) anything non-array (null, {}, undefined) → []
// This MUST be used in every fn_save/fn_delete/fn_*_save before calling
// .findIndex / .push / .filter on configs, otherwise function nodes throw
// TypeError, never return msg, and the http-in request hangs forever.
const ARRAY_GUARD = [
  "function _coerceArr(_v) {",
  "  if (_v && typeof _v === 'object' && !Array.isArray(_v) && 'msg' in _v) {",
  "    var _m = _v.msg;",
  "    if (typeof _m === 'string') { try { _v = JSON.parse(_m); } catch(_e) { _v = []; } }",
  "    else _v = _m;",
  "  }",
  "  if (typeof _v === 'string') { try { _v = JSON.parse(_v); } catch(_e) { _v = []; } }",
  "  return Array.isArray(_v) ? _v : [];",
  "}"
].join('\n');

// Backup stored directly in global context (no fs/filesystem needed).
// With localfilesystem context storage it persists to /data/context/global/global.json automatically.
const CFG_BACKUP_SNIPPET = [
  "try {",
  "  function _parseForSnap(v){if(v&&typeof v==='object'&&!Array.isArray(v)&&'msg'in v){var m=v.msg;if(typeof m==='string'){try{return JSON.parse(m);}catch(e){return m;}}return m;}if(typeof v==='string'){try{return JSON.parse(v);}catch(e){return v;}}return v;}",
  "  var _snap = {",
  "    timestamp:         new Date().toISOString(),",
  "    arcgis_configs:    _parseForSnap(global.get('arcgis_configs'))    || [],",
  "    tc_configs:        _parseForSnap(global.get('tc_configs'))        || [],",
  "    tak_settings:      _parseForSnap(global.get('tak_settings'))      || {},",
  "    ipaws_config:      _parseForSnap(global.get('ipaws_config'))      || {},",
  "    pp_configs:        _parseForSnap(global.get('pp_configs'))        || []",
  "  };",
  "  // Keep rolling list of up to 10 snapshots in context (no fs required)",
  "  var _hist = global.get('ctx_backups') || [];",
  "  if (!Array.isArray(_hist)) _hist = [];",
  "  _hist.unshift(_snap);",
  "  if (_hist.length > 10) _hist = _hist.slice(0, 10);",
  "  global.set('ctx_backups', _hist);",
  "} catch(_be) { node.warn('Config backup failed: '+_be.message); }"
].join('\n');

// ╔══════════════════════════════════════════════════════════════╗
// ║  FEEDS — STATIC ArcGIS engine tabs in the shipped flows.   ║
// ║  Leave EMPTY. Do not ship named feeds (e.g. CA AIR INTEL) in ║
// ║  the repo — every box would get those tabs. Add feeds via   ║
// ║  the ArcGIS Configurator (dynamic tabs merged on deploy).   ║
// ╚══════════════════════════════════════════════════════════════╝
const FEEDS = [];

/** Configurator POST /arcgis-tak/kml/fetch — discover attribute keys from KML (same parse rules as engine). */
const FN_KML_FETCH_FIELDS = [
  "var urlMod = require('url');",
  "var https = require('https');",
  "var http = require('http');",
  "var startUrl = String((msg.payload && msg.payload.url) || '').trim();",
  "if (!startUrl) { msg.payload = { error: 'Missing url' }; return msg; }",
  "",
  "function decodeXmlText(s) {",
  "  if (!s) return '';",
  "  return String(s).replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&').replace(/&quot;/g,'\"').replace(/&#39;/g, String.fromCharCode(39)).replace(/&nbsp;/g,' ').trim();",
  "}",
  "function parseHtmlAttrTable(html) {",
  "  var out = {};",
  "  if (!html || html.indexOf('<td') < 0) return out;",
  "  var re = /<td[^>]*>([\\s\\S]*?)<\\/td>\\s*<td[^>]*>([\\s\\S]*?)<\\/td>/gi;",
  "  var m;",
  "  while ((m = re.exec(html)) !== null) {",
  "    var k = m[1].replace(/<[^>]+>/g,'').replace(/&nbsp;/g,' ').trim();",
  "    var v = m[2].replace(/<[^>]+>/g,'').trim();",
  "    k = decodeXmlText(k); v = decodeXmlText(v);",
  "    if (/^<Null>$/i.test(v) || v === '<Null>') v = '';",
  "    if (k) out[k] = v;",
  "  }",
  "  return out;",
  "}",
  "function parseExtendedData(block) {",
  "  var out = {};",
  "  var em = block.match(/<ExtendedData[^>]*>([\\s\\S]*?)<\\/ExtendedData>/i);",
  "  if (!em) return out;",
  "  var inner = em[1];",
  "  var re = /<SimpleData[^>]*name=[\"']([^\"']*)[\"'][^>]*>([\\s\\S]*?)<\\/SimpleData>/gi;",
  "  var m;",
  "  while ((m = re.exec(inner)) !== null) {",
  "    var k = decodeXmlText(m[1]);",
  "    var v = decodeXmlText(m[2].replace(/<[^>]+>/g,''));",
  "    if (k) out[k] = v;",
  "  }",
  "  re = /<Data[^>]*name=[\"']([^\"']*)[\"'][^>]*>[\\s\\S]*?<value>([\\s\\S]*?)<\\/value>/gi;",
  "  while ((m = re.exec(inner)) !== null) {",
  "    var k2 = decodeXmlText(m[1]);",
  "    var v2 = decodeXmlText(m[2].replace(/<[^>]+>/g,''));",
  "    if (k2) out[k2] = v2;",
  "  }",
  "  return out;",
  "}",
  "function buildAttributes(block, placemarkName, oid) {",
  "  var dm = block.match(/<description[^>]*>([\\s\\S]*?)<\\/description>/i);",
  "  var descRaw = dm ? dm[1] : '';",
  "  var ext = parseExtendedData(block);",
  "  var table = parseHtmlAttrTable(descRaw);",
  "  var attrs = {}; var k;",
  "  for (k in ext) attrs[k] = ext[k];",
  "  for (k in table) attrs[k] = table[k];",
  "  attrs.name = placemarkName;",
  "  attrs.OBJECTID = oid;",
  "  if (attrs.description == null || attrs.description === '') {",
  "    attrs.description = descRaw.replace(/<[^>]+>/g,' ').replace(/\\s+/g,' ').trim();",
  "  }",
  "  return attrs;",
  "}",
  "function networkHref(xml) {",
  "  var m = xml.match(/<NetworkLink[^>]*>[\\s\\S]*?<\\/NetworkLink>/i);",
  "  if (!m) return '';",
  "  var h = m[0].match(/<href[^>]*>([\\s\\S]*?)<\\/href>/i);",
  "  if (!h) return '';",
  "  return h[1].replace(/<[^>]+>/g,'').trim();",
  "}",
  "function fetchUrl(u, cb) {",
  "  var done = false;",
  "  function once(err, body, code) { if (done) return; done = true; cb(err, body, code); }",
  "  var lib = u.indexOf('https') === 0 ? https : http;",
  "  var req = lib.get(u, function(res) {",
  "    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {",
  "      res.resume();",
  "      return fetchUrl(res.headers.location, cb);",
  "    }",
  "    var chunks = [];",
  "    res.on('data', function(c) { chunks.push(c); });",
  "    res.on('end', function() { once(null, Buffer.concat(chunks).toString('utf8'), res.statusCode); });",
  "    res.on('error', function(e) { once(e); });",
  "  });",
  "  req.setTimeout(15000, function() { req.destroy(new Error('Request timeout (15s)')); });",
  "  req.on('error', function(e) { once(e); });",
  "}",
  "function discoverKeys(xml) {",
  "  var keyObj = {}; var samples = []; var nGeo = 0; var totalPm = 0;",
  "  var re = /<Placemark([^>]*)>([\\s\\S]*?)<\\/Placemark>/gi;",
  "  var m;",
  "  while ((m = re.exec(xml)) !== null) { totalPm++; }",
  "  re = /<Placemark([^>]*)>([\\s\\S]*?)<\\/Placemark>/gi;",
  "  while ((m = re.exec(xml)) !== null && nGeo < 20) {",
  "    var block = m[2];",
  "    var hasGeo = /<Point[^>]*>/i.test(block) || /<Polygon[^>]*>/i.test(block) || /<LineString[^>]*>/i.test(block);",
  "    if (!hasGeo) continue;",
  "    var name = 'Placemark';",
  "    var nm = block.match(/<name[^>]*>([\\s\\S]*?)<\\/name>/i);",
  "    if (nm) name = nm[1].replace(/<[^>]+>/g,'').trim() || name;",
  "    var attrs = buildAttributes(block, name, nGeo);",
  "    if (samples.length < 15) samples.push(attrs);",
  "    Object.keys(attrs).forEach(function(k) { keyObj[k] = true; });",
  "    nGeo++;",
  "  }",
  "  return {",
  "    keys: Object.keys(keyObj).sort(),",
  "    sample: samples.length ? samples[0] : {},",
  "    samples: samples,",
  "    placemarksWithGeometry: nGeo,",
  "    placemarkTags: totalPm",
  "  };",
  "}",
  "function sendDiscovered(xmlBody, httpStatus) {",
  "  if (httpStatus >= 400) {",
  "    msg.payload = { error: 'HTTP ' + httpStatus };",
  "    return node.send(msg);",
  "  }",
  "  var d = discoverKeys(xmlBody);",
  "  msg.payload = { ok: true, keys: d.keys, sample: d.sample, samples: d.samples, placemarksWithGeometry: d.placemarksWithGeometry, placemarkTags: d.placemarkTags };",
  "  node.send(msg);",
  "}",
  "fetchUrl(startUrl, function(err, xml0, st0) {",
  "  if (err) { msg.payload = { error: err.message || 'fetch failed' }; return node.send(msg); }",
  "  if (st0 >= 400) { msg.payload = { error: 'HTTP ' + st0 }; return node.send(msg); }",
  "  var inner = networkHref(xml0);",
  "  var target = '';",
  "  if (inner) {",
  "    if (/^https?:\\/\\//i.test(inner)) target = inner;",
  "    else if (inner.indexOf('//') === 0) { var pr = urlMod.parse(startUrl); target = (pr.protocol || 'http:') + inner; }",
  "    else target = urlMod.resolve(startUrl, inner);",
  "  }",
  "  if (target) {",
  "    fetchUrl(target, function(e2, xml1, st1) {",
  "      if (e2) { msg.payload = { error: e2.message || 'inner fetch failed' }; return node.send(msg); }",
  "      sendDiscovered(xml1, st1);",
  "    });",
  "    return;",
  "  }",
  "  sendDiscovered(xml0, st0);",
  "});",
  "return null;"
].join('\n');

/** Pure XML parse — no require(), called after the http request node fetches the KML text. */
const FN_KML_PARSE_FIELDS = [
  "var sc = msg.statusCode || 200;",
  "if (sc >= 400) { msg.payload = { error: 'HTTP ' + sc }; return msg; }",
  "var xml = typeof msg.payload === 'string' ? msg.payload",
  "  : (Buffer.isBuffer(msg.payload) ? msg.payload.toString('utf8') : String(msg.payload || ''));",
  "function decodeXmlText(s) {",
  "  if (!s) return '';",
  "  return String(s).replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&')",
  "    .replace(/&quot;/g,'\"').replace(/&#39;/g,\"'\").replace(/&nbsp;/g,' ').trim();",
  "}",
  "function parseHtmlAttrTable(html) {",
  "  var out = {};",
  "  if (!html || html.indexOf('<td') < 0) return out;",
  "  var re = /<td[^>]*>([\\s\\S]*?)<\\/td>\\s*<td[^>]*>([\\s\\S]*?)<\\/td>/gi;",
  "  var m;",
  "  while ((m = re.exec(html)) !== null) {",
  "    var k = decodeXmlText(m[1].replace(/<[^>]+>/g,'').replace(/&nbsp;/g,' ').trim());",
  "    var v = decodeXmlText(m[2].replace(/<[^>]+>/g,'').trim());",
  "    if (/^<Null>$/i.test(v)) v = '';",
  "    if (k) out[k] = v;",
  "  }",
  "  return out;",
  "}",
  "function parseExtData(block) {",
  "  var out = {};",
  "  var em = block.match(/<ExtendedData[^>]*>([\\s\\S]*?)<\\/ExtendedData>/i);",
  "  if (!em) return out;",
  "  var inner = em[1];",
  "  var re = /<SimpleData[^>]*name=[\"']([^\"']*)[\"'][^>]*>([\\s\\S]*?)<\\/SimpleData>/gi;",
  "  var m;",
  "  while ((m = re.exec(inner)) !== null) { var k=decodeXmlText(m[1]),v=decodeXmlText(m[2].replace(/<[^>]+>/g,'')); if(k) out[k]=v; }",
  "  re = /<Data[^>]*name=[\"']([^\"']*)[\"'][^>]*>[\\s\\S]*?<value>([\\s\\S]*?)<\\/value>/gi;",
  "  while ((m = re.exec(inner)) !== null) { var k2=decodeXmlText(m[1]),v2=decodeXmlText(m[2].replace(/<[^>]+>/g,'')); if(k2) out[k2]=v2; }",
  "  return out;",
  "}",
  "var keyObj = {}; var samples = []; var nGeo = 0; var totalPm = 0;",
  "var re = /<Placemark([^>]*)>([\\s\\S]*?)<\\/Placemark>/gi; var m;",
  "while ((m = re.exec(xml)) !== null) { totalPm++; }",
  "re = /<Placemark([^>]*)>([\\s\\S]*?)<\\/Placemark>/gi;",
  "while ((m = re.exec(xml)) !== null && nGeo < 20) {",
  "  var block = m[2];",
  "  var hasGeo = /<Point[^>]*>/i.test(block)||/<Polygon[^>]*>/i.test(block)||/<LineString[^>]*>/i.test(block);",
  "  if (!hasGeo) continue;",
  "  var nm = block.match(/<name[^>]*>([\\s\\S]*?)<\\/name>/i);",
  "  var pmName = nm ? nm[1].replace(/<[^>]+>/g,'').trim() : 'Placemark';",
  "  var dm = block.match(/<description[^>]*>([\\s\\S]*?)<\\/description>/i);",
  "  var descRaw = dm ? dm[1] : '';",
  "  var ext = parseExtData(block);",
  "  var tbl = parseHtmlAttrTable(descRaw);",
  "  var attrs = {}; var k;",
  "  for (k in ext) attrs[k] = ext[k];",
  "  for (k in tbl) attrs[k] = tbl[k];",
  "  attrs.name = pmName; attrs.OBJECTID = nGeo;",
  "  if (!attrs.description) attrs.description = descRaw.replace(/<[^>]+>/g,' ').replace(/\\s+/g,' ').trim();",
  "  Object.keys(attrs).forEach(function(k){ keyObj[k]=true; });",
  "  if (samples.length < 15) samples.push(attrs);",
  "  nGeo++;",
  "}",
  "if (nGeo === 0) { msg.payload = { error: 'No placemarks with geometry found in KML' }; return msg; }",
  "var keys = Object.keys(keyObj).sort();",
  "msg.payload = { ok: true, keys: keys, sample: samples[0]||{}, samples: samples, placemarksWithGeometry: nGeo, placemarkTags: totalPm };",
  "return msg;"
].join('\n');

// ════════════════════════════════════════════════════════════════
//  Configurator tab — shared UI + persistence (global context)
// ════════════════════════════════════════════════════════════════

// Tablet Command: default ATAK OSM iconset icons + CoT helpers (used by CFG tab + TC engine template)
// OSM iconset uid: 6d781afb-89a6-4c07-b2b9-a89748b6a38f  (Service group)
const TC_ICON_FIRE = '6d781afb-89a6-4c07-b2b9-a89748b6a38f/Service/firebrigade.png';
const TC_ICON_AMB  = '6d781afb-89a6-4c07-b2b9-a89748b6a38f/Service/emergency.png';

const TC_COT_TYPE_FN = [
  "function tcCotType(r) {",
  "  r = (r||'').toUpperCase().replace(/\\s+/g,'');",
  "  if (/^E\\d|^ENG/.test(r))                       return 'a-f-G-E-V-C'; // Engine",
  "  if (/^(T|TRK|LAD|TK)\\d/.test(r))               return 'a-f-G-E-V-C'; // Truck/Ladder",
  "  if (/^(M|MED|AMB|ALS|BLS)\\d/.test(r))          return 'a-f-G-E-V-M'; // Medical",
  "  if (/^(BC|BAT|CHIEF|AC|DC|DIV|CMD)/.test(r))    return 'a-f-G-E-V-C'; // Chief/Command",
  "  if (/^(H|HELO|AIR|HT|CHP)\\d/.test(r))          return 'a-f-A-C-H';   // Helicopter",
  "  if (/^(WT|WAT|WATER)\\d/.test(r))               return 'a-f-G-E-V-C'; // Water Tender",
  "  if (/^(RES|RESCUE|SQ|SQUAD)\\d/.test(r))        return 'a-f-G-E-V-C'; // Rescue/Squad",
  "  if (/^(HAZ|HM)\\d/.test(r))                     return 'a-f-G-E-V-C'; // Hazmat",
  "  return 'a-f-G-E-V-C'; // default: friendly ground vehicle",
  "}",
  "function tcDefaultIconset(ct) {",
  "  if (ct === 'a-f-G-E-V-M') return '" + TC_ICON_AMB + "';",
  "  if (ct === 'a-f-A-C-H') return '';",
  "  return '" + TC_ICON_FIRE + "';",
  "}"
].join('\n');

const FN_TC_FEED_SNAPSHOT = [
  TC_COT_TYPE_FN,
  '',
  'var body = msg.payload || {};',
  "var agencyUrl = (body.agencyUrl || '').trim();",
  'if (!agencyUrl) { msg.payload = { ok:false, error:"agencyUrl required" }; return msg; }',
  'var parsed;',
  'try { parsed = new URL(agencyUrl); } catch (e) { msg.payload = { ok:false, error:"invalid URL" }; return msg; }',
  "if (parsed.protocol !== 'https:') { msg.payload = { ok:false, error:'https only' }; return msg; }",
  "if (!/tabletcommand\\.com$/i.test(parsed.hostname)) { msg.payload = { ok:false, error:'hostname must end with tabletcommand.com' }; return msg; }",
  "var base = agencyUrl.replace(/\\/+$/, '');",
  "var qurl = base + '/0/query?where=1%3D1&outFields=*&returnGeometry=false&f=json';",
  "var https = global.get('nodeHttps');",
  'if (!https) { msg.payload = { ok:false, error:"nodeHttps missing in Node-RED functionGlobalContext" }; return msg; }',
  "https.get(qurl, { headers: { 'User-Agent': 'infra-TAK/tc-feed-snapshot' } }, function (res) {",
  "  var chunks = [];",
  "  res.on('data', function (d) { chunks.push(d); });",
  "  res.on('end', function () {",
  '    try {',
  "      var txt = Buffer.concat(chunks).toString('utf8');",
  '      var data = JSON.parse(txt);',
  "      if (res.statusCode !== 200) { msg.payload = { ok:false, error:'HTTP '+res.statusCode, body: txt.slice(0,500) }; return node.send(msg); }",
  '      var feats = data.features || [];',
  '      function escCell(s) {',
  "        s = String(s == null ? '' : s);",
  "        if (/[\",\\n\\r]/.test(s)) return '\"' + s.replace(/\"/g,'\"\"') + '\"';",
  '        return s;',
  '      }',
  "      var lines = ['radioName,callsign,cotType,iconsetpath'];",
  '      var seen = {};',
  '      feats.forEach(function (f) {',
  "        var a = f.attributes || {};",
  "        var radio = (a.radioName || '').trim();",
  '        if (!radio || seen[radio]) return;',
  '        seen[radio] = true;',
  "        var ct = tcCotType(radio);",
  "        var ic = tcDefaultIconset(ct);",
  "        lines.push([escCell(radio), escCell(radio), escCell(ct), escCell(ic)].join(','));",
  '      });',
  "      msg.payload = { ok:true, count: Object.keys(seen).length, csv: lines.join('\\n') };",
  '    } catch (e) {',
  "      msg.payload = { ok:false, error: e.message };",
  '    }',
  '    node.send(msg);',
  '  });',
  "}).on('error', function (e) {",
  "  msg.payload = { ok:false, error: e.message };",
  '  node.send(msg);',
  '});',
  'return null;'
].join('\n');

const configFlows = [
  {
    id: CFG_TAB, type: 'tab',
    label: 'ArcGIS Configurator',
    disabled: false,
    info: 'Shared UI, proxy APIs, config & TAK settings persistence. Configs stored in global context so per-feed engine tabs can read them.'
  },

  // ── Migration: flow → global context (one-time at startup) ──
  {
    id: 'migrate_inject', type: 'inject', z: CFG_TAB,
    name: 'Startup migration',
    props: [{ p: 'payload' }],
    repeat: '', crontab: '',
    once: true, onceDelay: '2',
    topic: '', payload: '', payloadType: 'date',
    x: 180, y: 40, wires: [['migrate_fn']]
  },
  {
    id: 'migrate_fn', type: 'function', z: CFG_TAB,
    name: 'Migrate flow->global',
    func: [
      "var cfgs = flow.get('arcgis_configs');",
      "var tak  = flow.get('tak_settings');",
      "if (cfgs && cfgs.length > 0 && !(global.get('arcgis_configs') || []).length) {",
      "  global.set('arcgis_configs', cfgs);",
      "  node.warn('Migrated ' + cfgs.length + ' configs to global context');",
      "}",
      "if (tak && Object.keys(tak).length > 0 && !Object.keys(global.get('tak_settings') || {}).length) {",
      "  global.set('tak_settings', tak);",
      "  node.warn('Migrated TAK settings to global context');",
      "}",
      "return null;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 400, y: 40, wires: [[]]
  },

  // ── Startup context cleanup: AUTO-HEAL corrupted values ──
  // Independent inject (does NOT chain off migrate_fn — that returns null).
  // Runs at 5s so it fires AFTER migrate_fn (2s) but BEFORE engine tabs poll (30s).
  {
    id: 'ctx_cleanup_inject', type: 'inject', z: CFG_TAB,
    name: 'Startup context normalize',
    props: [{ p: 'payload' }],
    repeat: '', crontab: '',
    once: true, onceDelay: '5',
    topic: '', payload: '', payloadType: 'date',
    x: 200, y: 80, wires: [['ctx_cleanup_fn']]
  },
  // Engines (per-feed dynamic tabs) call `global.get('arcgis_configs') || []` and iterate.
  // If the on-disk value is a JSON-string `"[...]"` or a wrapped envelope `{msg, format}`,
  // engines silently fail (string.length iterates characters, envelope has no .length).
  // This function runs ONCE at startup, normalizes every known config key into its
  // expected type, and re-saves it via global.set() so disk converges to the right shape.
  //
  // CRITICAL: This function NEVER silently wipes data. If a value can't be parsed into
  // the expected type, the original is saved to `<key>_quarantine_<ts>` BEFORE replacing
  // with an empty default. User can always inspect the quarantine value and recover.
  {
    id: 'ctx_cleanup_fn', type: 'function', z: CFG_TAB,
    name: 'Normalize corrupted context values',
    func: [
      "function _norm(v) {",
      "  // Wrapped envelope from older buggy migrations: {msg: '<json>', format: '...'}",
      "  if (v && typeof v === 'object' && !Array.isArray(v) && 'msg' in v) {",
      "    var inner = v.msg;",
      "    if (typeof inner === 'string') {",
      "      try { return JSON.parse(inner); } catch(e) { return inner; }",
      "    }",
      "    return inner;",
      "  }",
      "  // Stringified JSON stored as a literal string (THIS is the arcgis_configs bug)",
      "  if (typeof v === 'string') {",
      "    try { return JSON.parse(v); } catch(e) { return v; }",
      "  }",
      "  return v;",
      "}",
      "function _isNonEmpty(v) {",
      "  if (v === null || v === undefined) return false;",
      "  if (typeof v === 'string') return v.length > 0;",
      "  if (Array.isArray(v)) return v.length > 0;",
      "  if (typeof v === 'object') return Object.keys(v).length > 0;",
      "  return true;",
      "}",
      "var EXPECTED = {",
      "  arcgis_configs: 'array',",
      "  tc_configs:     'array',",
      "  pp_configs:     'array',",
      "  tak_settings:   'object',",
      "  ipaws_config:   'object'",
      "};",
      "var fixed = [], initialized = [], quarantined = [];",
      "var ts = new Date().toISOString().replace(/[:.]/g, '_');",
      "Object.keys(EXPECTED).forEach(function(k) {",
      "  var orig = global.get(k);",
      "  if (orig === undefined || orig === null) {",
      "    global.set(k, EXPECTED[k] === 'array' ? [] : {});",
      "    initialized.push(k);",
      "    return;",
      "  }",
      "  var n = _norm(orig);",
      "  var typeOk = EXPECTED[k] === 'array' ? Array.isArray(n)",
      "             : (typeof n === 'object' && !Array.isArray(n) && n !== null);",
      "  if (typeOk) {",
      "    if (n !== orig) {",
      "      global.set(k, n);",
      "      fixed.push(k + (Array.isArray(n) ? '(' + n.length + ')' : '(obj)'));",
      "    }",
      "    return;",
      "  }",
      "  // Type can't be coerced. NEVER silently wipe — quarantine the original first.",
      "  if (_isNonEmpty(orig)) {",
      "    var qkey = k + '_quarantine_' + ts;",
      "    global.set(qkey, orig);",
      "    quarantined.push(qkey);",
      "  }",
      "  global.set(k, EXPECTED[k] === 'array' ? [] : {});",
      "});",
      "if (fixed.length)       node.warn('Context auto-heal: normalized ' + fixed.join(', '));",
      "if (initialized.length) node.warn('Context auto-heal: initialized empty ' + initialized.join(', '));",
      "if (quarantined.length) node.warn('Context auto-heal: QUARANTINED unparseable values to ' + quarantined.join(', ') + ' — inspect via /context/global');",
      "if (!fixed.length && !initialized.length && !quarantined.length) node.warn('Context auto-heal: all keys clean');",
      "return null;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 640, y: 40, wires: [[]]
  },

  // ── Configurator UI ──
  {
    id: 'c_ui', type: 'comment', z: CFG_TAB,
    name: '── Configurator UI (/configurator) ──',
    info: '', x: 240, y: 80, wires: []
  },
  {
    id: 'hi_ui', type: 'http in', z: CFG_TAB,
    name: 'GET /configurator',
    url: '/configurator', method: 'get',
    upload: false, swaggerDoc: '',
    x: 170, y: 120, wires: [['t_ui']]
  },
  {
    id: 't_ui', type: 'template', z: CFG_TAB,
    name: 'Configurator HTML',
    field: 'payload', fieldType: 'msg',
    format: 'html', syntax: 'plain',
    template: html,
    output: 'str',
    x: 390, y: 120, wires: [['ho_ui']]
  },
  {
    id: 'ho_ui', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200',
    headers: { 'content-type': 'text/html', 'cache-control': 'no-cache, no-store, must-revalidate' },
    x: 590, y: 120, wires: []
  },

  // ── ArcGIS Proxy APIs ──
  {
    id: 'c_api', type: 'comment', z: CFG_TAB,
    name: '── ArcGIS Proxy APIs ──',
    info: '', x: 240, y: 200, wires: []
  },
  {
    id: 'hi_svc', type: 'http in', z: CFG_TAB,
    name: 'POST /arcgis-tak/arcgis/service',
    url: '/arcgis-tak/arcgis/service', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 240, wires: [['fn_svc']]
  },
  {
    id: 'fn_svc', type: 'function', z: CFG_TAB,
    name: 'Build service URL',
    func: "const base = msg.payload.url.replace(/\\/+$/, '');\nmsg.url = base + '?f=json';\nreturn msg;",
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 240, wires: [['hr_svc']]
  },
  {
    id: 'hr_svc', type: 'http request', z: CFG_TAB,
    name: 'GET service info',
    method: 'GET', ret: 'obj', paytoqs: 'ignore',
    url: '', tls: '', persist: false, proxy: '',
    insecureHTTPParser: false, authType: '',
    senderr: false, headers: [],
    x: 620, y: 240, wires: [['fn_svc_parse']]
  },
  {
    id: 'fn_svc_parse', type: 'function', z: CFG_TAB,
    name: 'Parse service',
    func: [
      "if (msg.payload.error) {",
      "  msg.payload = { error: msg.payload.error.message || 'ArcGIS error' };",
      "} else {",
      "  msg.payload = {",
      "    layers: (msg.payload.layers || []).map(function(l) {",
      "      return { id: l.id, name: l.name, geometryType: l.geometryType || null };",
      "    })",
      "  };",
      "}",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 810, y: 240, wires: [['ho_svc']]
  },
  {
    id: 'ho_svc', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 1000, y: 240, wires: []
  },

  {
    id: 'hi_lyr', type: 'http in', z: CFG_TAB,
    name: 'POST /arcgis-tak/arcgis/layer',
    url: '/arcgis-tak/arcgis/layer', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 340, wires: [['fn_lyr']]
  },
  {
    id: 'fn_lyr', type: 'function', z: CFG_TAB,
    name: 'Build layer URL',
    func: "const base = msg.payload.url.replace(/\\/+$/, '');\nmsg.url = base + '/' + msg.payload.layerId + '?f=json';\nreturn msg;",
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 340, wires: [['hr_lyr']]
  },
  {
    id: 'hr_lyr', type: 'http request', z: CFG_TAB,
    name: 'GET layer info',
    method: 'GET', ret: 'obj', paytoqs: 'ignore',
    url: '', tls: '', persist: false, proxy: '',
    insecureHTTPParser: false, authType: '',
    senderr: false, headers: [],
    x: 620, y: 340, wires: [['fn_lyr_parse']]
  },
  {
    id: 'fn_lyr_parse', type: 'function', z: CFG_TAB,
    name: 'Parse layer',
    func: [
      "if (msg.payload.error) {",
      "  msg.payload = { error: msg.payload.error.message || 'ArcGIS error' };",
      "} else {",
      "  msg.payload = {",
      "    name: msg.payload.name,",
      "    geometryType: msg.payload.geometryType,",
      "    fields: (msg.payload.fields || []).map(function(f) {",
      "      return { name: f.name, type: f.type, alias: f.alias || f.name };",
      "    })",
      "  };",
      "}",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 810, y: 340, wires: [['ho_lyr']]
  },
  {
    id: 'ho_lyr', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 1000, y: 340, wires: []
  },

  {
    id: 'hi_smp', type: 'http in', z: CFG_TAB,
    name: 'POST /arcgis-tak/arcgis/sample',
    url: '/arcgis-tak/arcgis/sample', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 440, wires: [['fn_smp']]
  },
  {
    id: 'fn_smp', type: 'function', z: CFG_TAB,
    name: 'Build sample query URL',
    func: [
      "const base = msg.payload.url.replace(/\\/+$/, '');",
      "const lid  = msg.payload.layerId;",
      "msg.url = base + '/' + lid + '/query?where=1%3D1&outFields=*&resultRecordCount=50&f=json';",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 440, wires: [['hr_smp']]
  },
  {
    id: 'hr_smp', type: 'http request', z: CFG_TAB,
    name: 'GET sample features',
    method: 'GET', ret: 'obj', paytoqs: 'ignore',
    url: '', tls: '', persist: false, proxy: '',
    insecureHTTPParser: false, authType: '',
    senderr: false, headers: [],
    x: 620, y: 440, wires: [['fn_smp_parse']]
  },
  {
    id: 'fn_smp_parse', type: 'function', z: CFG_TAB,
    name: 'Parse sample',
    func: [
      "if (msg.payload.error) {",
      "  msg.payload = { error: msg.payload.error.message || 'ArcGIS error' };",
      "} else {",
      "  msg.payload = { features: (msg.payload.features || []).slice(0, 50) };",
      "}",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 810, y: 440, wires: [['ho_smp']]
  },
  {
    id: 'ho_smp', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 1000, y: 440, wires: []
  },

  {
    id: 'hi_dist', type: 'http in', z: CFG_TAB,
    name: 'POST /arcgis-tak/arcgis/distinct',
    url: '/arcgis-tak/arcgis/distinct', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 540, wires: [['fn_dist']]
  },
  {
    id: 'fn_dist', type: 'function', z: CFG_TAB,
    name: 'Build distinct query URL',
    func: [
      "const base  = msg.payload.url.replace(/\\/+$/, '');",
      "const lid   = msg.payload.layerId;",
      "const field = encodeURIComponent(msg.payload.field);",
      "msg.url = base + '/' + lid + '/query'",
      "  + '?where=1%3D1'",
      "  + '&outFields=' + field",
      "  + '&returnDistinctValues=true'",
      "  + '&orderByFields=' + field",
      "  + '&resultRecordCount=500'",
      "  + '&f=json';",
      "msg._field = msg.payload.field;",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 540, wires: [['hr_dist']]
  },
  {
    id: 'hr_dist', type: 'http request', z: CFG_TAB,
    name: 'GET distinct values',
    method: 'GET', ret: 'obj', paytoqs: 'ignore',
    url: '', tls: '', persist: false, proxy: '',
    insecureHTTPParser: false, authType: '',
    senderr: false, headers: [],
    x: 620, y: 540, wires: [['fn_dist_parse']]
  },
  {
    id: 'fn_dist_parse', type: 'function', z: CFG_TAB,
    name: 'Parse distinct',
    func: [
      "if (msg.payload.error) {",
      "  msg.payload = { error: msg.payload.error.message || 'ArcGIS error' };",
      "} else {",
      "  var field = msg._field;",
      "  var vals = (msg.payload.features || []).map(function(f) {",
      "    return f.attributes[field];",
      "  });",
      "  msg.payload = { values: vals };",
      "}",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 810, y: 540, wires: [['ho_dist']]
  },
  {
    id: 'ho_dist', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 1000, y: 540, wires: []
  },

  // ── KML field discovery (Fetch button) ─────────────────────────
  // Uses the same HTTP request node pattern as the ArcGIS proxy so
  // async require() issues in function nodes cannot cause spinning.
  // Flow: POST → prep URL → GET KML → check NetworkLink →
  //       [no NL] parse → respond
  //       [has NL] GET inner → parse → respond
  {
    id: 'hi_kml_fetch', type: 'http in', z: CFG_TAB,
    name: 'POST /arcgis-tak/kml/fetch',
    url: '/arcgis-tak/kml/fetch', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 580, wires: [['fn_kml_prep']]
  },
  {
    id: 'fn_kml_prep', type: 'function', z: CFG_TAB,
    name: 'Set KML URL',
    func: [
      "var u = String((msg.payload && msg.payload.url) || '').trim();",
      "if (!u) { msg.payload = { error: 'Missing url' }; return [null, msg]; }",
      "msg._kmlStartUrl = u;",
      "msg.url = u;",
      "msg.method = 'GET';",
      "msg.headers = { Accept: 'application/vnd.google-earth.kml+xml, application/xml, text/xml, */*' };",
      "return [msg, null];"
    ].join('\n'),
    outputs: 2, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 400, y: 580, wires: [['hr_kml_main'], ['ho_kml_fetch']]
  },
  {
    id: 'hr_kml_main', type: 'http request', z: CFG_TAB,
    name: 'GET KML (outer)',
    method: 'use', ret: 'txt', paytoqs: 'ignore',
    url: '', tls: '', persist: false, proxy: '',
    insecureHTTPParser: false, authType: '',
    senderr: false, headers: [],
    x: 600, y: 560, wires: [['fn_kml_check_nl']]
  },
  {
    id: 'fn_kml_check_nl', type: 'function', z: CFG_TAB,
    name: 'Check NetworkLink',
    func: [
      "var sc = msg.statusCode || 200;",
      "if (sc >= 400) { msg.payload = { error: 'HTTP ' + sc }; return [null, msg]; }",
      "var xml = msg.payload || '';",
      "var nlm = xml.match(/<NetworkLink[^>]*>[\\s\\S]*?<\\/NetworkLink>/i);",
      "if (nlm) {",
      "  var hm = nlm[0].match(/<href[^>]*>([\\s\\S]*?)<\\/href>/i);",
      "  var href = hm ? hm[1].replace(/<[^>]+>/g,'').trim() : '';",
      "  if (href) {",
      "    var base = msg._kmlStartUrl || '';",
      "    if (/^https?:\\/\\//i.test(href)) { msg.url = href; }",
      "    else if (href.indexOf('//') === 0) { msg.url = (base.match(/^https?:/i) || ['http:'])[0] + href; }",
      "    else { try { msg.url = new URL(href, base).href; } catch(e) { msg.url = href; } }",
      "    msg.method = 'GET';",
      "    msg.headers = { Accept: 'application/vnd.google-earth.kml+xml, application/xml, text/xml, */*' };",
      "    msg.payload = null;",
      "    return [msg, null, null];",
      "  }",
      "}",
      "return [null, msg, null];"
    ].join('\n'),
    outputs: 3, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 800, y: 560, wires: [['hr_kml_inner'], ['fn_kml_parse'], ['ho_kml_fetch']]
  },
  {
    id: 'hr_kml_inner', type: 'http request', z: CFG_TAB,
    name: 'GET KML (inner NetworkLink)',
    method: 'use', ret: 'txt', paytoqs: 'ignore',
    url: '', tls: '', persist: false, proxy: '',
    insecureHTTPParser: false, authType: '',
    senderr: false, headers: [],
    x: 1020, y: 540, wires: [['fn_kml_parse']]
  },
  {
    id: 'fn_kml_parse', type: 'function', z: CFG_TAB,
    name: 'Parse KML → attribute keys',
    func: FN_KML_PARSE_FIELDS,
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 1020, y: 600, wires: [['ho_kml_fetch']]
  },
  {
    id: 'ho_kml_fetch', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 1220, y: 580, wires: []
  },

  // ── Config persistence (global context) ──
  {
    id: 'c_save', type: 'comment', z: CFG_TAB,
    name: '── Config Save ──',
    info: '', x: 240, y: 620, wires: []
  },
  {
    id: 'hi_save', type: 'http in', z: CFG_TAB,
    name: 'POST /arcgis-tak/config/save',
    url: '/arcgis-tak/config/save', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 660, wires: [['fn_save']]
  },
  {
    id: 'fn_save', type: 'function', z: CFG_TAB,
    name: 'Save to global context',
    func: [
      ARRAY_GUARD,
      "var config  = msg.payload;",
      "var configs = _coerceArr(global.get('arcgis_configs'));",
      "var idx = configs.findIndex(function(c) {",
      "  if (config.sourceType === 'faa_tfr') return c.configName === config.configName && c.sourceType === 'faa_tfr';",
      "  if (config.sourceType === 'kml') return c.configName === config.configName && c.sourceType === 'kml';",
      "  return c.source && config.source && c.source.serviceUrl === config.source.serviceUrl",
      "      && c.source.layerId === config.source.layerId;",
      "});",
      "if (idx >= 0) { configs[idx] = config; }",
      "else           { configs.push(config); }",
      "global.set('arcgis_configs', configs);",
      CFG_BACKUP_SNIPPET + "\n",
      "var certUser = (config.streamCertUser || '').trim();",
      "if (certUser) {",
      "  try {",
      "  var fs = global.get('fs') || require('fs');",
      "    var pem = '/certs/' + certUser + '.pem';",
      "    var key = '/certs/' + certUser + '.key';",
      "    if (fs.existsSync(pem)) fs.chmodSync(pem, 0o644);",
      "    if (fs.existsSync(key)) fs.chmodSync(key, 0o644);",
      "    node.warn('Cert permissions fixed for ' + certUser);",
      "  } catch(e) { node.warn('chmod failed: ' + e.message); }",
      "}",
      "msg.payload = { ok: true, configCount: configs.length };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 660, wires: [['ho_save']]
  },
  {
    id: 'ho_save', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 640, y: 660, wires: []
  },
  {
    id: 'hi_saveall', type: 'http in', z: CFG_TAB,
    name: 'POST /arcgis-tak/config/save-all',
    url: '/arcgis-tak/config/save-all', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 700, wires: [['fn_saveall']]
  },
  {
    id: 'fn_saveall', type: 'function', z: CFG_TAB,
    name: 'Replace all configs',
    func: [
      "global.set('arcgis_configs', msg.payload.configs || []);",
      CFG_BACKUP_SNIPPET + "\n",
      "msg.payload = { ok: true };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 700, wires: [['ho_saveall']]
  },
  {
    id: 'ho_saveall', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 640, y: 700, wires: []
  },
  {
    id: 'hi_load', type: 'http in', z: CFG_TAB,
    name: 'GET /arcgis-tak/config/load',
    url: '/arcgis-tak/config/load', method: 'get',
    upload: false, swaggerDoc: '',
    x: 200, y: 740, wires: [['fn_load']]
  },
  {
    id: 'fn_load', type: 'function', z: CFG_TAB,
    name: 'Load from global context',
    func: [
      "var _raw = global.get('arcgis_configs');",
      "if (_raw && typeof _raw === 'object' && !Array.isArray(_raw) && 'msg' in _raw) { try { _raw = JSON.parse(_raw.msg); } catch(e) { _raw = []; } }",
      "if (typeof _raw === 'string') { try { _raw = JSON.parse(_raw); } catch(e) { _raw = []; } }",
      "var configs = (Array.isArray(_raw) ? _raw : null) || [];",
      "msg.payload = { configs: configs };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 740, wires: [['ho_load']]
  },
  {
    id: 'ho_load', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 640, y: 740, wires: []
  },

  // ── TAK Settings persistence (global context) ──
  {
    id: 'c_tak', type: 'comment', z: CFG_TAB,
    name: '── TAK Settings ──',
    info: '', x: 240, y: 820, wires: []
  },
  {
    id: 'hi_tak_save', type: 'http in', z: CFG_TAB,
    name: 'POST /arcgis-tak/tak-settings/save',
    url: '/arcgis-tak/tak-settings/save', method: 'post',
    upload: false, swaggerDoc: '',
    x: 220, y: 860, wires: [['fn_tak_save']]
  },
  {
    id: 'fn_tak_save', type: 'function', z: CFG_TAB,
    name: 'Save TAK settings',
    func: [
      "global.set('tak_settings', msg.payload);",
      CFG_BACKUP_SNIPPET + "\n",
      "msg.payload = { ok: true };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 450, y: 860, wires: [['ho_tak_save']]
  },
  {
    id: 'ho_tak_save', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 640, y: 860, wires: []
  },
  {
    id: 'hi_tak_load', type: 'http in', z: CFG_TAB,
    name: 'GET /arcgis-tak/tak-settings/load',
    url: '/arcgis-tak/tak-settings/load', method: 'get',
    upload: false, swaggerDoc: '',
    x: 220, y: 900, wires: [['fn_tak_load']]
  },
  {
    id: 'fn_tak_load', type: 'function', z: CFG_TAB,
    name: 'Load TAK settings',
    func: [
      "msg.payload = { settings: global.get('tak_settings') || {} };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 450, y: 900, wires: [['ho_tak_load']]
  },
  {
    id: 'ho_tak_load', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 640, y: 900, wires: []
  },

  // ── Mission ensure (Phase 1A — create DataSync mission as nodered cert) ──
  // POST /arcgis-tak/mission/ensure
  // Body: { missionName, group, defaultRole?, creatorUid? }
  // Behavior: GET mission first; if 404, PUT it. Uses /certs/nodered.pem if present, else /certs/admin.pem.
  // When nodered creates the mission, nodered is automatically MISSION_OWNER and the engine doesn't
  // need any role-elevation hack to write to it. If the mission already exists (e.g. created in Portal
  // by admin), this endpoint just verifies — it does NOT change ownership.
  {
    id: 'hi_mission_ensure', type: 'http in', z: CFG_TAB,
    name: 'POST /arcgis-tak/mission/ensure',
    url: '/arcgis-tak/mission/ensure', method: 'post',
    upload: false, swaggerDoc: '',
    x: 220, y: 940, wires: [['fn_mission_ensure']]
  },
  {
    id: 'fn_mission_ensure', type: 'function', z: CFG_TAB,
    name: 'Ensure mission exists',
    func: [
      "var p = msg.payload || {};",
      "var name = String(p.missionName || '').trim();",
      "var group = String(p.group || 'DATASYNC-FEEDS').trim();",
      "var defaultRole = String(p.defaultRole || 'MISSION_READONLY_SUBSCRIBER').trim();",
      "var tak = global.get('tak_settings') || {};",
      "var creatorUid = String(p.creatorUid || tak.creatorUid || 'nodered').trim();",
      "if (!name) {",
      "  msg.statusCode = 400;",
      "  msg.payload = { ok: false, error: 'missionName required' };",
      "  return msg;",
      "}",
      "// Cert preference: nodered.pem (Phase 1A) > admin.pem (fallback).",
      "var certPath, keyPath;",
      "if (_fs.existsSync('/certs/nodered.pem') && _fs.existsSync('/certs/nodered.key')) {",
      "  certPath = '/certs/nodered.pem'; keyPath = '/certs/nodered.key';",
      "} else if (_fs.existsSync('/certs/admin.pem') && _fs.existsSync('/certs/admin.key')) {",
      "  certPath = '/certs/admin.pem'; keyPath = '/certs/admin.key';",
      "} else {",
      "  msg.statusCode = 500;",
      "  msg.payload = { ok: false, error: 'no usable cert in /certs (nodered or admin)' };",
      "  return msg;",
      "}",
      "var host = String(tak.serverUrl || '').replace(/^https?:\\/\\//i, '').replace(/\\/$/, '');",
      "if (!host) {",
      "  msg.statusCode = 400;",
      "  msg.payload = { ok: false, error: 'TAK Settings not configured (serverUrl missing)' };",
      "  return msg;",
      "}",
      "var port = parseInt(String(tak.missionApiPort || 8443));",
      "var certOpts = { cert: _fs.readFileSync(certPath), key: _fs.readFileSync(keyPath), passphrase: 'atakatak' };",
      "var commonOpts = Object.assign({ hostname: host, port: port, rejectUnauthorized: false }, certOpts);",
      "function tryRequest(opts, body) {",
      "  return new Promise(function(resolve) {",
      "    var req = _https.request(opts, function(res) {",
      "      var chunks = [];",
      "      res.on('data', function(c) { chunks.push(c); });",
      "      res.on('end', function() { resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }); });",
      "    });",
      "    req.on('error', function(e) { resolve({ status: 0, body: 'request error: ' + e.message }); });",
      "    if (body) req.write(body);",
      "    req.end();",
      "  });",
      "}",
      "var getOpts = Object.assign({}, commonOpts, {",
      "  method: 'GET', path: '/Marti/api/missions/' + encodeURIComponent(name),",
      "  headers: { 'accept': '*/*' }",
      "});",
      "var putOpts = Object.assign({}, commonOpts, {",
      "  method: 'PUT',",
      "  path: '/Marti/api/missions/' + encodeURIComponent(name)",
      "        + '?creatorUid=' + encodeURIComponent(creatorUid)",
      "        + '&group=' + encodeURIComponent(group)",
      "        + '&defaultRole=' + encodeURIComponent(defaultRole),",
      "  headers: { 'accept': '*/*', 'Content-Type': 'application/json', 'Content-Length': '0' }",
      "});",
      "tryRequest(getOpts, null).then(function(getRes) {",
      "  if (getRes.status === 200) {",
      "    msg.payload = {",
      "      ok: true, action: 'verified', missionName: name,",
      "      cert: certPath.indexOf('nodered') >= 0 ? 'nodered' : 'admin',",
      "      note: 'mission already exists; ownership unchanged'",
      "    };",
      "    node.send(msg); return;",
      "  }",
      "  if (getRes.status === 404) {",
      "    return tryRequest(putOpts, null).then(function(putRes) {",
      "      if (putRes.status >= 200 && putRes.status < 300) {",
      "        msg.payload = {",
      "          ok: true, action: 'created', missionName: name,",
      "          group: group, defaultRole: defaultRole, creatorUid: creatorUid,",
      "          cert: certPath.indexOf('nodered') >= 0 ? 'nodered' : 'admin',",
      "          note: 'creator (' + creatorUid + ') is now MISSION_OWNER'",
      "        };",
      "      } else {",
      "        msg.statusCode = putRes.status || 500;",
      "        msg.payload = {",
      "          ok: false, action: 'create_failed', missionName: name,",
      "          status: putRes.status, body: String(putRes.body).slice(0, 500)",
      "        };",
      "      }",
      "      node.send(msg);",
      "    });",
      "  }",
      "  msg.statusCode = getRes.status || 500;",
      "  msg.payload = {",
      "    ok: false, action: 'check_failed',",
      "    status: getRes.status, body: String(getRes.body).slice(0, 500)",
      "  };",
      "  node.send(msg);",
      "});",
      "return null;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [
      { var: '_https', module: 'https' },
      { var: '_fs', module: 'fs' }
    ],
    x: 470, y: 940, wires: [['ho_mission_ensure']]
  },
  {
    id: 'ho_mission_ensure', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 700, y: 940, wires: []
  },

  // ── Tablet Command config persistence ──
  {
    id: 'c_tc', type: 'comment', z: CFG_TAB,
    name: '── Tablet Command Config ──',
    info: '', x: 260, y: 960, wires: []
  },
  {
    id: 'hi_tc_save', type: 'http in', z: CFG_TAB,
    name: 'POST /tc/config/save',
    url: '/tc/config/save', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 1000, wires: [['fn_tc_save']]
  },
  {
    id: 'fn_tc_save', type: 'function', z: CFG_TAB,
    name: 'Save TC config',
    func: [
      ARRAY_GUARD,
      "var cfg = msg.payload || {};",
      "if (!cfg.id) { msg.payload = { ok:false, error:'missing id' }; return msg; }",
      "var configs = _coerceArr(global.get('tc_configs'));",
      "var idx = configs.findIndex(function(c){ return c.id === cfg.id; });",
      "if (idx >= 0) { configs[idx] = cfg; } else { configs.push(cfg); }",
      "global.set('tc_configs', configs);",
      CFG_BACKUP_SNIPPET + "\n",
      "msg.payload = { ok: true, configCount: configs.length };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 1000, wires: [['ho_tc_save']]
  },
  {
    id: 'ho_tc_save', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
    x: 640, y: 1000, wires: []
  },
  {
    id: 'hi_tc_delete', type: 'http in', z: CFG_TAB,
    name: 'POST /tc/config/delete',
    url: '/tc/config/delete', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 1040, wires: [['fn_tc_delete']]
  },
  {
    id: 'fn_tc_delete', type: 'function', z: CFG_TAB,
    name: 'Delete TC config',
    func: [
      ARRAY_GUARD,
      "var id = (msg.payload||{}).id;",
      "if (!id) { msg.payload = { ok:false, error:'missing id' }; return msg; }",
      "var configs = _coerceArr(global.get('tc_configs')).filter(function(c){ return c.id !== id; });",
      "global.set('tc_configs', configs);",
      "global.set('tc_units_'+id, null);",
      CFG_BACKUP_SNIPPET + "\n",
      "msg.payload = { ok: true };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 1040, wires: [['ho_tc_delete']]
  },
  {
    id: 'ho_tc_delete', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
    x: 640, y: 1040, wires: []
  },
  {
    id: 'hi_tc_load', type: 'http in', z: CFG_TAB,
    name: 'GET /tc/config/load',
    url: '/tc/config/load', method: 'get',
    upload: false, swaggerDoc: '',
    x: 200, y: 1080, wires: [['fn_tc_load']]
  },
  {
    id: 'fn_tc_load', type: 'function', z: CFG_TAB,
    name: 'Load TC configs',
    func: [
      "var _raw = global.get('tc_configs');",
      "if (_raw && typeof _raw === 'object' && !Array.isArray(_raw) && 'msg' in _raw) { try { _raw = JSON.parse(_raw.msg); } catch(e) { _raw = []; } }",
      "if (typeof _raw === 'string') { try { _raw = JSON.parse(_raw); } catch(e) { _raw = []; } }",
      "var configs = (Array.isArray(_raw) ? _raw : null) || [];",
      "msg.payload = { configs: configs, _ctx_type: typeof global.get('tc_configs') };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 1080, wires: [['ho_tc_load']]
  },
  {
    id: 'ho_tc_load', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
    x: 640, y: 1080, wires: []
  },
  {
    id: 'hi_tc_units_save', type: 'http in', z: CFG_TAB,
    name: 'POST /tc/units/save',
    url: '/tc/units/save', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 1120, wires: [['fn_tc_units_save']]
  },
  {
    id: 'fn_tc_units_save', type: 'function', z: CFG_TAB,
    name: 'Save TC known units',
    func: [
      "var id    = (msg.payload||{}).id;",
      "var units = (msg.payload||{}).units || {};",
      "if (!id) { msg.payload = { ok:false, error:'missing id' }; return msg; }",
      "global.set('tc_units_'+id, units);",
      "msg.payload = { ok: true, count: Object.keys(units).length };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 1120, wires: [['ho_tc_units_save']]
  },
  {
    id: 'ho_tc_units_save', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
    x: 640, y: 1120, wires: []
  },
  {
    id: 'hi_tc_units_load', type: 'http in', z: CFG_TAB,
    name: 'GET /tc/units/load',
    url: '/tc/units/load', method: 'get',
    upload: false, swaggerDoc: '',
    x: 200, y: 1160, wires: [['fn_tc_units_load']]
  },
  {
    id: 'fn_tc_units_load', type: 'function', z: CFG_TAB,
    name: 'Load TC known units',
    func: [
      "var id = msg.req && msg.req.query && msg.req.query.id;",
      "var units = id ? (global.get('tc_units_'+id) || {}) : {};",
      "msg.payload = { units: units };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 1160, wires: [['ho_tc_units_load']]
  },
  {
    id: 'ho_tc_units_load', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
    x: 640, y: 1160, wires: []
  },
  {
    id: 'hi_tc_feed_snapshot', type: 'http in', z: CFG_TAB,
    name: 'POST /tc/feed/snapshot',
    url: '/tc/feed/snapshot', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 1200, wires: [['fn_tc_feed_snapshot']]
  },
  {
    id: 'fn_tc_feed_snapshot', type: 'function', z: CFG_TAB,
    name: 'TC live feed → CSV template',
    func: FN_TC_FEED_SNAPSHOT,
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 1200, wires: [['ho_tc_feed_snapshot']]
  },
  {
    id: 'ho_tc_feed_snapshot', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
    x: 640, y: 1200, wires: []
  },

  // ── TC connection test (build URL → http request → parse → respond) ──
  {
    id: 'hi_tc_test', type: 'http in', z: CFG_TAB,
    name: 'POST /tc/config/test',
    url: '/tc/config/test', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 1215, wires: [['fn_tc_test_build']]
  },
  {
    id: 'fn_tc_test_build', type: 'function', z: CFG_TAB,
    name: 'Build TC test URL',
    func: [
      "var body = msg.payload || {};",
      "var agencyUrl = (body.agencyUrl || '').trim().replace(/\\/+$/, '');",
      "if (!agencyUrl) {",
      "  msg.payload = { ok: false, error: 'No URL provided' };",
      "  msg._tcTestSkip = true;",
      "  return msg;",
      "}",
      "msg._tcTestOriginReq = msg.req;",
      "msg._tcTestOriginRes = msg.res;",
      "msg.url = agencyUrl + '/0?f=json';",
      "msg.method = 'GET';",
      "msg.headers = { 'User-Agent': 'infra-TAK/tc-test', 'Accept': 'application/json' };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 410, y: 1215, wires: [['http_tc_test']]
  },
  {
    id: 'http_tc_test', type: 'http request', z: CFG_TAB,
    name: 'GET TC layer info',
    method: 'GET', ret: 'obj',
    paytoqs: 'ignore', url: '', tls: '',
    persist: false, proxy: '', insecureHTTPParser: false,
    authType: '', senderror: false, headers: [],
    x: 620, y: 1215, wires: [['fn_tc_test_parse']]
  },
  {
    id: 'fn_tc_test_parse', type: 'function', z: CFG_TAB,
    name: 'Parse TC test result',
    func: [
      "if (msg._tcTestSkip) { return msg; }",
      "var d = msg.payload || {};",
      "var sc = msg.statusCode || 200;",
      "if (d.error) {",
      "  msg.payload = { ok: false, error: 'Service error: ' + (d.error.message || JSON.stringify(d.error)) };",
      "} else if (sc >= 400) {",
      "  msg.payload = { ok: false, error: 'HTTP ' + sc };",
      "} else {",
      "  // Extract field names from layer metadata (for remarks picker)",
      "  var SKIP = ['Shape__Area','Shape__Length','Shape_Area','Shape_Length','objectid','OBJECTID','GlobalID','globalid'];",
      "  var fields = (d.fields || []).map(function(f){ return { key: f.name, label: f.alias || f.name }; })",
      "    .filter(function(f){ return SKIP.indexOf(f.key) === -1 && f.key.toLowerCase() !== 'shape'; });",
      "  msg.payload = {",
      "    ok: true,",
      "    name: d.name || d.serviceName || 'Feature Layer',",
      "    type: d.geometryType || d.type || '',",
      "    status: sc,",
      "    fields: fields",
      "  };",
      "}",
      "msg.req = msg._tcTestOriginReq;",
      "msg.res = msg._tcTestOriginRes;",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 820, y: 1215, wires: [['ho_tc_test']]
  },
  {
    id: 'ho_tc_test', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
    x: 1020, y: 1215, wires: []
  },

  // ── Config backup list / restore ──
  {
    id: 'c_backups', type: 'comment', z: CFG_TAB,
    name: '── Config Backups ──',
    info: '', x: 260, y: 1220, wires: []
  },
  {
    id: 'hi_cfg_bk_list', type: 'http in', z: CFG_TAB,
    name: 'GET /config/backups',
    url: '/config/backups', method: 'get',
    upload: false, swaggerDoc: '',
    x: 200, y: 1260, wires: [['fn_cfg_bk_list']]
  },
  {
    id: 'fn_cfg_bk_list', type: 'function', z: CFG_TAB,
    name: 'List config backups',
    func: [
      "function _pc(v){if(v&&typeof v==='object'&&!Array.isArray(v)&&'msg'in v){var m=v.msg;if(typeof m==='string'){try{return JSON.parse(m);}catch(e){return m;}}return m;}if(typeof v==='string'){try{return JSON.parse(v);}catch(e){return v;}}return v;}",
      "function _snapInfo(d, filename) {",
      "  var ac=_pc(d.arcgis_configs); if(!Array.isArray(ac)) ac=[];",
      "  var tc=_pc(d.tc_configs);     if(!Array.isArray(tc)) tc=[];",
      "  return { filename: filename, timestamp: d.timestamp||null,",
      "    arcgis_count: ac.filter(function(c){return c.sourceType==='arcgis'||!c.sourceType;}).length,",
      "    tfr_count:    ac.filter(function(c){return c.sourceType==='faa_tfr';}).length,",
      "    kml_count:    ac.filter(function(c){return c.sourceType==='kml';}).length,",
      "    tc_count: tc.length,",
      "    has_tak: !!(d.tak_settings && Object.keys(d.tak_settings||{}).length),",
      "    has_ipaws: !!(d.ipaws_config && d.ipaws_config.activated),",
      "    has_pulsepoint: !!(d.pp_configs && Array.isArray(d.pp_configs) && d.pp_configs.some(function(c){return c.activated;})) };",
      "}",
      "var backups = [];",
      "// Primary: context-stored snapshots (no fs needed)",
      "try {",
      "  var _hist = global.get('ctx_backups') || [];",
      "  if (!Array.isArray(_hist)) _hist = [];",
      "  _hist.forEach(function(snap, i) {",
      "    try { backups.push(_snapInfo(snap, 'ctx:' + i)); } catch(e) {}",
      "  });",
      "} catch(e) {}",
      "// Secondary: filesystem backups (if available)",
      "try {",
      "  var _fs = global.get('fs');",
      "  if (_fs) {",
      "    var _bd = '/data/config-backups';",
      "    if (_fs.existsSync(_bd)) {",
      "      var files = _fs.readdirSync(_bd).filter(function(f){ return f==='latest.json'||f.startsWith('backup_'); }).sort().reverse();",
      "      files.forEach(function(f) {",
      "        try { var d=JSON.parse(_fs.readFileSync(_bd+'/'+f,'utf8')); backups.push(_snapInfo(d,'fs:'+f)); } catch(e) {}",
      "      });",
      "    }",
      "  }",
      "} catch(e) {}",
      "msg.payload = { backups: backups };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 1260, wires: [['ho_cfg_bk_list']]
  },
  {
    id: 'ho_cfg_bk_list', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
    x: 640, y: 1260, wires: []
  },
  {
    id: 'hi_cfg_restore', type: 'http in', z: CFG_TAB,
    name: 'POST /config/restore',
    url: '/config/restore', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 1300, wires: [['fn_cfg_restore']]
  },
  {
    id: 'fn_cfg_restore', type: 'function', z: CFG_TAB,
    name: 'Restore from backup',
    func: [
      "function _pc(v){if(v&&typeof v==='object'&&!Array.isArray(v)&&'msg'in v){var m=v.msg;if(typeof m==='string'){try{return JSON.parse(m);}catch(e){return m;}}return m;}if(typeof v==='string'){try{return JSON.parse(v);}catch(e){return v;}}return v;}",
      "var filename = (msg.payload||{}).filename;",
      "if (!filename) { msg.payload = { ok:false, error:'missing filename' }; return msg; }",
      "try {",
      "  var d;",
      "  if (filename.indexOf('ctx:') === 0) {",
      "    // Restore from context-stored snapshot",
      "    var idx = parseInt(filename.slice(4), 10);",
      "    var _hist = global.get('ctx_backups') || [];",
      "    if (!Array.isArray(_hist) || !_hist[idx]) { msg.payload={ok:false,error:'backup index not found'}; return msg; }",
      "    d = _hist[idx];",
      "  } else {",
      "    // Restore from filesystem backup",
      "    var fn2 = filename.indexOf('fs:') === 0 ? filename.slice(3) : filename;",
      "    if (fn2.indexOf('/') >= 0 || fn2.indexOf('..') >= 0) { msg.payload={ok:false,error:'invalid filename'}; return msg; }",
      "    var _fs = global.get('fs');",
      "    if (!_fs) { msg.payload={ok:false,error:'fs not available — use a context backup instead'}; return msg; }",
      "    d = JSON.parse(_fs.readFileSync('/data/config-backups/'+fn2,'utf8'));",
      "  }",
      "  var ac=_pc(d.arcgis_configs); if(!Array.isArray(ac)) ac=[];",
      "  var tc=_pc(d.tc_configs);     if(!Array.isArray(tc)) tc=[];",
      "  var ts=_pc(d.tak_settings);   if(!ts||typeof ts!=='object'||Array.isArray(ts)) ts={};",
      "  var ip=_pc(d.ipaws_config);   if(!ip||typeof ip!=='object'||Array.isArray(ip)) ip={};",
      "  var pp=_pc(d.pp_configs);     if(!Array.isArray(pp)) pp=[];",
      "  global.set('arcgis_configs',    ac);",
      "  global.set('tc_configs',        tc);",
      "  global.set('tak_settings',      ts);",
      "  global.set('ipaws_config',      ip);",
      "  global.set('pp_configs',        pp);",
      "  msg.payload = { ok:true, restored_from:filename, timestamp:d.timestamp, arcgis_count:ac.length, tc_count:tc.length };",
      "} catch(e) {",
      "  msg.payload = { ok:false, error:e.message };",
      "}",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 430, y: 1300, wires: [['ho_cfg_restore']]
  },
  {
    id: 'ho_cfg_restore', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
    x: 640, y: 1300, wires: []
  },

  // ── Deploy-time context restore (called by deploy.sh after container starts) ──
  // Accepts the full backed-up context JSON and pushes it into global context via
  // global.set() so it works regardless of contextStorage backend (memory or filesystem).
  {
    id: 'hi_deploy_restore', type: 'http in', z: CFG_TAB,
    name: 'POST /config/deploy-restore',
    url: '/config/deploy-restore', method: 'post',
    upload: false, swaggerDoc: '',
    x: 200, y: 1340, wires: [['fn_deploy_restore']]
  },
  {
    id: 'fn_deploy_restore', type: 'function', z: CFG_TAB,
    name: 'Deploy restore — set global context',
    func: [
      "var d = msg.payload;",
      "// Body parser may deliver a Buffer or string if Content-Type negotiation fails",
      "if (typeof d === 'string' || Buffer.isBuffer(d)) {",
      "  try { d = JSON.parse(d.toString()); } catch(e) { d = {}; }",
      "}",
      "if (!d || typeof d !== 'object' || Array.isArray(d)) d = {};",
      "// localfilesystem contextStorage wraps keys under a 'default' envelope",
      "if (d['default'] && typeof d['default'] === 'object' && !Array.isArray(d['default'])) d = d['default'];",
      "// localfilesystem context REST API wraps each value as {msg: <json>, format: <hint>} — unwrap it.",
      "// Also handles bare strings: deploy.sh sometimes serializes values to JSON-strings; if we wrote",
      "// those into context as-is, downstream fn_save would crash on configs.findIndex (TypeError).",
      "function unwrapCtxVal(v) {",
      "  if (v && typeof v === 'object' && !Array.isArray(v) && 'msg' in v) {",
      "    var inner = v.msg;",
      "    if (typeof inner === 'string') { try { return JSON.parse(inner); } catch(e) { return inner; } }",
      "    return inner;",
      "  }",
      "  if (typeof v === 'string') { try { return JSON.parse(v); } catch(e) { return v; } }",
      "  return v;",
      "}",
      "// Type-coerce restored values. CRITICAL: NEVER silently overwrite a non-empty",
      "// existing value with empty. If the payload value can't be coerced AND the",
      "// existing cache value is non-empty, KEEP THE EXISTING VALUE and quarantine the",
      "// bad payload for inspection. This is the strongest \"never lose data on update\"",
      "// guarantee: even if deploy.sh sends garbage, your live configs survive.",
      "var EXPECTED = {",
      "  arcgis_configs: 'array',",
      "  tc_configs:     'array',",
      "  pp_configs:     'array',",
      "  tak_settings:   'object',",
      "  ipaws_config:   'object'",
      "};",
      "function _isNonEmpty(v) {",
      "  if (v === null || v === undefined) return false;",
      "  if (Array.isArray(v)) return v.length > 0;",
      "  if (typeof v === 'object') return Object.keys(v).length > 0;",
      "  if (typeof v === 'string') return v.length > 0;",
      "  return true;",
      "}",
      "function _typeOk(k, v) {",
      "  if (EXPECTED[k] === 'array')  return Array.isArray(v);",
      "  if (EXPECTED[k] === 'object') return v && typeof v === 'object' && !Array.isArray(v);",
      "  return true;",
      "}",
      "var restored = [], skipped = [], quarantined = [];",
      "var KEYS = Object.keys(EXPECTED);",
      "var ts = new Date().toISOString().replace(/[:.]/g, '_');",
      "KEYS.forEach(function(k) {",
      "  if (d[k] === undefined) {",
      "    if (global.get(k) === undefined || global.get(k) === null) {",
      "      global.set(k, EXPECTED[k] === 'array' ? [] : {});",
      "      restored.push(k + '(empty)');",
      "    }",
      "    return;",
      "  }",
      "  var unwrapped = unwrapCtxVal(d[k]);",
      "  if (_typeOk(k, unwrapped)) {",
      "    global.set(k, unwrapped);",
      "    restored.push(k + (Array.isArray(unwrapped) ? '(' + unwrapped.length + ')' : ''));",
      "    return;",
      "  }",
      "  // Payload value is wrong type. Don't blindly wipe.",
      "  var existing = global.get(k);",
      "  if (_isNonEmpty(existing) && _typeOk(k, existing)) {",
      "    // Existing cache has good data — keep it, quarantine the bad payload",
      "    var qkey = k + '_quarantine_' + ts;",
      "    global.set(qkey, d[k]);",
      "    quarantined.push(qkey);",
      "    skipped.push(k + '(kept existing)');",
      "    return;",
      "  }",
      "  // No good existing data either — initialize empty (last resort)",
      "  global.set(k, EXPECTED[k] === 'array' ? [] : {});",
      "  restored.push(k + '(coerced empty)');",
      "});",
      "msg.payload = { ok: true, restored: restored, skipped: skipped, quarantined: quarantined, keys_in_payload: Object.keys(d).filter(function(k){ return KEYS.indexOf(k)>=0; }) };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 440, y: 1340, wires: [['ho_deploy_restore']]
  },
  {
    id: 'ho_deploy_restore', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
    x: 660, y: 1340, wires: []
  },

  // ── Force re-subscribe ──
  {
    id: 'hi_force_sub', type: 'http in', z: CFG_TAB,
    name: 'POST /arcgis-tak/tak/force-subscribe',
    url: '/arcgis-tak/tak/force-subscribe', method: 'post',
    upload: false, swaggerDoc: '',
    x: 220, y: 960, wires: [['fn_force_sub']]
  },
  {
    id: 'fn_force_sub', type: 'function', z: CFG_TAB,
    name: 'Clear mission subscribe cache',
    func: [
      "var sub = global.get('_subscribed') || {};",
      "var mn = (msg.payload && msg.payload.missionName) ? String(msg.payload.missionName).trim() : '';",
      "if (mn) {",
      "  delete sub[mn];",
      "  global.set('_subscribed', sub);",
      "  msg.payload = { ok: true, cleared: mn };",
      "} else {",
      "  global.set('_subscribed', {});",
      "  msg.payload = { ok: true, cleared: 'all' };",
      "}",
      "node.warn('force-subscribe: next poll will PUT /subscription for ' + (mn || 'all missions'));",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 480, y: 960, wires: [['ho_force_sub']]
  },
  {
    id: 'ho_force_sub', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 720, y: 960, wires: []
  },

  // ── Purge orphan UIDs (one-shot) ──
  {
    id: 'hi_purge', type: 'http in', z: CFG_TAB,
    name: 'POST /arcgis-tak/tak/purge-orphans',
    url: '/arcgis-tak/tak/purge-orphans', method: 'post',
    upload: false, swaggerDoc: '',
    x: 220, y: 990, wires: [['fn_purge']]
  },
  {
    id: 'fn_purge', type: 'function', z: CFG_TAB,
    name: 'Queue one-shot orphan purge',
    func: [
      "var name = (msg.payload && msg.payload.configName) ? String(msg.payload.configName).trim() : '';",
      "if (!name) {",
      "  msg.statusCode = 400;",
      "  msg.payload = { ok: false, error: 'configName required' };",
      "  return msg;",
      "}",
      "var fp = global.get('_forcePurge') || {};",
      "fp[name] = true;",
      "global.set('_forcePurge', fp);",
      "var pollKey = '_lastPoll_' + name.replace(/[^A-Za-z0-9]/g, '_');",
      "global.set(pollKey, 0);",
      "node.warn('purge-orphans queued for ' + name + ' — next poll will DELETE any UIDs in mission not in current ArcGIS set');",
      "msg.payload = { ok: true, queued: name, note: 'Next poll cycle will remove orphans. Click Update Now or wait for poll interval.' };",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '', libs: [],
    x: 500, y: 990, wires: [['ho_purge']]
  },
  {
    id: 'ho_purge', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '', headers: {},
    x: 720, y: 990, wires: []
  },

  // ── Icon catalog endpoint ──
  {
    id: 'c_icons', type: 'comment', z: CFG_TAB,
    name: '── Icon Catalog ──',
    info: '', x: 240, y: 1020, wires: []
  },
  {
    id: 'hi_icons', type: 'http in', z: CFG_TAB,
    name: 'GET /arcgis-tak/icons',
    url: '/arcgis-tak/icons', method: 'get',
    upload: false, swaggerDoc: '',
    x: 200, y: 1060, wires: [['fn_icons']]
  },
  {
    id: 'fn_icons', type: 'function', z: CFG_TAB,
    name: 'Serve icon catalog',
    func: [
      "try {",
      "  msg.payload = JSON.parse(fs.readFileSync('/data/icon-catalog.json', 'utf8'));",
      "} catch(e) { msg.payload = { error: e.message }; }",
      "return msg;"
    ].join('\n'),
    outputs: 1, timeout: '', noerr: 0,
    initialize: '', finalize: '',
    libs: [{ var: 'fs', module: 'fs' }],
    x: 430, y: 1060, wires: [['ho_icons']]
  },
  {
    id: 'ho_icons', type: 'http response', z: CFG_TAB,
    name: '', statusCode: '200',
    headers: { 'content-type': 'application/json', 'cache-control': 'public, max-age=86400' },
    x: 640, y: 1060, wires: []
  }
];

// ════════════════════════════════════════════════════════════════
//  TLS configs — global nodes, shared by all engine tabs
// ════════════════════════════════════════════════════════════════

// Do not ship paths to real cert files — fresh clones have no /certs mount until configured.
// deploy.sh auto-fills /certs/admin.pem when /opt/tak/certs/files/admin.pem exists on the host.
// Otherwise: mount host certs to /certs in the nodered container and set paths in the editor, or upload certs in the TLS node UI.
const tlsNodes = [
  {
    id: 'tls_tak', type: 'tls-config',
    name: 'TAK Mission API TLS',
    cert: '', key: '', ca: '',
    certname: '', keyname: '', caname: '',
    servername: '', verifyservercert: false
  }
];

// ════════════════════════════════════════════════════════════════
//  Shared function code strings (used by all engine tabs)
// ════════════════════════════════════════════════════════════════

const FN_TTL = [
  "function ttlMs(c) {",
  "  var u = c.ttlUnit || 'hours';",
  "  var v;",
  "  if (c.ttlValue != null && c.ttlValue !== '') v = Number(c.ttlValue);",
  "  else if (c.ttlHours != null && c.ttlHours !== '') { v = Number(c.ttlHours); u = 'hours'; }",
  "  else return 0;",
  "  if (!(v > 0) || v !== v) return 0;",
  "  if (u === 'minutes') return v * 60 * 1000;",
  "  if (u === 'days') return v * 24 * 3600000;",
  "  return v * 3600000;",
  "}"
].join('\n');

const FN_BUILD_QUERY = [
  FN_TTL,
  "var cfg = msg.payload;",
  "msg.topic = (cfg.configName && String(cfg.configName).trim()) ? String(cfg.configName).trim() : 'unnamed';",
  "var base = cfg.source.serviceUrl.replace(/\\/+$/, '');",
  "var parts = [];",
  "if (cfg.source.where) parts.push(cfg.source.where);",
  "if (cfg.mapping.timeField && ttlMs(cfg) > 0) {",
  "  var cutoffMs = Date.now() - ttlMs(cfg);",
  "  if (cfg.mapping.timeFieldEpochMs) {",
  "    parts.push(cfg.mapping.timeField + ' >= ' + Math.floor(cutoffMs));",
  "  } else {",
  "    var cd = new Date(cutoffMs);",
  "    var y = cd.getUTCFullYear();",
  "    var mo = ('0' + (cd.getUTCMonth() + 1)).slice(-2);",
  "    var da = ('0' + cd.getUTCDate()).slice(-2);",
  "    parts.push(cfg.mapping.timeField + \" >= DATE '\" + y + '-' + mo + '-' + da + \"'\");",
  "  }",
  "}",
  "var where = parts.length > 0 ? parts.join(' AND ') : '1=1';",
  "var isMultiLayer = cfg.source.layers && cfg.source.layers.length > 1;",
  "var layers = cfg.source.layers || [{ layerId: cfg.source.layerId, layerName: cfg.source.layerName || '', geometryType: cfg.source.geometryType || '' }];",
  "var msgs = [];",
  "for (var li = 0; li < layers.length; li++) {",
  "  var lyr = layers[li];",
  "  var m = { topic: msg.topic, _config: JSON.parse(JSON.stringify(cfg)), headers: msg.headers || {}, takSettings: msg.takSettings };",
  "  m._config.source.layerId = lyr.layerId;",
  "  m._config.source.layerName = lyr.layerName || '';",
  "  m._config.source.geometryType = lyr.geometryType || cfg.source.geometryType || '';",
  "  m._layerName = isMultiLayer ? (lyr.layerName || String(lyr.layerId)) : '';",
  "  m.url = base + '/' + lyr.layerId + '/query'",
  "    + '?where=' + encodeURIComponent(where)",
  "    + '&outFields=*&returnGeometry=true&outSR=4326&f=json';",
  "  msgs.push(m);",
  "}",
  "node.warn(msg.topic + ' ArcGIS query (' + layers.length + ' layers) where: ' + where);",
  "return [msgs];"
].join('\n');

const FN_PARSE_COT = [
  "var features = (msg.payload && msg.payload.features) || [];",
  "var cfg = msg._config;",
  "msg._arcgisStatus = msg.statusCode || 200;",
  "if (features.length === 0) {",
  "  node.warn(cfg.configName + ': 0 features from ArcGIS (status ' + msg._arcgisStatus + ')');",
  "  msg._features = [];",
  "  var lc0 = msg._layerName || '';",
  "  msg._layerPrefix = lc0 ? (cfg.uidPrefix || 'arcgis') + lc0.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') + '-' : '';",
  "  msg._config = cfg;",
  "  return msg;",
  "}",
  "",
  "var dedupField = (cfg.mapping && cfg.mapping.dedupField) || null;",
  "var timeField  = (cfg.mapping && cfg.mapping.timeField)  || null;",
  "if (dedupField && timeField) {",
  "  // toMs: numeric epoch passes through; date strings (e.g. '5/19/2026 11:22 AM') parsed via Date.",
  "  function toMs(v) {",
  "    if (v == null) return -Infinity;",
  "    var n = Number(v);",
  "    if (!isNaN(n)) return n;",
  "    try { var d = new Date(String(v)); var t = d.getTime(); return isNaN(t) ? -Infinity : t; }",
  "    catch(e) { return -Infinity; }",
  "  }",
  "  // Keep ALL records sharing the same latest timestamp per dedupField group.",
  "  // This handles sources like FIRIS KML where each ring is a separate placemark",
  "  // but all rings in a snapshot share the same source value and Created On.",
  "  var groups = {};",
  "  for (var di = 0; di < features.length; di++) {",
  "    var da = features[di].attributes || {};",
  "    var key = String(da[dedupField] || '');",
  "    var tms = toMs(da[timeField]);",
  "    if (!groups[key] || tms > groups[key].maxT) {",
  "      groups[key] = { maxT: tms, records: [features[di]] };",
  "    } else if (tms === groups[key].maxT) {",
  "      groups[key].records.push(features[di]);",
  "    }",
  "  }",
  "  var before = features.length;",
  "  features = [];",
  "  Object.keys(groups).forEach(function(k) {",
  "    groups[k].records.forEach(function(r) { features.push(r); });",
  "  });",
  "  if (features.length < before) {",
  "    node.warn(cfg.configName + ': dedup by ' + dedupField + ': ' + before + ' -> ' + features.length + ' features');",
  "  }",
  "}",
  "",
  FN_TTL,
  "",
  "function hexArgb(hex, a) {",
  "  var r = parseInt(hex.substr(1,2),16);",
  "  var g = parseInt(hex.substr(3,2),16);",
  "  var b = parseInt(hex.substr(5,2),16);",
  "  var ai = Math.round((a !== undefined ? a : 1) * 255);",
  "  return ((ai << 24) | (r << 16) | (g << 8) | b);",
  "}",
  "",
  "var sColor = cfg.style.strokeColor || cfg.style.color || '#FF0000';",
  "var fColor = cfg.style.fillColor || cfg.style.color || '#FF0000';",
  "var strokeArgb = hexArgb(sColor, 1);",
  "var rawAlpha = cfg.style.fillAlpha;",
  "var fillAlphaFloat;",
  "if (typeof rawAlpha === 'number') fillAlphaFloat = rawAlpha / 100;",
  "else if (typeof rawAlpha === 'string' && /^[0-9a-fA-F]{1,2}$/.test(rawAlpha)) fillAlphaFloat = parseInt(rawAlpha, 16) / 255;",
  "else fillAlphaFloat = 0.33;",
  "var fillArgb = hexArgb(fColor, fillAlphaFloat);",
  "var now = new Date();",
  "var tm = ttlMs(cfg);",
  "var staleMs = tm > 0 ? tm : 3600000;",
  "var stale = new Date(now.getTime() + staleMs);",
  "var classField = (cfg.classField && String(cfg.classField).trim()) || null;",
  "var layerClass = msg._layerName || '';",
  "var classes = cfg.classes || {};",
  "var defaultClass = classes._default || {};",
  "",
  "function geomKind(g) {",
  "  if (g.rings && g.rings[0]) return 'polygon';",
  "  if (g.paths && g.paths[0]) return 'polyline';",
  "  if (g.x != null && g.y != null) return 'point';",
  "  return 'unknown';",
  "}",
  "function cotTypeForKind(kind) {",
  "  if (kind === 'polygon' || kind === 'polyline') return 'u-d-f';",
  "  return 'a-u-G';",
  "}",
  "",
  "function djb2(s) {",
  "  var h = 5381;",
  "  for (var c = 0; c < s.length; c++) { h = ((h << 5) + h) + s.charCodeAt(c); h = h & h; }",
  "  return String(h >>> 0);",
  "}",
  "// ArcGIS REST: outer rings are CW (signed area < 0 in Y-up geographic coords); holes are CCW.",
  "function ringArea2x(ring) {",
  "  var a = 0;",
  "  for (var k = 0; k < ring.length - 1; k++) a += ring[k][0]*ring[k+1][1] - ring[k+1][0]*ring[k][1];",
  "  return a;",
  "}",
  "",
  "var results = [];",
  "for (var i = 0; i < features.length; i++) {",
  "  var f = features[i];",
  "  var a = f.attributes || {};",
  "  var g = f.geometry;",
  "  if (!g) continue;",
  "  var gKey;",
  "  if (g.x!=null) { gKey=Math.round(g.x*1e6)/1e6+','+Math.round(g.y*1e6)/1e6; }",
  "  else if (g.rings&&g.rings[0]) { var r=g.rings[0],sx=0,sy=0; for(var gi=0;gi<r.length;gi++){sx+=r[gi][0];sy+=r[gi][1];} gKey=r.length+','+Math.round(sx/r.length*1e4)/1e4+','+Math.round(sy/r.length*1e4)/1e4; }",
  "  else if (g.paths&&g.paths[0]) { var pp=g.paths[0],sx=0,sy=0; for(var gi=0;gi<pp.length;gi++){sx+=pp[gi][0];sy+=pp[gi][1];} gKey=pp.length+','+Math.round(sx/pp.length*1e4)/1e4+','+Math.round(sy/pp.length*1e4)/1e4; }",
  "  else { gKey=JSON.stringify(g); }",
  "  var idFields = (cfg.mapping.idFields && cfg.mapping.idFields.length) ? cfg.mapping.idFields : (cfg.mapping.idField ? [cfg.mapping.idField] : []);",
"  var hp = [gKey];",
"  for (var hfi = 0; hfi < idFields.length; hfi++) hp.push(String(a[idFields[hfi]] != null ? a[idFields[hfi]] : ''));",
"  if (cfg.style.labelFields && cfg.style.labelFields.length) {",
"    for (var __hli = 0; __hli < cfg.style.labelFields.length; __hli++) {",
"      hp.push(String(a[cfg.style.labelFields[__hli]] || ''));",
"    }",
"  } else if (cfg.style.labelField) hp.push(String(a[cfg.style.labelField] || ''));",
"  if (cfg.remarksFields) { for (var ri=0;ri<cfg.remarksFields.length;ri++) hp.push(String(a[cfg.remarksFields[ri]] || '')); }",
"  var _hash = djb2(hp.join('|'));",
  "",
  "  var idVal;",
  "  if (idFields.length === 0) {",
  "    idVal = 'f' + i;",
  "  } else if (idFields.length === 1) {",
  "    idVal = (a[idFields[0]] != null && a[idFields[0]] !== '') ? a[idFields[0]] : ('f' + i);",
  "  } else {",
  "    var idParts = [];",
  "    for (var ifi = 0; ifi < idFields.length; ifi++) idParts.push(String(a[idFields[ifi]] != null ? a[idFields[ifi]] : ''));",
  "    idVal = 'c' + djb2(idParts.join('|'));",
  "  }",
  "  var layerTag = layerClass ? layerClass.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') + '-' : '';",
  "  var uid = (cfg.uidPrefix || 'arcgis') + layerTag + String(idVal).replace(/[^a-zA-Z0-9_.-]/g, '_');",
  "",
  "  var kind = geomKind(g);",
  "  var classVal = classField === '_layer' ? layerClass : (classField ? String(a[classField] || '') : (layerClass || ''));",
  "  var cls = (classVal && classes[classVal]) || defaultClass;",
  "  if (cls.enabled === false) continue;",
  "  var fCotType = cls.cotType || cotTypeForKind(kind);",
  "  var fIconsetpath = cls.iconsetpath || null;",
  "  var noColor = (cls.color === '' && classes[classVal]);",
  "  var fColor_s = noColor ? null : (cls.color || sColor);",
  "  var fColor_f = noColor ? null : (cls.fillColor || cls.color || fColor);",
  "  var fStrokeArgb = fColor_s ? hexArgb(fColor_s, 1) : null;",
  "  var fFillArgb = fColor_f ? hexArgb(fColor_f, fillAlphaFloat) : null;",
  "",
  "  var _parts = [];",
  "  if (kind === 'polygon') {",
  "    var _outer = [];",
  "    for (var _ri = 0; _ri < g.rings.length; _ri++) {",
  "      var _rr = g.rings[_ri];",
  "      if (_rr.length >= 4 && ringArea2x(_rr) <= 0) _outer.push(_rr);",
  "    }",
  "    if (_outer.length === 0) _outer = g.rings.slice(0);",
  "    var _isMultiPoly = _outer.length > 1;",
  "    for (var _ri2 = 0; _ri2 < _outer.length; _ri2++) {",
  "      var _rr2 = _outer[_ri2]; var _rsx = 0, _rsy = 0;",
  "      for (var _rj = 0; _rj < _rr2.length; _rj++) { _rsx += _rr2[_rj][0]; _rsy += _rr2[_rj][1]; }",
  "      var _rgk = _rr2.length+','+Math.round(_rsx/_rr2.length*1e4)/1e4+','+Math.round(_rsy/_rr2.length*1e4)/1e4;",
  "      _parts.push({ uid: _isMultiPoly ? uid+'-r'+_ri2 : uid, _hash: _isMultiPoly ? djb2(_hash+'|r'+_ri2+'|'+_rgk) : _hash, lat: _rsy/_rr2.length, lon: _rsx/_rr2.length, verts: _rr2 });",
  "    }",
  "  } else if (kind === 'polyline') {",
  "    var _isMultiPath = g.paths.length > 1;",
  "    for (var _pi = 0; _pi < g.paths.length; _pi++) {",
  "      var _pp = g.paths[_pi]; var _psx = 0, _psy = 0;",
  "      for (var _pj = 0; _pj < _pp.length; _pj++) { _psx += _pp[_pj][0]; _psy += _pp[_pj][1]; }",
  "      var _pgk = _pp.length+','+Math.round(_psx/_pp.length*1e4)/1e4+','+Math.round(_psy/_pp.length*1e4)/1e4;",
  "      _parts.push({ uid: _isMultiPath ? uid+'-p'+_pi : uid, _hash: _isMultiPath ? djb2(_hash+'|p'+_pi+'|'+_pgk) : _hash, lat: _psy/_pp.length, lon: _psx/_pp.length, verts: _pp });",
  "    }",
  "  } else {",
  "    _parts.push({ uid: uid, _hash: _hash, lat: g.y || 0, lon: g.x || 0, verts: null });",
  "  }",
  "  for (var _pIdx = 0; _pIdx < _parts.length; _pIdx++) {",
  "    var _pt = _parts[_pIdx]; var lat = _pt.lat, lon = _pt.lon, verts = _pt.verts;",
  "",
  "  function fmtVal(v) {",
  "    if (v == null) return '';",
  "    var n = Number(v);",
  "    if (!isNaN(n) && n > 1e12) {",
  "      var d = new Date(n);",
  "      var utc = d.getTime() + (d.getTimezoneOffset() * 60000);",
  "      var pst = new Date(utc - 28800000);",
  "      var mo = ('0'+(pst.getMonth()+1)).slice(-2);",
  "      var da = ('0'+pst.getDate()).slice(-2);",
  "      var yr = pst.getFullYear();",
  "      var hr = ('0'+pst.getHours()).slice(-2);",
  "      var mi = ('0'+pst.getMinutes()).slice(-2);",
  "      return mo+'/'+da+'/'+yr+' '+hr+':'+mi+' PST';",
  "    }",
  "    if (!isNaN(n) && String(v).indexOf('.') !== -1) return String(Math.round(n));",
  "    return String(v);",
  "  }",
  "  function tmpl(t, attrs) {",
  "    var out = t.replace(/\\{([^}]+)\\}/g, function(m, key) { return fmtVal(attrs[key]); });",
  "    return out.replace(/ *\\| *$/,'').replace(/^ *\\| */,'').replace(/ *\\| *\\| */g,' | ').replace(/  +/g,' ').trim();",
  "  }",
  "",
  "  var callsign = uid;",
  "  if (cls.labelTemplate) callsign = tmpl(cls.labelTemplate, a);",
  "  else if (cls.customLabel) callsign = String(cls.customLabel);",
  "  else if (cfg.style.labelTemplate && String(cfg.style.labelTemplate).trim()) callsign = tmpl(cfg.style.labelTemplate, a);",
  "  else if (cfg.style.customLabel) callsign = String(cfg.style.customLabel);",
  "  else if (cfg.style.labelField && a[cfg.style.labelField] != null) callsign = String(a[cfg.style.labelField]);",
  "  if (cls.labelUpperCase || cfg.style.labelUpperCase) callsign = callsign.toUpperCase();",
  "",
  "  var remarks = '';",
  "  if (cls.remarksTemplate) {",
  "    remarks = tmpl(cls.remarksTemplate, a);",
  "  } else {",
  "    var rmkFields = (cls.remarksFields && cls.remarksFields.length) ? cls.remarksFields : (cfg.remarksFields || []);",
  "    if (rmkFields.length) {",
  "      var rp = [];",
  "      for (var k=0;k<rmkFields.length;k++) {",
  "        var fn = rmkFields[k];",
  "        rp.push(fn + ': ' + fmtVal(a[fn]));",
  "      }",
  "      remarks = rp.join(' | ');",
  "    }",
  "  }",
  "",
  "  var detail = {",
  "    contact: [{ _attributes: { callsign: callsign } }],",
  "    remarks: remarks,",
  "    labels_on: [{ _attributes: { value: (cls.labelsOn != null ? cls.labelsOn : cfg.style.labelsOn) ? 'true' : 'false' } }]",
  "  };",
  "  if (fStrokeArgb != null) detail.strokeColor = [{ _attributes: { value: String(fStrokeArgb) } }];",
  "  if (!noColor) detail.strokeWeight = [{ _attributes: { value: String(cfg.style.strokeWeight || 3) + '.0' } }];",
  "  if (fFillArgb != null) detail.fillColor = [{ _attributes: { value: String(fFillArgb) } }];",
  "",
  "  if (fIconsetpath && kind === 'point') {",
  "    detail.usericon = [{ _attributes: { iconsetpath: fIconsetpath } }];",
  "  }",
  "",
  "  if (verts) {",
  "    var links = [];",
  "    var ring2 = verts;",
  "    var MAX_VERTS = 200;",
  "    if (ring2.length > MAX_VERTS) {",
  "      var step = ring2.length / MAX_VERTS;",
  "      var simplified = [];",
  "      for (var s = 0; s < MAX_VERTS; s++) simplified.push(ring2[Math.floor(s * step)]);",
  "      if (ring2[ring2.length-1]) simplified.push(ring2[ring2.length-1]);",
  "      ring2 = simplified;",
  "    }",
  "    for (var j=0;j<ring2.length;j++) links.push({ _attributes: { point: ring2[j][1]+','+ring2[j][0] } });",
  "    detail.link = links;",
  "  }",
  "",
  "    results.push({",
  "      uid: _pt.uid,",
  "      _hash: _pt._hash,",
  "      cot: {",
  "        event: {",
  "          _attributes: {",
  "            version: '2.0', uid: _pt.uid, type: fCotType,",
  "            how: 'h-e',",
  "            time: now.toISOString(),",
  "            start: now.toISOString(),",
  "            stale: stale.toISOString()",
  "          },",
  "          point: { _attributes: { lat: String(lat), lon: String(lon), hae: '9999999.0', ce: '9999999.0', le: '9999999.0' } },",
  "          detail: detail",
  "        }",
  "      }",
  "    });",
  "  } // end parts loop",
  "}",
  "",
  "var lp = layerClass ? (cfg.uidPrefix || 'arcgis') + layerClass.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') + '-' : '';",
  "node.warn(cfg.configName + (layerClass ? ' [' + layerClass + ']' : '') + ': ' + results.length + ' CoT events built from ' + features.length + ' features');",
  "msg._features = results;",
  "msg._layerPrefix = lp;",
  "msg._config = cfg;",
  "return msg;"
].join('\n');

const FN_COT_TO_XML = [
  "var e = msg.payload && msg.payload.event;",
  "if (!e || !e._attributes) return null;",
  "var a = e._attributes;",
  "var p = e.point._attributes;",
  "var d = e.detail || {};",
  "",
  "var xml = '<event version=\"' + a.version + '\" uid=\"' + a.uid + '\" type=\"' + a.type + '\"'",
  "  + ' how=\"' + a.how + '\" time=\"' + a.time + '\" start=\"' + a.start + '\" stale=\"' + a.stale + '\">'",
  "  + '<point lat=\"' + p.lat + '\" lon=\"' + p.lon + '\" hae=\"' + p.hae + '\" ce=\"' + p.ce + '\" le=\"' + p.le + '\"/>'",
  "  + '<detail>';",
  "",
  "if (d.contact && d.contact[0]) xml += '<contact callsign=\"' + d.contact[0]._attributes.callsign + '\"/>';",
  "if (d.remarks != null) xml += '<remarks>' + String(d.remarks).replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</remarks>';",
  "if (d.strokeColor && d.strokeColor[0]) xml += '<strokeColor value=\"' + d.strokeColor[0]._attributes.value + '\"/>';",
  "if (d.strokeWeight && d.strokeWeight[0]) xml += '<strokeWeight value=\"' + d.strokeWeight[0]._attributes.value + '\"/>';",
  "if (d.fillColor && d.fillColor[0]) xml += '<fillColor value=\"' + d.fillColor[0]._attributes.value + '\"/>';",
  "if (d.labels_on && d.labels_on[0]) xml += '<labels_on value=\"' + d.labels_on[0]._attributes.value + '\"/>';",
  "",
  "if (d.link && d.link.length) {",
  "  for (var i = 0; i < d.link.length; i++) {",
  "    var la = d.link[i]._attributes;",
  "    if (la.point) {",
  "      xml += '<link point=\"' + la.point + '\"/>';",
  "    } else if (la.url) {",
  "      xml += '<link url=\"' + la.url.replace(/&/g,'&amp;') + '\"';",
  "      if (la.remarks) xml += ' remarks=\"' + la.remarks.replace(/&/g,'&amp;').replace(/\"/g,'&quot;') + '\"';",
  "      if (la.relation) xml += ' relation=\"' + la.relation + '\"';",
  "      if (la.mime) xml += ' mime=\"' + la.mime + '\"';",
  "      xml += '/>';",
  "    }",
  "  }",
  "}",
  "",
  "if (d.usericon && d.usericon[0]) xml += '<usericon iconsetpath=\"' + d.usericon[0]._attributes.iconsetpath + '\"/>';",
  "if (d.height && d.height[0]) xml += '<height value=\"' + d.height[0]._attributes.value + '\"/>';",
  "if (d.status && d.status[0]) xml += '<status readiness=\"' + d.status[0]._attributes.readiness + '\"/>';",
  "if (d.precisionlocation && d.precisionlocation[0]) xml += '<precisionlocation altsrc=\"' + d.precisionlocation[0]._attributes.altsrc + '\"/>';",
  "if (d._geofence && d._geofence[0]) {",
  "  var gf = d._geofence[0]._attributes;",
  "  xml += '<_geofence elevationMonitored=\"' + gf.elevationMonitored + '\"'",
  "    + ' minElevation=\"' + gf.minElevation + '\"'",
  "    + ' monitor=\"' + gf.monitor + '\"'",
  "    + ' trigger=\"' + gf.trigger + '\"'",
  "    + ' tracking=\"' + gf.tracking + '\"'",
  "    + ' maxElevation=\"' + gf.maxElevation + '\"'",
  "    + ' boundingSphere=\"' + gf.boundingSphere + '\"/>';",
  "}",
  "",
  "if (msg._missionName) {",
  "  xml += '<marti><dest mission=\"' + msg._missionName + '\"/></marti>';",
  "}",
  "// Phase 1B: flow attribution inside <detail>. TAK Server's CoT parser ignores unknown",
  "// elements, so this is a safe no-op for downstream consumers but lets centralized log",
  "// correlation tie each CoT back to a specific Configurator feed even when multiple",
  "// feeds share a cert identity (admin or nodered). The element is <__nodered> with a",
  "// double-underscore prefix to match TAK's convention for proprietary/extension tags.",
  "var _flowName = (msg._config && msg._config.configName) || msg.topic || '';",
  "if (_flowName) {",
  "  var _flowEsc = String(_flowName).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/\"/g,'&quot;');",
  "  xml += '<__nodered flow=\"' + _flowEsc + '\"/>';",
  "}",
  "xml += '</detail></event>\\n';",
  "",
  "msg.payload = Buffer.from(xml, 'utf8');",
  "if (msg.payload.length > 5000) node.warn('CoT ' + a.uid + ': ' + msg.payload.length + ' bytes');",
  "return msg;"
].join('\n');

// ════════════════════════════════════════════════════════════════
//  Per-feed engine tab generator
// ════════════════════════════════════════════════════════════════

function makeEngineTab(feed) {
  const FID = 'flow_eng_' + feed.id;
  const P   = feed.id + '_';

  // Reconcile — stream ALL CoTs via TCP, PUT new UIDs, DELETE stale
  const FN_RECONCILE = [
    "var features = msg._features || [];",
    "var mData = msg.payload;",
    "var cfg = msg._config;",
    "var tak = msg.takSettings;",
    "var topicCfg = cfg.configName || 'unnamed';",
    "msg.topic = topicCfg;",
    "var prefix = msg._layerPrefix || cfg.uidPrefix || 'arcgis';",
    "var arcgisOk = !msg._arcgisStatus || msg._arcgisStatus === 200;",
    "",
    "var existing = {};",
    "try {",
    "  var mission = null;",
    "  if (mData && mData.data) {",
    "    mission = Array.isArray(mData.data) ? mData.data[0] : mData.data;",
    "  }",
    "  if (mission && mission.uids) {",
    "    for (var i=0;i<mission.uids.length;i++) {",
    "      var u = mission.uids[i];",
    "      var uid = (typeof u === 'string') ? u : (u.data || u.uid || u);",
    "      if (typeof uid === 'string') existing[uid] = true;",
    "    }",
    "  }",
    "  if (mission && mission.contents) {",
    "    for (var i=0;i<mission.contents.length;i++) {",
    "      var c = mission.contents[i];",
    "      if (c.data && c.data.uid) existing[c.data.uid] = true;",
    "    }",
    "  }",
    "} catch(e) { node.warn('Could not parse mission contents: ' + e.message); }",
    "",
    "var arcgis = {};",
    "for (var i=0;i<features.length;i++) arcgis[features[i].uid] = features[i];",
    "",
    "var host = String(tak.serverUrl || '').replace(/^https?:\\/\\//i, '').replace(/\\/$/, '');",
    "var baseUrl = 'https://' + host + ':' + (tak.missionApiPort || 8443)",
    "  + '/Marti/api/missions/' + encodeURIComponent(cfg.missionName);",
    "var creatorUidRaw = String((cfg && cfg.creatorUid) || (tak && tak.creatorUid) || 'nodered').trim();",
    "var creator = encodeURIComponent(creatorUidRaw);",
    "",
    "var cookie = msg._missionCookie || '';",
    "var bearer = msg._missionBearer || '';",
    "if (!cookie && msg.responseCookies && msg.responseCookies.JSESSIONID && msg.responseCookies.JSESSIONID.value) {",
    "  cookie = 'JSESSIONID=' + String(msg.responseCookies.JSESSIONID.value);",
    "}",
    "if (!cookie && msg.headers && msg.headers['set-cookie']) {",
    "  var sc = msg.headers['set-cookie'];",
    "  if (Array.isArray(sc) && sc.length) {",
    "    var a2 = String(sc[0]).match(/JSESSIONID=([^;]+)/);",
    "    if (a2 && a2[1]) cookie = 'JSESSIONID=' + a2[1];",
    "  } else if (typeof sc === 'string') {",
    "    var b = sc.match(/JSESSIONID=([^;]+)/);",
    "    if (b && b[1]) cookie = 'JSESSIONID=' + b[1];",
    "  }",
    "}",
    "",
    "var hashKey = '_featureHashes' + (msg._layerPrefix ? '_' + msg._layerPrefix : '');",
    "var prevHashes = flow.get(hashKey) || {};",
    "var coldStart = (Object.keys(prevHashes).length === 0);",
    "var newHashes = {};",
    "var nStream = 0, nSkip = 0, nPut = 0, nDel = 0, nSeed = 0;",
    "var newUids = [];",
    "for (var uid in arcgis) {",
    "  var feat = arcgis[uid];",
    "  newHashes[uid] = feat._hash || '';",
    "  var changed = (prevHashes[uid] !== newHashes[uid]);",
    "  if (!existing[uid]) { nPut++; newUids.push(uid); }",
    "  if (coldStart && existing[uid]) {",
    "    nSeed++;",
    "  } else if (changed || !existing[uid]) {",
    "    nStream++;",
    "    node.send([",
    "      { payload: feat.cot, topic: topicCfg,",
    "        _missionName: cfg.missionName,",
    "        host: host,",
    "        port: Number(cfg.cotStreamPort) || Number(cfg.streamPort) || Number(tak.streamingPort) || Number(tak.streamPort) || 8089 },",
    "      null",
    "    ]);",
    "  } else { nSkip++; }",
    "}",
    "if (Object.keys(newHashes).length > 0) {",
    "  flow.set(hashKey, newHashes);",
    "} else if (Object.keys(prevHashes).length > 0) {",
    "  node.warn(topicCfg + ': 0 features from ArcGIS — keeping previous hashes to avoid false churn');",
    "}",
    "if (coldStart && nSeed > 0) node.warn(topicCfg + ' cold start: seeded ' + nSeed + ' hashes without re-streaming');",
    "if (coldStart && nSeed === 0) node.warn(topicCfg + ' cold start: no ArcGIS features this poll, nothing to reconcile');",
    "",
    "if (newUids.length > 0) {",
    "  node.send([",
    "    { topic: topicCfg, payload: {},",
    "      _missionCookie: cookie,",
    "      _missionBearer: bearer,",
    "      _putUrl: baseUrl + '/contents?creatorUid=' + creator,",
    "      _putUids: newUids },",
    "    null",
    "  ]);",
    "}",
    "",
    "if (!arcgisOk) {",
    "  node.warn(topicCfg + ': ArcGIS fetch failed (status ' + msg._arcgisStatus + ') - skipping deletes');",
    "} else if (Object.keys(arcgis).length === 0) {",
    "  node.warn(topicCfg + ': 0 features from ArcGIS (status 200) — skipping deletes to protect mission contents');",
    "} else {",
    "  var forcePurge = global.get('_forcePurge') || {};",
    "  var strictMode = (cfg.strictMode !== false);",
    "  var oneShotPurge = forcePurge[topicCfg] === true;",
    "  var isMultiLayerPass = !!msg._layerPrefix;",
    "  // Strict/purge disabled on multi-layer passes — each layer would DELETE sibling layers' UIDs, causing massive churn.",
    "  var cleanOrphans = (strictMode || oneShotPurge) && !isMultiLayerPass;",
    "  if ((strictMode || oneShotPurge) && isMultiLayerPass) {",
    "    node.warn(topicCfg + ' [' + msg._layerPrefix + ']: strict/purge disabled on this multi-layer pass — using prefix-guarded DELETE to protect sibling layers');",
    "  }",
    "  for (var uid in existing) {",
    "    var matchesPrefix = (uid.indexOf(prefix) === 0);",
    "    if (!arcgis[uid] && (cleanOrphans || matchesPrefix)) {",
    "      nDel++;",
    "      node.send([null, {",
    "        method: 'DELETE',",
    "        url: baseUrl + '/contents?uid=' + encodeURIComponent(uid) + '&creatorUid=' + creator,",
    "        headers: { 'accept': '*/*' },",
    "        _missionCookie: cookie,",
    "        _missionBearer: bearer,",
    "        payload: '',",
    "        topic: topicCfg",
    "      }]);",
    "    }",
    "  }",
    "  if (oneShotPurge) {",
    "    delete forcePurge[topicCfg];",
    "    global.set('_forcePurge', forcePurge);",
    "    if (isMultiLayerPass) {",
    "      node.warn(topicCfg + ': one-shot purge finished in prefix-guarded mode (multi-layer), DELETED ' + nDel + ' UIDs matching ' + prefix);",
    "    } else {",
    "      node.warn(topicCfg + ': one-shot purge complete, DELETED ' + nDel + ' orphan UIDs');",
    "    }",
    "  }",
    "}",
    "",
    "node.warn(topicCfg + ' reconcile: ' + nStream + ' streamed, ' + nSkip + ' unchanged, ' + nPut + ' PUT, ' + nDel + ' DELETE, '",
    "  + Object.keys(arcgis).length + ' ArcGIS, ' + Object.keys(existing).length + ' in mission' + (strictMode ? ' [strict]' : ''));",
    "return null;"
  ].join('\n');

  return [
    // ── Tab ──
    {
      id: FID, type: 'tab',
      label: feed.configName,
      disabled: false,
      info: 'DataSync engine for ' + feed.configName + '. Stream CoT via TCP, PUT UIDs to mission.'
    },

    // ── SA ident (identify TCP connection to TAK Server) ──
    {
      id: P + 'sa_inject', type: 'inject', z: FID,
      name: 'SA ident (startup)',
      props: [{ p: 'payload' }, { p: 'topic', vt: 'str' }],
      repeat: '600', crontab: '',
      once: true, onceDelay: '10',
      topic: 'sa-ident', payload: '', payloadType: 'date',
      x: 180, y: 40, wires: [[P + 'sa_build']]
    },
    {
      id: P + 'sa_build', type: 'function', z: FID,
      name: 'Build SA ident CoT',
      func: [
        "var tak = global.get('tak_settings') || {};",
        "var configs = global.get('arcgis_configs') || [];",
        "var cfg = null;",
        "for (var i = 0; i < configs.length; i++) {",
        "  if (configs[i].configName === '" + feed.configName + "') { cfg = configs[i]; break; }",
        "}",
        "var creatorUid = '';",
        "if (cfg && cfg.creatorUid) creatorUid = String(cfg.creatorUid).trim();",
        "if (!creatorUid && tak.creatorUid) creatorUid = String(tak.creatorUid).trim();",
        "if (!creatorUid) { return null; }",
        "",
        "var now = new Date();",
        "var stale = new Date(now.getTime() + 120000);",
        "msg.payload = {",
        "  event: {",
        "    _attributes: {",
        "      version: '2.0', uid: creatorUid,",
        "      type: 'a-f-G-E-S', how: 'h-g-i-g-o',",
        "      time: now.toISOString(), start: now.toISOString(), stale: stale.toISOString()",
        "    },",
        "    point: { _attributes: { lat: '0', lon: '0', hae: '0', ce: '9999999', le: '9999999' } },",
        "    detail: {",
        "      contact: [{ _attributes: { callsign: creatorUid } }],",
        "      __group: [{ _attributes: { name: 'Purple', role: 'Team Member' } }]",
        "    }",
        "  }",
        "};",
        "return msg;"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 400, y: 40, wires: [[P + 'cot_to_xml']]
    },

    // ── Poll timer + config loader ──
    {
      id: P + 'inject', type: 'inject', z: FID,
      name: 'Poll timer (60s base)',
      props: [{ p: 'payload' }, { p: 'topic', vt: 'str' }],
      repeat: '60', crontab: '',
      once: true, onceDelay: '30',
      topic: 'poll', payload: '', payloadType: 'date',
      x: 180, y: 120, wires: [[P + 'load']]
    },
    {
      id: P + 'load', type: 'function', z: FID,
      name: 'Load ' + feed.configName,
      func: [
        "var configs = global.get('arcgis_configs') || [];",
        "var tak = global.get('tak_settings') || {};",
        "var cfg = null;",
        "for (var i = 0; i < configs.length; i++) {",
        "  if (configs[i].configName === '" + feed.configName + "') { cfg = configs[i]; break; }",
        "}",
        "if (!cfg) { return null; }",
        "if (!tak.serverUrl) { node.warn('" + feed.configName + ": No TAK Server URL'); return null; }",
        "var pollKey = '_lastPoll_' + String(cfg.configName || '').replace(/[^A-Za-z0-9]/g, '_');",
        "var lastPoll = global.get(pollKey) || 0;",
        "var now = Date.now();",
        "var intervalMs = ((cfg.pollInterval || 5) * 60000);",
        "if (now - lastPoll < intervalMs) return null;",
        "global.set(pollKey, now);",
        "node.warn('Polling: " + feed.configName + "');",
        "return { payload: cfg, takSettings: tak, topic: '" + feed.configName + "' };"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 400, y: 120, wires: [[P + 'build_q']]
    },

    // ── ArcGIS query ──
    {
      id: P + 'build_q', type: 'function', z: FID,
      name: 'Build ArcGIS query',
      _templateKey: 'arcgis.build_query',
      func: FN_BUILD_QUERY,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 180, y: 200, wires: [[P + 'http_ag']]
    },
    {
      id: P + 'http_ag', type: 'http request', z: FID,
      name: 'GET ArcGIS features',
      method: 'GET', ret: 'obj', paytoqs: 'ignore',
      url: '', tls: '', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 400, y: 200, wires: [[P + 'parse']]
    },

    // ── Parse & build CoT ──
    {
      id: P + 'parse', type: 'function', z: FID,
      name: 'Parse & build CoT',
      _templateKey: 'arcgis.parse_cot',
      func: FN_PARSE_COT,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 600, y: 200, wires: [[P + 'build_sub', P + 'build_m']]
    },

    // ── Subscribe ──
    {
      id: P + 'build_sub', type: 'function', z: FID,
      name: 'Build subscribe URL',
      _templateKey: 'shared.build_sub',
      func: [
        "var tak = msg.takSettings;",
        "var cfg = msg._config;",
        "var missionName = cfg.missionName;",
        "var subscribed = global.get('_subscribed') || {};",
        "if (subscribed[missionName]) return null;",
        "subscribed[missionName] = Date.now();",
        "global.set('_subscribed', subscribed);",
        "var host = String(tak.serverUrl || '').replace(/^https?:\\/\\//i, '').replace(/\\/$/, '');",
        "var creatorUid = String((cfg && cfg.creatorUid) || (tak && tak.creatorUid) || 'nodered').trim();",
        "msg.url = 'https://' + host + ':' + (tak.missionApiPort || 8443)",
        "  + '/Marti/api/missions/' + encodeURIComponent(missionName)",
        "  + '/subscription?uid=' + encodeURIComponent(creatorUid);",
        "msg.method = 'PUT';",
        "msg.headers = { 'accept': '*/*', 'Content-Type': 'application/json' };",
        "if (tak && tak.missionBearerToken) {",
        "  msg.headers.Authorization = 'Bearer ' + String(tak.missionBearerToken).trim();",
        "}",
        "msg.payload = '';",
        "node.warn('Subscribing to ' + missionName + ' as ' + creatorUid);",
        "var _tak = tak; var _mn = missionName; var _uid = creatorUid;",
        "setTimeout(function() {",
        "  try {",
        "    // Cert preference: nodered.pem (Phase 1A flat-file user) > admin.pem (fallback).",
        "    // When nodered created the mission itself, it's already MISSION_OWNER; the elevation",
        "    // call is a no-op success. When admin is in use, this re-asserts admin's owner role",
        "    // after the subscribe step downgraded it via defaultRole assignment.",
        "    var _c, _k;",
        "    if (_nodeFs.existsSync('/certs/nodered.pem') && _nodeFs.existsSync('/certs/nodered.key')) {",
        "      _c = '/certs/nodered.pem'; _k = '/certs/nodered.key';",
        "    } else {",
        "      _c = '/certs/admin.pem'; _k = '/certs/admin.key';",
        "    }",
        "    var _co = _nodeFs.existsSync(_c) ? { cert: _nodeFs.readFileSync(_c), key: _nodeFs.readFileSync(_k), passphrase: 'atakatak' } : {};",
        "    var _ro = Object.assign({ hostname: _tak.serverUrl.replace(/^https?:\\/\\//i,'').replace(/\\/$/,''),",
        "      port: parseInt(String(_tak.missionApiPort || 8443)),",
        "      path: '/Marti/api/missions/' + encodeURIComponent(_mn) + '/role?username=' + encodeURIComponent(_uid) + '&clientUid=' + encodeURIComponent(_uid) + '&role=MISSION_OWNER',",
        "      method: 'PUT', rejectUnauthorized: false,",
        "      headers: { 'accept': '*/*', 'Content-Type': 'application/json', 'Content-Length': '0' }",
        "    }, _co);",
        "    if (_tak.missionBearerToken) _ro.headers.Authorization = 'Bearer ' + String(_tak.missionBearerToken).trim();",
        "    var _r = _nodeHttps.request(_ro, function(rs) { node.warn('Elevated ' + _uid + ' to MISSION_OWNER on ' + _mn + ' (HTTP ' + rs.statusCode + ', cert=' + (_c.indexOf('nodered')>=0?'nodered':'admin') + ')'); });",
        "    _r.on('error', function(e) { node.warn('Elevation error: ' + e.message); });",
        "    _r.end();",
        "  } catch(e) { node.warn('Elevation setup error: ' + e.message); }",
        "}, 5000);",
        "return msg;"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0,
      initialize: "global.set('_subscribed', {});", finalize: '', libs: [
        { var: '_nodeHttps', module: 'https' },
        { var: '_nodeFs', module: 'fs' }
      ],
      x: 180, y: 300, wires: [[P + 'http_sub']]
    },
    {
      id: P + 'http_sub', type: 'http request', z: FID,
      name: 'Subscribe to mission',
      method: 'use', ret: 'txt', paytoqs: 'ignore',
      url: '', tls: 'tls_tak', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 380, y: 300, wires: [[P + 'fn_elevate']]
    },
    {
      id: P + 'fn_elevate', type: 'function', z: FID,
      name: 'Elevate to MISSION_OWNER',
      _templateKey: 'arcgis.fn_elevate',
      func: [
        "var tak = msg.takSettings;",
        "var cfg = msg._config;",
        "var missionName = cfg.missionName;",
        "var subStatus = msg.statusCode || '?';",
        "// Log subscribe result for diagnostics. Elevation is also handled inline (setTimeout).",
        "// Do NOT clear _subscribed on 5xx — TAK Server returns 500 for re-subscribe on read-only",
        "// missions / already-subscribed users. Clearing would cause retry spam every poll.",
        "if (typeof subStatus === 'number' && subStatus >= 400) {",
        "  node.warn('Subscribe ' + missionName + ' HTTP ' + subStatus + ' (already subscribed or read-only — normal)');",
        "}",
        "var host = String(tak.serverUrl || '').replace(/^https?:\\/\\//i, '').replace(/\\/$/, '');",
        "var creatorUid = String((cfg && cfg.creatorUid) || (tak && tak.creatorUid) || 'nodered').trim();",
        "msg.url = 'https://' + host + ':' + (tak.missionApiPort || 8443)",
        "  + '/Marti/api/missions/' + encodeURIComponent(missionName)",
        "  + '/role?username=' + encodeURIComponent(creatorUid)",
        "  + '&clientUid=' + encodeURIComponent(creatorUid)",
        "  + '&role=MISSION_OWNER';",
        "msg.method = 'PUT';",
        "msg.headers = { 'accept': '*/*', 'Content-Type': 'application/json' };",
        "if (tak && tak.missionBearerToken) {",
        "  msg.headers.Authorization = 'Bearer ' + String(tak.missionBearerToken).trim();",
        "}",
        "msg.payload = '';",
        "node.warn('Elevating ' + creatorUid + ' to MISSION_OWNER on ' + missionName + ' (subscribe was HTTP ' + subStatus + ')');",
        "return msg;"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0, initialize: '', finalize: '', libs: [],
      x: 580, y: 300, wires: [[P + 'http_elevate']]
    },
    {
      id: P + 'http_elevate', type: 'http request', z: FID,
      name: 'Set MISSION_OWNER role',
      method: 'use', ret: 'txt', paytoqs: 'ignore',
      url: '', tls: 'tls_tak', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 780, y: 300, wires: [[P + 'debug_sub']]
    },
    {
      id: P + 'debug_sub', type: 'debug', z: FID,
      name: 'Subscribe result',
      active: true, tosidebar: true, console: false, tostatus: true,
      complete: 'true', targetType: 'full',
      statusVal: 'topic', statusType: 'auto',
      x: 980, y: 300, wires: []
    },

    // ── GET mission + Reconcile ──
    {
      id: P + 'build_m', type: 'function', z: FID,
      name: 'Build mission GET URL',
      _templateKey: 'shared.build_m',
      func: [
        "var tak = msg.takSettings;",
        "var cfg = msg._config;",
        "var host = String(tak.serverUrl || '').replace(/^https?:\\/\\//i, '').replace(/\\/$/, '');",
        "function getJsid(m) {",
        "  if (m && m.responseCookies && m.responseCookies.JSESSIONID && m.responseCookies.JSESSIONID.value) {",
        "    return String(m.responseCookies.JSESSIONID.value);",
        "  }",
        "  var sc = m && m.headers && m.headers['set-cookie'];",
        "  if (Array.isArray(sc) && sc.length) {",
        "    var x = String(sc[0]).match(/JSESSIONID=([^;]+)/);",
        "    if (x && x[1]) return x[1];",
        "  }",
        "  if (typeof sc === 'string') {",
        "    var y = sc.match(/JSESSIONID=([^;]+)/);",
        "    if (y && y[1]) return y[1];",
        "  }",
        "  return '';",
        "}",
        "function getBearer(m, tk) {",
        "  if (tk && tk.missionBearerToken) return String(tk.missionBearerToken).trim();",
        "  if (m && m._missionBearer) return String(m._missionBearer).trim();",
        "  return '';",
        "}",
        "msg.url = 'https://' + host + ':' + (tak.missionApiPort || 8443)",
        "  + '/Marti/api/missions/' + encodeURIComponent(cfg.missionName);",
        "var jsid = getJsid(msg);",
        "if (jsid) msg._missionCookie = 'JSESSIONID=' + jsid;",
        "var bearer = getBearer(msg, tak);",
        "if (bearer) msg._missionBearer = bearer;",
        "msg.headers = { 'accept': '*/*' };",
        "if (msg._missionCookie) msg.headers.Cookie = msg._missionCookie;",
        "if (msg._missionBearer) msg.headers.Authorization = 'Bearer ' + msg._missionBearer;",
        "return msg;"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 560, y: 320, wires: [[P + 'http_m']]
    },
    {
      id: P + 'http_m', type: 'http request', z: FID,
      name: 'GET mission',
      method: 'GET', ret: 'obj', paytoqs: 'ignore',
      url: '', tls: 'tls_tak', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 740, y: 360, wires: [[P + 'reconcile']]
    },
    {
      id: P + 'reconcile', type: 'function', z: FID,
      name: 'Reconcile (diff)',
      _templateKey: 'arcgis.reconcile',
      func: FN_RECONCILE,
      outputs: 2, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 180, y: 440,
      wires: [[P + 'cot_to_xml', P + 'delay_put'], [P + 'delay_del']]
    },

    // ── CoT -> XML -> Rate limiter -> TCP out (stream to TAK Server) ──
    {
      id: P + 'cot_to_xml', type: 'function', z: FID,
      name: 'CoT JSON -> XML',
      _templateKey: 'shared.cot_to_xml',
      func: FN_COT_TO_XML,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 180, y: 520, wires: [[P + 'rate_stream']]
    },
    {
      id: P + 'rate_stream', type: 'delay', z: FID,
      name: 'Throttle (10/sec)', pauseType: 'rate',
      timeout: '1', timeoutUnits: 'seconds',
      rate: '10', nbRateUnits: '1', rateUnits: 'second',
      randomFirst: '1', randomLast: '5', randomUnits: 'seconds',
      drop: false, allowrate: false, outputs: 1,
      x: 400, y: 520, wires: [[P + 'tcp_out']]
    },
    {
      id: P + 'tcp_out', type: 'tcp out', z: FID,
      name: 'CoT -> TAK :8089',
      host: 'host.docker.internal', port: '8089', beserver: 'client',
      base64: false, end: false, tls: 'tls_tak',
      x: 600, y: 520, wires: []
    },
    {
      id: P + 'catch_stream', type: 'catch', z: FID,
      name: 'Stream errors',
      scope: [P + 'tcp_out'],
      uncaught: false,
      x: 180, y: 580, wires: [[P + 'debug_stream']]
    },
    {
      id: P + 'debug_stream', type: 'debug', z: FID,
      name: 'Stream error',
      active: true, tosidebar: true, console: false, tostatus: true,
      complete: 'true', targetType: 'full',
      statusVal: '', statusType: 'auto',
      x: 400, y: 580, wires: []
    },

    // ── Delay -> PUT new UIDs to mission ──
    {
      id: P + 'delay_put', type: 'delay', z: FID,
      name: 'Wait 30s for cache',
      pauseType: 'delay', timeout: '30', timeoutUnits: 'seconds',
      rate: '1', nbRateUnits: '1', rateUnits: 'second',
      randomFirst: '1', randomLast: '5', randomUnits: 'seconds',
      drop: false, allowrate: false, outputs: 1,
      x: 400, y: 440, wires: [[P + 'build_put']]
    },
    {
      id: P + 'build_put', type: 'function', z: FID,
      name: 'Build PUT UIDs',
      _templateKey: 'shared.build_put',
      func: [
        "var uids = msg._putUids || [];",
        "if (!msg._putUrl || uids.length === 0) return null;",
        "msg.method = 'PUT';",
        "msg.url = msg._putUrl;",
        "msg.headers = { 'accept': '*/*', 'Content-Type': 'application/json' };",
        "if (msg._missionCookie) msg.headers.Cookie = msg._missionCookie;",
        "if (msg._missionBearer) msg.headers.Authorization = 'Bearer ' + msg._missionBearer;",
        "msg.payload = { uids: uids };",
        "node.warn(msg.topic + ' PUT -> ' + uids.length + ' UIDs -> ' + msg.url);",
        "return msg;"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 600, y: 440, wires: [[P + 'http_action']]
    },

    // ── Mission API (PUT/DELETE) ──
    {
      id: P + 'http_action', type: 'http request', z: FID,
      name: 'Mission API (PUT/DELETE)',
      method: 'use', ret: 'txt', paytoqs: 'body',
      url: '', tls: 'tls_tak', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 800, y: 440, wires: [[P + 'log_action']]
    },
    {
      id: P + 'delay_del', type: 'delay', z: FID,
      name: '', pauseType: 'delay', timeout: '1', timeoutUnits: 'seconds',
      rate: '1', nbRateUnits: '1', rateUnits: 'second',
      randomFirst: '1', randomLast: '5', randomUnits: 'seconds',
      drop: false, allowrate: false, outputs: 1,
      x: 600, y: 490, wires: [[P + 'http_action']]
    },
    {
      id: P + 'log_action', type: 'function', z: FID,
      name: 'Log API result',
      _templateKey: 'shared.log_action',
      func: [
        "var code = msg.statusCode || '?';",
        "var method = msg.method || '?';",
        "var feed = msg.topic || 'unknown';",
        "var ok = (code >= 200 && code < 300);",
        "var label = feed + ' ' + method + ' -> ' + code + (ok ? ' OK' : ' FAIL');",
        "if (!ok) {",
        "  var body = (typeof msg.payload === 'string') ? msg.payload.substring(0, 200) : '';",
        "  node.warn(label + (body ? ' - ' + body : ''));",
        "} else {",
        "  node.warn(label);",
        "}",
        "return msg;"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 960, y: 440, wires: [[]]
    }
  ];
}

// KML Network Link → same downstream as ArcGIS (parse_cot, reconcile, TCP)
const FN_KML_BUILD_URL = [
  "var cfg = msg.payload;",
  "if (!cfg || cfg.sourceType !== 'kml') { return null; }",
  "msg._config = cfg;",
  "msg.takSettings = msg.takSettings || {};",
  "var u = (cfg.source && cfg.source.networkLinkUrl) ? String(cfg.source.networkLinkUrl).trim() : '';",
  "if (!u) { node.warn((cfg.configName || 'KML') + ': No network link URL'); return null; }",
  "msg.url = u;",
  "msg.method = 'GET';",
  "msg.headers = { Accept: 'application/vnd.google-earth.kml+xml, application/xml, text/xml, */*' };",
  "return msg;"
].join('\n');

/** Check for NetworkLink in the fetched KML — no require(), pure sync.
 *  Output 1: has NetworkLink → go to hr_kml_inner
 *  Output 2: no NetworkLink  → go straight to parse_kml
 */
const FN_KML_CHECK_NL = [
  "var sc = msg.statusCode || 200;",
  "var cfg = msg._config;",
  "if (sc >= 400) {",
  "  node.warn((cfg && cfg.configName || 'KML') + ': HTTP ' + sc + ' fetching KML');",
  "  msg.payload = { features: [] };",
  "  msg._arcgisStatus = sc;",
  "  return [null, msg];",
  "}",
  "var xml = typeof msg.payload === 'string' ? msg.payload",
  "  : (Buffer.isBuffer(msg.payload) ? msg.payload.toString('utf8') : String(msg.payload || ''));",
  "var nlm = xml.match(/<NetworkLink[\\s\\S]*?<\\/NetworkLink>/i);",
  "if (nlm) {",
  "  var hm = nlm[0].match(/<href[^>]*>([\\s\\S]*?)<\\/href>/i);",
  "  var href = hm ? hm[1].replace(/<[^>]+>/g,'').trim() : '';",
  "  if (href) {",
  "    var base = (cfg && cfg.source && cfg.source.networkLinkUrl) ? cfg.source.networkLinkUrl : '';",
  "    if (/^https?:\\/\\//i.test(href)) { msg.url = href; }",
  "    else if (href.indexOf('//') === 0) { msg.url = (base.match(/^https?:/i) || ['http:'])[0] + href; }",
  "    else { try { msg.url = new URL(href, base).href; } catch(e) { msg.url = href; } }",
  "    msg.method = 'GET';",
  "    msg.headers = { Accept: 'application/vnd.google-earth.kml+xml, application/xml, text/xml, */*' };",
  "    msg.payload = null;",
  "    return [msg, null];",
  "  }",
  "}",
  "return [null, msg];"
].join('\n');

/** Pure synchronous KML → Feature JSON — no require(), no async, no network. */
const FN_KML_TO_FEATURES = [
  "var cfg = msg._config;",
  "var sc = msg.statusCode || 200;",
  "",
  "function xmlFromPayload(p) {",
  "  if (typeof p === 'string') return p;",
  "  if (Buffer.isBuffer(p)) return p.toString('utf8');",
  "  if (p && typeof p === 'object' && p.data) return Buffer.from(p.data).toString('utf8');",
  "  return String(p || '');",
  "}",
  "",
  "function decodeXmlText(s) {",
  "  if (!s) return '';",
  "  return String(s).replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&').replace(/&quot;/g,'\"').replace(/&#39;/g, String.fromCharCode(39)).replace(/&nbsp;/g,' ').trim();",
  "}",
  "",
  "function parseHtmlAttrTable(html) {",
  "  var out = {};",
  "  if (!html || html.indexOf('<td') < 0) return out;",
  "  var re = /<td[^>]*>([\\s\\S]*?)<\\/td>\\s*<td[^>]*>([\\s\\S]*?)<\\/td>/gi;",
  "  var m;",
  "  while ((m = re.exec(html)) !== null) {",
  "    var k = m[1].replace(/<[^>]+>/g,'').replace(/&nbsp;/g,' ').trim();",
  "    var v = m[2].replace(/<[^>]+>/g,'').trim();",
  "    k = decodeXmlText(k);",
  "    v = decodeXmlText(v);",
  "    if (/^<Null>$/i.test(v) || v === '<Null>') v = '';",
  "    if (k) out[k] = v;",
  "  }",
  "  return out;",
  "}",
  "",
  "function parseExtendedData(block) {",
  "  var out = {};",
  "  var em = block.match(/<ExtendedData[^>]*>([\\s\\S]*?)<\\/ExtendedData>/i);",
  "  if (!em) return out;",
  "  var inner = em[1];",
  "  var re = /<SimpleData[^>]*name=[\"']([^\"']*)[\"'][^>]*>([\\s\\S]*?)<\\/SimpleData>/gi;",
  "  var m;",
  "  while ((m = re.exec(inner)) !== null) {",
  "    var k = decodeXmlText(m[1]);",
  "    var v = decodeXmlText(m[2].replace(/<[^>]+>/g,''));",
  "    if (k) out[k] = v;",
  "  }",
  "  re = /<Data[^>]*name=[\"']([^\"']*)[\"'][^>]*>[\\s\\S]*?<value>([\\s\\S]*?)<\\/value>/gi;",
  "  while ((m = re.exec(inner)) !== null) {",
  "    var k2 = decodeXmlText(m[1]);",
  "    var v2 = decodeXmlText(m[2].replace(/<[^>]+>/g,''));",
  "    if (k2) out[k2] = v2;",
  "  }",
  "  return out;",
  "}",
  "",
  "function buildAttributes(block, placemarkName, oid) {",
  "  var dm = block.match(/<description[^>]*>([\\s\\S]*?)<\\/description>/i);",
  "  var descRaw = dm ? dm[1] : '';",
  "  var ext = parseExtendedData(block);",
  "  var table = parseHtmlAttrTable(descRaw);",
  "  var attrs = {};",
  "  var k;",
  "  for (k in ext) attrs[k] = ext[k];",
  "  for (k in table) attrs[k] = table[k];",
  "  attrs.name = placemarkName;",
  "  attrs.OBJECTID = oid;",
  "  if (attrs.description == null || attrs.description === '') {",
  "    attrs.description = descRaw.replace(/<[^>]+>/g,' ').replace(/\\s+/g,' ').trim();",
  "  }",
  "  return attrs;",
  "}",
  "",
  "function parsePlacemarks(xml) {",
  "  var features = [];",
  "  var re = /<Placemark([^>]*)>([\\s\\S]*?)<\\/Placemark>/gi;",
  "  var m;",
  "  var oid = 0;",
  "  while ((m = re.exec(xml)) !== null) {",
  "    var block = m[2];",
  "    var name = 'Placemark';",
  "    var nm = block.match(/<name[^>]*>([\\s\\S]*?)<\\/name>/i);",
  "    if (nm) name = nm[1].replace(/<[^>]+>/g,'').trim() || name;",
  "    var attrs = buildAttributes(block, name, oid);",
  "    var pt = block.match(/<Point[^>]*>[\\s\\S]*?<coordinates[^>]*>\\s*([^<]+)\\s*<\\/coordinates>/i);",
  "    if (pt) {",
  "      var parts = pt[1].trim().split(/[\\s,]+/);",
  "      var lon = parseFloat(parts[0]), lat = parseFloat(parts[1]);",
  "      if (!isNaN(lat) && !isNaN(lon))",
  "        features.push({ attributes: attrs, geometry: { x: lon, y: lat } });",
  "      oid++;",
  "      continue;",
  "    }",
  "    // Collect ALL <Polygon> outer rings — handles both single <Polygon> and",
  "    // <MultiGeometry> placemarks with multiple <Polygon> children.",
  "    var polyRe = /<Polygon[^>]*>[\\s\\S]*?<\\/Polygon>/gi;",
  "    var pm;",
  "    var rings = [];",
  "    while ((pm = polyRe.exec(block)) !== null) {",
  "      var ob = pm[0].match(/<outerBoundaryIs>[\\s\\S]*?<coordinates[^>]*>\\s*([^<]+)\\s*<\\/coordinates>/i);",
  "      if (ob) {",
  "        var ring = [];",
  "        ob[1].trim().split(/\\s+/).forEach(function(pair) {",
  "          var p = pair.split(',');",
  "          if (p.length >= 2) ring.push([parseFloat(p[0]), parseFloat(p[1])]);",
  "        });",
  "        if (ring.length) rings.push(ring);",
  "      }",
  "    }",
  "    if (rings.length) {",
  "      features.push({ attributes: attrs, geometry: { rings: rings } });",
  "      oid++;",
  "      continue;",
  "    }",
  "    // Collect ALL <LineString> paths — handles <MultiGeometry> with multiple paths.",
  "    var lsRe = /<LineString[^>]*>[\\s\\S]*?<coordinates[^>]*>\\s*([^<]+)\\s*<\\/coordinates>/gi;",
  "    var paths = [];",
  "    while ((pm = lsRe.exec(block)) !== null) {",
  "      var path = [];",
  "      pm[1].trim().split(/\\s+/).forEach(function(pair) {",
  "        var p = pair.split(',');",
  "        if (p.length >= 2) path.push([parseFloat(p[0]), parseFloat(p[1])]);",
  "      });",
  "      if (path.length) paths.push(path);",
  "    }",
  "    if (paths.length) {",
  "      features.push({ attributes: attrs, geometry: { paths: paths } });",
  "      oid++;",
  "    }",
  "  }",
  "  return features;",
  "}",
  "",
  "if (sc >= 400) {",
  "  node.warn((cfg && cfg.configName || 'KML') + ': HTTP ' + sc);",
  "  msg.payload = { features: [] };",
  "  msg._arcgisStatus = sc;",
  "  return msg;",
  "}",
  "var xml = xmlFromPayload(msg.payload);",
  "var feats = parsePlacemarks(xml);",
  "msg.payload = { features: feats };",
  "msg._arcgisStatus = 200;",
  "msg._layerName = '';",
  "return msg;"
].join('\n');

/** ArcGIS engine tab, then swap query chain for KML GET + parse (shared parse_cot / reconcile). */
function makeKmlEngineTab(feed) {
  const nodes = makeEngineTab(feed);
  const P = feed.id + '_';
  const FID = 'flow_eng_' + feed.id;
  const tab = nodes.find(function(n) { return n.type === 'tab'; });
  if (tab) {
    tab.info = 'KML Network Link engine for ' + feed.configName + '. Fetch KML, stream CoT via TCP, sync to mission.';
  }
  nodes.forEach(function(n) {
    if (n.id !== P + 'load') return;
    n.func = [
      "var configs = global.get('arcgis_configs') || [];",
      "var tak = global.get('tak_settings') || {};",
      "var cfg = null;",
      "for (var i = 0; i < configs.length; i++) {",
      "  if (configs[i].configName === '" + feed.configName + "') { cfg = configs[i]; break; }",
      "}",
      "if (!cfg) { return null; }",
      "if (cfg.sourceType !== 'kml') { return null; }",
      "if (!tak.serverUrl) { node.warn('" + feed.configName + ": No TAK Server URL'); return null; }",
      "var nl = (cfg.source && cfg.source.networkLinkUrl) ? String(cfg.source.networkLinkUrl).trim() : '';",
      "if (!nl) { node.warn('" + feed.configName + ": No KML network link URL'); return null; }",
      "var pollKey = '_lastPoll_' + String(cfg.configName || '').replace(/[^A-Za-z0-9]/g, '_');",
      "var lastPoll = global.get(pollKey) || 0;",
      "var now = Date.now();",
      "var intervalMs = ((cfg.pollInterval || 5) * 60000);",
      "if (now - lastPoll < intervalMs) return null;",
      "global.set(pollKey, now);",
      "node.warn('Polling KML: " + feed.configName + "');",
      "return { payload: cfg, takSettings: tak, topic: '" + feed.configName + "' };"
    ].join('\n');
    n.wires = [[P + 'build_kml']];
  });
  const iq = nodes.findIndex(function(n) { return n.id === P + 'build_q'; });
  if (iq < 0) return nodes;
  const kmlChain = [
    {
      id: P + 'build_kml', type: 'function', z: FID,
      name: 'Build KML URL',
      _templateKey: 'kml.build_url',
      func: FN_KML_BUILD_URL,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 180, y: 200, wires: [[P + 'http_kml']]
    },
    {
      id: P + 'http_kml', type: 'http request', z: FID,
      name: 'GET KML',
      method: 'use', ret: 'txt', paytoqs: 'ignore',
      url: '', tls: '', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 380, y: 200, wires: [[P + 'check_nl']]
    },
    {
      id: P + 'check_nl', type: 'function', z: FID,
      name: 'Check NetworkLink',
      _templateKey: 'kml.check_nl',
      func: FN_KML_CHECK_NL,
      outputs: 2, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 560, y: 200,
      wires: [[P + 'http_kml_inner'], [P + 'parse_kml']]
    },
    {
      id: P + 'http_kml_inner', type: 'http request', z: FID,
      name: 'GET inner KML',
      method: 'use', ret: 'txt', paytoqs: 'ignore',
      url: '', tls: '', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 760, y: 160, wires: [[P + 'parse_kml']]
    },
    {
      id: P + 'parse_kml', type: 'function', z: FID,
      name: 'KML to Feature JSON',
      _templateKey: 'kml.xml_to_features',
      func: FN_KML_TO_FEATURES,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 960, y: 200, wires: [[P + 'parse']]
    }
  ];
  nodes.splice(iq, 2, kmlChain[0], kmlChain[1], kmlChain[2], kmlChain[3], kmlChain[4]);
  return nodes;
}

// ════════════════════════════════════════════════════════════════
//  Per-feed TFR engine tab generator
// ════════════════════════════════════════════════════════════════

const FN_TFR_FILTER_SPLIT = [
  "var tfrs = msg.payload || [];",
  "var cfg = msg._config;",
  "var states = cfg.tfrStates || [];",
  "",
  "// Build set of enabled type strings from config",
  "var typeMap = {",
  "  hazards: 'HAZARDS', security: 'SECURITY', vip: 'VIP',",
  "  spaceOps: 'SPACE OPERATIONS', airShows: 'AIR SHOWS/SPORTS',",
  "  uas: 'UAS PUBLIC GATHERING', special: 'SPECIAL'",
  "};",
  "var enabledTypes = [];",
  "var tt = cfg.tfrTypes || {};",
  "for (var k in typeMap) {",
  "  if (tt[k] !== false) enabledTypes.push(typeMap[k]);",
  "}",
  "",
  "// Haversine distance in nautical miles",
  "function distNM(lat1, lon1, lat2, lon2) {",
  "  var R = 3440.065; // earth radius NM",
  "  var dLat = (lat2 - lat1) * Math.PI / 180;",
  "  var dLon = (lon2 - lon1) * Math.PI / 180;",
  "  var a = Math.sin(dLat/2) * Math.sin(dLat/2) +",
  "    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *",
  "    Math.sin(dLon/2) * Math.sin(dLon/2);",
  "  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));",
  "}",
  "",
  "var rad = cfg.tfrRadius;",
  "var filtered = [];",
  "for (var i = 0; i < tfrs.length; i++) {",
  "  var t = tfrs[i];",
  "  // State filter",
  "  if (states.length > 0 && states.indexOf(t.state) < 0) continue;",
  "  // Type filter",
  "  if (enabledTypes.indexOf(t.type) < 0) continue;",
  "  var nid = t.notam_id.replace(/\\//g, '_');",
  "  filtered.push({",
  "    url: 'https://tfr.faa.gov/download/detail_' + nid + '.xml',",
  "    notamId: nid, state: t.state, type: t.type,",
  "    lat: t.lat, lon: t.lon",
  "  });",
  "}",
  "",
  "// Radius filter (applied after state+type since API gives lat/lon in description only)",
  "// The API doesn't provide lat/lon directly, so radius is applied in the CoT builder",
  "// after parsing the XML. Store the radius config for downstream use.",
  "",
"node.warn(cfg.configName + ': ' + filtered.length + ' TFRs after filter (from ' + tfrs.length + ', types: ' + enabledTypes.length + ')');",
"if (filtered.length > 0) {",
"  flow.set('_tfrUids', []);",
"  flow.set('_tfrCount', filtered.length);",
"  flow.set('_tfrDone', 0);",
"} else {",
"  node.warn(cfg.configName + ': 0 TFRs after filter — keeping previous UIDs to avoid false deletions');",
"  return null;",
"}",
  "",
  "var msgs = [];",
  "for (var i = 0; i < filtered.length; i++) {",
  "  msgs.push({ url: filtered[i].url, method: 'GET',",
  "    _tfrMeta: filtered[i], _config: cfg, takSettings: msg.takSettings,",
  "    topic: cfg.configName });",
  "}",
  "return [msgs];"
].join('\n');

const FN_TFR_PARSE_BUILD_COT = [
  "var xml = msg.payload;",
  "var cfg = msg._config;",
  "var tak = global.get('tak_settings') || {};",
  "var tfrHost = String(tak.serverUrl || '').replace(/^https?:\\/\\//i, '').replace(/\\/$/, '').trim() || tak.takHost || 'host.docker.internal';",
  "var tfrBaseP = Number(tak.streamingPort || tak.streamPort || 8089);",
  "var tfrPort = Number(cfg.cotStreamPort) || tfrBaseP;",
  "",
  "function hexArgb(hex, a) {",
  "  var r = parseInt(hex.substr(1,2),16);",
  "  var g = parseInt(hex.substr(3,2),16);",
  "  var b = parseInt(hex.substr(5,2),16);",
  "  var ai = Math.round((a !== undefined ? a : 1) * 255);",
  "  return ((ai << 24) | (r << 16) | (g << 8) | b);",
  "}",
  "",
  "var sColor = (cfg.style && cfg.style.strokeColor) || '#FF6600';",
  "var fColor = (cfg.style && cfg.style.fillColor) || '#FF6600';",
  "var rawAlpha = cfg.style && cfg.style.fillAlpha;",
  "var fa = (typeof rawAlpha === 'number') ? rawAlpha / 100 : 0.25;",
  "var strokeArgb = hexArgb(sColor, 1);",
  "var fillArgb = hexArgb(fColor, fa);",
  "",
  "function distNM(lat1, lon1, lat2, lon2) {",
  "  var R = 3440.065;",
  "  var dLat = (lat2 - lat1) * Math.PI / 180;",
  "  var dLon = (lon2 - lon1) * Math.PI / 180;",
  "  var a = Math.sin(dLat/2) * Math.sin(dLat/2) +",
  "    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *",
  "    Math.sin(dLon/2) * Math.sin(dLon/2);",
  "  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));",
  "}",
  "",
  "try {",
  "  var xnotam = xml['XNOTAM-Update'];",
  "  if (!xnotam || !xnotam.Group) throw new Error('Invalid XNOTAM');",
  "  var tfr_dict = xnotam.Group[0].Add[0].Not[0];",
  "  var tfr_info = tfr_dict.TfrNot[0].TFRAreaGroup;",
  "  var meta = msg._tfrMeta || {};",
  "  // Prefer list API notam_id (e.g. 6/4160 -> 6_4160). XML txtLocalName / hardcoded FDC series often mismatches FAA site.",
  "  var tfrId = meta.notamId || '';",
  "  if (!tfrId && tfr_dict.NotUid && tfr_dict.NotUid[0].txtLocalName) {",
  "    tfrId = String(tfr_dict.NotUid[0].txtLocalName[0]).replace(/\\//g, '_');",
  "  }",
  "  var remarks = (tfr_dict.txtDescrTraditional && tfr_dict.txtDescrTraditional[0]) || '';",
  "  var detailPageUrl = 'https://tfr.faa.gov/save_pages/detail_' + tfrId + '.html';",
  "  var detailViewerUrl = 'https://tfr.faa.gov/tfr3/?page=detail_' + tfrId;",
  "",
  "  var now = new Date();",
  "  var staleMs = ((cfg.tfrPollInterval || 15) * 60000) + 120000;",
  "  var stale = new Date(now.getTime() + staleMs);",
  "",
  "  function parseDMS(s) {",
  "    s = String(s).trim();",
  "    var m = s.match(/^(\\d{2,3})(\\d{2})(\\d{2}(?:\\.\\d+)?)([NSEW])$/);",
  "    if (m) {",
  "      var deg = parseInt(m[1]) + parseInt(m[2])/60 + parseFloat(m[3])/3600;",
  "      if (m[4] === 'S' || m[4] === 'W') deg = -deg;",
  "      return deg;",
  "    }",
  "    var n = parseFloat(s.replace(/[NSEW]/g, ''));",
  "    if (s.indexOf('S') >= 0 || s.indexOf('W') >= 0) n = -n;",
  "    return n;",
  "  }",
  "",
  "  function circleToRing(cLat, cLon, radiusNM, nPts) {",
  "    var ring = [];",
  "    var rLat = (radiusNM / 60) * (Math.PI / 180);",
  "    var rLon = rLat / Math.cos(cLat * Math.PI / 180);",
  "    for (var k = 0; k < nPts; k++) {",
  "      var angle = (2 * Math.PI * k) / nPts;",
  "      var lat = cLat + (radiusNM / 60) * Math.cos(angle);",
  "      var lon = cLon + (radiusNM / 60 / Math.cos(cLat * Math.PI / 180)) * Math.sin(angle);",
  "      ring.push({ lat: lat, lon: lon });",
  "    }",
  "    ring.push(ring[0]);",
  "    return ring;",
  "  }",
  "",
  "  for (var i = 0; i < tfr_info.length; i++) {",
  "    var isShape = !!tfr_info[i].aseShapes;",
  "    var isCircle = !isShape && tfr_info[i].aseCircle;",
  "    if (!isShape && !isCircle) continue;",
  "",
  "    var labelArea = '';",
  "    if (i >= 1 && tfr_info[i].aseTFRArea && tfr_info[i].aseTFRArea[0].txtName) {",
  "      labelArea = tfr_info[i].aseTFRArea[0].txtName[0];",
  "    }",
  "    var idLabel = 'tfr-' + String(tfrId).replace(/_/g, '-');",
  "    var baseCallsign = (idLabel + (labelArea ? ' ' + labelArea : '')).trim();",
  "    var callsign = baseCallsign;",
  "    var lm = cfg.tfrLabelMode || 'faa_sequence';",
  "    if (lm === 'notam_first_line' && remarks) {",
  "      var lines = remarks.split(/\\r?\\n/);",
  "      var firstLn = '';",
  "      for (var li = 0; li < lines.length; li++) { if (lines[li] && String(lines[li]).trim()) { firstLn = String(lines[li]).trim(); break; } }",
  "      if (firstLn) callsign = firstLn.length > 96 ? firstLn.substring(0, 93) + '...' : firstLn;",
  "    } else if (lm === 'notam_short' && remarks) {",
  "      var one = String(remarks).replace(/\\s+/g, ' ').trim();",
  "      if (one.length > 64) one = one.substring(0, 61) + '...';",
  "      callsign = one;",
  "    } else if (lm === 'area_name' && labelArea) {",
  "      callsign = String(labelArea).trim();",
  "    }",
"    callsign = String(callsign).replace(/[\\x00-\\x1f\\x7f]/g, '').replace(/\"/g, \"'\").trim();",
"    if (!callsign) callsign = baseCallsign;",
"    if (cfg.tfrUpperCase) callsign = callsign.toUpperCase();",
  "    var uid = (cfg.uidPrefix || 'tfr-') + tfrId + (labelArea ? '_' + labelArea.replace(/[^a-zA-Z0-9]/g,'_') : '');",
  "",
  "    var lat, lon, links = [];",
  "",
  "    if (isCircle) {",
  "      var circ = tfr_info[i].aseCircle[0];",
  "      lat = parseDMS(String(circ.geoLatCen[0]));",
  "      lon = parseDMS(String(circ.geoLongCen[0]));",
  "      var radVal = parseFloat(circ.valRadiusArc[0]) || 0;",
  "      var radUnit = String(circ.uomRadiusArc ? circ.uomRadiusArc[0] : 'NM').toUpperCase();",
  "      if (radUnit === 'KM') radVal *= 0.539957;",
  "      else if (radUnit === 'M') radVal *= 0.000539957;",
  "      var ring = circleToRing(lat, lon, radVal, 36);",
  "      for (var j = 0; j < ring.length; j++) {",
  "        links.push({ _attributes: { point: ring[j].lat + ',' + ring[j].lon } });",
  "      }",
  "    } else {",
  "      var firstAvx = tfr_info[i].aseShapes[0].Abd[0].Avx[0];",
  "      lat = parseDMS(String(firstAvx.geoLat[0]));",
  "      lon = parseDMS(String(firstAvx.geoLong[0]));",
  "      var linkPoints = tfr_info[i].abdMergedArea[0].Avx;",
  "      for (var j = 0; j < linkPoints.length; j++) {",
  "        var ptLat = parseDMS(String(linkPoints[j].geoLat[0]));",
  "        var ptLon = parseDMS(String(linkPoints[j].geoLong[0]));",
  "        links.push({ _attributes: { point: ptLat + ',' + ptLon } });",
  "      }",
  "    }",
  "",
  "    var rad = cfg.tfrRadius;",
  "    if (rad && rad.lat != null && rad.lon != null && rad.radiusNM) {",
  "      var d = distNM(rad.lat, rad.lon, lat, lon);",
  "      if (d > rad.radiusNM) { continue; }",
  "    }",
  "",
  "    var heightFt = 0;",
  "    if (tfr_info[i].aseTFRArea && tfr_info[i].aseTFRArea[0].valDistVerUpper) {",
  "      heightFt = parseFloat(tfr_info[i].aseTFRArea[0].valDistVerUpper[0]) || 0;",
  "    }",
  "    var heightM = heightFt * 0.3048;",
  "",
  "    // Add FAA detail page as Associated Link (like tfr2cot)",
  "    links.push({ _attributes: {",
  "      url: detailViewerUrl, relation: 'r-u', mime: 'text/html',",
  "      remarks: 'FAA TFR Detail: ' + callsign",
  "    } });",
  "",
  "    // Build rich remarks: NOTAM text + effective dates + FAA link",
  "    var richRemarks = remarks;",
  "    if (tfr_info[i].aseTFRArea && tfr_info[i].aseTFRArea[0]) {",
  "      var area = tfr_info[i].aseTFRArea[0];",
  "      if (area.dateEffective && area.dateEffective[0]) richRemarks += '\\nEffective: ' + area.dateEffective[0];",
  "      if (area.dateExpire && area.dateExpire[0]) richRemarks += '\\nExpires: ' + area.dateExpire[0];",
  "      if (area.valDistVerLower) richRemarks += '\\nFloor: ' + (area.valDistVerLower[0] || '0') + ' ft';",
  "      if (area.valDistVerUpper) richRemarks += '\\nCeiling: ' + (area.valDistVerUpper[0] || '0') + ' ft';",
  "    }",
  "    richRemarks += '\\n' + detailPageUrl + '\\n' + detailViewerUrl;",
  "",
  "    var detail = {",
  "      contact: [{ _attributes: { callsign: callsign } }],",
  "      remarks: richRemarks,",
  "      strokeColor: [{ _attributes: { value: String(strokeArgb) } }],",
  "      strokeWeight: [{ _attributes: { value: '2.0' } }],",
  "      fillColor: [{ _attributes: { value: String(fillArgb) } }],",
  "      labels_on: [{ _attributes: { value: (cfg.tfrLabelsOn !== false) ? 'true' : 'false' } }],",
  "      status: [{ _attributes: { readiness: 'true' } }],",
  "      link: links",
  "    };",
  "",
  "    if (cfg.tfr3D && heightM > 0) {",
  "      detail.height = [{ _attributes: { value: String(heightM) } }];",
  "      detail._geofence = [{ _attributes: {",
  "        elevationMonitored: 'true', minElevation: '0.0',",
  "        monitor: 'All', trigger: 'Both', tracking: 'false',",
  "        maxElevation: String(heightM), boundingSphere: '96000.0'",
  "      } }];",
  "    }",
  "",
  "    var uids = flow.get('_tfrUids') || [];",
  "    uids.push(uid);",
  "    flow.set('_tfrUids', uids);",
  "",
  "    node.send({",
  "      payload: { event: {",
  "        _attributes: { version: '2.0', uid: uid, type: 'u-d-f', how: 'h-e',",
  "          time: now.toISOString(), start: now.toISOString(), stale: stale.toISOString() },",
  "        point: { _attributes: { lat: String(lat), lon: String(lon), hae: '9999999.0', ce: '9999999.0', le: '9999999.0' } },",
  "        detail: detail",
  "      } },",
  "      topic: cfg.configName, _missionName: cfg.missionName,",
  "      host: tfrHost, port: tfrPort",
  "    });",
  "  }",
  "} catch(e) { node.warn(cfg.configName + ' TFR parse error: ' + e.message); }",
  "",
  "var done = (flow.get('_tfrDone') || 0) + 1;",
  "flow.set('_tfrDone', done);",
  "node.warn(cfg.configName + ': TFR ' + done + '/' + flow.get('_tfrCount') + ' parsed');",
  "return null;"
].join('\n');

const FN_TFR_RECONCILE = [
  "var mData = msg.payload;",
  "var cfg = msg._config;",
  "var tak = msg.takSettings;",
  "var topicCfg = cfg.configName || 'unnamed';",
  "msg.topic = topicCfg;",
  "var prefix = cfg.uidPrefix || 'tfr-';",
  "",
  "var tfrUids = flow.get('_tfrUids') || [];",
  "if (tfrUids.length === 0) {",
  "  node.warn(topicCfg + ' reconcile: skipping — poll has not produced TFR data yet');",
  "  return null;",
  "}",
  "var tfrMap = {};",
  "for (var i = 0; i < tfrUids.length; i++) tfrMap[tfrUids[i]] = true;",
  "",
  "var existing = {};",
  "try {",
  "  var mission = null;",
  "  if (mData && mData.data) {",
  "    mission = Array.isArray(mData.data) ? mData.data[0] : mData.data;",
  "  }",
  "  if (mission && mission.uids) {",
  "    for (var i=0;i<mission.uids.length;i++) {",
  "      var u = mission.uids[i];",
  "      var uid = (typeof u === 'string') ? u : (u.data || u.uid || u);",
  "      if (typeof uid === 'string') existing[uid] = true;",
  "    }",
  "  }",
  "  if (mission && mission.contents) {",
  "    for (var i=0;i<mission.contents.length;i++) {",
  "      var c = mission.contents[i];",
  "      if (c.data && c.data.uid) existing[c.data.uid] = true;",
  "    }",
  "  }",
  "} catch(e) { node.warn('Could not parse mission: ' + e.message); }",
  "",
  "var host = String(tak.serverUrl || '').replace(/^https?:\\/\\//i, '').replace(/\\/$/, '');",
  "var baseUrl = 'https://' + host + ':' + (tak.missionApiPort || 8443)",
  "  + '/Marti/api/missions/' + encodeURIComponent(cfg.missionName);",
  "var creator = encodeURIComponent(String((cfg && cfg.creatorUid) || (tak && tak.creatorUid) || 'nodered').trim());",
  "",
  "var cookie = msg._missionCookie || '';",
  "var bearer = msg._missionBearer || '';",
  "if (!cookie && msg.responseCookies && msg.responseCookies.JSESSIONID && msg.responseCookies.JSESSIONID.value) {",
  "  cookie = 'JSESSIONID=' + String(msg.responseCookies.JSESSIONID.value);",
  "}",
  "if (!cookie && msg.headers && msg.headers['set-cookie']) {",
  "  var sc = msg.headers['set-cookie'];",
  "  if (Array.isArray(sc) && sc.length) {",
  "    var a2 = String(sc[0]).match(/JSESSIONID=([^;]+)/);",
  "    if (a2 && a2[1]) cookie = 'JSESSIONID=' + a2[1];",
  "  } else if (typeof sc === 'string') {",
  "    var b = sc.match(/JSESSIONID=([^;]+)/);",
  "    if (b && b[1]) cookie = 'JSESSIONID=' + b[1];",
  "  }",
  "}",
  "",
  "var nPut = 0, nDel = 0;",
  "var newUids = [];",
  "for (var uid in tfrMap) {",
  "  if (!existing[uid]) { nPut++; newUids.push(uid); }",
  "}",
  "if (newUids.length > 0) {",
  "  var putMsg = {",
  "    topic: topicCfg, payload: {},",
  "    _missionCookie: cookie, _missionBearer: bearer,",
  "    _putUrl: baseUrl + '/contents?creatorUid=' + creator,",
  "    _putUids: newUids",
  "  };",
  "  node.warn(topicCfg + ' reconcile: sending PUT msg, url=' + putMsg._putUrl + ' uids=' + newUids.length);",
  "  node.send([putMsg, null]);",
  "}",
  "var forcePurge = global.get('_forcePurge') || {};",
  "var strictMode = (cfg.strictMode !== false);",
  "var oneShotPurge = forcePurge[topicCfg] === true;",
  "var cleanOrphans = strictMode || oneShotPurge;",
  "for (var uid in existing) {",
  "  var matchesPrefix = (uid.indexOf(prefix) === 0);",
  "  if (!tfrMap[uid] && (cleanOrphans || matchesPrefix)) {",
  "    nDel++;",
  "    node.send([null, {",
  "      method: 'DELETE',",
  "      url: baseUrl + '/contents?uid=' + encodeURIComponent(uid) + '&creatorUid=' + creator,",
  "      headers: { 'accept': '*/*' },",
  "      _missionCookie: cookie, _missionBearer: bearer,",
  "      payload: '', topic: topicCfg",
  "    }]);",
  "  }",
  "}",
  "if (oneShotPurge) {",
  "  delete forcePurge[topicCfg];",
  "  global.set('_forcePurge', forcePurge);",
  "  node.warn(topicCfg + ': one-shot purge complete, DELETED ' + nDel + ' orphan UIDs');",
  "}",
  "node.warn(topicCfg + ' reconcile: ' + nPut + ' PUT, ' + nDel + ' DELETE, '",
  "  + tfrUids.length + ' TFR, ' + Object.keys(existing).length + ' in mission' + (strictMode ? ' [strict]' : ''));",
  "// _tfrUids is reset only at the start of each poll (Filter & split), not here —",
  "// clearing here caused the next timer reconcile to DELETE everything.",
  "return null;"
].join('\n');

function makeTfrEngineTab(feed) {
  const FID = 'flow_eng_' + feed.id;
  const P   = feed.id + '_';

  // Subscribe URL build (shared with ArcGIS)
  const FN_SUB = [
    "var tak = msg.takSettings;",
    "var cfg = msg._config;",
    "var missionName = cfg.missionName;",
    "var subscribed = global.get('_subscribed') || {};",
    "if (subscribed[missionName]) return null;",
    "subscribed[missionName] = Date.now();",
    "global.set('_subscribed', subscribed);",
    "var host = String(tak.serverUrl || '').replace(/^https?:\\/\\//i, '').replace(/\\/$/, '');",
    "var creatorUid = String((cfg && cfg.creatorUid) || (tak && tak.creatorUid) || 'nodered').trim();",
    "msg.url = 'https://' + host + ':' + (tak.missionApiPort || 8443)",
    "  + '/Marti/api/missions/' + encodeURIComponent(missionName)",
    "  + '/subscription?uid=' + encodeURIComponent(creatorUid);",
    "msg.method = 'PUT';",
    "msg.headers = { 'accept': '*/*', 'Content-Type': 'application/json' };",
    "if (tak && tak.missionBearerToken) {",
    "  msg.headers.Authorization = 'Bearer ' + String(tak.missionBearerToken).trim();",
    "}",
    "msg.payload = '';",
    "node.warn('Subscribing to ' + missionName + ' as ' + creatorUid);",
    "var _tak = tak; var _mn = missionName; var _uid = creatorUid;",
    "setTimeout(function() {",
    "  try {",
    "    // Cert preference: nodered.pem (Phase 1A flat-file user) > admin.pem (fallback).",
    "    var _c, _k;",
    "    if (_nodeFs.existsSync('/certs/nodered.pem') && _nodeFs.existsSync('/certs/nodered.key')) {",
    "      _c = '/certs/nodered.pem'; _k = '/certs/nodered.key';",
    "    } else {",
    "      _c = '/certs/admin.pem'; _k = '/certs/admin.key';",
    "    }",
    "    var _co = _nodeFs.existsSync(_c) ? { cert: _nodeFs.readFileSync(_c), key: _nodeFs.readFileSync(_k), passphrase: 'atakatak' } : {};",
    "    var _ro = Object.assign({ hostname: _tak.serverUrl.replace(/^https?:\\/\\//i,'').replace(/\\/$/,''),",
    "      port: parseInt(String(_tak.missionApiPort || 8443)),",
    "      path: '/Marti/api/missions/' + encodeURIComponent(_mn) + '/role?username=' + encodeURIComponent(_uid) + '&clientUid=' + encodeURIComponent(_uid) + '&role=MISSION_OWNER',",
    "      method: 'PUT', rejectUnauthorized: false,",
    "      headers: { 'accept': '*/*', 'Content-Type': 'application/json', 'Content-Length': '0' }",
    "    }, _co);",
    "    if (_tak.missionBearerToken) _ro.headers.Authorization = 'Bearer ' + String(_tak.missionBearerToken).trim();",
    "    var _r = _nodeHttps.request(_ro, function(rs) { node.warn('Elevated ' + _uid + ' to MISSION_OWNER on ' + _mn + ' (HTTP ' + rs.statusCode + ', cert=' + (_c.indexOf('nodered')>=0?'nodered':'admin') + ')'); });",
    "    _r.on('error', function(e) { node.warn('Elevation error: ' + e.message); });",
    "    _r.end();",
    "  } catch(e) { node.warn('Elevation setup error: ' + e.message); }",
    "}, 5000);",
    "return msg;"
  ].join('\n');

  const FN_ELEVATE_ROLE = [
    "var cfg = msg._config || {};",
    "var missionName = cfg.missionName || '?';",
    "var sc = msg.statusCode || '?';",
    "// Elevation is handled inline (setTimeout w/ nodered.pem-or-admin.pem in Build subscribe URL).",
    "// Log subscribe result only — do NOT clear _subscribed on 5xx.",
    "// TAK Server returns 500 for re-subscribe on read-only missions; clearing causes retry spam.",
    "if (typeof sc === 'number' && sc >= 400) {",
    "  node.warn('Subscribe ' + missionName + ' HTTP ' + sc + ' (already subscribed or read-only — normal)');",
    "} else {",
    "  node.warn('Subscribe ' + missionName + ' HTTP ' + sc + ' OK — elevation handled inline');",
    "}",
    "return null;"
  ].join('\n');

  // Mission GET URL build (shared with ArcGIS)
  const FN_GET_MISSION = [
    "var tak = msg.takSettings;",
    "var cfg = msg._config;",
    "var host = String(tak.serverUrl || '').replace(/^https?:\\/\\//i, '').replace(/\\/$/, '');",
    "function getJsid(m) {",
    "  if (m && m.responseCookies && m.responseCookies.JSESSIONID && m.responseCookies.JSESSIONID.value) {",
    "    return String(m.responseCookies.JSESSIONID.value);",
    "  }",
    "  var sc = m && m.headers && m.headers['set-cookie'];",
    "  if (Array.isArray(sc) && sc.length) {",
    "    var x = String(sc[0]).match(/JSESSIONID=([^;]+)/);",
    "    if (x && x[1]) return x[1];",
    "  }",
    "  if (typeof sc === 'string') {",
    "    var y = sc.match(/JSESSIONID=([^;]+)/);",
    "    if (y && y[1]) return y[1];",
    "  }",
    "  return '';",
    "}",
    "function getBearer(m, tk) {",
    "  if (tk && tk.missionBearerToken) return String(tk.missionBearerToken).trim();",
    "  if (m && m._missionBearer) return String(m._missionBearer).trim();",
    "  return '';",
    "}",
    "msg.url = 'https://' + host + ':' + (tak.missionApiPort || 8443)",
    "  + '/Marti/api/missions/' + encodeURIComponent(cfg.missionName);",
    "var jsid = getJsid(msg);",
    "if (jsid) msg._missionCookie = 'JSESSIONID=' + jsid;",
    "var bearer = getBearer(msg, tak);",
    "if (bearer) msg._missionBearer = bearer;",
    "msg.headers = { 'accept': '*/*' };",
    "if (msg._missionCookie) msg.headers.Cookie = msg._missionCookie;",
    "if (msg._missionBearer) msg.headers.Authorization = 'Bearer ' + msg._missionBearer;",
    "return msg;"
  ].join('\n');

  return [
    // Tab
    {
      id: FID, type: 'tab',
      label: feed.configName,
      disabled: false,
      info: 'FAA TFR engine for ' + feed.configName + '. Fetch TFRs, build 3D CoT, stream via TCP, sync to mission.'
    },

    // SA ident
    {
      id: P + 'sa_inject', type: 'inject', z: FID,
      name: 'SA ident (startup)',
      props: [{ p: 'payload' }, { p: 'topic', vt: 'str' }],
      repeat: '600', crontab: '',
      once: true, onceDelay: '10',
      topic: 'sa-ident', payload: '', payloadType: 'date',
      x: 180, y: 40, wires: [[P + 'sa_build']]
    },
    {
      id: P + 'sa_build', type: 'function', z: FID,
      name: 'Build SA ident CoT',
      func: [
        "var tak = global.get('tak_settings') || {};",
        "var configs = global.get('arcgis_configs') || [];",
        "var cfg = null;",
        "for (var i = 0; i < configs.length; i++) {",
        "  if (configs[i].configName === '" + feed.configName + "') { cfg = configs[i]; break; }",
        "}",
        "var creatorUid = '';",
        "if (cfg && cfg.creatorUid) creatorUid = String(cfg.creatorUid).trim();",
        "if (!creatorUid && tak.creatorUid) creatorUid = String(tak.creatorUid).trim();",
        "if (!creatorUid) { return null; }",
        "var now = new Date();",
        "var stale = new Date(now.getTime() + 120000);",
        "msg.payload = {",
        "  event: {",
        "    _attributes: {",
        "      version: '2.0', uid: creatorUid,",
        "      type: 'a-f-G-E-S', how: 'h-g-i-g-o',",
        "      time: now.toISOString(), start: now.toISOString(), stale: stale.toISOString()",
        "    },",
        "    point: { _attributes: { lat: '0', lon: '0', hae: '0', ce: '9999999', le: '9999999' } },",
        "    detail: {",
        "      contact: [{ _attributes: { callsign: creatorUid } }],",
        "      __group: [{ _attributes: { name: 'Purple', role: 'Team Member' } }]",
        "    }",
        "  }",
        "};",
        "return msg;"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 400, y: 40, wires: [[P + 'cot_to_xml']]
    },

    // Poll timer + config loader
    {
      id: P + 'inject', type: 'inject', z: FID,
      name: 'Poll timer (60s base)',
      props: [{ p: 'payload' }, { p: 'topic', vt: 'str' }],
      repeat: '60', crontab: '',
      once: true, onceDelay: '30',
      topic: 'poll', payload: '', payloadType: 'date',
      x: 180, y: 120, wires: [[P + 'load']]
    },
    {
      id: P + 'load', type: 'function', z: FID,
      name: 'Load TFR ' + feed.configName,
      func: [
        "var configs = global.get('arcgis_configs') || [];",
        "var tak = global.get('tak_settings') || {};",
        "var cfg = null;",
        "for (var i = 0; i < configs.length; i++) {",
        "  if (configs[i].configName === '" + feed.configName + "') { cfg = configs[i]; break; }",
        "}",
        "if (!cfg) { return null; }",
        "if (!tak.serverUrl) { node.warn('" + feed.configName + ": No TAK Server URL'); return null; }",
        "var pollKey = '_lastPoll_' + String(cfg.configName || '').replace(/[^A-Za-z0-9]/g, '_');",
        "var lastPoll = global.get(pollKey) || 0;",
        "var now = Date.now();",
        "var intervalMs = ((cfg.tfrPollInterval || 15) * 60000);",
        "if (now - lastPoll < intervalMs) return null;",
        "global.set(pollKey, now);",
        "node.warn('Polling: " + feed.configName + "');",
        "msg.url = 'https://tfr.faa.gov/tfrapi/exportTfrList';",
        "msg._config = cfg;",
        "msg.takSettings = tak;",
        "msg.topic = '" + feed.configName + "';",
        "return msg;"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 400, y: 120, wires: [[P + 'http_list']]
    },

    // Fetch TFR list
    {
      id: P + 'http_list', type: 'http request', z: FID,
      name: 'GET TFR list',
      method: 'GET', ret: 'obj', paytoqs: 'ignore',
      url: '', tls: '', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 600, y: 120, wires: [[P + 'filter']]
    },

    // Filter by state & split
    {
      id: P + 'filter', type: 'function', z: FID,
      name: 'Filter & split TFRs',
      _templateKey: 'tfr.filter_split',
      func: FN_TFR_FILTER_SPLIT,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 180, y: 220,
      wires: [[P + 'http_xml']]
    },

    // Per-TFR XML fetch
    {
      id: P + 'http_xml', type: 'http request', z: FID,
      name: 'GET TFR XML',
      method: 'use', ret: 'txt', paytoqs: 'ignore',
      url: '', tls: '', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 400, y: 220, wires: [[P + 'xml_parse']]
    },

    // XML -> JSON
    {
      id: P + 'xml_parse', type: 'xml', z: FID,
      name: 'Parse XNOTAM',
      property: 'payload', attr: '', chr: '',
      x: 580, y: 220, wires: [[P + 'build_cot']]
    },

    // Parse XNOTAM & build CoT
    {
      id: P + 'build_cot', type: 'function', z: FID,
      name: 'Build TFR CoT',
      _templateKey: 'tfr.build_cot',
      func: FN_TFR_PARSE_BUILD_COT,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 740, y: 220, wires: [[P + 'cot_to_xml']]
    },

    // CoT -> XML -> Throttle -> TCP out (same as ArcGIS)
    {
      id: P + 'cot_to_xml', type: 'function', z: FID,
      name: 'CoT JSON -> XML',
      _templateKey: 'shared.cot_to_xml',
      func: FN_COT_TO_XML,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 180, y: 320, wires: [[P + 'rate_stream']]
    },
    {
      id: P + 'rate_stream', type: 'delay', z: FID,
      name: 'Throttle (10/sec)', pauseType: 'rate',
      timeout: '1', timeoutUnits: 'seconds',
      rate: '10', nbRateUnits: '1', rateUnits: 'second',
      randomFirst: '1', randomLast: '5', randomUnits: 'seconds',
      drop: false, allowrate: false, outputs: 1,
      x: 400, y: 320, wires: [[P + 'tcp_out']]
    },
    {
      id: P + 'tcp_out', type: 'tcp out', z: FID,
      name: 'CoT -> TAK :8089',
      host: 'host.docker.internal', port: '8089', beserver: 'client',
      base64: false, end: false, tls: 'tls_tak',
      x: 600, y: 320, wires: []
    },
    {
      id: P + 'catch_stream', type: 'catch', z: FID,
      name: 'Stream errors',
      scope: [P + 'tcp_out'],
      uncaught: false,
      x: 180, y: 380, wires: [[P + 'debug_stream']]
    },
    {
      id: P + 'debug_stream', type: 'debug', z: FID,
      name: 'Stream error',
      active: true, tosidebar: true, console: false, tostatus: true,
      complete: 'true', targetType: 'full',
      statusVal: '', statusType: 'auto',
      x: 400, y: 380, wires: []
    },

    // Reconcile path: independent timer -> load config -> subscribe -> GET mission -> reconcile -> PUT/DELETE
    {
      id: P + 'recon_inject', type: 'inject', z: FID,
      name: 'Reconcile timer (90s)',
      props: [{ p: 'payload' }, { p: 'topic', vt: 'str' }],
      repeat: '60', crontab: '',
      once: true, onceDelay: '90',
      topic: 'reconcile', payload: '', payloadType: 'date',
      x: 180, y: 460, wires: [[P + 'recon_load']]
    },
    {
      id: P + 'recon_load', type: 'function', z: FID,
      name: 'Load config for reconcile',
      func: [
        "var configs = global.get('arcgis_configs') || [];",
        "var tak = global.get('tak_settings') || {};",
        "var cfg = null;",
        "for (var i = 0; i < configs.length; i++) {",
        "  if (configs[i].configName === '" + feed.configName + "') { cfg = configs[i]; break; }",
        "}",
        "if (!cfg) { node.warn('" + feed.configName + " reconcile: no config in global arcgis_configs'); return null; }",
        "if (!tak.serverUrl) { node.warn('" + feed.configName + " reconcile: no TAK serverUrl'); return null; }",
        "msg._config = cfg;",
        "msg.takSettings = tak;",
        "msg.topic = '" + feed.configName + "';",
        "return msg;"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      // Fan-out like ArcGIS parse: subscribe AND mission GET in parallel. If FN_SUB skips
      // (mission already in _subscribed), GET mission still runs — otherwise reconcile never fires.
      x: 400, y: 460, wires: [[P + 'build_sub', P + 'build_m']]
    },
    {
      id: P + 'build_sub', type: 'function', z: FID,
      name: 'Build subscribe URL',
      _templateKey: 'shared.build_sub',
      func: FN_SUB,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [
        { var: '_nodeHttps', module: 'https' },
        { var: '_nodeFs', module: 'fs' }
      ],
      x: 400, y: 460, wires: [[P + 'http_sub']]
    },
    {
      id: P + 'http_sub', type: 'http request', z: FID,
      name: 'Subscribe to mission',
      method: 'use', ret: 'txt', paytoqs: 'ignore',
      url: '', tls: 'tls_tak', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 600, y: 460, wires: [[P + 'fn_elevate']]
    },
    {
      id: P + 'fn_elevate', type: 'function', z: FID,
      name: 'Elevate to MISSION_OWNER',
      _templateKey: 'kml.fn_elevate',
      func: FN_ELEVATE_ROLE,
      outputs: 1, timeout: '', noerr: 0, initialize: '', finalize: '', libs: [],
      x: 800, y: 460, wires: [[P + 'debug_sub']]
    },
    {
      id: P + 'debug_sub', type: 'debug', z: FID,
      name: 'Subscribe result ' + feed.configName,
      active: true, tosidebar: true, console: false, tostatus: true,
      complete: 'true', targetType: 'full',
      statusVal: 'topic', statusType: 'auto',
      x: 1000, y: 460, wires: [[]]
    },

    {
      id: P + 'build_m', type: 'function', z: FID,
      name: 'Build mission GET URL',
      _templateKey: 'shared.build_m',
      func: FN_GET_MISSION,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 180, y: 540, wires: [[P + 'http_m']]
    },
    {
      id: P + 'http_m', type: 'http request', z: FID,
      name: 'GET mission',
      method: 'GET', ret: 'obj', paytoqs: 'ignore',
      url: '', tls: 'tls_tak', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 400, y: 540, wires: [[P + 'reconcile']]
    },
    {
      id: P + 'reconcile', type: 'function', z: FID,
      name: 'TFR Reconcile (diff)',
      _templateKey: 'tfr.reconcile',
      func: FN_TFR_RECONCILE,
      outputs: 2, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 580, y: 540,
      wires: [[P + 'delay_put'], [P + 'delay_del']]
    },

    // PUT new UIDs
    {
      id: P + 'delay_put', type: 'delay', z: FID,
      name: 'Wait 30s for cache',
      pauseType: 'delay', timeout: '30', timeoutUnits: 'seconds',
      rate: '1', nbRateUnits: '1', rateUnits: 'second',
      randomFirst: '1', randomLast: '5', randomUnits: 'seconds',
      drop: false, allowrate: false, outputs: 1,
      x: 780, y: 540, wires: [[P + 'build_put']]
    },
    {
      id: P + 'build_put', type: 'function', z: FID,
      name: 'Build PUT UIDs',
      _templateKey: 'shared.build_put',
      func: [
        "var uids = msg._putUids || [];",
        "if (!msg._putUrl || uids.length === 0) return null;",
        "msg.method = 'PUT';",
        "msg.url = msg._putUrl;",
        "msg.headers = { 'accept': '*/*', 'Content-Type': 'application/json' };",
        "if (msg._missionCookie) msg.headers.Cookie = msg._missionCookie;",
        "if (msg._missionBearer) msg.headers.Authorization = 'Bearer ' + msg._missionBearer;",
        "msg.payload = { uids: uids };",
        "node.warn(msg.topic + ' PUT -> ' + uids.length + ' UIDs -> ' + msg.url);",
        "return msg;"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 180, y: 620, wires: [[P + 'http_action']]
    },
    {
      id: P + 'http_action', type: 'http request', z: FID,
      name: 'Mission API (PUT/DELETE)',
      method: 'use', ret: 'txt', paytoqs: 'body',
      url: '', tls: 'tls_tak', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 420, y: 620, wires: [[P + 'log_action']]
    },
    {
      id: P + 'delay_del', type: 'delay', z: FID,
      name: '', pauseType: 'delay', timeout: '1', timeoutUnits: 'seconds',
      rate: '1', nbRateUnits: '1', rateUnits: 'second',
      randomFirst: '1', randomLast: '5', randomUnits: 'seconds',
      drop: false, allowrate: false, outputs: 1,
      x: 420, y: 670, wires: [[P + 'http_action']]
    },
    {
      id: P + 'log_action', type: 'function', z: FID,
      name: 'Log API result',
      _templateKey: 'shared.log_action',
      func: [
        "var code = msg.statusCode || '?';",
        "var method = msg.method || '?';",
        "var feed = msg.topic || 'unknown';",
        "var ok = (code >= 200 && code < 300);",
        "var label = feed + ' ' + method + ' -> ' + code + (ok ? ' OK' : ' FAIL');",
        "if (!ok) {",
        "  var body = (typeof msg.payload === 'string') ? msg.payload.substring(0, 200) : '';",
        "  node.warn(label + (body ? ' - ' + body : ''));",
        "} else {",
        "  node.warn(label);",
        "}",
        "return msg;"
      ].join('\n'),
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 640, y: 620, wires: [[]]
    }
  ];
}

// ════════════════════════════════════════════════════════════════
//  IPAWS Alerts tab — KML network link for ATAK
//  Serves GET /ipaws/alerts.kml  — add that URL as a KML Network Link
//  in ATAK (TAK Settings → Data Packages → Network Links or via
//  Overlay Manager → Add → URL).  Refresh: match your poll interval.
// ════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════
//  Tablet Command AVL engine
//  One card per agency in the Configurator → one Node-RED tab per card.
//  Streams CoT via TCP to TAK server — no DataSync / no KML.
//  Schema: latitude, longitude, radioName, time(epoch ms), vehicleStatus
// ════════════════════════════════════════════════════════════════

function makeTCEngineTab(feed) {
  const FID = 'flow_tc_' + feed.id;
  const P   = feed.id + '_tc_';

  const FN_TC_INIT = [
    "var cfg = (global.get('tc_configs')||[]).find(function(c){return c.configName==='"+feed.configName+"';});",
    "global.set('tc_last_fetch_"+feed.id+"', 0); // force immediate first poll",
    "if (!cfg) { node.warn('TC "+feed.configName+": config not found in global context'); return null; }",
    "return msg;"
  ].join('\n');

  const FN_TC_POLL = [
    "var cfg = (global.get('tc_configs')||[]).find(function(c){return c.configName==='"+feed.configName+"';});",
    "if (!cfg || !cfg.activated) return null;",
    "var intervalMs = Math.max(1, cfg.pollInterval||1) * 60000;",
    "var lastFetch  = global.get('tc_last_fetch_"+feed.id+"') || 0;",
    "if ((Date.now() - lastFetch) < intervalMs) return null;",
    "return msg;"
  ].join('\n');

  const FN_TC_BUILD_URL = [
    "var cfg = (global.get('tc_configs')||[]).find(function(c){return c.configName==='"+feed.configName+"';});",
    "if (!cfg || !cfg.activated) return null;",
    "var base = (cfg.agencyUrl||'').replace(/\\/+$/,'');",
    "msg.url    = base + '/0/query?where=1%3D1&outFields=*&returnGeometry=false&f=json';",
    "msg.method = 'GET';",
    "msg.headers = { 'User-Agent': 'infra-TAK/tabletcommand' };",
    "msg._tcCfg = cfg;",
    "return msg;"
  ].join('\n');

  const FN_TC_BUILD_COT = [
    TC_COT_TYPE_FN,
    "",
    "var cfg   = msg._tcCfg || (global.get('tc_configs')||[]).find(function(c){return c.configName==='"+feed.configName+"';}) || {};",
    "var data  = msg.payload || {};",
    "var feats = data.features || [];",
    "var knownUnits = global.get('tc_units_"+feed.id+"') || {};",
    "var tak   = global.get('tak_settings') || {};",
    "var host  = String(tak.serverUrl || '').replace(/^https?:\\/\\//i, '').replace(/\\/$/, '').trim() || tak.takHost || 'host.docker.internal';",
    "var baseP = Number(tak.streamingPort || tak.streamPort || 8089);",
    "var port  = Number(cfg.cotStreamPort) || baseP;",
    "var staleMs = (cfg.staleMinutes||5) * 60000;",
    "var sent  = 0;",
    "",
    "global.set('tc_last_fetch_"+feed.id+"', Date.now());",
    "",
    "feats.forEach(function(f) {",
    "  var a = f.attributes || {};",
    "  var radioName = (a.radioName||'').trim();",
    "  if (!radioName) return;",
    "  var lat = parseFloat(a.latitude);",
    "  var lon = parseFloat(a.longitude);",
    "  if (isNaN(lat)||isNaN(lon)) return;",
    "  var ts    = a.time ? new Date(a.time) : new Date();",
    "  var stale = new Date(ts.getTime() + staleMs);",
    "  var uid   = 'tc-' + (a.deviceUuid || ('obj-'+a.OBJECTID));",
    "  var ov    = knownUnits[radioName] || knownUnits[radioName.toUpperCase()] || {};",
    "  var callsign = ov.callsign || radioName;",
    "  var cotType  = ov.cotType  || tcCotType(radioName);",
    "  var iconRaw  = (ov.iconsetpath && String(ov.iconsetpath).trim()) || '';",
    "  var iconpath = iconRaw || tcDefaultIconset(cotType);",
    "  var _rmkFields = cfg.remarksFields && cfg.remarksFields.length ? cfg.remarksFields : null;",
    "  var remarks;",
    "  if (_rmkFields) {",
    "    var _rp = _rmkFields.map(function(k){ return k + ': ' + (a[k]||''); });",
    "    if (cfg.remarksCustomText) _rp.push(cfg.remarksCustomText);",
    "    remarks = _rp.join(' | ');",
    "  } else {",
    "    remarks = (cfg.configName||'TC') + ' | ' + radioName",
    "             + ' | Status: ' + (a.vehicleStatus||'') + ' | ' + ts.toLocaleString();",
    "  }",
    "  var detail = {",
    "    contact: [{ _attributes:{ callsign:callsign } }],",
    "    remarks: remarks,",
    "    status:  [{ _attributes:{ readiness:'true' } }]",
    "  };",
    "  if (iconpath) detail.usericon = [{ _attributes: { iconsetpath: iconpath } }];",
    "  var cotMsg = {",
    "    payload: {",
    "      event: {",
    "        _attributes: {",
    "          version:'2.0', uid:uid, type:cotType,",
    "          how:'m-g',",
    "          time:ts.toISOString(), start:ts.toISOString(), stale:stale.toISOString()",
    "        },",
    "        point:  { _attributes:{ lat:String(lat), lon:String(lon), hae:'9999999.0', ce:'50', le:'9999999.0' } },",
    "        detail: detail",
    "      }",
    "    },",
    "    host: host,",
    "    port: port",
    "  };",
    "  node.send(cotMsg);",
    "  sent++;",
    "});",
    "node.warn('TC "+feed.configName+": '+sent+' CoT events streamed from '+feats.length+' features');",
    "return null;"
  ].join('\n');

  return [
    // ── Tab ──
    {
      id: FID, type: 'tab',
      label: 'TC: ' + feed.configName,
      disabled: false,
      info: 'Tablet Command AVL engine for ' + feed.configName + '. Streams CoT via TCP — no DataSync.'
    },

    // ── Startup inject → immediate first poll ──
    {
      id: P+'init_inj', type: 'inject', z: FID,
      name: 'Startup init',
      props: [{ p:'payload' }],
      repeat: '', crontab: '',
      once: true, onceDelay: '3',
      topic: '', payload: '', payloadType: 'date',
      x: 160, y: 40, wires: [[P+'init_fn']]
    },
    {
      id: P+'init_fn', type: 'function', z: FID,
      name: 'Init TC config',
      func: FN_TC_INIT,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 380, y: 40, wires: [[P+'poll_fn']]
    },

    // ── 60-second timer → poll check ──
    {
      id: P+'timer', type: 'inject', z: FID,
      name: 'Every 60 s',
      props: [{ p:'payload' }],
      repeat: '60', crontab: '',
      once: false, onceDelay: '0',
      topic: '', payload: '', payloadType: 'date',
      x: 160, y: 100, wires: [[P+'poll_fn']]
    },
    {
      id: P+'poll_fn', type: 'function', z: FID,
      name: 'Check poll interval',
      func: FN_TC_POLL,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 380, y: 100, wires: [[P+'build_url']]
    },

    // ── Build URL → HTTP request → Build CoT ──
    {
      id: P+'build_url', type: 'function', z: FID,
      name: 'Build TC query URL',
      func: FN_TC_BUILD_URL,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 600, y: 100, wires: [[P+'http_req']]
    },
    {
      id: P+'http_req', type: 'http request', z: FID,
      name: 'GET TC FeatureServer',
      method: 'GET', ret: 'obj', paytoqs: 'ignore',
      url: '', tls: '', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 840, y: 100, wires: [[P+'build_cot']]
    },
    {
      id: P+'build_cot', type: 'function', z: FID,
      name: 'Build + stream CoT',
      func: FN_TC_BUILD_COT,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 1080, y: 100, wires: [[P+'cot_xml']]
    },

    // ── CoT JSON → XML → TCP out ──
    {
      id: P+'cot_xml', type: 'function', z: FID,
      name: 'CoT JSON -> XML',
      _templateKey: 'shared.cot_to_xml',
      func: FN_COT_TO_XML,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 300, y: 200, wires: [[P+'tcp_out']]
    },
    {
      id: P+'tcp_out', type: 'tcp out', z: FID,
      name: 'CoT -> TAK :8089',
      host: 'host.docker.internal', port: '8089', beserver: 'client',
      base64: false, doend: false, addCR: false, tls: 'tls_tak',
      x: 520, y: 200, wires: []
    },
    {
      id: P+'dbg', type: 'debug', z: FID,
      name: 'TC poll log',
      active: true, tosidebar: true, console: false, tostatus: true,
      complete: 'payload', targetType: 'msg',
      statusVal: '', statusType: 'auto',
      x: 1300, y: 100, wires: []
    }
  ];
}

const IPAWS_TAB_ID = 'flow_ipaws';

// ── Check poll interval then build NWS API request ──────────────
// Called by the 60-second timer inject; only proceeds if interval has elapsed.
const FN_IPAWS_POLL = [
  "var cfg = global.get('ipaws_config') || {};",
  "if (!cfg.activated) return null;",
  "var intervalMs = Math.max(1, cfg.pollInterval || 1) * 60 * 1000;",
  "var lastFetch = global.get('ipaws_last_fetch') || 0;",
  "if ((Date.now() - lastFetch) < intervalMs) return null;",
  "return msg;"
].join('\n');

const FN_IPAWS_BUILD_REQ = [
  "var cfg = global.get('ipaws_config') || {};",
  "if (!cfg.activated) return null;",
  "var params = ['status=actual'];",
  "if (cfg.states && cfg.states.length > 0) {",
  "  params.push('area=' + cfg.states.map(function(s){return String(s).trim().toUpperCase();}).filter(Boolean).join(','));",
  "}",
  "if (cfg.severity && cfg.severity.length > 0) {",
  "  params.push('severity=' + cfg.severity.join(','));",
  "}",
  "msg.url = 'https://api.weather.gov/alerts/active?' + params.join('&');",
  "msg.method = 'GET';",
  "msg.headers = { 'User-Agent': '(infra-TAK IPAWS, nodered@localhost)', 'Accept': 'application/geo+json' };",
  "return msg;"
].join('\n');

// ── Parse NWS GeoJSON → KML ──────────────────────────────────────
const FN_IPAWS_BUILD_KML = [
  "var data = msg.payload;",
  "var cfg  = global.get('ipaws_config') || {};",
  "",
  "// Return empty feed if not activated via Configurator",
  "if (cfg.activated === false) {",
  "  msg.payload = '<kml xmlns=\"http://www.opengis.net/kml/2.2\"><Document>' +",
  "    '<name>IPAWS Alerts (inactive)</name>' +",
  "    '<description>IPAWS feed not yet activated. Open the infra-TAK Configurator and click Deploy IPAWS.</description>' +",
  "    '</Document></kml>';",
  "  msg.headers = { 'Content-Type': 'application/vnd.google-earth.kml+xml' };",
  "  return msg;",
  "}",
  "",
  "// NAPSG Public Alert icons hosted on NAPSG S3 CDN (CC BY 4.0)",
  "// https://www.napsgfoundation.org/all-resources/symbology-library/",
  "var NAPSG_BASE = 'https://napsg-web.s3.amazonaws.com/symbology/data/PNG/Public_Alert/Public_Alerts_and_Warnings/';",
  "var NAPSG_ACT  = 'https://napsg-web.s3.amazonaws.com/symbology/data/PNG/Public_Alert/Public_Alerts_and_Warnings_%28Actions%29/';",
  "var NAPSG_SIZE = '_128_20151203.PNG';",
  "",
  "// icon key → full URL",
  "var ICON_URLS = {",
  "  'Tornado':           NAPSG_BASE + 'Tornado'           + NAPSG_SIZE,",
  "  'Blizzard_Warning':  NAPSG_BASE + 'Blizzard_Warning'  + NAPSG_SIZE,",
  "  'Civil_Emergency':   NAPSG_BASE + 'Civil_Emergency'   + NAPSG_SIZE,",
  "  'Dust_Storm':        NAPSG_BASE + 'Dust_Storm'        + NAPSG_SIZE,",
  "  'Earthquake':        NAPSG_BASE + 'Earthquake'        + NAPSG_SIZE,",
  "  'Fire':              NAPSG_BASE + 'Fire'              + NAPSG_SIZE,",
  "  'Flood':             NAPSG_BASE + 'Flood'             + NAPSG_SIZE,",
  "  'Hurricane':         NAPSG_BASE + 'Hurricane'         + NAPSG_SIZE,",
  "  'Law_Enforcement':   NAPSG_BASE + 'Law_Enforcement'   + NAPSG_SIZE,",
  "  'Nuclear_Power_Plant':NAPSG_BASE+ 'Nuclear_Power_Plant'+ NAPSG_SIZE,",
  "  'Radiological':      NAPSG_BASE + 'Radiological'      + NAPSG_SIZE,",
  "  'Shelter_in_Place':  NAPSG_ACT  + 'Shelter_in_Place'  + NAPSG_SIZE,",
  "  'Avalanche':         NAPSG_BASE + 'Avalanche'         + NAPSG_SIZE,",
  "};",
  "",
  "// Override base URL from config if set (must be a full URL ending in /)",
  "if (cfg.iconBaseUrl) {",
  "  var b = cfg.iconBaseUrl.replace(/\\/$/, '') + '/';",
  "  Object.keys(ICON_URLS).forEach(function(k){ ICON_URLS[k] = b + k + '.png'; });",
  "}",
  "",
  "if (msg.statusCode >= 400 || !data || !Array.isArray(data.features)) {",
  "  var errKml = '<?xml version=\"1.0\" encoding=\"UTF-8\"?>' +",
  "    '<kml xmlns=\"http://www.opengis.net/kml/2.2\"><Document>' +",
  "    '<name>IPAWS Error</name>' +",
  "    '<description>NWS API error — HTTP ' + (msg.statusCode||'?') + '</description>' +",
  "    '</Document></kml>';",
  "  msg.payload = errKml;",
  "  return msg;",
  "}",
  "var features = data.features;",
  "",
  "// NWS event type → NAPSG icon key",
  "var ICON_MAP = {",
  "  'Tornado Warning':'Tornado','Tornado Watch':'Tornado','Tornado Emergency':'Tornado',",
  "  'Severe Thunderstorm Warning':'Tornado','Severe Thunderstorm Watch':'Tornado',",
  "  'Flash Flood Warning':'Flood','Flash Flood Watch':'Flood','Flash Flood Emergency':'Flood',",
  "  'Flood Warning':'Flood','Flood Watch':'Flood','Flood Advisory':'Flood','Flood Statement':'Flood',",
  "  'Areal Flood Warning':'Flood','Areal Flood Watch':'Flood','Areal Flood Advisory':'Flood',",
  "  'Coastal Flood Warning':'Flood','Coastal Flood Watch':'Flood','Coastal Flood Advisory':'Flood',",
  "  'High Surf Warning':'Flood','High Surf Advisory':'Flood','Special Marine Warning':'Flood',",
  "  'Lake Shore Flood Warning':'Flood','Beach Hazards Statement':'Flood',",
  "  'Storm Surge Warning':'Flood','Storm Surge Watch':'Flood',",
  "  'Tsunami Warning':'Flood','Tsunami Watch':'Flood','Tsunami Advisory':'Flood',",
  "  'Red Flag Warning':'Fire','Fire Weather Watch':'Fire','Fire Warning':'Fire',",
  "  'Hurricane Warning':'Hurricane','Hurricane Watch':'Hurricane',",
  "  'Hurricane Local Statement':'Hurricane','Post-Tropical Cyclone Warning':'Hurricane',",
  "  'Tropical Storm Warning':'Hurricane','Tropical Storm Watch':'Hurricane',",
  "  'High Wind Warning':'Dust_Storm','High Wind Watch':'Dust_Storm','Wind Advisory':'Dust_Storm',",
  "  'Extreme Wind Warning':'Dust_Storm','Lake Wind Advisory':'Dust_Storm',",
  "  'Dust Storm Warning':'Dust_Storm','Blowing Dust Advisory':'Dust_Storm',",
  "  'Dense Smoke Advisory':'Dust_Storm','Air Quality Alert':'Dust_Storm','Air Stagnation Advisory':'Dust_Storm',",
  "  'Ashfall Warning':'Dust_Storm','Ashfall Advisory':'Dust_Storm',",
  "  'Winter Storm Warning':'Blizzard_Warning','Winter Storm Watch':'Blizzard_Warning',",
  "  'Blizzard Warning':'Blizzard_Warning','Ice Storm Warning':'Blizzard_Warning',",
  "  'Winter Weather Advisory':'Blizzard_Warning','Snow Squall Warning':'Blizzard_Warning',",
  "  'Heavy Snow Warning':'Blizzard_Warning','Freezing Rain Advisory':'Blizzard_Warning','Sleet Warning':'Blizzard_Warning',",
  "  'Wind Chill Warning':'Blizzard_Warning','Wind Chill Watch':'Blizzard_Warning','Wind Chill Advisory':'Blizzard_Warning',",
  "  'Freeze Warning':'Blizzard_Warning','Freeze Watch':'Blizzard_Warning','Frost Advisory':'Blizzard_Warning',",
  "  'Hard Freeze Warning':'Blizzard_Warning','Hard Freeze Watch':'Blizzard_Warning',",
  "  'Excessive Heat Warning':'Civil_Emergency','Excessive Heat Watch':'Civil_Emergency','Heat Advisory':'Civil_Emergency',",
  "  'Volcano Warning':'Earthquake','Volcano Watch':'Earthquake',",
  "  'Earthquake Warning':'Earthquake',",
  "  'Avalanche Warning':'Avalanche','Avalanche Watch':'Avalanche','Avalanche Advisory':'Avalanche',",
  "  'Hazardous Materials Warning':'Nuclear_Power_Plant','Chemical Hazard Warning':'Nuclear_Power_Plant',",
  "  'Nuclear Power Plant Warning':'Nuclear_Power_Plant',",
  "  'Radiological Hazard Warning':'Radiological',",
  "  'Child Abduction Emergency':'Civil_Emergency','AMBER Alert':'Civil_Emergency',",
  "  'Shelter In Place Warning':'Shelter_in_Place',",
  "  'Law Enforcement Warning':'Law_Enforcement',",
  "  'Local Area Emergency':'Civil_Emergency','Civil Emergency Message':'Civil_Emergency',",
  "  'Evacuation Immediate':'Civil_Emergency','Civil Danger Warning':'Civil_Emergency',",
  "  'Immediate Evacuation Warning':'Civil_Emergency','911 Telephone Outage Emergency':'Civil_Emergency'",
  "};",
  "",
  "// Severity → KML polygon/line colors (AABBGGRR format)",
  "var SEV_COLOR = {",
  "  'Extreme':  { fill:'660000ff', line:'ff0000ff' },",
  "  'Severe':   { fill:'6600a5ff', line:'ff00a5ff' },",
  "  'Moderate': { fill:'6600ffff', line:'ff00ffff' },",
  "  'Minor':    { fill:'66ff6400', line:'ffff6400' },",
  "  'Unknown':  { fill:'66808080', line:'ff808080' }",
  "};",
  "",
  "function xmlEsc(s) {",
  "  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');",
  "}",
  "",
  "function ringCoords(coords) {",
  "  return coords.map(function(c){return c[0]+','+c[1]+',0';}).join(' ');",
  "}",
  "",
  "function centroid(coords) {",
  "  var ln=0,lt=0,n=coords.length;",
  "  for(var i=0;i<n;i++){ln+=coords[i][0];lt+=coords[i][1];}",
  "  return {lon:ln/n, lat:lt/n};",
  "}",
  "",
  "function getRings(geom) {",
  "  // Returns array of coordinate rings from GeoJSON Polygon or MultiPolygon",
  "  if (!geom) return [];",
  "  if (geom.type === 'Polygon' && geom.coordinates && geom.coordinates[0]) {",
  "    return [geom.coordinates[0]];",
  "  }",
  "  if (geom.type === 'MultiPolygon' && geom.coordinates) {",
  "    return geom.coordinates.map(function(p){return p[0]||[];}).filter(function(r){return r.length>2;});",
  "  }",
  "  return [];",
  "}",
  "",
  "// Zone geometry cache — NWS zone boundaries rarely change, 5-day TTL is fine",
  "var ZONE_CACHE_KEY = 'ipaws_zone_geo';",
  "var ZONE_TTL = 5 * 24 * 3600 * 1000;",
  "var zoneCache = global.get(ZONE_CACHE_KEY) || {};",
  "var cacheNow = Date.now();",
  "",
  "// Collect all unique zone URLs referenced by zone-based alerts",
  "var allZoneUrls = {};",
  "features.forEach(function(f) {",
  "  if (!getRings(f.geometry).length) {",
  "    (f.properties.affectedZones || []).forEach(function(u) { allZoneUrls[u] = true; });",
  "  }",
  "});",
  "",
  "// Which zones are not yet cached (or expired)?",
  "var toFetch = Object.keys(allZoneUrls).filter(function(u) {",
  "  var c = zoneCache[u];",
  "  return !c || (cacheNow - c.ts) > ZONE_TTL;",
  "});",
  "",
  "// State/territory + NWS marine zone prefix centroids [lon, lat]",
  "// Used only as last-resort fallback when zone geometry fetch fails",
  "var STATE_CENTROIDS = {",
  "  'AL':[-86.9023,32.3182],'AK':[-153.3691,64.2008],'AZ':[-111.0937,34.2744],'AR':[-92.4426,34.7465],",
  "  'CA':[-119.4179,37.1551],'CO':[-105.5478,38.9972],'CT':[-72.7273,41.6032],'DE':[-75.5277,38.9108],",
  "  'FL':[-81.5158,27.7663],'GA':[-83.6431,32.9866],'HI':[-155.5828,19.8968],'ID':[-114.7420,44.2394],",
  "  'IL':[-89.1965,40.3495],'IN':[-86.2816,39.8494],'IA':[-93.2140,42.0115],'KS':[-98.3804,38.5266],",
  "  'KY':[-85.3021,37.6690],'LA':[-91.9623,31.1695],'ME':[-69.3819,44.6939],'MD':[-76.8021,39.0639],",
  "  'MA':[-71.5301,42.2302],'MI':[-84.5603,43.3266],'MN':[-94.6859,45.6945],'MS':[-89.6678,32.7364],",
  "  'MO':[-92.3022,38.4623],'MT':[-110.3626,46.8797],'NE':[-99.9018,41.4925],'NV':[-116.4194,38.8026],",
  "  'NH':[-71.5724,43.1939],'NJ':[-74.4057,40.0583],'NM':[-106.1126,34.5199],'NY':[-74.9481,42.1657],",
  "  'NC':[-79.0193,35.6301],'ND':[-101.0020,47.5289],'OH':[-82.9071,40.3888],'OK':[-97.0929,35.5653],",
  "  'OR':[-120.5542,44.5720],'PA':[-77.1945,40.5908],'RI':[-71.4774,41.6809],'SC':[-81.1637,33.8569],",
  "  'SD':[-99.9018,44.2998],'TN':[-86.6923,35.7478],'TX':[-99.3413,31.4757],'UT':[-111.0937,39.3210],",
  "  'VT':[-72.7107,44.0459],'VA':[-78.6569,37.4316],'WA':[-120.7401,47.4009],'WV':[-80.4549,38.9179],",
  "  'WI':[-89.6165,44.2685],'WY':[-107.5512,43.0760],",
  "  'DC':[-77.0369,38.9072],'PR':[-66.5901,18.2208],'VI':[-64.8963,17.7297],",
  "  'GU':[144.7937,13.4443],'AS':[-170.7020,-14.2710],'MP':[145.6739,14.8901],",
  "  'AN':[-70.0,40.5],'AM':[-78.0,32.0],'GM':[-89.5,27.0],",
  "  'PZ':[-124.5,38.5],'PH':[-157.5,21.0],'PK':[-153.0,57.5],'BZ':[-170.0,60.5],",
  "  'LS':[-86.5,47.0],'LM':[-87.0,44.0],'LH':[-83.0,44.5],'LE':[-81.0,42.0],'LO':[-77.0,43.5]",
  "};",
  "",
  "// ── Core KML builder (called once zone cache is warm) ──────────",
  "function buildKml(zc) {",
  "  var usedStyles = {};",
  "  var placemarkXml = [];",
  "  var nPoly = 0, nZone = 0, nPoint = 0, nSkip = 0;",
  "",
  "  features.forEach(function(f) {",
  "    var p = f.properties || {};",
  "    var event    = p.event    || 'Unknown';",
  "    var severity = p.severity || 'Unknown';",
  "    var icon     = ICON_MAP[event] || 'Civil_Emergency';",
  "    var sc       = SEV_COLOR[severity] || SEV_COLOR['Unknown'];",
  "    var styleId  = icon + '-' + severity.toLowerCase();",
  "    usedStyles[styleId] = { icon: icon, sc: sc };",
  "",
  "    var rings  = getRings(f.geometry);",
  "    var hasPoly = rings.length > 0;",
  "    var cen;",
  "",
  "    if (!hasPoly) {",
  "      // Look up zone polygons from cache",
  "      var zoneRings = [];",
  "      (p.affectedZones || []).forEach(function(u) {",
  "        var ce = zc[u];",
  "        if (ce && ce.geom) {",
  "          var r = getRings(ce.geom);",
  "          if (r.length) zoneRings = zoneRings.concat(r);",
  "        }",
  "      });",
  "      if (zoneRings.length) {",
  "        rings   = zoneRings;",
  "        hasPoly = true;",
  "        cen     = centroid(rings[0]);",
  "        nZone++;",
  "      } else {",
  "        // Last resort: state-centroid point",
  "        var ugcList = (p.geocode && p.geocode.UGC) || [];",
  "        var stCode  = ugcList.length ? ugcList[0].slice(0,2).toUpperCase() : '';",
  "        var stXY    = STATE_CENTROIDS[stCode];",
  "        if (!stXY) { nSkip++; return; }",
  "        cen    = { lon: stXY[0], lat: stXY[1] };",
  "        nPoint++;",
  "      }",
  "    } else {",
  "      cen = centroid(rings[0]);",
  "      nPoly++;",
  "    }",
  "",
  "    // ── Rich HTML description ───────────────────────────────────",
  "    var areaDesc = p.areaDesc   || '';",
  "    var descText = p.description || '';",
  "    var instr    = p.instruction || '';",
  "    var sender   = p.senderName || p.sender || '';",
  "    var expires  = p.expires   || p.ends   || '';",
  "    var onset    = p.onset     || p.effective || '';",
  "    var response = p.response  || '';",
  "",
  "    var descHtml = '<b>&#128205; Areas:</b><br/>' + areaDesc.replace(/;/g,'<br/>')",
  "      + '<br/><br/><b>&#128196; Details:</b><br/>' + descText.replace(/\\*/g,'•').replace(/\\n/g,'<br/>')",
  "      + (instr ? '<br/><br/><b>&#9888;&#65039; Instructions:</b><br/>' + instr.replace(/\\n/g,'<br/>') : '')",
  "      + '<br/><br/><table>'",
  "      + '<tr><td><b>Severity</b></td><td>' + severity + '</td></tr>'",
  "      + '<tr><td><b>Certainty</b></td><td>' + (p.certainty||'') + '</td></tr>'",
  "      + '<tr><td><b>Urgency</b></td><td>' + (p.urgency||'') + '</td></tr>'",
  "      + (response ? '<tr><td><b>Response</b></td><td>' + response + '</td></tr>' : '')",
  "      + (sender   ? '<tr><td><b>Issued by</b></td><td>' + sender + '</td></tr>' : '')",
  "      + (onset    ? '<tr><td><b>Effective</b></td><td>' + onset + '</td></tr>' : '')",
  "      + (expires  ? '<tr><td><b>Expires</b></td><td>' + expires + '</td></tr>' : '')",
  "      + '</table>';",
  "",
  "    var pmName = xmlEsc(event + ' \\u2014 ' + areaDesc.split(';')[0].trim());",
  "",
  "    var timeBlock = '';",
  "    if (onset || expires) {",
  "      timeBlock = '<TimeSpan>'",
  "        + (onset   ? '<begin>' + xmlEsc(onset)   + '</begin>' : '')",
  "        + (expires ? '<end>'   + xmlEsc(expires) + '</end>'   : '')",
  "        + '</TimeSpan>';",
  "    }",
  "",
  "    var descBlock = '<description><![CDATA[' + descHtml + ']]></description>';",
  "",
  "    // Polygon placemarks",
  "    if (hasPoly) rings.forEach(function(ring) {",
  "      if (ring.length < 3) return;",
  "      placemarkXml.push(",
  "        '<Placemark>',",
  "        '<name>' + pmName + '</name>',",
  "        '<styleUrl>#poly-' + styleId + '</styleUrl>',",
  "        timeBlock,",
  "        descBlock,",
  "        '<Polygon><tessellate>1</tessellate>',",
  "        '<outerBoundaryIs><LinearRing>',",
  "        '<coordinates>' + ringCoords(ring) + '</coordinates>',",
  "        '</LinearRing></outerBoundaryIs></Polygon>',",
  "        '</Placemark>'",
  "      );",
  "    });",
  "",
  "    // Center icon",
  "    placemarkXml.push(",
  "      '<Placemark>',",
  "      '<name>' + pmName + '</name>',",
  "      '<styleUrl>#icon-' + styleId + '</styleUrl>',",
  "      timeBlock,",
  "      descBlock,",
  "      '<Point><coordinates>' + cen.lon + ',' + cen.lat + ',0</coordinates></Point>',",
  "      '</Placemark>'",
  "    );",
  "  });",
  "",
  "  // Style elements",
  "  var styleXml = [];",
  "  Object.keys(usedStyles).forEach(function(sid) {",
  "    var s   = usedStyles[sid];",
  "    var url = xmlEsc(ICON_URLS[s.icon] || ICON_URLS['Civil_Emergency']);",
  "    styleXml.push(",
  "      '<Style id=\"poly-' + sid + '\">',",
  "      '<LineStyle><color>' + s.sc.line + '</color><width>2</width></LineStyle>',",
  "      '<PolyStyle><color>' + s.sc.fill + '</color><outline>1</outline></PolyStyle>',",
  "      '</Style>',",
  "      '<Style id=\"icon-' + sid + '\">',",
  "      '<LabelStyle><scale>0</scale></LabelStyle>',",
  "      '<IconStyle><Icon>',",
  "      '<href>' + url + '</href>',",
  "      '<hotSpot x=\"0.5\" y=\"0.5\" xunits=\"fraction\" yunits=\"fraction\"/>',",
  "      '</Icon></IconStyle>',",
  "      '</Style>'",
  "    );",
  "  });",
  "",
  "  var ts = new Date().toISOString();",
  "  var kml = [",
  "    '<kml xmlns=\"http://www.opengis.net/kml/2.2\">',",
  "    '<Document>',",
  "    '<name>IPAWS Active Alerts</name>',",
  "    '<description>NWS Active Alerts \\u2014 ' + ts + ' \\u2014 ' + features.length + ' alerts</description>',",
  "    styleXml.join('\\n'),",
  "    placemarkXml.join('\\n'),",
  "    '</Document></kml>'",
  "  ].join('\\n');",
  "",
  "  node.warn('IPAWS KML: ' + features.length + ' alerts \\u2192 ' + nPoly + ' inline-poly, ' + nZone + ' zone-poly, ' + nPoint + ' state-pt, ' + nSkip + ' skipped | zone cache: ' + Object.keys(zc).length + ' entries');",
  "  return kml;",
  "}",
  "",
  "// ── Sync path: all zones already cached — store KML and done ──",
  "if (toFetch.length === 0) {",
  "  var kml = buildKml(zoneCache);",
  "  global.set('ipaws_kml_cache', { kml: kml, ts: Date.now() });",
  "  global.set('ipaws_last_fetch', Date.now());",
  "  msg.payload = 'IPAWS: cache updated — ' + features.length + ' alerts at ' + new Date().toISOString();",
  "  return msg;",
  "}",
  "",
  "// ── Async path: fetch missing zone geometries then store KML ───",
  "var https = global.get('nodeHttps');",
  "function fetchZone(u) {",
  "  return new Promise(function(resolve) {",
  "    var req = https.get(u, { headers: { 'User-Agent': '(infra-TAK IPAWS, nodered@localhost)', 'Accept': 'application/geo+json' } }, function(res) {",
  "      var buf = '';",
  "      res.on('data', function(c) { buf += c; });",
  "      res.on('end', function() {",
  "        try { var d = JSON.parse(buf); resolve({ u: u, geom: d && d.geometry ? d.geometry : null }); }",
  "        catch(e) { resolve({ u: u, geom: null }); }",
  "      });",
  "    });",
  "    req.on('error', function() { resolve({ u: u, geom: null }); });",
  "    req.setTimeout(15000, function() { req.destroy(); resolve({ u: u, geom: null }); });",
  "  });",
  "}",
  "node.warn('IPAWS: fetching ' + toFetch.length + ' uncached zone geometries...');",
  "Promise.all(toFetch.map(fetchZone)).then(function(results) {",
  "  var newCount = 0;",
  "  results.forEach(function(r) {",
  "    zoneCache[r.u] = { geom: r.geom || null, ts: cacheNow };",
  "    if (r.geom) newCount++;",
  "  });",
  "  global.set(ZONE_CACHE_KEY, zoneCache);",
  "  node.warn('IPAWS: zone fetch done — ' + newCount + '/' + toFetch.length + ' geometries retrieved');",
  "  var kml = buildKml(zoneCache);",
  "  global.set('ipaws_kml_cache', { kml: kml, ts: Date.now() });",
  "  global.set('ipaws_last_fetch', Date.now());",
  "  msg.payload = 'IPAWS: cache updated — ' + features.length + ' alerts (zone fetch) at ' + new Date().toISOString();",
  "  node.send(msg);",
  "}).catch(function(err) {",
  "  node.warn('IPAWS zone fetch error: ' + (err.message || err) + ' — using partial cache');",
  "  var kml = buildKml(zoneCache);",
  "  global.set('ipaws_kml_cache', { kml: kml, ts: Date.now() });",
  "  global.set('ipaws_last_fetch', Date.now());",
  "  msg.payload = 'IPAWS: cache updated with partial zone data — ' + features.length + ' alerts';",
  "  node.send(msg);",
  "});",
  "return; // async — node.send() called from Promise"
].join('\n');

// ── Save IPAWS config ────────────────────────────────────────────
const FN_IPAWS_SAVE_CFG = [
  "var body = msg.payload || {};",
  "var existing = global.get('ipaws_config') || {};",
  "var updated = Object.assign({}, existing, body);",
  "global.set('ipaws_config', updated);",
  "// Reset fetch timestamp so next timer tick triggers immediate re-fetch with new settings",
  "global.set('ipaws_last_fetch', 0);",
  CFG_BACKUP_SNIPPET,
  "msg.payload = { ok: true, config: updated };",
  "return msg;"
].join('\n');

// ── Get IPAWS config ─────────────────────────────────────────────
const FN_IPAWS_GET_CFG = [
  "var cfg = global.get('ipaws_config') || {};",
  "msg.payload = { ok: true, config: cfg };",
  "return msg;"
].join('\n');

// ── Init default config on startup ──────────────────────────────
const FN_IPAWS_INIT = [
  "var existing = global.get('ipaws_config');",
  "if (!existing || !existing._initialized) {",
  "  global.set('ipaws_config', {",
  "    _initialized: true,",
  "    activated: false,",
  "    severity: ['Extreme', 'Severe'],",
  "    states: [],",
  "    pollInterval: 1,",
  "    iconBaseUrl: ''",
  "  });",
  "  node.warn('IPAWS: default config initialized — activate via Configurator to enable KML feed');",
  "}",
  "return msg; // chain to poll_fn for immediate first fetch attempt"
].join('\n');

// ── Serve cached KML to ATAK clients ────────────────────────────
// HTTP handler — instant response from global context cache.
const FN_IPAWS_SERVE_KML = [
  "var cfg = global.get('ipaws_config') || {};",
  "if (!cfg.activated) {",
  "  msg.payload = '<kml xmlns=\"http://www.opengis.net/kml/2.2\"><Document>' +",
  "    '<name>IPAWS Alerts (inactive)</name>' +",
  "    '<description>IPAWS feed not yet activated. Open the infra-TAK Configurator and click Deploy IPAWS.</description>' +",
  "    '</Document></kml>';",
  "  msg.headers = { 'Content-Type': 'application/vnd.google-earth.kml+xml; charset=utf-8' };",
  "  return msg;",
  "}",
  "var cache = global.get('ipaws_kml_cache');",
  "if (!cache || !cache.kml) {",
  "  var mins = cfg.pollInterval || 1;",
  "  msg.payload = '<kml xmlns=\"http://www.opengis.net/kml/2.2\"><Document>' +",
  "    '<name>IPAWS Alerts (initializing)</name>' +",
  "    '<description>Feed is initializing — first build within ' + mins + ' minute(s). Check back shortly.</description>' +",
  "    '</Document></kml>';",
  "  msg.headers = { 'Content-Type': 'application/vnd.google-earth.kml+xml; charset=utf-8' };",
  "  return msg;",
  "}",
  "msg.payload = cache.kml;",
  "msg.headers = { 'Content-Type': 'application/vnd.google-earth.kml+xml; charset=utf-8' };",
  "return msg;"
].join('\n');

function makeIpawsTab() {
  const Z = IPAWS_TAB_ID;
  return [
    {
      id: Z, type: 'tab',
      label: 'IPAWS Alerts',
      disabled: false,
      info: 'FEMA IPAWS / NWS active alerts KML feed for ATAK.\n' +
            'KML is pre-built on a configurable timer (default: every 1 min).\n' +
            'GET /ipaws/alerts.kml instantly serves the cached KML — any number of\n' +
            'ATAK clients at any poll interval only costs 1 NWS API call per interval.\n' +
            'Configure via Configurator or POST /ipaws/config.'
    },

    // ── Startup init → immediate first poll attempt ───────────────
    {
      id: Z + '_init_inj', type: 'inject', z: Z,
      name: 'Startup init',
      props: [{ p: 'payload' }],
      repeat: '', crontab: '',
      once: true, onceDelay: '2',
      topic: '', payload: '', payloadType: 'date',
      x: 160, y: 40, wires: [[Z + '_init_fn']]
    },
    {
      id: Z + '_init_fn', type: 'function', z: Z,
      name: 'Init default config',
      func: FN_IPAWS_INIT,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 400, y: 40, wires: [[Z + '_poll_fn']]
    },

    // ── 60-second timer → poll check → NWS fetch ─────────────────
    {
      id: Z + '_timer_inj', type: 'inject', z: Z,
      name: 'Every 60 s',
      props: [{ p: 'payload' }],
      repeat: '60', crontab: '',
      once: false, onceDelay: '0',
      topic: '', payload: '', payloadType: 'date',
      x: 160, y: 100, wires: [[Z + '_poll_fn']]
    },
    {
      id: Z + '_poll_fn', type: 'function', z: Z,
      name: 'Check poll interval',
      func: FN_IPAWS_POLL,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 400, y: 100, wires: [[Z + '_fn_req']]
    },
    {
      id: Z + '_fn_req', type: 'function', z: Z,
      name: 'Build NWS request',
      func: FN_IPAWS_BUILD_REQ,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 640, y: 100, wires: [[Z + '_http_nws']]
    },
    {
      id: Z + '_http_nws', type: 'http request', z: Z,
      name: 'GET NWS alerts',
      method: 'use', ret: 'obj', paytoqs: 'ignore',
      url: '', tls: '', persist: false, proxy: '',
      insecureHTTPParser: false, authType: '',
      senderr: false, headers: [],
      x: 880, y: 100, wires: [[Z + '_fn_kml']]
    },
    {
      id: Z + '_fn_kml', type: 'function', z: Z,
      name: 'Build + cache IPAWS KML',
      func: FN_IPAWS_BUILD_KML,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 1120, y: 100, wires: [[Z + '_dbg_kml']]
    },
    {
      id: Z + '_dbg_kml', type: 'debug', z: Z,
      name: 'Cache update log',
      active: true, tosidebar: true, console: false, tostatus: true,
      complete: 'payload', targetType: 'msg',
      statusVal: '', statusType: 'auto',
      x: 1360, y: 100, wires: []
    },

    // ── KML endpoint — instant serve from cache ───────────────────
    {
      id: Z + '_c_kml', type: 'comment', z: Z,
      name: '── GET /ipaws/alerts.kml  ← ATAK Network Link URL (served from cache) ──',
      info: '', x: 320, y: 200, wires: []
    },
    {
      id: Z + '_hi_kml', type: 'http in', z: Z,
      name: 'GET /ipaws/alerts.kml',
      url: '/ipaws/alerts.kml', method: 'get',
      upload: false, swaggerDoc: '',
      x: 180, y: 240, wires: [[Z + '_fn_serve']]
    },
    {
      id: Z + '_fn_serve', type: 'function', z: Z,
      name: 'Serve cached KML',
      func: FN_IPAWS_SERVE_KML,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 420, y: 240, wires: [[Z + '_ho_kml']]
    },
    {
      id: Z + '_ho_kml', type: 'http response', z: Z,
      name: '', statusCode: '200',
      headers: {},
      x: 640, y: 240, wires: []
    },

    // ── Config API ───────────────────────────────────────────────
    {
      id: Z + '_c_cfg', type: 'comment', z: Z,
      name: '── Config API  GET/POST /ipaws/config ──',
      info: '', x: 220, y: 340, wires: []
    },
    {
      id: Z + '_hi_cfg_get', type: 'http in', z: Z,
      name: 'GET /ipaws/config',
      url: '/ipaws/config', method: 'get',
      upload: false, swaggerDoc: '',
      x: 180, y: 380, wires: [[Z + '_fn_get_cfg']]
    },
    {
      id: Z + '_fn_get_cfg', type: 'function', z: Z,
      name: 'Get IPAWS config',
      func: FN_IPAWS_GET_CFG,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 420, y: 380, wires: [[Z + '_ho_cfg_get']]
    },
    {
      id: Z + '_ho_cfg_get', type: 'http response', z: Z,
      name: '', statusCode: '200',
      headers: { 'content-type': 'application/json' },
      x: 660, y: 380, wires: []
    },
    {
      id: Z + '_hi_cfg_post', type: 'http in', z: Z,
      name: 'POST /ipaws/config',
      url: '/ipaws/config', method: 'post',
      upload: false, swaggerDoc: '',
      x: 180, y: 440, wires: [[Z + '_fn_save_cfg']]
    },
    {
      id: Z + '_fn_save_cfg', type: 'function', z: Z,
      name: 'Save IPAWS config',
      func: FN_IPAWS_SAVE_CFG,
      outputs: 1, timeout: '', noerr: 0,
      initialize: '', finalize: '', libs: [],
      x: 420, y: 440, wires: [[Z + '_ho_cfg_post']]
    },
    {
      id: Z + '_ho_cfg_post', type: 'http response', z: Z,
      name: '', statusCode: '200',
      headers: { 'content-type': 'application/json' },
      x: 660, y: 440, wires: []
    }
  ];
}

// ════════════════════════════════════════════════════════════════
//  PulsePoint — streaming CoT over TCP (same delivery model as Tablet Command;
//  not KML / not Data Sync). Polls PulsePoint web API per [snstac/pulsecot](https://github.com/snstac/pulsecot).
// ════════════════════════════════════════════════════════════════

const PULSEPOINT_TAB_ID = 'flow_pulsepoint_cfg';

// ── Per-agency poll check (parameterised by __CONFIG_NAME__) ──────────────────
const FN_PP_POLL_V2 = [
  "var _cn = '__CONFIG_NAME__';",
  "var _cfgs = global.get('pp_configs') || [];",
  "if (!Array.isArray(_cfgs)) { try { _cfgs = JSON.parse(_cfgs); } catch(e) { _cfgs = []; } }",
  "var cfg = _cfgs.find(function(c){ return c.configName === _cn; }) || {};",
  "if (!cfg.activated) return null;",
  "var intervalMs = Math.max(15, Number(cfg.pollIntervalSec) || 120) * 1000;",
  "var lastKey = 'pp_last_fetch___FEED_ID__';",
  "var lastFetch = global.get(lastKey) || 0;",
  "if ((Date.now() - lastFetch) < intervalMs) return null;",
  "msg._ppCfg = cfg;",
  "return msg;"
].join('\n');

// ── Per-agency fetch (parameterised) ─────────────────────────────────────────
// Reads cfg from msg._ppCfg (set by poll check)

// HTTPS GET + AES decode (same algorithm as pulsecot gnu.decode_pulse).
const FN_PP_FETCH_V2 = [
  "var cfg = msg._ppCfg || {};",
  "if (!cfg.activated) return null;",
  "var rawIds = String(cfg.agencyIds || '').split(/[,\\s]+/).map(function(s){ return s.trim(); }).filter(Boolean);",
  "if (!rawIds.length) { node.warn('PulsePoint: no agency IDs configured'); return null; }",
  "var https = global.get('nodeHttps');",
  "if (!https) { node.warn('PulsePoint: nodeHttps missing'); return null; }",
  "var urlMod = require('url');",
  "var crypto = require('crypto');",
  "var base = String(cfg.ppBaseUrl || 'https://api.pulsepoint.org/v1/webapp').replace(/\\/+$/, '');",
  "var hdr = {",
  "  'accept': '*/*',",
  "  'accept-language': 'en-US,en;q=0.9',",
  "  'user-agent': 'infra-TAK/pulsepoint',",
  "  'referer': 'https://web.pulsepoint.org/'",
  "};",
  "function decodePulse(data) {",
  "  if (!data || !data.ct || !data.iv || !data.s) return data;",
  "  var ct = Buffer.from(data.ct, 'base64');",
  "  var iv = Buffer.from(String(data.iv), 'hex');",
  "  var salt = Buffer.from(String(data.s), 'hex');",
  "  var ekey = 'CommonIncidents';",
  "  var token = ekey[13] + ekey[1] + ekey[2] + 'brady' + '5' + 'r' + ekey.toLowerCase()[6] + ekey[5] + 'gs';",
  "  var key = Buffer.alloc(0);",
  "  var block = null;",
  "  while (key.length < 32) {",
  "    var h = crypto.createHash('md5');",
  "    if (block) h.update(block);",
  "    h.update(token, 'utf8');",
  "    h.update(salt);",
  "    block = h.digest();",
  "    key = Buffer.concat([key, block]);",
  "  }",
  "  key = key.slice(0, 32);",
  "  var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);",
  "  var dec = Buffer.concat([decipher.update(ct), decipher.finalize()]);",
  "  var q = 34;",
  "  var end = dec.lastIndexOf(q);",
  "  if (end < 1) throw new Error('decode: no trailing quote');",
  "  var txt = dec.slice(1, end).toString('utf8');",
  "  txt = txt.split(String.fromCharCode(92,34)).join(String.fromCharCode(34));",
  "  txt = txt.split(String.fromCharCode(92,92,34)).join(String.fromCharCode(39));",
  "  return JSON.parse(txt);",
  "}",
  "function activeList(dec) {",
  "  if (!dec || typeof dec !== 'object') return [];",
  "  var w = dec.incidents;",
  "  if (!w) return [];",
  "  var act = w.active;",
  "  if (Array.isArray(act)) return act;",
  "  if (act && typeof act === 'object') return Object.keys(act).map(function(k){ return act[k]; });",
  "  return [];",
  "}",
  "function getJson(u, cb) {",
  "  var p = urlMod.parse(u);",
  "  var opts = { hostname: p.hostname, port: p.port || 443, path: p.path, method: 'GET', headers: hdr };",
  "  var req = https.request(opts, function(res) {",
  "    var buf = '';",
  "    res.setEncoding('utf8');",
  "    res.on('data', function(c){ buf += c; });",
  "    res.on('end', function(){",
  "      try { cb(null, res.statusCode, JSON.parse(buf)); }",
  "      catch(e) { cb(e, res.statusCode, null); }",
  "    });",
  "  });",
  "  req.on('error', function(e){ cb(e); });",
  "  req.setTimeout(25000, function(){ try { req.destroy(); } catch(_e){} cb(new Error('timeout')); });",
  "  req.end();",
  "}",
  "var pending = rawIds.length;",
  "var all = [];",
  "var errs = [];",
  "rawIds.forEach(function(aid) {",
  "  var u = base + '?resource=incidents&agencyid=' + encodeURIComponent(aid);",
  "  getJson(u, function(err, code, j) {",
  "    if (err) errs.push(aid + ':' + err.message);",
  "    else if (code !== 200) errs.push(aid + ':HTTP' + code);",
  "    else try {",
  "      var dec = (j && j.ct) ? decodePulse(j) : j;",
  "      activeList(dec).forEach(function(inc) { if (inc && inc.ID) all.push(inc); });",
  "    } catch(e2) { errs.push(aid + ':' + e2.message); }",
  "    pending--;",
  "    if (pending > 0) return;",
  "    if (errs.length) node.warn('PulsePoint fetch: ' + errs.join(' | '));",
  "    var sk = {}; var dedup = [];",
  "    all.forEach(function(inc) {",
  "      var u = 'PP-' + String(inc.AgencyID||'x') + '-' + String(inc.ID);",
  "      if (sk[u]) return;",
  "      sk[u] = true;",
  "      dedup.push(inc);",
  "    });",
  "    msg._ppIncidents = dedup;",
  "    node.send(msg);",
  "  });",
  "});",
  "return;"
].join('\n');

const FN_PP_BUILD_COT_V2 = [
  "var cfg = msg._ppCfg || {};",
  "if (!cfg.activated) return null;",
  "var incidents = msg._ppIncidents || [];",
  "var tak = global.get('tak_settings') || {};",
  "var host = String(tak.serverUrl || '').replace(/^https?:\\/\\//i, '').replace(/\\/$/, '').trim() || tak.takHost || 'host.docker.internal';",
  "var baseP = Number(tak.streamingPort || tak.streamPort || 8089);",
  "var port = Number(cfg.cotStreamPort) || baseP;",
  "var icon = cfg.uniformIcon || {};",
  "var cotType = String(icon.cotType || 'a-u-G').trim() || 'a-u-G';",
  "var iconpath = String(icon.iconsetpath || '').trim();",
  "if (!iconpath) iconpath = 'f7f71666-8b28-4b57-9fbb-e38e61d33b79/Google/caution.png';",
  "var staleSec = Math.max(30, Number(cfg.cotStaleSec) || 600);",
  "var _prevKey = 'pp_prev_uids___FEED_ID__';",
  "var prev = global.get(_prevKey) || {};",
  "var curr = {};",
  "var nowIso = new Date().toISOString();",
  "incidents.forEach(function(inc) {",
  "  var lat = parseFloat(inc.Latitude);",
  "  var lon = parseFloat(inc.Longitude);",
  "  if (isNaN(lat) || isNaN(lon)) return;",
  "  if (String(inc.Latitude) === '0.0000000000' && String(inc.Longitude) === '0.0000000000') return;",
  "  var uid = 'PP-' + String(inc.AgencyID || 'x') + '-' + String(inc.ID);",
  "  curr[uid] = true;",
  "});",
  "var stalePast = new Date(Date.now() - 5000).toISOString();",
  "Object.keys(prev).forEach(function(uid) {",
  "  if (curr[uid]) return;",
  "  node.send({",
  "    payload: {",
  "      event: {",
  "        _attributes: { version:'2.0', uid:uid, type:cotType, how:'m-g', time: nowIso, start: nowIso, stale: stalePast },",
  "        point: { _attributes:{ lat:'0', lon:'0', hae:'9999999.0', ce:'9999999', le:'9999999.0' } },",
  "        detail: { status: [{ _attributes:{ readiness:'false' } }] }",
  "      }",
  "    },",
  "    host: host, port: port",
  "  });",
  "});",
  "var sent = 0;",
  "incidents.forEach(function(inc) {",
  "  var lat = parseFloat(inc.Latitude);",
  "  var lon = parseFloat(inc.Longitude);",
  "  if (isNaN(lat) || isNaN(lon)) return;",
  "  if (String(inc.Latitude) === '0.0000000000' && String(inc.Longitude) === '0.0000000000') return;",
  "  var uid = 'PP-' + String(inc.AgencyID || 'x') + '-' + String(inc.ID);",
  "  var startStr = inc.CallReceivedDateTime || nowIso;",
  "  var st = new Date(startStr);",
  "  if (isNaN(st.getTime())) st = new Date();",
  "  var stl = new Date(st.getTime() + staleSec * 1000);",
  "  var ct = inc.PulsePointIncidentCallType || '';",
  "  var addr = (inc.FullDisplayAddress || '').trim();",
  "  var cs = (addr || ct || 'PulsePoint').substring(0, 100);",
  "  var remarks = 'PulsePoint | ' + ct + ' | ' + addr;",
  "  var detail = {",
  "    contact: [{ _attributes:{ callsign: cs } }],",
  "    remarks: remarks,",
  "    status: [{ _attributes:{ readiness:'true' } }]",
  "  };",
  "  if (iconpath) detail.usericon = [{ _attributes:{ iconsetpath: iconpath } }];",
  "  node.send({",
  "    payload: {",
  "      event: {",
  "        _attributes: {",
  "          version:'2.0', uid: uid, type: cotType, how:'m-g',",
  "          time: st.toISOString(), start: st.toISOString(), stale: stl.toISOString()",
  "        },",
  "        point: { _attributes:{ lat:String(lat), lon:String(lon), hae:'9999999.0', ce:'50', le:'9999999.0' } },",
  "        detail: detail",
  "      }",
  "    },",
  "    host: host, port: port",
  "  });",
  "  sent++;",
  "});",
  "global.set(_prevKey, curr);",
  "global.set('pp_last_fetch___FEED_ID__', Date.now());",
  "var dropped = 0;",
  "Object.keys(prev).forEach(function(u){ if (!curr[u]) dropped++; });",
  "node.warn('PulsePoint: ' + sent + ' CoT streamed (TCP), ' + dropped + ' cleared');",
  "return null;"
].join('\n');

// ── PP config CRUD (array-based, like TC) ────────────────────────────────────
const FN_PP_SAVE = [
  ARRAY_GUARD,
  "var cfg = msg.payload || {};",
  "if (!cfg.id) { msg.payload = { ok:false, error:'missing id' }; return msg; }",
  "var configs = _coerceArr(global.get('pp_configs'));",
  "var idx = configs.findIndex(function(c){ return c.id === cfg.id; });",
  "if (idx >= 0) { configs[idx] = cfg; } else { configs.push(cfg); }",
  "global.set('pp_configs', configs);",
  CFG_BACKUP_SNIPPET,
  "msg.payload = { ok: true, configCount: configs.length };",
  "return msg;"
].join('\n');

const FN_PP_LOAD = [
  ARRAY_GUARD,
  "var configs = _coerceArr(global.get('pp_configs'));",
  "msg.payload = { configs: configs };",
  "return msg;"
].join('\n');

const FN_PP_DELETE = [
  ARRAY_GUARD,
  "var id = (msg.payload || {}).id;",
  "if (!id) { msg.payload = { ok:false, error:'missing id' }; return msg; }",
  "var configs = _coerceArr(global.get('pp_configs')).filter(function(c){ return c.id !== id; });",
  "global.set('pp_configs', configs);",
  CFG_BACKUP_SNIPPET,
  "msg.payload = { ok: true, configCount: configs.length };",
  "return msg;"
].join('\n');

function makePulsepointTab() {
  const Z = PULSEPOINT_TAB_ID;
  return [
    {
      id: Z, type: 'tab',
      label: 'PulsePoint Config API',
      disabled: false,
      info: 'CRUD endpoints for multi-agency PulsePoint configs (pp_configs[]). Per-agency engine tabs created dynamically via Configurator.'
    },
    // ── Save ──────────────────────────────────────────────────────
    {
      id: Z + '_hi_save', type: 'http in', z: Z,
      name: 'POST /pp/config/save', url: '/pp/config/save', method: 'post',
      upload: false, swaggerDoc: '', x: 180, y: 80, wires: [[Z + '_fn_save']]
    },
    {
      id: Z + '_fn_save', type: 'function', z: Z,
      name: 'Save PP config', func: FN_PP_SAVE,
      outputs: 1, timeout: '', noerr: 0, initialize: '', finalize: '', libs: [],
      x: 420, y: 80, wires: [[Z + '_ho_save']]
    },
    {
      id: Z + '_ho_save', type: 'http response', z: Z,
      name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
      x: 640, y: 80, wires: []
    },
    // ── Load ──────────────────────────────────────────────────────
    {
      id: Z + '_hi_load', type: 'http in', z: Z,
      name: 'GET /pp/config/load', url: '/pp/config/load', method: 'get',
      upload: false, swaggerDoc: '', x: 180, y: 140, wires: [[Z + '_fn_load']]
    },
    {
      id: Z + '_fn_load', type: 'function', z: Z,
      name: 'Load PP configs', func: FN_PP_LOAD,
      outputs: 1, timeout: '', noerr: 0, initialize: '', finalize: '', libs: [],
      x: 420, y: 140, wires: [[Z + '_ho_load']]
    },
    {
      id: Z + '_ho_load', type: 'http response', z: Z,
      name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
      x: 640, y: 140, wires: []
    },
    // ── Delete ────────────────────────────────────────────────────
    {
      id: Z + '_hi_del', type: 'http in', z: Z,
      name: 'POST /pp/config/delete', url: '/pp/config/delete', method: 'post',
      upload: false, swaggerDoc: '', x: 180, y: 200, wires: [[Z + '_fn_del']]
    },
    {
      id: Z + '_fn_del', type: 'function', z: Z,
      name: 'Delete PP config', func: FN_PP_DELETE,
      outputs: 1, timeout: '', noerr: 0, initialize: '', finalize: '', libs: [],
      x: 420, y: 200, wires: [[Z + '_ho_del']]
    },
    {
      id: Z + '_ho_del', type: 'http response', z: Z,
      name: '', statusCode: '200', headers: { 'content-type': 'application/json' },
      x: 640, y: 200, wires: []
    }
  ];
}

// ── PP engine tab template (one per agency, created by configurator UI) ───────
function makePPEngineTab(feed) {
  const Z = 'flow_pp_' + feed.id;
  const cn = feed.configName;
  const poll = FN_PP_POLL_V2
    .replace(/__CONFIG_NAME__/g, cn)
    .replace(/__FEED_ID__/g, feed.id);
  const fetch = FN_PP_FETCH_V2.replace(/__FEED_ID__/g, feed.id);
  const build = FN_PP_BUILD_COT_V2.replace(/__FEED_ID__/g, feed.id);
  return [
    { id: Z, type: 'tab', label: 'PP: ' + cn, disabled: false, info: '' },
    {
      id: Z + '_timer', type: 'inject', z: Z,
      name: 'Every 60 s', props: [{ p: 'payload' }],
      repeat: '60', crontab: '', once: true, onceDelay: '3',
      topic: '', payload: '', payloadType: 'date',
      x: 160, y: 80, wires: [[Z + '_poll']]
    },
    {
      id: Z + '_poll', type: 'function', z: Z,
      name: 'Poll check', func: poll,
      _templateKey: 'pp.poll.' + feed.id,
      outputs: 1, timeout: '', noerr: 0, initialize: '', finalize: '', libs: [],
      x: 380, y: 80, wires: [[Z + '_fetch']]
    },
    {
      id: Z + '_fetch', type: 'function', z: Z,
      name: 'Fetch + decode', func: fetch,
      _templateKey: 'pp.fetch.' + feed.id,
      outputs: 1, timeout: '', noerr: 0, initialize: '', finalize: '', libs: [],
      x: 600, y: 80, wires: [[Z + '_build']]
    },
    {
      id: Z + '_build', type: 'function', z: Z,
      name: 'Build CoT', func: build,
      _templateKey: 'pp.build.' + feed.id,
      outputs: 1, timeout: '', noerr: 0, initialize: '', finalize: '', libs: [],
      x: 820, y: 80, wires: [[Z + '_xml']]
    },
    {
      id: Z + '_xml', type: 'function', z: Z,
      name: 'CoT → XML', func: FN_COT_TO_XML,
      _templateKey: 'shared.cot_to_xml',
      outputs: 1, timeout: '', noerr: 0, initialize: '', finalize: '', libs: [],
      x: 1040, y: 80, wires: [[Z + '_tcp']]
    },
    {
      id: Z + '_tcp', type: 'tcp out', z: Z,
      name: 'CoT → TAK', host: 'host.docker.internal',
      port: String(feed.cotStreamPort || 8089),
      beserver: 'client', base64: false, doend: false, addCR: false, tls: 'tls_tak',
      x: 1260, y: 80, wires: []
    }
  ];
}

// ════════════════════════════════════════════════════════════════
//  Engine tab templates (embedded in configurator.html for dynamic creation)
// ════════════════════════════════════════════════════════════════

const templateFeed = { id: '__FEED_ID__', configName: '__CONFIG_NAME__' };
const templateNodes = makeEngineTab(templateFeed);
const engineTabTemplate = JSON.stringify(templateNodes);

const tfrTemplateNodes = makeTfrEngineTab(templateFeed);
const tfrEngineTabTemplate = JSON.stringify(tfrTemplateNodes);

const kmlTemplateNodes = makeKmlEngineTab(templateFeed);
const kmlEngineTabTemplate = JSON.stringify(kmlTemplateNodes);

const tcTemplateNodes = makeTCEngineTab(templateFeed);
const tcEngineTabTemplate = JSON.stringify(tcTemplateNodes);

const ppTemplateNodes = makePPEngineTab({ id: '__FEED_ID__', configName: '__CONFIG_NAME__', cotStreamPort: 8089 });
const ppEngineTabTemplate = JSON.stringify(ppTemplateNodes);

// ════════════════════════════════════════════════════════════════
//  Assembly
// ════════════════════════════════════════════════════════════════

const allFlows = [
  ...configFlows,
  ...tlsNodes,
  ...FEEDS.flatMap(f => makeEngineTab(f)),
  ...makeIpawsTab(),
  ...makePulsepointTab()
];

const out = path.join(__dirname, 'flows.json');
fs.writeFileSync(out, JSON.stringify(allFlows, null, 2));
console.log('flows.json generated  (' + allFlows.length + ' nodes, ' + FEEDS.length + ' engine tabs)  →  ' + out);

// Write template function map (ArcGIS + TFR + KML + TC) for deploy.sh dynamic-tab sync
// Format: { key: { func, libs } } — deploy.sh syncs both func and libs
const templateFuncMap = {};
[...templateNodes, ...tfrTemplateNodes, ...kmlTemplateNodes, ...tcTemplateNodes, ...ppTemplateNodes].forEach(n => {
  if (n._templateKey) templateFuncMap[n._templateKey] = { func: n.func, libs: n.libs || [] };
});
fs.writeFileSync(path.join(__dirname, 'template-functions.json'), JSON.stringify(templateFuncMap));
console.log('template-functions.json: ' + Object.keys(templateFuncMap).length + ' keys');

// Inject engine tab templates into configurator.html (skip if read-only, e.g. inside Docker)
try {
  const htmlPath = path.join(__dirname, 'configurator.html');
  let htmlContent = fs.readFileSync(htmlPath, 'utf8');

  // ArcGIS template
  const startMarker = '/* __ENGINE_TAB_TEMPLATE_START__ */';
  const endMarker   = '/* __ENGINE_TAB_TEMPLATE_END__ */';
  const b64 = Buffer.from(engineTabTemplate, 'utf8').toString('base64');
  const templateBlock = startMarker + '\n'
    + 'var ENGINE_TAB_TEMPLATE = decodeURIComponent(escape(atob("' + b64 + '")));\n'
    + endMarker;
  if (htmlContent.includes(startMarker)) {
    const re = new RegExp(
      startMarker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      + '[\\s\\S]*?'
      + endMarker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    );
    htmlContent = htmlContent.replace(re, templateBlock);
  } else {
    htmlContent = htmlContent.replace(
      '</script>\n</body>',
      '\n' + templateBlock + '\n</script>\n</body>'
    );
  }

  // TFR template
  const tfrStart = '/* __TFR_ENGINE_TAB_TEMPLATE_START__ */';
  const tfrEnd   = '/* __TFR_ENGINE_TAB_TEMPLATE_END__ */';
  const tfrB64 = Buffer.from(tfrEngineTabTemplate, 'utf8').toString('base64');
  const tfrBlock = tfrStart + '\n'
    + 'var TFR_ENGINE_TAB_TEMPLATE = decodeURIComponent(escape(atob("' + tfrB64 + '")));\n'
    + tfrEnd;
  if (htmlContent.includes(tfrStart)) {
    const re2 = new RegExp(
      tfrStart.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      + '[\\s\\S]*?'
      + tfrEnd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    );
    htmlContent = htmlContent.replace(re2, tfrBlock);
  } else {
    htmlContent = htmlContent.replace(
      endMarker,
      endMarker + '\n' + tfrBlock
    );
  }

  // KML template
  const kmlStart = '/* __KML_ENGINE_TAB_TEMPLATE_START__ */';
  const kmlEnd   = '/* __KML_ENGINE_TAB_TEMPLATE_END__ */';
  const kmlB64 = Buffer.from(kmlEngineTabTemplate, 'utf8').toString('base64');
  const kmlBlock = kmlStart + '\n'
    + 'var KML_ENGINE_TAB_TEMPLATE = decodeURIComponent(escape(atob("' + kmlB64 + '")));\n'
    + kmlEnd;
  if (htmlContent.includes(kmlStart)) {
    const re3 = new RegExp(
      kmlStart.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      + '[\\s\\S]*?'
      + kmlEnd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    );
    htmlContent = htmlContent.replace(re3, kmlBlock);
  } else {
    htmlContent = htmlContent.replace(
      tfrEnd,
      tfrEnd + '\n' + kmlBlock
    );
  }

  // TC template
  const tcStart = '/* __TC_ENGINE_TAB_TEMPLATE_START__ */';
  const tcEnd   = '/* __TC_ENGINE_TAB_TEMPLATE_END__ */';
  const tcB64 = Buffer.from(tcEngineTabTemplate, 'utf8').toString('base64');
  const tcBlock = tcStart + '\n'
    + 'var TC_ENGINE_TAB_TEMPLATE = decodeURIComponent(escape(atob("' + tcB64 + '")));\n'
    + tcEnd;
  if (htmlContent.includes(tcStart)) {
    const re4 = new RegExp(
      tcStart.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      + '[\\s\\S]*?'
      + tcEnd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    );
    htmlContent = htmlContent.replace(re4, tcBlock);
  } else {
    htmlContent = htmlContent.replace(
      kmlEnd,
      kmlEnd + '\n' + tcBlock
    );
  }

  // PP template
  const ppStart = '/* __PP_ENGINE_TAB_TEMPLATE_START__ */';
  const ppEnd   = '/* __PP_ENGINE_TAB_TEMPLATE_END__ */';
  const ppB64 = Buffer.from(ppEngineTabTemplate, 'utf8').toString('base64');
  const ppBlock = ppStart + '\n'
    + 'var PP_ENGINE_TAB_TEMPLATE = decodeURIComponent(escape(atob("' + ppB64 + '")));\n'
    + ppEnd;
  if (htmlContent.includes(ppStart)) {
    const re5 = new RegExp(
      ppStart.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      + '[\\s\\S]*?'
      + ppEnd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    );
    htmlContent = htmlContent.replace(re5, ppBlock);
  } else {
    htmlContent = htmlContent.replace(tcEnd, tcEnd + '\n' + ppBlock);
  }

  fs.writeFileSync(htmlPath, htmlContent);
  console.log('Engine tab templates injected into configurator.html (ArcGIS + TFR + KML + TC + PP)');
} catch(e) {
  console.log('Skipped configurator.html template injection (' + e.code + ')');
}
