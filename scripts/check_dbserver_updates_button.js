// SPDX-License-Identifier: AGPL-3.0-or-later
// infra-TAK — TAK Infrastructure Platform
// Copyright (C) 2026 Andreas Johansson (TAKWERX)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
/*
 * Drives the database server card's "Reboot / updates..." button (ops #535).
 *
 * Field (Fri Nov 6, 2026): on a split install the card's update button opened
 * "Upgrade the database server to Ubuntu 24.04 LTS", a one-way job, instead of
 * a routine update. A grep for the new function name would still pass if the
 * button were wired back to the upgrade dialog, so this reads the button off
 * the page and runs the real modal functions against a hand-rolled DOM and a
 * canned preflight answer.
 *
 *   node scripts/check_dbserver_updates_button.js
 */

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(ROOT, "templates", "console.html"), "utf8");

const scripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
  .map((m) => m[1])
  .join("\n")
  .replace(/\{%[\s\S]*?%\}/g, "")
  .replace(/\{\{[\s\S]*?\}\}/g, "null");

let fails = 0;
function check(name, ok, detail) {
  if (ok) console.log("  ok   " + name);
  else {
    fails += 1;
    console.log("  FAIL " + name + (detail ? "  |  " + detail : ""));
  }
}

// Cut one named top-level function out of the page script (they all end at "\n}\n").
function fn(name) {
  const m = new RegExp("\\n(async )?function " + name + "\\(").exec(scripts);
  if (!m) return "";
  const end = scripts.indexOf("\n}\n", m.index);
  return scripts.slice(m.index, end + 3);
}

// 1. The buttons on the card.
const cardBtn = (id) => (html.match(new RegExp('<button[^>]*id="' + id + '"[^>]*onclick="([^"]*)"')) || [])[1];
const updClick = cardBtn("dbs-card-updates-btn"), rbClick = cardBtn("dbs-card-reboot-btn");
check("the database server card has an Updates button", !!updClick);
check("the Updates needed button installs the updates (after a confirm), it does not just open a dialog", /dbsCardInstallUpdates\(\)/.test(updClick || "") && !/dbsOpenUpdates/.test(updClick || ""), updClick);
check("the card has its own Reboot button that is always there (not tied to a pending reboot)", !!rbClick &&
  !/\{%[^%]*reboot_required[^%]*%\}[^<]*<button[^>]*id="dbs-card-reboot-btn"/.test(html), rbClick);
check("the Reboot button opens the reboot view", /dbsOpenReboot\(\)/.test(rbClick || ""), rbClick);
check("no card button calls the upgrade dialog", !/osupOpenPreflight/.test((updClick || "") + (rbClick || "")));
check("the card says in plain words when no restart is needed", /id="uu-noreboot-\{\{ host\.id \}\}"[^>]*>&#10003; No restart needed/.test(html));
check("the card has an updates status line, hidden until there is something to say", /id="dbs-card-updates-line" style="display:none/.test(html));
check("the card Updates button starts hidden (shown only when updates are waiting)", /id="dbs-card-updates-btn"[^>]*style="display:none/.test(html));
check("the card Reboot button is never hidden", !/id="dbs-card-reboot-btn"[^>]*style="display:none/.test(html));

// 2. The modal, driven.
const NAMES = [
  "_osupApi", "_osupEsc", "_osupApplyMode", "osupOpenPreflight", "dbsOpenUpdates", "osupLoadPreflight",
  "_osupSetStartEnabled", "_dbsRenderUpdatesView", "_osupRenderPreflight", "_dbsRenderActions", "dbsOpenReboot",
];
const labels = (scripts.match(/var _OSUP_LABELS=\{[^\n]*\};/) || [""])[0];
const acks = (scripts.match(/var _OSUP_ACK=\{[^\n]*\};/) || [""])[0];
const source = [labels, acks, ...NAMES.map(fn)].join("\n");
check("every modal function is on the page", NAMES.every((n) => fn(n)), NAMES.filter((n) => !fn(n)).join(","));

function makeDom() {
  const els = {};
  const get = (id) => els[id] || (els[id] = { id, appendChild() {}, style: {}, textContent: "", innerHTML: "", value: "", checked: true, disabled: false, placeholder: "" });
  return { get, els };
}

async function open(openFn, preflight) {
  const dom = makeDom();
  const sandbox = {
    document: { getElementById: dom.get, createElement: () => ({ textContent: "" }) },
    fetch: async () => ({ ok: true, status: 200, json: async () => preflight }),
    _dbsTargetHost: "10.0.0.9", _rhHost: "", _rhKey: "", _osupTarget: "core",
    console,
  };
  vm.createContext(sandbox);
  vm.runInContext(source + "\n_osupUpdatesOnly=false;_dbsRebootMode=false;", sandbox);
  vm.runInContext(openFn, sandbox);
  await new Promise((r) => setTimeout(r, 0));
  return dom.els;
}

const ck = (name, pass, detail) => ({ name, pass, detail: detail || "", notice: false });
function pf(over) {
  return Object.assign({
    ok: false, pending_count: 95, reboot_required: true, os_version: "22.04",
    checks: [
      ck("split_config", true), ck("ssh_sudo", true), ck("os_type", true, "Ubuntu 22.04.3 LTS"),
      ck("release_upgrader", true, "ubuntu-release-upgrader-core 1:22.04.17"),
      ck("os_up_to_date", false, "95 update(s) pending ... Ubuntu's upgrader refuses until every update is installed"),
      ck("no_reboot_pending", false, "a reboot is pending after updating libc6"),
    ],
    irreversible: ["The database server goes from Ubuntu 22.04 to Ubuntu 24.04."],
  }, over || {});
}
const shown = (e) => e && e.style.display && e.style.display !== "none";

(async () => {
  // A. Field case: updates due and a reboot pending (test8's database server).
  let e = await open("dbsOpenUpdates()", pf());
  check("updates view: title is about updates, not the 24.04 upgrade",
    /Database server updates/.test(e["osup-modal-title"].innerHTML) && !/24\.04/.test(e["osup-modal-title"].innerHTML),
    e["osup-modal-title"].innerHTML);
  check("updates view: no Start upgrade button", e["osup-start-btn"].style.display === "none");
  check("updates view: no snapshot acknowledgment or password block", e["osup-ack-block"].style.display === "none");
  check("updates view: no 'cannot be undone' list", e["osup-irr-head"].style.display === "none" && e["osup-irreversible"].style.display === "none");
  check("updates view: Install updates is offered", shown(e["dbs-updates-btn"]) && e["dbs-updates-btn"].style.display !== "none");
  check("updates view: the pending count is shown", /95 pending/.test(e["osup-checks"].innerHTML), e["osup-checks"].innerHTML);
  check("updates view: no release-upgrader check row", !/release upgrader/i.test(e["osup-checks"].innerHTML));
  check("updates view: says it does not upgrade Ubuntu", /does not upgrade Ubuntu/.test(e["osup-modal-intro"].textContent), e["osup-modal-intro"].textContent);
  check("updates view: the upgrade stays reachable as its own named button", shown(e["osup-upgrade-link-btn"]) && /Upgrade to Ubuntu 24\.04/.test(html.match(/id="osup-upgrade-link-btn"[^>]*>([^<]*)</)[1]));

  // B. Reboot only: updates are done, kernel not running.
  e = await open("dbsOpenUpdates()", pf({ pending_count: 0, checks: pf().checks.map((c) => (c.name === "os_up_to_date" ? ck("os_up_to_date", true) : c)) }));
  check("reboot only: Reboot is offered, Install updates is not", shown(e["dbs-reboot-btn"]) && !shown(e["dbs-updates-btn"]));
  check("reboot only: message is about finishing updates, not Ubuntu's upgrader",
    /finish its updates/.test(e["dbs-actions-msg"].textContent) && !/upgrader/.test(e["dbs-actions-msg"].textContent), e["dbs-actions-msg"].textContent);

  // C. Nothing pending: says so, and Reboot is still there (AJ, Sat Nov 7: "a way to reboot anytime I want").
  e = await open("dbsOpenUpdates()", pf({
    pending_count: 0, reboot_required: false,
    checks: [ck("split_config", true), ck("ssh_sudo", true), ck("os_up_to_date", true), ck("no_reboot_pending", true)],
  }));
  check("nothing pending: says so", /Nothing to do/.test(e["osup-modal-intro"].textContent), e["osup-modal-intro"].textContent);
  check("nothing pending: Reboot is still offered, Install updates is not", shown(e["dbs-reboot-btn"]) && !shown(e["dbs-updates-btn"]) && shown(e["dbs-actions"]));
  check("nothing pending: the message says no reboot is needed but you may reboot",
    /No reboot is needed, but you can reboot/.test(e["dbs-actions-msg"].textContent), e["dbs-actions-msg"].textContent);

  // C2. Updates due, no reboot pending: both buttons.
  e = await open("dbsOpenUpdates()", pf({ reboot_required: false, checks: pf().checks.map((c) => (c.name === "no_reboot_pending" ? ck("no_reboot_pending", true) : c)) }));
  check("updates due, no reboot pending: Install updates and Reboot are both offered", shown(e["dbs-updates-btn"]) && shown(e["dbs-reboot-btn"]));

  // C3. The card's Reboot button: a reboot window, no updates button, Reboot even with nothing pending.
  e = await open("dbsOpenReboot()", pf({
    pending_count: 0, reboot_required: false,
    checks: [ck("split_config", true), ck("ssh_sudo", true), ck("os_up_to_date", true), ck("no_reboot_pending", true)],
  }));
  check("reboot view: title says Reboot the database server, not the 24.04 upgrade",
    /Reboot the database server/.test(e["osup-modal-title"].innerHTML) && !/24\.04/.test(e["osup-modal-title"].innerHTML), e["osup-modal-title"].innerHTML);
  check("reboot view: Reboot is offered and Install updates is not", shown(e["dbs-reboot-btn"]) && !shown(e["dbs-updates-btn"]));
  check("reboot view: no Start upgrade button", e["osup-start-btn"].style.display === "none");
  check("reboot view: intro says it reboots and TAK Server stays up", /Reboots the database server now/.test(e["osup-modal-intro"].textContent) && /TAK Server stays up/.test(e["osup-modal-intro"].textContent), e["osup-modal-intro"].textContent);
  e = await open("dbsOpenReboot()", pf());
  check("reboot view with updates pending: still only Reboot, never Install updates", shown(e["dbs-reboot-btn"]) && !shown(e["dbs-updates-btn"]));
  e = await open("dbsOpenReboot()", pf({ pending_count: null, checks: [ck("split_config", true), ck("ssh_sudo", false, "cannot reach the database server over SSH: timeout")] }));
  check("reboot view, server unreachable: no Reboot button", !shown(e["dbs-reboot-btn"]) && e["dbs-actions"].style.display === "none");

  // D. Server unreachable: the reason, no action buttons.
  e = await open("dbsOpenUpdates()", pf({ pending_count: null, checks: [ck("split_config", true), ck("ssh_sudo", false, "cannot reach the database server over SSH: timeout")] }));
  check("unreachable: the reason is shown and no action is offered",
    /cannot reach the database server/.test(e["osup-checks"].innerHTML) && e["dbs-actions"].style.display === "none");

  // E. The named upgrade action still opens the real upgrade dialog.
  e = await open("dbsOpenUpdates(); osupOpenPreflight('dbserver')", pf({ ok: true, pending_count: 0, reboot_required: false,
    checks: [ck("split_config", true), ck("ssh_sudo", true), ck("os_up_to_date", true), ck("no_reboot_pending", true)] }));
  check("upgrade action: title names the 24.04 upgrade", /to Ubuntu 24\.04 LTS/.test(e["osup-modal-title"].innerHTML), e["osup-modal-title"].innerHTML);
  check("upgrade action: Start upgrade and the 'cannot be undone' list are back",
    e["osup-start-btn"].style.display === "" && e["osup-irr-head"].style.display === "block" && e["osup-irreversible"].style.display === "block");
  check("upgrade action: the acknowledgment block is back", e["osup-ack-block"].style.display === "block", JSON.stringify(e["osup-ack-block"]) + " err=" + e["osup-modal-err"].textContent);
  check("upgrade action: the updates-view button is hidden", e["osup-upgrade-link-btn"].style.display === "none");

  // F. After "Install updates" the result banner must lead to the reboot (Sat Nov 7, 2026: it only offered
  //    Check & upgrade, which opens the Ubuntu upgrade dialog, so there was no way to reboot).
  // what the server says right after Install updates: nothing pending, reboot still needed
  const afterInstall = pf({ pending_count: 0, checks: pf().checks.map((c) => (c.name === "os_up_to_date" ? ck("os_up_to_date", true) : c)) });
  async function banner(d) {
    const dom = makeDom();
    const sb = {
      document: { getElementById: dom.get, createElement: () => ({ textContent: "" }) },
      fetch: async () => ({ ok: true, status: 200, json: async () => afterInstall }),
      _dbsTargetHost: "10.0.0.9", _rhHost: "", _rhKey: "", _osupTarget: "core",
      dbsDismiss: async () => {}, console,
    };
    vm.createContext(sb);
    const more = ["_dbsRenderResult", "_dbsHostLabel"].map(fn).join("\n");
    vm.runInContext(source + "\n" + more + "\nvar _DBS_TITLE={};_osupUpdatesOnly=false;_dbsRebootMode=false;", sb);
    vm.runInContext("_dbsRenderResult(" + JSON.stringify(d) + ")", sb);
    const nx = dom.els["dbs-result-next"];
    // the button's own handler: whatever the render set, else the inline one written in the page
    const inline = (html.match(/id="dbs-result-next" onclick="([^"]*)"/) || [, ""])[1];
    if (typeof nx.onclick === "function") await nx.onclick();
    else await vm.runInContext("(function(){" + inline + "})()", sb);
    await new Promise((r) => setTimeout(r, 0));
    return { els: dom.els, nx };
  }
  let b = await banner({ state: "done", job: "updates", reboot_required: true });
  check("updates done, reboot pending: the banner button says Reboot", /^Reboot/.test(b.nx.innerHTML) && shown(b.nx), b.nx.innerHTML);
  check("updates done, reboot pending: the banner text points to Reboot, not Check & upgrade",
    /press Reboot/.test(b.els["dbs-result-body"].textContent) && !/Check & upgrade/.test(b.els["dbs-result-body"].textContent), b.els["dbs-result-body"].textContent);
  check("updates done, reboot pending: the button opens the updates view where Reboot is offered",
    /Database server updates/.test(b.els["osup-modal-title"].innerHTML) && shown(b.els["dbs-reboot-btn"]),
    b.els["osup-modal-title"].innerHTML + " | reboot btn display=" + b.els["dbs-reboot-btn"].style.display);
  b = await banner({ state: "done", job: "updates", reboot_required: false, detail: "" });
  check("updates done, no reboot: the banner button is Check & upgrade and opens the upgrade dialog",
    /Check &amp; upgrade/.test(b.nx.innerHTML) && /to Ubuntu 24\.04 LTS/.test(b.els["osup-modal-title"].innerHTML), b.nx.innerHTML + " | " + b.els["osup-modal-title"].innerHTML);
  b = await banner({ state: "done", job: "reboot" });
  check("rebooted: the banner button is Check & upgrade", /Check &amp; upgrade/.test(b.nx.innerHTML), b.nx.innerHTML);

  // G. The card's updates line (AJ, Sat Nov 7: "the card should clearly say if an update is needed").
  async function cardLine(answer) {
    const dom = makeDom();
    const store = {};
    const sb = {
      document: { getElementById: dom.get },
      fetch: async () => ({ ok: true, json: async () => answer }),
      sessionStorage: { getItem: (k) => store[k] || null, setItem: (k, v) => { store[k] = v; } },
      Date, JSON, console,
    };
    vm.createContext(sb);
    vm.runInContext(["dbsCardCheck", "_dbsCardUpdatesText"].map(fn).join("\n"), sb);
    await vm.runInContext("dbsCardCheck(true)", sb);
    const line = dom.els["dbs-card-updates-line"];
    line.updBtn = dom.els["dbs-card-updates-btn"];
    return line;
  }
  const hidden = (e) => e.style.display === "none";
  let l = await cardLine(pf({ pending_count: 95 }));
  check("card: 95 pending shows an 'Updates needed' button with the count", /Updates needed \(95\)/.test(l.updBtn.innerHTML) && l.updBtn.style.display === "inline-block", l.updBtn.innerHTML);
  l = await cardLine(pf({ pending_count: 1 }));
  check("card: one pending still says Updates needed", /Updates needed \(1\)/.test(l.updBtn.innerHTML), l.updBtn.innerHTML);
  l = await cardLine(pf({ pending_count: 0 }));
  check("card: nothing pending shows no updates line and no Updates button",
    hidden(l) && hidden(l.updBtn) && l.textContent === "", "line=" + l.style.display + " btn=" + l.updBtn.style.display);
  l = await cardLine(pf({ pending_count: null, checks: [ck("split_config", true), ck("ssh_sudo", false, "cannot reach the database server over SSH: timeout")] }));
  check("card: unreachable says it could not check, never 'all installed', and offers no install button",
    /could not check/.test(l.textContent) && !/all installed/.test(l.textContent) && !hidden(l) && hidden(l.updBtn), l.textContent + " btn=" + l.updBtn.style.display);

  // H. Clicking Updates needed goes straight to the confirm and the install job (AJ, Sat Nov 7: "you click on that, it updates").
  async function clickCard(confirmAnswer, postAnswer) {
    const dom = makeDom();
    const calls = { confirm: 0, posts: [], started: 0, closed: 0, alerts: [] };
    const sb = {
      document: { getElementById: dom.get },
      fetch: async (url) => { calls.posts.push(url); return { ok: postAnswer.ok, status: postAnswer.ok ? 200 : 500, json: async () => postAnswer.body }; },
      confirm: () => { calls.confirm += 1; return confirmAnswer; },
      alert: (m) => calls.alerts.push(m),
      _dbsTargetHost: "10.0.0.9", _rhHost: "", _osupTarget: "core", _dbsBusy: false,
      osupCloseModal: () => { calls.closed += 1; }, _dbsJobStarted: () => { calls.started += 1; },
      _osupApi: (p) => "/api/console/dbserver/" + p, console,
    };
    vm.createContext(sb);
    vm.runInContext(["dbsCardInstallUpdates", "dbsInstallUpdates", "_dbsPost"].map(fn).join("\n") + "\nvar _osupUpdatesOnly=false,_dbsRebootMode=false;", sb);
    await vm.runInContext("dbsCardInstallUpdates()", sb);
    return { calls, dom, target: vm.runInContext("_osupTarget", sb) };
  }
  let c = await clickCard(true, { ok: true, body: { ok: true, message: "started" } });
  check("click: targets the database server, asks once, posts to /updates and starts the job",
    c.target === "dbserver" && c.calls.confirm === 1 && c.calls.posts.length === 1 && /\/updates$/.test(c.calls.posts[0]) && c.calls.started === 1, JSON.stringify(c.calls));
  c = await clickCard(false, { ok: true, body: { ok: true } });
  check("click, then Cancel at the confirm: nothing is posted", c.calls.confirm === 1 && c.calls.posts.length === 0 && c.calls.started === 0, JSON.stringify(c.calls));
  c = await clickCard(true, { ok: false, body: { ok: false, error: "a job is already running" } });
  check("click, server refuses: the reason is shown (the dialog is closed, so as an alert)", c.calls.alerts.length === 1 && /already running/.test(c.calls.alerts[0]) && c.calls.started === 0, JSON.stringify(c.calls));

  console.log(fails ? "\n" + fails + " check(s) failed" : "\nall checks passed");
  process.exit(fails ? 1 : 0);
})();
