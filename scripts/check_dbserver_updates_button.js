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

// 1. The button on the card.
const card = html.match(/\{% if host\.id == 'tak_db' %\}<button[^>]*onclick="([^"]*)"/);
check("the database server card has its update button", !!card);
const onclick = card ? card[1] : "";
check("the card button opens the routine updates view", /dbsOpenUpdates\(\)/.test(onclick), onclick);
check("the card button never calls the upgrade dialog", !/osupOpenPreflight/.test(onclick), onclick);

// 2. The modal, driven.
const NAMES = [
  "_osupApi", "_osupEsc", "_osupApplyMode", "osupOpenPreflight", "dbsOpenUpdates", "osupLoadPreflight",
  "_osupSetStartEnabled", "_dbsRenderUpdatesView", "_osupRenderPreflight", "_dbsRenderActions",
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
  vm.runInContext(source + "\n_osupUpdatesOnly=false;", sandbox);
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

  // C. Nothing pending: a plain "nothing to do", no buttons.
  e = await open("dbsOpenUpdates()", pf({
    pending_count: 0, reboot_required: false,
    checks: [ck("split_config", true), ck("ssh_sudo", true), ck("os_up_to_date", true), ck("no_reboot_pending", true)],
  }));
  check("nothing pending: says so and offers no action", /Nothing to do/.test(e["osup-modal-intro"].textContent) && e["dbs-actions"].style.display === "none");

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

  console.log(fails ? "\n" + fails + " check(s) failed" : "\nall checks passed");
  process.exit(fails ? 1 : 0);
})();
