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
 * Drives the console's OS-updates panel through the "installed but not
 * running" case (ops #154).
 *
 * The bug was a single early return: nothing pending -> hide the panel, while
 * the box kept running the old kernel for weeks. A grep for the new sentence
 * would pass with that return still in front of it, so this runs the real
 * checkKernelPatch() against a hand-rolled DOM and canned API answers.
 *
 *   node scripts/check_kernel_reboot_banner.js
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

const start = scripts.indexOf("var _kpatchPollTimer=null;");
// The page calls checkKernelPatch() at top level right after rebootForKernelPatch.
const end = scripts.indexOf("\ncheckKernelPatch();");
if (start < 0 || end < 0) {
  console.log("  FAIL the OS-updates panel script is not on the page in the shape expected");
  process.exit(1);
}
const source = scripts.slice(start, end);

let fails = 0;
function check(name, ok, detail) {
  if (ok) console.log("  ok   " + name);
  else {
    fails += 1;
    console.log("  FAIL " + name + (detail ? "  |  " + detail : ""));
  }
}

function makeEl(id) {
  const attrs = {};
  return {
    id,
    style: {},
    textContent: "",
    innerHTML: "",
    scrollTop: 0, scrollHeight: 0, clientHeight: 0,
    parentNode: { style: {}, innerHTML: "" },
    setAttribute(k, v) { attrs[k] = String(v); },
    getAttribute(k) { return Object.prototype.hasOwnProperty.call(attrs, k) ? attrs[k] : null; },
    removeAttribute(k) { delete attrs[k]; },
  };
}

const store = {};
const localStorage = {
  getItem: (k) => (Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null),
  setItem: (k, v) => { store[k] = String(v); },
  removeItem: (k) => { delete store[k]; },
};

function page(api) {
  const els = {};
  const document = {
    getElementById: (id) => (els[id] = els[id] || makeEl(id)),
    createElement: () => makeEl(""),
  };
  const ctx = {
    document, localStorage, console, Date, JSON, String, Math,
    confirm: () => true,
    setInterval: () => 1, clearInterval: () => {}, setTimeout: () => 1,
    location: { reload() {} },
    escapeHtml: (s) => String(s),
    setLogPane: (id, t) => { document.getElementById(id).textContent = t; },
    fetch: async (url) => {
      const key = Object.keys(api).find((k) => url.indexOf(k) === 0);
      return { json: async () => (key ? api[key] : {}) };
    },
  };
  vm.createContext(ctx);
  vm.runInContext(source, ctx);
  return { ctx, el: (id) => document.getElementById(id) };
}

const RUN = "5.15.0-190-generic", NEW = "5.15.0-198-generic";
const staged = (ver, extra) => Object.assign({
  pending: true, kernel: true, flag: true, running: RUN, staged: ver,
  sig: "reboot@" + ver, cve_banner: "CVE-2026-53266",
}, extra || {});
const NONE = { pending: false, kernel: false, flag: false, running: NEW, staged: NEW, sig: "", cve_banner: null };
const IDLE_JOB = { running: false, done: false, error: false };

async function main() {
  // 1. test12 as it stood: nothing to download, 198 installed, 190 running.
  let p = page({
    "/api/system/kernel-patch/job-status": IDLE_JOB,
    "/api/os-updates": { total: 0, reboot_required: true, reboot: staged(NEW) },
  });
  await p.ctx.checkKernelPatch();
  check("nothing pending + staged kernel shows the panel",
        p.el("kernel-patch-banner").style.display === "block", p.el("kernel-patch-banner").style.display);
  check("it is the restart panel", p.el("kpatch-reboot").style.display === "block");
  check("the install panel is not shown", p.el("kpatch-idle").style.display === "none");
  check("headline says a restart is needed",
        /installed but needs a restart/.test(p.el("kpatch-reboot-head").textContent), p.el("kpatch-reboot-head").textContent);
  check("CVE label is on it", /CVE-2026-53266/.test(p.el("kpatch-reboot-cve").textContent), p.el("kpatch-reboot-cve").textContent);
  check("body names both kernels",
        p.el("kpatch-reboot-body").textContent.indexOf(NEW) >= 0 && p.el("kpatch-reboot-body").textContent.indexOf(RUN) >= 0,
        p.el("kpatch-reboot-body").textContent);

  // 2. Dismissal is keyed to the staged kernel.
  p.ctx.dismissKernelBanner();
  p = page({
    "/api/system/kernel-patch/job-status": IDLE_JOB,
    "/api/os-updates": { total: 0, reboot_required: true, reboot: staged(NEW) },
  });
  await p.ctx.checkKernelPatch();
  check("dismissed restart prompt stays dismissed for the same kernel",
        p.el("kernel-patch-banner").style.display === "none", p.el("kernel-patch-banner").style.display);
  const NEWER = "5.15.0-199-generic";
  p = page({
    "/api/system/kernel-patch/job-status": IDLE_JOB,
    "/api/os-updates": { total: 0, reboot_required: true, reboot: staged(NEWER) },
  });
  await p.ctx.checkKernelPatch();
  check("a newer staged kernel shows it again",
        p.el("kernel-patch-banner").style.display === "block" && p.el("kpatch-reboot").style.display === "block");

  // 3. After the reboot: nothing pending, nothing staged -> no banner, record cleared.
  p = page({
    "/api/system/kernel-patch/job-status": IDLE_JOB,
    "/api/os-updates": { total: 0, reboot_required: false, reboot: NONE },
  });
  await p.ctx.checkKernelPatch();
  check("nothing staged shows no banner (no false alarm)",
        p.el("kernel-patch-banner").style.display === "none");
  check("the restart dismissal is cleared once the box is current",
        localStorage.getItem("kernel-patch-dismissed-reboot") === null);

  // 4. Older backend without `reboot`: unchanged behaviour (hidden).
  p = page({
    "/api/system/kernel-patch/job-status": IDLE_JOB,
    "/api/os-updates": { total: 0, reboot_required: false },
  });
  await p.ctx.checkKernelPatch();
  check("missing reboot field reads as nothing to do", p.el("kernel-patch-banner").style.display === "none");

  // 5. Ubuntu flag only (e.g. libc), no newer kernel.
  p = page({
    "/api/system/kernel-patch/job-status": IDLE_JOB,
    "/api/os-updates": { total: 0, reboot_required: true,
      reboot: { pending: true, kernel: false, flag: true, running: NEW, staged: NEW, sig: "reboot@flag-1760000000", cve_banner: null } },
  });
  await p.ctx.checkKernelPatch();
  check("reboot-required flag alone shows the restart panel",
        p.el("kpatch-reboot").style.display === "block" && p.el("kernel-patch-banner").style.display === "block");
  check("flag-only wording does not claim a kernel",
        /An installed update needs a restart/.test(p.el("kpatch-reboot-head").textContent), p.el("kpatch-reboot-head").textContent);
  check("no CVE label without a staged kernel", p.el("kpatch-reboot-cve").textContent === "");
  localStorage.removeItem("kernel-patch-dismissed-reboot");

  // 6. Updates pending AND a kernel already staged: install panel, plus Reboot now.
  p = page({
    "/api/system/kernel-patch/job-status": IDLE_JOB,
    "/api/os-updates": { total: 2, pkg_sig: "abc", managed: [], restarts: [], alerts: [], routine_count: 2,
      reboot_required: true, reboot: staged(NEW) },
    "/api/system/kernel-patch-status": { cve_banner: "CVE-2026-53266", patched: false, reboot_pending: true },
  });
  await p.ctx.checkKernelPatch();
  check("pending + staged shows the install panel", p.el("kpatch-idle").style.display === "block");
  check("pending + staged offers Reboot now", p.el("osupd-reboot-btn").style.display === "");
  check("pending + staged says the restart is needed now",
        /already installed and needs a restart/.test(p.el("osupd-plain").innerHTML), p.el("osupd-plain").innerHTML);
  check("pending + staged reads as a warning, not info",
        /234,179,8/.test(p.el("kernel-patch-banner").style.border || ""), p.el("kernel-patch-banner").style.border);
  p.ctx.dismissKernelBanner();
  check("dismissing that panel also quiets the restart prompt for the same kernel",
        /reboot@5\.15\.0-198/.test(localStorage.getItem("kernel-patch-dismissed-reboot") || ""));
  localStorage.removeItem("kernel-patch-dismissed-reboot");
  localStorage.removeItem("kernel-patch-dismissed-pending");

  // 7. Pending, no restart: Reboot now stays hidden.
  p = page({
    "/api/system/kernel-patch/job-status": IDLE_JOB,
    "/api/os-updates": { total: 1, pkg_sig: "def", managed: [], restarts: [], alerts: [], routine_count: 1,
      reboot_required: false, reboot: NONE },
    "/api/system/kernel-patch-status": { cve_banner: null, patched: true },
  });
  await p.ctx.checkKernelPatch();
  check("pending without a staged kernel hides Reboot now", p.el("osupd-reboot-btn").style.display === "none");

  // 8. Finished patch run closed with "I'll reboot later" must not swap in the
  //    restart panel for the same kernel on the next load.
  const DONE_JOB = { running: false, done: true, error: false, done_at: "2026-10-21T23:00:00",
    reboot_required: true, reboot_sig: "reboot@" + NEW, log_tail: "=== DONE" };
  p = page({
    "/api/system/kernel-patch/job-status": DONE_JOB,
    "/api/os-updates": { total: 0, reboot_required: true, reboot: staged(NEW) },
  });
  await p.ctx.checkKernelPatch();
  check("finished run shows the done panel first", p.el("kpatch-done").style.display === "block");
  p.ctx.dismissKernelBanner();
  p = page({
    "/api/system/kernel-patch/job-status": DONE_JOB,
    "/api/os-updates": { total: 0, reboot_required: true, reboot: staged(NEW) },
  });
  await p.ctx.checkKernelPatch();
  check("\"I'll reboot later\" on the done panel is honoured by the restart panel",
        p.el("kernel-patch-banner").style.display === "none", p.el("kernel-patch-banner").style.display);

  if (fails) {
    console.log(fails + " kernel-reboot banner check(s) failed");
    process.exit(1);
  }
  console.log("all kernel-reboot banner checks passed");
}

main().catch((e) => { console.log("  FAIL harness crashed: " + (e && e.stack || e)); process.exit(1); });
