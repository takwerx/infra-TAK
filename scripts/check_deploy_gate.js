// SPDX-License-Identifier: AGPL-3.0-or-later
// infra-TAK — TAK Infrastructure Platform
// Copyright (C) 2026 Michael Leckliter
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
 * Drives the deployment form's validation and its confirmation modal (W216).
 *
 * ⚠️ Plain node, a hand-rolled DOM, a stubbed capacity — no jsdom, no
 * dependencies. Everything here is behaviour: a button that enables at the right
 * moment, a refusal that explains itself, and a modal that repeats the choices
 * back before anything is built. None of it is visible in a string search.
 *
 * ⚠️ **This is the only test in the repository that executes the page's own
 * logic**, and it earns its keep. Three source-text assertions passed while
 * mutations replaced their guards with `if (false)`: the message stayed in the
 * source, so the assertion matched while the rule did nothing. Running the code
 * cannot be fooled that way.
 *
 * It replaced a harness that drove the retired single-instance gate. The
 * behaviours it checks are the same ones; the controls they live on are not.
 *
 *   node scripts/check_deploy_gate.js
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(ROOT, "templates", "atlas.html"), "utf8");

const scripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
  .map((m) => m[1])
  .join("\n")
  .replace(/\{%[\s\S]*?%\}/g, "")
  .replace(/\{\{[\s\S]*?\}\}/g, "null");

// ⚠️ Starts at `renderInstances` so the button wording is driven too: it
// is the one rule that depends on how many deployments came back.
const start = scripts.indexOf("function renderInstances");
// ⚠️ Past `openUninstall`, which is the one dialog that destroys every
// deployment on the box — and the one whose prose said otherwise until an
// operator asked what it did. `closeUninstall` is the next definition after it.
const end = scripts.indexOf("function closeUninstall");
if (start < 0 || end < 0) {
  console.log("  FAIL the deployment form's script is not on the page in the shape expected");
  process.exit(1);
}
const source = scripts.slice(start, end);

let fails = 0;

function labels(node) {
  return (node.children || []).map((c) => c.textContent);
}
function check(name, ok, detail) {
  if (ok) console.log("  ok   " + name);
  else {
    fails += 1;
    console.log("  FAIL " + name + (detail ? "  |  " + detail : ""));
  }
}

// Real proportions, read off the measured box.
const CAPACITY = {
  budget_gb: 354.6, committed_gb: 0, pool_gb: 354.6, remaining_gb: 354.6,
  min_gb: 2, max_gb: 319.6, may_deploy_plain: true, slugs: [],
  plain_host: "atlas.leckliter.net",
  host_template: "atlas.{slug}.leckliter.net",
};

function harness(capacity) {
  const els = {};
  const el = (id) => {
    if (!els[id]) {
      // ⚠️ `value` is a **string** on a real input, whatever is assigned to it.
      // A fake DOM that stores the raw number makes `.trim()` throw, which looks
      // exactly like a bug in the page. Faithful beats convenient.
      const node = {
        id, style: {}, textContent: "", innerHTML: "", _value: "",
        disabled: false, checked: false, hidden: false, children: [],
        className: "", onclick: null,
        appendChild(child) { this.children.push(child); return child; },
        classList: { _s: new Set(),
          add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
          contains(c) { return this._s.has(c); } },
      };
      Object.defineProperty(node, "value", {
        get() { return this._value; },
        set(v) { this._value = String(v); },
      });
      els[id] = node;
    }
    return els[id];
  };

  const radios = { dynamic: el("radio-dynamic"), fixed: el("radio-fixed") };
  radios.dynamic.checked = true;

  // ⚠️ `createElement` and `appendChild` exist because the page builds the
  // "finish deploying" buttons rather than toggling markup. A fake DOM that
  // lacks them fails with a stack trace rather than a failed check, which is
  // still the harness doing its job — it found the gap the moment the page
  // started creating nodes.
  const made = [];
  global.document = {
    getElementById: el,
    createElement(tag) {
      const node = el("made-" + tag + "-" + made.length);
      node.tag = tag;
      made.push(node);
      return node;
    },
    querySelector(sel) {
      const m = /value="(\w+)"/.exec(sel);
      return m ? radios[m[1]] || null : null;
    },
  };
  // The page declares `capacityState` above this slice, so the extracted
  // functions resolve it up the scope chain to here.
  global.capacityState = capacity;
  // ⚠️ And `polling`, which is true while a deploy is being built. The page
  // hides every destructive control behind it, so a harness without it throws
  // `polling is not defined` — which is the harness doing its job: the page
  // grew a dependency and said so.
  global.polling = false;
  // ⚠️ A request that never settles, so the state the page shows *while* it is
  // waiting can be asserted. That moment is the whole subject: before this, the
  // dialog closed and the operator was left with no sign anything was happening.
  global.fetch = () => new Promise(() => {});

  const ctx = {};
  // eslint-disable-next-line no-eval
  eval(source
    + "\n;ctx.problem = addInstanceProblem; ctx.gate = refreshAddGate;"
    + "ctx.render = renderInstances;"
    + "ctx.onMode = onModeChanged; ctx.preview = previewSlug;"
    + "ctx.open = openInstanceConfirm; ctx.close = closeInstanceConfirm;"
    + "ctx.openRemove = openRemove; ctx.removeGate = refreshRemoveGate;"
    + "ctx.openName = openNameDeployment;"
    + "ctx.doRemove = doRemove; ctx.askAgain = removeAskAgain;"
    + "ctx.renderRemoval = renderRemoval;"
    + "ctx.openUninstall = openUninstall;");

  return {
    el,
    problem: ctx.problem, open: ctx.open, close: ctx.close,
    render: ctx.render,
    openRemove: ctx.openRemove,
    openName: ctx.openName,
    doRemove: ctx.doRemove,
    askAgain: ctx.askAgain,
    renderRemoval: ctx.renderRemoval,
    openUninstall: ctx.openUninstall,
    typeConfirm(v) { el("removeConfirm").value = v; ctx.removeGate(); },
    pick(mode) {
      radios.dynamic.checked = mode === "dynamic";
      radios.fixed.checked = mode === "fixed";
      ctx.onMode();
    },
    size(v) { el("instanceSize").value = v; ctx.gate(); },
    building(on) { global.polling = !!on; },
    slug(v) { el("agencySlug").value = v; ctx.preview(); },
    agencyName(v) { el("agencyName").value = v; ctx.preview(); },
  };
}

// --- the type decides what is asked for ------------------------------------ //
{
  const h = harness({ ...CAPACITY });
  h.pick("dynamic");
  check("dynamic hides the size field", h.el("sizeField").style.display === "none");
  check("dynamic says what it will share",
    h.el("dynamicNote").textContent.includes("354.6"),
    h.el("dynamicNote").textContent);

  h.pick("fixed");
  check("fixed shows the size field", h.el("sizeField").style.display === "");
}

// --- a blank slug means the box's general deployment ----------------------- //
{
  const h = harness({ ...CAPACITY, may_deploy_plain: true });
  h.pick("dynamic");
  h.slug("");
  check("a blank slug is allowed on an empty box", h.problem() === null,
    String(h.problem()));
  check("and the page says it becomes the general ATLAS",
    h.el("slugPreview").textContent.includes("general ATLAS"),
    h.el("slugPreview").textContent);
}

{
  const h = harness({ ...CAPACITY, may_deploy_plain: false });
  h.pick("dynamic");
  h.slug("");
  check("a blank slug is refused once a general ATLAS exists",
    (h.problem() || "").includes("already has a general ATLAS"),
    String(h.problem()));
  check("and the button is disabled for it",
    h.el("createInstanceBtn").disabled === true);
}

// --- slugs ------------------------------------------------------------------ //
{
  const h = harness({ ...CAPACITY, slugs: ["agencya"] });
  h.pick("dynamic");

  h.slug("agencya");
  check("a slug already in use is refused",
    (h.problem() || "").includes("already a deployment"), String(h.problem()));

  h.slug("AgencyB");
  check("an uppercase slug is accepted as its lowercase form",
    h.problem() === null, String(h.problem()));
  check("and is shown back normalised",
    h.el("slugPreview").textContent.includes("atlas.agencyb.leckliter.net"),
    h.el("slugPreview").textContent);

  h.slug("AGENCYA");
  check("a duplicate is caught whatever the case",
    (h.problem() || "").includes("already a deployment"), String(h.problem()));

  // ⚠️ The field **strips** what it will not accept rather than refusing the
  // keystroke, so an invalid slug cannot be held at all. The preview then shows
  // what was actually kept — the operator sees the name they will get, which is
  // the same rule that forces case.
  h.slug("two words");
  check("a space is stripped as it is typed",
    h.el("agencySlug").value === "twowords", h.el("agencySlug").value);
  check("and what is left is accepted", h.problem() === null, String(h.problem()));
  check("with the preview showing what was kept",
    h.el("slugPreview").textContent.includes("atlas.twowords.leckliter.net"),
    h.el("slugPreview").textContent);

  h.slug("county-1");
  check("hyphens and digits are stripped too",
    h.el("agencySlug").value === "county", h.el("agencySlug").value);

  h.slug("!!!");
  check("a slug of nothing but symbols empties the field",
    h.el("agencySlug").value === "", h.el("agencySlug").value);
}

// --- fixed sizes are bounded ------------------------------------------------ //
{
  const h = harness({ ...CAPACITY });
  h.pick("fixed");
  h.slug("pd");

  h.size("");
  check("fixed with no size is refused",
    (h.problem() || "").includes("Enter a size"), String(h.problem()));
  check("and the button is disabled",
    h.el("createInstanceBtn").disabled === true);

  h.size("1");
  check("below the floor is refused",
    (h.problem() || "").includes("at least 2 GB"), String(h.problem()));

  h.size("400");
  check("above the 85% ceiling is refused",
    (h.problem() || "").includes("at most 319.6 GB"), String(h.problem()));

  h.size("50");
  check("a workable size is accepted", h.problem() === null, String(h.problem()));
  check("and the button enables", h.el("createInstanceBtn").disabled === false);
}

// --- dynamic is never asked for a size -------------------------------------- //
{
  const h = harness({ ...CAPACITY });
  h.pick("dynamic");
  h.slug("pd");
  check("dynamic needs no size at all", h.problem() === null, String(h.problem()));
}

// --- the confirmation modal -------------------------------------------------- //
{
  const h = harness({ ...CAPACITY });
  h.pick("fixed");
  h.slug("pd");
  h.size("50");
  h.open();
  const summary = h.el("instanceConfirmSummary").textContent;
  check("the modal opens for a valid choice",
    h.el("instanceModal").classList.contains("open"));
  check("the summary names the agency", summary.includes("pd"), summary);
  check("the summary names the real hostname",
    summary.includes("atlas.pd.leckliter.net"), summary);
  check("the summary names the type", summary.includes("fixed"), summary);
  check("the summary names the size", summary.includes("50 GB"), summary);

  h.close();
  check("cancelling closes it",
    h.el("instanceModal").classList.contains("open") === false);
}

{
  const h = harness({ ...CAPACITY });
  h.pick("fixed");
  h.slug("pd");
  h.size("");                    // invalid
  h.open();
  check("the modal refuses to open on an invalid choice",
    h.el("instanceModal").classList.contains("open") === false);
}

{
  const h = harness({ ...CAPACITY });
  h.pick("dynamic");
  h.slug("");
  h.open();
  const summary = h.el("instanceConfirmSummary").textContent;
  check("a general dynamic deployment summarises as sharing the pool",
    summary.includes("shares the") && summary.includes("general ATLAS"), summary);
}

// --- the button says what it can actually do -------------------------------- //
{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [], capacity: { ...CAPACITY } });
  check("with nothing deployed the button says 'Deploy instance'",
    h.el("addInstanceBtn").textContent === "Deploy instance",
    h.el("addInstanceBtn").textContent);

  h.render({ instances: [{ slug: null, mode: "dynamic", size_gb: 50 }],
             capacity: { ...CAPACITY, may_deploy_plain: false } });
  check("once one exists it says 'Deploy additional instance'",
    h.el("addInstanceBtn").textContent === "Deploy additional instance",
    h.el("addInstanceBtn").textContent);

  h.render({ instances: [], capacity: { ...CAPACITY } });
  check("and it goes back when the last one is removed",
    h.el("addInstanceBtn").textContent === "Deploy instance",
    h.el("addInstanceBtn").textContent);
}

// --- the confirmation names the real domain --------------------------------- //
{
  const h = harness({ ...CAPACITY });
  h.pick("dynamic");
  h.slug("corona");
  check("the preview names the real domain",
    h.el("slugPreview").textContent.includes("atlas.corona.leckliter.net"),
    h.el("slugPreview").textContent);

  h.open();
  const summary = h.el("instanceConfirmSummary").textContent;
  check("and so does the confirmation",
    summary.includes("atlas.corona.leckliter.net")
    && !summary.includes("<your-domain>"), summary);
}

{
  // ⚠️ Before the box has an FQDN there is nothing truthful to show, and an
  // invented domain in a confirmation is worse than an obvious placeholder.
  const h = harness({ ...CAPACITY, plain_host: "", host_template: "" });
  h.pick("dynamic");
  h.slug("corona");
  h.open();
  check("without an FQDN it falls back to the placeholder rather than guessing",
    h.el("instanceConfirmSummary").textContent.includes("<your-domain>"),
    h.el("instanceConfirmSummary").textContent);
}

{
  const h = harness({ ...CAPACITY });
  h.pick("dynamic");
  h.slug("");
  h.open();
  check("a general deployment names the plain host",
    h.el("instanceConfirmSummary").textContent.includes("atlas.leckliter.net"),
    h.el("instanceConfirmSummary").textContent);
}

// --- an unfinished deployment can be finished ------------------------------- //
{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [{ slug: "corona", mode: "dynamic", size_gb: 354.6,
                           built: false }],
             capacity: { ...CAPACITY, may_deploy_plain: true } });
  check("an unfinished deployment is labelled as such",
    h.el("instanceList").textContent.includes("not finished"),
    h.el("instanceList").textContent);
  check("and offers a way to finish it",
    h.el("retryRow").hidden === false
    && labels(h.el("retryRow")).includes("Finish deploying corona"),
    JSON.stringify(labels(h.el("retryRow"))));
  // ⚠️ **And a way out of it.** "Forget" refuses once a directory exists
  // on disk — exactly what a deploy that cloned and then failed leaves behind
  // — so without this the only route out of a failed deploy was to finish it,
  // with the slug claimed and the store unreclaimable either way.
  check("and a way to abandon it",
    labels(h.el("retryRow")).includes("Remove corona"),
    JSON.stringify(labels(h.el("retryRow"))));
}

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [{ slug: "corona", mode: "dynamic", size_gb: 354.6,
                           built: true }],
             capacity: { ...CAPACITY } });
  check("a finished deployment offers nothing to finish",
    h.el("retryRow").hidden === true);
  check("and is not labelled unfinished",
    !h.el("instanceList").textContent.includes("not finished"),
    h.el("instanceList").textContent);
}

// --- one row per finished deployment, each acting on itself ---------------- //
//
// ⚠️ The single "Update ATLAS" / Restart / Stop trio acted on `takmdm` whatever
// the box held, so on a box whose only deployment is an agency all three did
// nothing and said nothing. These drive the replacement.

const RUNNING = { slug: "corona", mode: "dynamic", size_gb: 354.6,
                  built: true, running: true, version: "1.48.0" };
const STOPPED = { slug: "redlands", mode: "dynamic", size_gb: 50,
                  built: true, running: false, version: "1.48.0" };
const UNFINISHED = { slug: "gone", mode: "dynamic", size_gb: 50,
                     built: false, running: false, version: "1.48.0" };

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [RUNNING], capacity: { ...CAPACITY } });
  const rows = h.el("instanceRows").children;

  check("a finished deployment gets a row", rows.length === 1);
  check("the row links to that deployment's own host",
    labels(rows[0]).some((t) => t === "atlas.corona.leckliter.net"),
    JSON.stringify(labels(rows[0])));
  check("and says it is running, with its version",
    labels(rows[0]).some((t) => t === "running  v1.48.0"),
    JSON.stringify(labels(rows[0])));
  check("a running deployment offers Update, Restart and Stop",
    ["Update", "Restart", "Stop"].every((t) => labels(rows[0]).includes(t)),
    JSON.stringify(labels(rows[0])));
  check("and not Start",
    !labels(rows[0]).includes("Start"), JSON.stringify(labels(rows[0])));
}

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [STOPPED], capacity: { ...CAPACITY } });
  const row = h.el("instanceRows").children[0];

  check("a stopped deployment says so", labels(row).includes("stopped  v1.48.0"),
    JSON.stringify(labels(row)));
  // ⚠️ Start, not Restart. `docker compose restart` on a stopped project does
  // nothing and reports success, so the button would look broken.
  check("and offers Start rather than Stop",
    labels(row).includes("Start") && !labels(row).includes("Stop"),
    JSON.stringify(labels(row)));
}

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [UNFINISHED], capacity: { ...CAPACITY } });

  check("an unfinished deployment gets no row of buttons",
    h.el("instanceRows").children.length === 0);
  check("it is offered a way to finish instead",
    h.el("retryRow").hidden === false);
}

// --- update all ------------------------------------------------------------- //
{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [RUNNING], capacity: { ...CAPACITY } });
  check("one deployment is not offered 'update all'",
    h.el("updateAllRow").hidden === true);

  h.render({ instances: [RUNNING, STOPPED], capacity: { ...CAPACITY } });
  check("two are", h.el("updateAllRow").hidden === false);

  h.render({ instances: [RUNNING, UNFINISHED], capacity: { ...CAPACITY } });
  check("an unfinished one does not count towards it",
    h.el("updateAllRow").hidden === true);
}

// --- drift ------------------------------------------------------------------ //
{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [RUNNING, STOPPED], capacity: { ...CAPACITY } });
  check("deployments on the same release are not called drifted",
    h.el("driftNote").hidden === true);

  h.render({ instances: [RUNNING, { ...STOPPED, version: "1.47.3" }],
             capacity: { ...CAPACITY } });
  check("deployments on different releases are",
    h.el("driftNote").hidden === false);
  check("and both releases are named",
    h.el("driftNote").textContent.includes("1.47.3")
    && h.el("driftNote").textContent.includes("1.48.0"),
    h.el("driftNote").textContent);
}

{
  // ⚠️ An unfinished deployment carries a VERSION the moment its clone
  // succeeds, so counting it would report drift on a box where everything
  // running agrees — true, and not something anybody can act on.
  const h = harness({ ...CAPACITY });
  h.render({ instances: [RUNNING, { ...UNFINISHED, version: "1.47.3" }],
             capacity: { ...CAPACITY } });
  check("an unfinished deployment is not drift",
    h.el("driftNote").hidden === true, h.el("driftNote").textContent);
}

// --- removing one deployment ----------------------------------------------- //
//
// ⚠️ Removing a deployment destroys *its* device CA, so every tablet enrolled
// against it needs a factory reset in person. Deployments do not share a CA —
// that is the point of the per-agency trust pool — so this is exactly one
// agency's fleet, and a red button beside five rows is one mis-click away from
// the wrong one.

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [RUNNING], capacity: { ...CAPACITY } });
  const row = h.el("instanceRows").children[0];

  check("a finished deployment can be removed",
    labels(row).includes("Remove"), JSON.stringify(labels(row)));
}

{
  const h = harness({ ...CAPACITY });
  h.openRemove(RUNNING);

  check("the confirmation names the deployment",
    h.el("removeTitle").textContent === "Remove corona",
    h.el("removeTitle").textContent);
  check("and names its own hostname, not the box's",
    h.el("removeWhat").textContent.includes("atlas.corona.leckliter.net"),
    h.el("removeWhat").textContent);
  check("and says what it destroys",
    ["device volume", "reserved store", "install directory", "Authentik"]
      .some((t) => h.el("removeWhat").textContent.includes(t))
    && h.el("removeWhat").textContent.includes("store"),
    h.el("removeWhat").textContent);
  check("and asks for the name to be typed",
    h.el("removePrompt").textContent === "Type corona to confirm.",
    h.el("removePrompt").textContent);
  check("the button starts disabled",
    h.el("removeGo").disabled === true);

  h.typeConfirm("coron");
  check("a partial name does not enable it", h.el("removeGo").disabled === true);

  // ⚠️ The typed name must match the deployment the modal was opened for, not
  // merely be a name that exists. Accepting any of them is how the wrong agency
  // gets destroyed by an operator typing from memory.
  h.typeConfirm("redlands");
  check("another deployment's name does not enable it",
    h.el("removeGo").disabled === true);

  h.typeConfirm("corona");
  check("the exact name enables it", h.el("removeGo").disabled === false);

  h.typeConfirm("  corona  ");
  check("and surrounding whitespace is forgiven",
    h.el("removeGo").disabled === false);
}

{
  // ⚠️ "" is not something an operator can type, and the server expects the
  // same word this asks for.
  const h = harness({ ...CAPACITY });
  h.openRemove({ slug: null, built: true, running: true, version: "1.48.0" });

  check("the general deployment is confirmed by typing 'general'",
    h.el("removePrompt").textContent === "Type general to confirm.",
    h.el("removePrompt").textContent);

  h.typeConfirm("atlas");
  check("its URL name is not what is asked for",
    h.el("removeGo").disabled === true);

  h.typeConfirm("general");
  check("but 'general' is", h.el("removeGo").disabled === false);
}

{
  const h = harness({ ...CAPACITY });
  h.openRemove(RUNNING);
  h.typeConfirm("corona");
  h.openRemove(STOPPED);
  check("re-opening for another deployment clears the confirmation",
    h.el("removeGo").disabled === true
    && h.el("removeConfirm").value === "",
    h.el("removeConfirm").value);
}

// --- nothing destructive while a deployment is being built ----------------- //
//
// ⚠️ **Measured, not imagined.** On the box, 2026-09-18: a removal started
// while a deploy was at step 4, ran `docker compose down -v` over the containers
// the deploy had just created, and the deploy failed three seconds later with an
// empty message. An unfinished deployment is exactly what a deploy *in progress*
// looks like, so the retry row sat beside a running build offering to delete it.

{
  const h = harness({ ...CAPACITY });
  h.building(true);
  h.render({ instances: [RUNNING], capacity: { ...CAPACITY } });

  check("a running deployment cannot be removed mid-build",
    !labels(h.el("instanceRows").children[0]).includes("Remove"),
    JSON.stringify(labels(h.el("instanceRows").children[0])));
  check("but it can still be updated and restarted",
    labels(h.el("instanceRows").children[0]).includes("Update"));
}

{
  const h = harness({ ...CAPACITY });
  h.building(true);
  h.render({ instances: [UNFINISHED], capacity: { ...CAPACITY } });

  check("the retry row stands down while a build is running",
    h.el("retryRow").hidden === true);
  check("offering neither finish nor remove",
    h.el("retryRow").children.length === 0,
    JSON.stringify(labels(h.el("retryRow"))));
}

{
  const h = harness({ ...CAPACITY });
  h.building(false);
  h.render({ instances: [UNFINISHED], capacity: { ...CAPACITY } });

  check("and comes back once the build is over",
    h.el("retryRow").hidden === false
    && labels(h.el("retryRow")).includes("Finish deploying gone")
    && labels(h.el("retryRow")).includes("Remove gone"),
    JSON.stringify(labels(h.el("retryRow"))));
}

// --- the agency name, beside the slug -------------------------------------- //
//
// ⚠️ **The slug is not the name.** `corona` goes into a hostname, a systemd
// unit, a Compose project and a Docker volume; "Corona Fire Department" is what
// the agency calls itself and what an administrator reads in that deployment's
// own footer before pushing a policy. One cannot be derived from the other.

{
  const h = harness({ ...CAPACITY });
  h.pick("dynamic");
  h.slug("corona");
  h.agencyName("Corona Fire Department");
  h.open();
  const summary = h.el("instanceConfirmSummary").textContent;

  check("the confirmation repeats the agency name back",
    summary.includes("Corona Fire Department"), summary);
  check("beside the slug it is not derived from",
    summary.includes("corona") && summary.includes("Corona Fire Department"),
    summary);
}

{
  const h = harness({ ...CAPACITY });
  h.pick("dynamic");
  h.slug("corona");
  h.open();

  check("no name is summarised as 'not set', not as blank",
    h.el("instanceConfirmSummary").textContent.includes("not set"),
    h.el("instanceConfirmSummary").textContent);
}

{
  // ⚠️ A name is optional. Requiring one would block a deploy over a label
  // the operator can add in ten seconds afterwards.
  const h = harness({ ...CAPACITY });
  h.pick("dynamic");
  h.slug("corona");
  h.agencyName("");
  check("a deployment without a name is still allowed",
    h.problem() === null, String(h.problem()));
}

// --- naming a deployment that already exists -------------------------------- //
{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [{ ...RUNNING, agency_name: "" }],
             capacity: { ...CAPACITY } });
  const row = h.el("instanceRows").children[0];

  check("an unnamed deployment offers to be named",
    labels(row).includes("Name"), JSON.stringify(labels(row)));
}

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [{ ...RUNNING, agency_name: "Corona Fire Department" }],
             capacity: { ...CAPACITY } });
  const row = h.el("instanceRows").children[0];

  check("a named deployment shows its agency",
    labels(row).includes("Corona Fire Department"), JSON.stringify(labels(row)));
  check("and offers to be renamed rather than named",
    labels(row).includes("Rename") && !labels(row).includes("Name"),
    JSON.stringify(labels(row)));
}

{
  const h = harness({ ...CAPACITY });
  h.openName({ slug: "corona", agency_name: "Corona Fire Department" });

  check("the rename dialog names the deployment",
    h.el("nameTitle").textContent === "Rename corona",
    h.el("nameTitle").textContent);
  check("and the hostname it serves",
    h.el("nameWhat").textContent.includes("atlas.corona.leckliter.net"),
    h.el("nameWhat").textContent);
  // ⚠️ Seeded, so correcting one character does not mean retyping fifty
  // from memory.
  check("the field starts from what is set",
    h.el("nameField").value === "Corona Fire Department",
    h.el("nameField").value);
}

{
  const h = harness({ ...CAPACITY });
  h.openName({ slug: "redlands", agency_name: "" });

  check("naming an unnamed deployment starts empty",
    h.el("nameField").value === "");
  check("and says so in the title",
    h.el("nameTitle").textContent === "Name redlands",
    h.el("nameTitle").textContent);
}

// --- the removal dialog says it is working --------------------------------- //
//
// ⚠️ A teardown is a `docker compose down -v`, three unmounts, a loop device
// and an `rmtree` over a store — a minute or more. The dialog used to close on
// click and leave the log to appear in a card further down the page, so the only
// honest reading of the moment after the click was that it had missed.

{
  const h = harness({ ...CAPACITY });
  h.openRemove(RUNNING);
  h.typeConfirm("corona");
  h.doRemove();

  check("the prompt gives way while the removal runs",
    h.el("removeAsk").hidden === true);
  check("a spinner takes its place",
    h.el("removeBusy").hidden === false);
  check("and it names what is being removed",
    h.el("removeBusyText").textContent === "Removing corona\u2026 please wait.",
    h.el("removeBusyText").textContent);
  // ⚠️ The whole point: it does not close. Asserted against the class the
  // page actually toggles, not against `true`.
  check("the dialog stays open",
    h.el("instanceRemoveModal").classList.contains("open"));
}

{
  const h = harness({ ...CAPACITY });
  h.openRemove(RUNNING);
  h.typeConfirm("corona");
  h.doRemove();
  h.askAgain("An update is running \u2014 wait for it to finish");

  check("a refusal brings the prompt back",
    h.el("removeAsk").hidden === false && h.el("removeBusy").hidden === true);
  check("and says why",
    h.el("removeError").textContent.includes("An update is running"),
    h.el("removeError").textContent);
  // ⚠️ The typed name survives, so retrying does not mean typing it again.
  check("with the typed name still there",
    h.el("removeConfirm").value === "corona", h.el("removeConfirm").value);
  check("and the button still enabled for it",
    h.el("removeGo").disabled === false);
}

{
  // ⚠️ The dialog is reused. Opening it after a failed removal must not show
  // the previous attempt's log above a fresh prompt.
  const h = harness({ ...CAPACITY });
  h.openRemove(RUNNING);
  h.typeConfirm("corona");
  h.doRemove();
  h.el("removeSteps").hidden = false;
  h.el("removeSteps").textContent = "[03:14] STOPPED \u2014 mounts busy";

  h.openRemove(STOPPED);

  check("reopening clears the last attempt",
    h.el("removeSteps").hidden === true
    && h.el("removeSteps").textContent === "",
    h.el("removeSteps").textContent);
  check("and starts from the prompt again",
    h.el("removeAsk").hidden === false && h.el("removeBusy").hidden === true);
}

// --- and what it shows as the removal progresses --------------------------- //
//
// ⚠️ `renderRemoval` exists so these are reachable at all. The same logic
// inside the poll's `.then` needed a settled request to run, and three
// mutations survived the sweep because of it — a removal that never reloaded,
// one that reloaded over its own failure log, and one that wrote the log into
// the update card.

{
  const h = harness({ ...CAPACITY });
  h.openRemove(RUNNING);
  h.typeConfirm("corona");
  h.doRemove();

  const outcome = h.renderRemoval({
    running: true, complete: false, error: false,
    entries: ["[03:14] atlas-corona: containers removed"],
  });

  check("a removal in progress stays in progress", outcome === "running");
  check("its log appears in the dialog",
    h.el("removeSteps").hidden === false
    && h.el("removeSteps").textContent.includes("containers removed"),
    h.el("removeSteps").textContent);
  check("and the spinner is still turning",
    h.el("removeBusy").hidden === false);
}

{
  const h = harness({ ...CAPACITY });
  h.openRemove(RUNNING);
  h.typeConfirm("corona");
  h.doRemove();

  const outcome = h.renderRemoval({
    running: false, complete: true, error: false,
    entries: ["[03:14] \u2713 atlas-corona removed."],
  });

  check("a finished removal reports done", outcome === "done");
  check("the spinner stops", h.el("removeBusy").hidden === true);
  check("and it says the page is reloading",
    h.el("removeBusyText").textContent.includes("Reloading"),
    h.el("removeBusyText").textContent);
  check("with the steps left on screen to read",
    h.el("removeSteps").textContent.includes("removed."),
    h.el("removeSteps").textContent);
}

{
  const h = harness({ ...CAPACITY });
  h.openRemove(RUNNING);
  h.typeConfirm("corona");
  h.doRemove();

  const outcome = h.renderRemoval({
    running: false, complete: false, error: true,
    entries: ["[03:14] ERROR: could not unmount"],
  });

  check("a failed removal reports failed", outcome === "failed");
  // ⚠️ Not a reload. Its record and settings are left in place so it can be
  // retried, and this log is the only account of what is still on disk.
  check("the prompt comes back so it can be retried",
    h.el("removeAsk").hidden === false && h.el("removeBusy").hidden === true);
  check("the failure log stays on screen",
    h.el("removeSteps").hidden === false
    && h.el("removeSteps").textContent.includes("could not unmount"),
    h.el("removeSteps").textContent);
  check("and says where to look",
    h.el("removeError").textContent.includes("see the log above"),
    h.el("removeError").textContent);
}

// --- which deployments are behind, at a glance ----------------------------- //
//
// ⚠️ The server decides whether a deployment is behind; this only draws it.
// Comparing versions here would be a second implementation of a comparison that
// has to be on integers — `0.10.0` sorts before `0.9.0` as a string, which would
// stop showing the badge at the tenth release of any series, silently.

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [{ ...RUNNING, update_available: true,
                           latest: "1.49.0" }],
             capacity: { ...CAPACITY } });
  const row = h.el("instanceRows").children[0];

  check("a deployment that is behind carries a badge",
    labels(row).includes("v1.49.0 available"), JSON.stringify(labels(row)));
  // The badge answers "to what", not only "yes" — an operator comparing two
  // rows needs the target, not a dot.
  check("naming the release it points at",
    labels(row).some((t) => t.includes("1.49.0")), JSON.stringify(labels(row)));
  check("and its own version is still shown",
    labels(row).includes("running  v1.48.0"), JSON.stringify(labels(row)));
}

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [{ ...RUNNING, update_available: false,
                           latest: "1.48.0" }],
             capacity: { ...CAPACITY } });

  check("a current deployment carries none",
    !labels(h.el("instanceRows").children[0]).some((t) => t.includes("available")),
    JSON.stringify(labels(h.el("instanceRows").children[0])));
}

{
  // ⚠️ An unreachable GitHub leaves `update_available` false and `latest`
  // null. No badge is the honest reading: "no newer release established"
  // covers both "you are current" and "the check could not run".
  const h = harness({ ...CAPACITY });
  h.render({ instances: [{ ...RUNNING, update_available: false, latest: null }],
             capacity: { ...CAPACITY } });

  check("a check that could not run claims nothing",
    !labels(h.el("instanceRows").children[0]).some((t) => t.includes("available")),
    JSON.stringify(labels(h.el("instanceRows").children[0])));
}

{
  // The point of the whole thing: several deployments, and you can see which.
  const h = harness({ ...CAPACITY });
  h.render({ instances: [
      { ...RUNNING, update_available: true, latest: "1.49.0" },
      { ...STOPPED, update_available: false, latest: "1.49.0" },
    ], capacity: { ...CAPACITY } });
  const rows = h.el("instanceRows").children;

  check("with several deployments only the stale ones are marked",
    labels(rows[0]).includes("v1.49.0 available")
    && !labels(rows[1]).some((t) => t.includes("available")),
    JSON.stringify([labels(rows[0]), labels(rows[1])]));
}

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [{ ...UNFINISHED, update_available: true,
                           latest: "1.49.0" }],
             capacity: { ...CAPACITY } });

  check("an unfinished deployment has no row to badge",
    h.el("instanceRows").children.length === 0);
}

// --- uninstall says how much it destroys ----------------------------------- //
//
// ⚠️ It removes **every** deployment, and the prose hid that. The text was
// written when a box ran one ATLAS — "the database volume", "the device CA",
// "the ATLAS application", all singular. On a box with three agencies the same
// button destroys three fleets. Operator asked what it did, which is the
// clearest evidence the wording was not carrying it.

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [
      { ...RUNNING, agency_name: "Corona Fire" },
      { ...STOPPED, agency_name: "Test Agency" },
    ], capacity: { ...CAPACITY } });
  h.openUninstall();
  const scope = h.el("uninstallScope").textContent;

  check("the uninstall dialog counts the deployments",
    scope.includes("destroy 2 deployments"), scope);
  check("and names them",
    scope.includes("Corona Fire") && scope.includes("Test Agency"), scope);
  check("the list is shown", h.el("uninstallScope").hidden === false);
  // ⚠️ Only worth offering when there is another one to leave running.
  check("and it points at the per-deployment Remove instead",
    h.el("uninstallOneInstead").hidden === false);
}

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [{ ...RUNNING, agency_name: "" }],
             capacity: { ...CAPACITY } });
  h.openUninstall();
  const scope = h.el("uninstallScope").textContent;

  check("one deployment is not called two",
    scope.includes("destroy 1 deployment") && !scope.includes("deployments"),
    scope);
  check("an unnamed deployment is listed by its slug",
    scope.includes("corona"), scope);
  // Nothing else survives it, so there is no alternative to point at.
  check("with one deployment no alternative is offered",
    h.el("uninstallOneInstead").hidden === true);
}

{
  const h = harness({ ...CAPACITY });
  h.render({ instances: [], capacity: { ...CAPACITY } });
  h.openUninstall();

  check("a box with nothing deployed lists nothing",
    h.el("uninstallScope").hidden === true);
}

console.log(fails === 0
  ? "\n  all deployment-form checks passed"
  : "\n  " + fails + " check(s) failed");
process.exit(fails === 0 ? 0 : 1);
