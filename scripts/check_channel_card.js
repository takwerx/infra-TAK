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
 * Drives the release-channel card (W228).
 *
 * ⚠️ **Written because a source-text assertion could not tell the difference.**
 * A mutation wrapping the ahead-of-channel warning in `if (false)` survived the
 * whole Python suite: the sentence was still in the template, so the grep
 * matched while the rule did nothing. That is the same failure
 * `check_deploy_gate.js` was written for, one card over.
 *
 * Plain node, a hand-rolled DOM, no dependencies.
 *
 *   node scripts/check_channel_card.js
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

const start = scripts.indexOf("function renderChannels");
// `loadChannel` is the next definition, and it talks to the network.
const end = scripts.indexOf("async function loadChannel");
if (start < 0 || end < 0) {
  console.log("  FAIL the channel card's script is not on the page in the shape expected");
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

function node(id) {
  const n = {
    id, className: "", children: [], disabled: false,
    type: "", onclick: null, style: {}, _text: "",
    appendChild(child) { this.children.push(child); return child; },
  };
  // ⚠️ **Assigning `textContent` removes every child node**, which is how
  // the page clears the row before re-rendering. A fake that stored the string
  // and kept the children reported four buttons after two renders -- a failure
  // the browser does not have, which is the harness lying in the other
  // direction. Faithful beats convenient.
  Object.defineProperty(n, "textContent", {
    get() { return this._text; },
    set(v) { this._text = String(v); this.children.length = 0; },
  });
  return n;
}

function harness() {
  const els = {};
  const el = (id) => (els[id] = els[id] || node(id));
  global.document = {
    getElementById: el,
    createElement(tag) { const n = node("made-" + tag); n.tag = tag; return n; },
    querySelectorAll() { return []; },
  };
  const ctx = {};
  // eslint-disable-next-line no-eval
  eval(source + "\n;ctx.render = renderChannels;");
  return { ctx, row: el("channelRow"), note: el("channelNote") };
}

/** Every string the card put on screen, buttons and their contents included. */
function text(n) {
  return [n.textContent || ""]
    .concat((n.children || []).map(text))
    .join(" ");
}

const BOTH = {
  channel: "main",
  install_tag: "v1.49.0",
  channels: [
    { key: "main", label: "Main", version: "1.49.0", blurb: "Tested releases.", ahead: [] },
    { key: "dev", label: "Dev", version: "1.50.0", blurb: "The newest release.", ahead: [] },
  ],
};

// --- one button per channel, from the route -------------------------------- //
{
  const { ctx, row } = harness();
  ctx.render(BOTH);
  check("a button is rendered for each channel the route sent",
    row.children.length === 2, "got " + row.children.length);
}

{
  // ⚠️ A third channel must appear without a template change, or the server
  // and the page would drift the first time one is added.
  const { ctx, row } = harness();
  ctx.render({
    ...BOTH,
    channels: BOTH.channels.concat(
      [{ key: "canary", label: "Canary", version: "1.51.0", ahead: [] }]),
  });
  check("a channel the page has never heard of still renders",
    row.children.length === 3 && text(row).includes("Canary"));
}

// --- which one is being followed ------------------------------------------- //
{
  const { ctx, row } = harness();
  ctx.render(BOTH);
  const [main, dev] = row.children;
  check("the followed channel is the one marked",
    main.className.includes("on") && !dev.className.includes("on"),
    main.className + " / " + dev.className);
  check("the followed channel says so in words as well as colour",
    text(main).includes("following") && !text(dev).includes("following"));
}

// --- the numbers ------------------------------------------------------------ //
{
  const { ctx, row } = harness();
  ctx.render(BOTH);
  const all = text(row);
  check("both channels show what they offer",
    all.includes("1.49.0") && all.includes("1.50.0"), all);
}

{
  // ⚠️ Unknown is said, never rendered as up to date. A rate-limited box, or a
  // mirror with no such branch, lands here — and "offers nothing" read as
  // "nothing new" leaves a box a release behind looking perfectly healthy.
  const { ctx, row } = harness();
  ctx.render({
    ...BOTH,
    channels: [{ key: "dev", label: "Dev", version: null, ahead: [] }],
  });
  const all = text(row);
  check("a channel that could not be resolved says so",
    all.includes("could not ask GitHub"), all);
  check("and is not dressed up as being current",
    !/up to date|current|offers 1\./.test(all), all);
}

// --- the downgrade warning --------------------------------------------------- //
{
  // The mutation that started this file.
  const { ctx, row } = harness();
  ctx.render({
    ...BOTH,
    channels: [
      { key: "main", label: "Main", version: "1.49.0", ahead: ["corona", "test"] },
      { key: "dev", label: "Dev", version: "1.50.0", ahead: [] },
    ],
  });
  const [main, dev] = row.children;
  check("a channel a deployment is already ahead of carries a warning",
    text(main).includes("Already newer than this channel"), text(main));
  check("the warning names the deployments",
    text(main).includes("corona") && text(main).includes("test"));
  check("and says the update button will not move them back",
    text(main).includes("will not move") && text(main).includes("them"));
  check("a channel nothing is ahead of carries no warning",
    !text(dev).includes("Already newer"), text(dev));
}

{
  const { ctx, row } = harness();
  ctx.render({
    ...BOTH,
    channels: [{ key: "main", label: "Main", version: "1.49.0", ahead: ["corona"] }],
  });
  check("one deployment ahead reads as 'it', not 'them'",
    text(row.children[0]).includes("will not move it"), text(row.children[0]));
}

// --- the note ----------------------------------------------------------------- //
{
  const { ctx, note } = harness();
  ctx.render(BOTH);
  check("the note says a fresh install ignores the channel",
    note.textContent.includes("A new deployment always installs")
      && note.textContent.includes("v1.49.0"), note.textContent);
}

// --- clicking ------------------------------------------------------------------- //
{
  const { ctx, row } = harness();
  ctx.render(BOTH);
  check("each button is wired to switch to its own channel",
    row.children.every((c) => typeof c.onclick === "function"));
  check("the buttons are type=button",
    // Inside a card that is not a form today — but a bare <button> defaults to
    // submit, and the day this card gains a form that is a page reload.
    row.children.every((c) => c.type === "button"));
}

// --- re-rendering ------------------------------------------------------------------ //
{
  // ⚠️ `setChannel` re-renders with the route's fresh answer. Appending rather
  // than replacing would leave the old pair of buttons above the new ones, and
  // the stale one would still look selected.
  const { ctx, row } = harness();
  ctx.render(BOTH);
  ctx.render({ ...BOTH, channel: "dev" });
  check("re-rendering replaces the buttons rather than appending",
    row.children.length === 2, "got " + row.children.length);
  check("and moves the marker to the newly followed channel",
    row.children[1].className.includes("on")
      && !row.children[0].className.includes("on"));
}

console.log(
  fails ? "\n  " + fails + " channel-card check(s) failed"
        : "\n  all channel-card checks passed");
process.exit(fails ? 1 : 0);
