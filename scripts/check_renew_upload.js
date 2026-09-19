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
 * Drives the CA renewal modal's key handling (W236).
 *
 * ⚠️ **Written because a source-text assertion cannot tell a working file
 * read from a broken one.** The template will contain `input type="file"`
 * and `.text()` whether or not the bytes ever reach the request body, and
 * the one behaviour that matters most here is a *negative*: choosing no file
 * must still send an empty `root_key`, because that is how the console says
 * "use the key already on the server" — the normal path, and the one W235
 * had just restored. A grep cannot see that at all.
 *
 * Plain node, a hand-rolled DOM, no dependencies.
 *
 *   node scripts/check_renew_upload.js
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

const start = scripts.indexOf("async function doRenew(");
if (start < 0) {
  console.log("  FAIL doRenew is not on the page in the shape expected");
  process.exit(1);
}
// The next top-level definition ends it.
const rest = scripts.slice(start + 1);
const nextIdx = rest.search(/\n(?:async )?function /);
const source = scripts.slice(start, nextIdx < 0 ? undefined : start + 1 + nextIdx);

let fails = 0;
function check(name, ok, detail) {
  if (ok) console.log("  ok   " + name);
  else {
    fails += 1;
    console.log("  FAIL " + name + (detail ? "  |  " + detail : ""));
  }
}

// --- a DOM just real enough ------------------------------------------- //

function makeFile(text) {
  return { text: async () => text };
}

function buildDom(chosen) {
  const nodes = {
    renewError: { textContent: "", style: { display: "none" } },
    renewButtons: { hidden: false },
    renewBusy: { hidden: true },
    renewForm: { hidden: false },
    renewDone: { hidden: true },
    renewSteps: { textContent: "", innerHTML: "" },
    renewPw: { value: "hunter2" },
    renewDays: { value: "1825" },
    // ⚠️ A real file input exposes `files` as a list and `value` as a string.
    renewKeyFile: { files: chosen ? [chosen] : [], value: "C:\\fake\\ca.key" },
  };
  return {
    getElementById: (id) => nodes[id] || null,
    _nodes: nodes,
  };
}

async function run(chosen, reply) {
  const sent = [];
  const document = buildDom(chosen);
  const context = {
    document,
    caSlug: () => "testone",
    showRenewSteps: () => {},
    parseInt,
    fetch: async (url, opts) => {
      sent.push({ url, body: JSON.parse(opts.body) });
      return { json: async () => reply };
    },
  };
  const factory = new Function(
    "document", "caSlug", "showRenewSteps", "fetch",
    source + "\nreturn doRenew;"
  );
  const doRenew = factory(
    context.document, context.caSlug, context.showRenewSteps, context.fetch
  );
  await doRenew();
  return { sent, nodes: document._nodes };
}

// --- the behaviours ---------------------------------------------------- //

(async () => {
  // 1. No file: the request still goes, with an empty key.
  {
    const { sent, nodes } = await run(null, { success: true, steps: [] });
    check(
      "no file chosen still sends the renewal",
      sent.length === 1,
      "nothing was sent; the on-server key path is the normal one"
    );
    check(
      "no file chosen sends an empty root_key",
      sent.length === 1 && sent[0].body.root_key === "",
      JSON.stringify(sent[0] && sent[0].body.root_key)
    );
    check(
      "no file chosen is not treated as an error",
      nodes.renewError.style.display === "none",
      nodes.renewError.textContent
    );
  }

  // 2. A key file: its bytes reach the body.
  {
    const pem = "-----BEGIN PRIVATE KEY-----\nMIIBOgIB\n-----END PRIVATE KEY-----\n";
    const { sent } = await run(makeFile(pem), { success: true, steps: [] });
    check(
      "a chosen file's contents are sent",
      sent.length === 1 && sent[0].body.root_key === pem,
      JSON.stringify(sent[0] && sent[0].body.root_key)
    );
    check(
      "the other fields still travel",
      sent.length === 1 && sent[0].body.slug === "testone" &&
        sent[0].body.days === 1825 && sent[0].body.password === "hunter2",
      JSON.stringify(sent[0] && sent[0].body)
    );
  }

  // 3. The wrong file: refused in the browser, nothing sent.
  {
    const { sent, nodes } = await run(
      makeFile("this is my shopping list"), { success: true, steps: [] }
    );
    check(
      "a file that is not a private key is never sent",
      sent.length === 0,
      "its contents left the browser"
    );
    check(
      "and the operator is told why",
      nodes.renewError.style.display === "block" &&
        /PEM private key/.test(nodes.renewError.textContent),
      nodes.renewError.textContent
    );
    check(
      "and the dialog stays usable",
      nodes.renewButtons.hidden === false && nodes.renewBusy.hidden === true,
      "buttons hidden=" + nodes.renewButtons.hidden
    );
  }

  // 4. A refusal from the server leaves the dialog retryable.
  {
    const { sent, nodes } = await run(null, { success: false, error: "nope" });
    check(
      "a server refusal is shown",
      nodes.renewError.style.display === "block" &&
        nodes.renewError.textContent === "nope",
      nodes.renewError.textContent
    );
    check(
      "a server refusal leaves the buttons back",
      nodes.renewButtons.hidden === false,
      "buttons hidden=" + nodes.renewButtons.hidden
    );
    check("and it did reach the server", sent.length === 1);
  }

  // 5. Success clears the picker.
  {
    const pem = "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n";
    const { nodes } = await run(makeFile(pem), { success: true, steps: ["done"] });
    check(
      "success clears the chosen file",
      nodes.renewKeyFile.value === "",
      "picker still holds " + nodes.renewKeyFile.value
    );
    check("success clears the password", nodes.renewPw.value === "");
    check(
      "success shows the result",
      nodes.renewForm.hidden === true && nodes.renewDone.hidden === false
    );
  }

  if (fails) {
    console.log("\n" + fails + " renewal-upload check(s) failed");
    process.exit(1);
  }
  console.log("\nall renewal-upload checks passed");
})();
