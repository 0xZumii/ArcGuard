/**
 * End-to-end test of the page itself, against live Arc mainnet.
 *
 *   npm run test:page
 *
 * jsdom cannot load ES modules, so instead of letting jsdom parse the page we
 * give Node a real DOM and import docs/app.js into it directly. The app then
 * runs exactly as it does in a browser: same DOM, same code, same RPC calls —
 * the assertions read the rendered output, not internal functions.
 *
 * Needs the network. Not part of `npm test`.
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { JSDOM } from "jsdom";

let failures = 0;
const ok = (message) => console.log(`  ok    ${message}`);
const fail = (message) => { failures++; console.log(`  FAIL  ${message}`); };

const html = await readFile(fileURLToPath(new URL("../docs/index.html", import.meta.url)), "utf8");
const dom = new JSDOM(html, { url: "http://localhost:5173/" });

// The app uses these as globals, exactly as a browser provides them.
global.window = dom.window;
global.document = dom.window.document;
global.Node = dom.window.Node;
global.Event = dom.window.Event;
global.TextEncoder = global.TextEncoder ?? (await import("node:util")).TextEncoder;

const $ = (id) => dom.window.document.getElementById(id);
const text = (id) => $(id)?.textContent ?? "";

async function waitFor(label, predicate, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  fail(`timed out waiting for ${label}`);
  return false;
}

function render() {
  return text("tx-results");
}

console.log("booting docs/app.js in a real DOM");
await import("../docs/app.js");

console.log("\nchain handshake (live)");
await waitFor("the chain status to settle", () => !/connecting/.test(text("chain-text")), 30000);
const status = text("chain-text");
if (/Arc mainnet · chain 5042/.test(status)) ok(`status reads: ${status}`);
else fail(`status reads: ${status}`);

console.log("\nthe example buttons actually run checks");
const examples = [...dom.window.document.querySelectorAll(".example")];
if (examples.length === 6) ok(`${examples.length} examples rendered`);
else fail(`expected 6 examples, found ${examples.length}`);

// 1. "bridge" deposit to a wallet -> critical, with the claim mismatch named.
examples[0].dispatchEvent(new dom.window.Event("click", { bubbles: true }));
if (await waitFor("the scam example to render", () => /You were told this bridges/.test(render()))) {
  ok("scam example 1 catches a 'bridge' that only moves USDC to a wallet");
} else {
  fail(`scam example 1 rendered: ${render().slice(0, 200)}`);
}
if (/Do not sign this/.test(render())) ok("headline tells the user not to sign");
else fail(`headline was: ${render().slice(0, 90)}`);

// 2. USDC transfer called a bridge -> critical.
examples[1].dispatchEvent(new dom.window.Event("click", { bubbles: true }));
if (await waitFor("the fake-bridge example", () => /plain USDC transfer, not a bridge/.test(render()))) {
  ok("scam example 2 catches transfer() called a bridge");
} else {
  fail(`scam example 2 rendered: ${render().slice(0, 200)}`);
}

// 3. testnet address on mainnet -> critical.
examples[2].dispatchEvent(new dom.window.Event("click", { bubbles: true }));
if (await waitFor("the testnet example", () => /TESTNET address/.test(render()))) {
  ok("scam example 3 catches a testnet address offered as mainnet");
} else {
  fail(`scam example 3 rendered: ${render().slice(0, 200)}`);
}

// 4. "claim rewards" -> critical, and Arc has no rewards to claim.
examples[3].dispatchEvent(new dom.window.Event("click", { bubbles: true }));
if (await waitFor("the rewards example", () => /Arc has no rewards or airdrop/.test(render()))) {
  ok("scam example 4 refuses the premise: Arc has no rewards to claim");
  if (/Unlimited approval/.test(render())) ok("and it still catches the unlimited approval");
  else fail("the unlimited approval went unreported");
} else {
  fail(`scam example 4 rendered: ${render().slice(0, 200)}`);
}

// 5. The legitimate CCTP call must NOT be condemned.
examples[4].dispatchEvent(new dom.window.Event("click", { bubbles: true }));
if (await waitFor("the legit example", () => /claim matches the transaction/.test(render()))) {
  ok("legit CCTP example is recognised as matching the claim");
  if (/Do not sign this/.test(render())) fail("legit CCTP example was wrongly condemned as critical");
  else ok("legit CCTP example is not condemned");
} else {
  fail(`legit example rendered: ${render().slice(0, 200)}`);
}

// 6. A plain payment to a wallet must be quiet, not critical.
examples[5].dispatchEvent(new dom.window.Event("click", { bubbles: true }));
if (await waitFor("the payment example", () => /claim matches the transaction/.test(render()))) {
  ok("plain payment is accepted");
  if (/Do not sign this/.test(render())) fail("a plain payment was wrongly condemned");
  else ok("plain payment is not condemned (no false alarm on the most common Arc transaction)");
} else {
  fail(`payment example rendered: ${render().slice(0, 200)}`);
}

console.log("\naddress tab (live code lookup)");
$("addr-input").value = "0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d";
$("addr-form").dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
if (await waitFor("the address result", () => /Recognised Arc contract/.test(text("addr-results")))) {
  ok("recognises the real CCTP TokenMessenger");
} else {
  fail(`address result rendered: ${text("addr-results").slice(0, 200)}`);
}

$("addr-input").value = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
$("addr-form").dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
if (await waitFor("the EOA result", () => /No contract code/.test(text("addr-results")))) {
  ok("an address with no code is reported as a wallet");
} else {
  fail(`EOA result rendered: ${text("addr-results").slice(0, 200)}`);
}

console.log("\nlink tab (no network needed)");
$("link-input").value = "https://governance-arc.com/vote";
$("link-form").dispatchEvent(new dom.window.Event("submit", { bubbles: true, cancelable: true }));
if (await waitFor("the drainer result", () => /Known Arc drainer domain/.test(text("link-results")))) {
  ok("flags the documented drainer domain");
} else {
  fail(`link result rendered: ${text("link-results").slice(0, 200)}`);
}

console.log("\nthe page never claims safety");
if (/not an oracle/.test(html) && /never says/.test(html)) ok("the static copy states findings are not a safety guarantee");
else fail("the page does not state the limitation");

console.log("\nnon-affiliation");
if (/Not affiliated with Circle or Arc/.test(html)) ok("states it is not affiliated with Circle or Arc");
else fail("no non-affiliation notice");
if (/only official Arc site is/.test(html) && /arc\.io/.test(html)) ok("points at the real arc.io");
else fail("does not point at official arc.io");
if (/(^|\n)\s*<p class="affiliation"/.test(html)) ok("the notice is in the page body, not just the footer");
else fail("notice is not rendered in the body");

// With canonicalUrl empty (GitHub Pages), the notice must NOT pretend there is a
// canonical address it cannot name.
const slot = dom.window.document.getElementById("canonical-slot");
if (slot) ok("canonical slot is present");
else fail("canonical slot missing");
if (slot && !/published only at/.test(slot.textContent)) {
  ok("no canonical URL claimed while canonicalUrl is unset");
} else {
  fail("claims a canonical URL that is not configured");
}

// Re-run the quiet example and read the headline directly: a clean result must
// still refuse to say the transaction is safe.
examples[5].dispatchEvent(new dom.window.Event("click", { bubbles: true }));
if (await waitFor("the quiet headline", () => /not the same as safe/.test(render()))) {
  ok("a quiet result's headline still refuses to call it safe");
} else {
  fail(`quiet headline read: ${render().slice(0, 120)}`);
}

console.log(`\n${failures === 0 ? "Page test passed." : `${failures} failure(s).`}`);
process.exit(failures === 0 ? 0 : 1);
