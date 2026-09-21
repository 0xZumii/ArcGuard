/**
 * DOM wiring. All the judgement lives in lib/checks.js, lib/decode.js and
 * lib/domains.js; this file only moves values between the page and those
 * functions, and renders findings.
 *
 * Rendering builds DOM nodes rather than HTML strings, because the values
 * displayed include addresses and notes that originate on-chain. Nothing from
 * the network should ever be able to inject markup into the page.
 */

import { CONFIG } from "./config.js";
import { ArcRpc, codeSize } from "./lib/arc.js";
import { analyzeAddress, analyzeTransaction, planLookups } from "./lib/checks.js";
import { analyzeDomain } from "./lib/domains.js";
import { formatUnits, parseUnits } from "./lib/format.js";
import { selector } from "./lib/keccak.js";
import { isValidAddress, normalizeAddress, USDC, CCTP_TOKEN_MESSENGER_V2 } from "./lib/registry.js";

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = value;
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
function renderFindings(result) {
  const frag = document.createDocumentFragment();

  const verdict = h("div", { class: `verdict verdict--${result.findings[0]?.level ?? "info"}` });
  verdict.append(
    h("h2", { text: result.headline }),
    h("p", {
      text: result.findings.length
        ? `${result.findings.length} observation(s). This is a set of signals for you to read, not a verdict.`
        : "No observations at all. Read the limitation notes below before treating that as reassurance.",
    }),
  );
  frag.append(verdict);

  for (const f of result.findings) {
    const article = h("article", { class: `finding finding--${f.level}` });
    article.append(
      h("span", { class: `chip chip--${f.level}`, text: f.level }),
      h("h3", { text: f.title }),
      h("p", { text: f.detail }),
    );
    frag.append(article);
  }
  return frag;
}

function factsList(entries) {
  const dl = h("dl");
  for (const [term, value] of entries) {
    if (value === null || value === undefined || value === "") continue;
    dl.append(h("dt", { text: term }), h("dd", { text: String(value) }));
  }
  return dl;
}

function renderFacts(result) {
  const box = h("section", { class: "facts" }, h("h3", { text: "What was actually read from Arc" }));
  const facts = result.facts ?? {};
  const entries = [];

  if (facts.to) entries.push(["address", facts.to]);
  if (facts.toIsEoa === true) entries.push(["kind", "wallet (no contract code)"]);
  if (facts.toIsEoa === null && facts.to) entries.push(["kind", "not determined"]);
  if (typeof facts.toCodeSize === "number" && facts.toCodeSize > 0) entries.push(["code size", `${facts.toCodeSize} bytes`]);
  if (facts.isContract === true) entries.push(["kind", `contract (${facts.codeSize} bytes)`]);
  if (facts.isOfficial) entries.push(["matches Circle's published list", facts.officialName]);
  if (facts.isTestnetAddress) entries.push(["testnet address", "yes — mainnet has no such contract"]);
  if (facts.minimalProxyTarget) entries.push(["minimal proxy -> implementation", facts.minimalProxyTarget]);
  entries.push([
    "community registry",
    facts.registryChecked ? `${facts.registryReports} report(s)` : "not deployed yet — not checked",
  ]);

  box.append(factsList(entries));
  return box;
}

function renderDecoded(result) {
  const decoded = result.decoded;
  if (!decoded?.signature) return null;
  const box = h("section", { class: "decoded" },
    h("h3", { text: "Decoded calldata" }),
    h("p", { class: "hint", text: `${decoded.label} — ${decoded.signature}` }),
  );
  const table = h("table");
  table.append(h("tr", {}, h("th", { text: "argument" }), h("th", { text: "value" })));
  for (const arg of decoded.argList) {
    let value = arg.value;
    if (typeof value === "bigint") value = value.toString();
    else if (typeof value === "boolean") value = value ? "true" : "false";
    table.append(h("tr", {}, h("td", { text: `${arg.name} (${arg.type})` }), h("td", { text: String(value) })));
  }
  box.append(table);
  return box;
}

function renderError(message) {
  const box = h("div", { class: "verdict verdict--critical error" },
    h("h2", { text: "Could not run the check" }),
    h("p", { text: message }),
  );
  return box;
}

function show(container, ...nodes) {
  container.replaceChildren(...nodes.filter(Boolean));
}

// ---------------------------------------------------------------------------
// Chain connection — refuse to give findings on an unexpected chain
// ---------------------------------------------------------------------------
const rpc = CONFIG.rpcUrl
  ? new ArcRpc({ network: CONFIG.network, url: CONFIG.rpcUrl })
  : new ArcRpc({ network: CONFIG.network });

let chainOk = false;

async function verifyChain() {
  const status = $("chain-status");
  const text = $("chain-text");
  const dot = status.querySelector(".dot");
  try {
    const [chainId, block] = await Promise.all([rpc.chainId(), rpc.getBlockNumber()]);
    if (chainId !== CONFIG.requiredChainId) {
      chainOk = false;
      dot.className = "dot dot--bad";
      text.textContent = `wrong chain: got ${chainId}, expected ${CONFIG.requiredChainId}`;
      return;
    }
    chainOk = true;
    dot.className = "dot dot--ok";
    text.textContent = `Arc mainnet · chain ${chainId} · block ${block.toLocaleString("en-US")}`;
  } catch (error) {
    chainOk = false;
    dot.className = "dot dot--bad";
    text.textContent = `cannot reach Arc RPC — ${error.message}`;
  }
}

function requireChain(container) {
  if (chainOk) return true;
  show(container, renderError(
    "This tool will not analyse a transaction while it cannot confirm it is talking to Arc mainnet. " +
    "Analysing the wrong chain is itself a way to be misled. Reload to retry, or set a working RPC URL in config.js.",
  ));
  return false;
}

// ---------------------------------------------------------------------------
// Transaction checks
// ---------------------------------------------------------------------------
async function gatherFacts({ to, dataHex }) {
  const addresses = planLookups({ to, dataHex });
  const codes = {};
  await Promise.all(
    addresses.map(async (address) => {
      try {
        codes[address] = await rpc.getCode(address);
      } catch {
        // Leave undefined: checks.js treats missing code as "not checked",
        // never as "no contract".
      }
    }),
  );

  let registryReports = null;
  const target = normalizeAddress(to ?? "");
  if (CONFIG.registryAddress && target && isValidAddress(CONFIG.registryAddress)) {
    try {
      registryReports = await rpc.getReportCount(CONFIG.registryAddress, target);
    } catch {
      registryReports = null;
    }
  }
  return { codes, registryReports, network: CONFIG.network };
}

async function checkTransaction({ to, valueWei, dataHex, claim }) {
  const container = $("tx-results");
  if (!requireChain(container)) return;
  if (!to && (!dataHex || dataHex === "0x")) {
    show(container, renderError("Enter the address the transaction is sent to, or at least some calldata."));
    return;
  }
  show(container, h("p", { class: "hint", text: "Reading state from Arc mainnet…" }));
  try {
    const facts = await gatherFacts({ to, dataHex });
    const result = analyzeTransaction({ to, valueWei, dataHex, claim }, facts);
    show(container, renderFindings(result), renderDecoded(result), renderFacts(result));
  } catch (error) {
    show(container, renderError(error.message));
  }
}

async function loadTransactionByHash(hash) {
  const container = $("tx-results");
  if (!requireChain(container)) return;
  show(container, h("p", { class: "hint", text: "Fetching that transaction from Arc…" }));
  try {
    const tx = await rpc.getTransaction(hash);
    if (!tx) {
      show(container, renderError("No transaction with that hash on Arc mainnet. Check the hash, and check you are looking at mainnet (5042), not testnet."));
      return;
    }
    $("tx-to").value = tx.to ?? "";
    $("tx-value").value = formatUnits(BigInt(tx.value ?? "0x0"), 18);
    $("tx-data").value = tx.input ?? "0x";
    await checkTransaction({
      to: tx.to ?? "",
      valueWei: BigInt(tx.value ?? "0x0"),
      dataHex: tx.input ?? "0x",
    });
  } catch (error) {
    show(container, renderError(error.message));
  }
}

// ---------------------------------------------------------------------------
// Address checks
// ---------------------------------------------------------------------------
async function checkAddress(address) {
  const container = $("addr-results");
  if (!requireChain(container)) return;
  const key = normalizeAddress(address);
  if (!key) {
    show(container, renderError("That is not a valid 0x address. It needs 40 hex characters after 0x."));
    return;
  }
  show(container, h("p", { class: "hint", text: "Reading code from Arc mainnet…" }));
  try {
    let codeHex;
    try {
      codeHex = await rpc.getCode(key);
    } catch {
      codeHex = undefined; // report "not checked" rather than guessing
    }
    let registryReports = null;
    if (CONFIG.registryAddress && isValidAddress(CONFIG.registryAddress)) {
      try {
        registryReports = await rpc.getReportCount(CONFIG.registryAddress, key);
      } catch {
        registryReports = null;
      }
    }
    const result = analyzeAddress({ address: key, codeHex, registryReports, network: CONFIG.network });
    show(container, renderFindings(result), renderFacts(result));
  } catch (error) {
    show(container, renderError(error.message));
  }
}

// ---------------------------------------------------------------------------
// Link checks
// ---------------------------------------------------------------------------
function checkLink(input) {
  const container = $("link-results");
  const result = analyzeDomain(input);
  show(container, renderFindings(result));
}

// ---------------------------------------------------------------------------
// Examples — documented Arc scam shapes, loadable in one click
// ---------------------------------------------------------------------------
const ATTACKER = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
// Verified on Arc mainnet: this address has no contract code. (The previous
// value had 23 bytes of code there, which made the "plain payment" example
// misleading — a good reminder to check example data against the real chain.)
const PAYEE = "0x9f8c1d0a6b5b0c8f0e1a2b3c4d5e6f7080910111";
const TESTNET_MESSENGER = "0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA";

const word = (hex) => hex.padStart(64, "0");
const addressWord = (a) => word(a.slice(2).toLowerCase());
const uintWord = (v) => word(BigInt(v).toString(16));

const EXAMPLES = [
  {
    label: "scam · \"bridge\" deposit to a wallet",
    scam: true,
    claim: "bridge",
    note: "\"Send USDC to this address to bridge it.\" There is no contract there.",
    tx: { to: ATTACKER, valueUsdc: "250", dataHex: "0x" },
  },
  {
    label: "scam · USDC transfer called a bridge",
    scam: true,
    claim: "bridge",
    note: "Calls transfer() on USDC directly. Real bridging calls depositForBurn on the TokenMessenger.",
    tx: {
      to: USDC,
      valueUsdc: "0",
      dataHex: selector("transfer(address,uint256)") + addressWord(ATTACKER) + uintWord(250_000_000n),
    },
  },
  {
    label: "scam · testnet address offered as mainnet",
    scam: true,
    claim: "bridge",
    note: "This is Arc's TESTNET TokenMessenger. It has no role on mainnet.",
    tx: { to: TESTNET_MESSENGER, valueUsdc: "0", dataHex: "0x" },
  },
  {
    label: "scam · \"claim rewards\" → unlimited approval",
    scam: true,
    claim: "rewards",
    note: "Dressed as an Arc rewards claim. It is an unlimited approval to a wallet, and Arc has no rewards.",
    tx: {
      to: USDC,
      valueUsdc: "0",
      dataHex: selector("approve(address,uint256)") + addressWord(ATTACKER) + uintWord((1n << 256n) - 1n),
    },
  },
  {
    label: "legit · CCTP bridge-out",
    scam: false,
    claim: "bridge",
    note: "depositForBurn sent to the real Arc TokenMessenger. The tool should NOT cry wolf.",
    tx: {
      to: CCTP_TOKEN_MESSENGER_V2,
      valueUsdc: "0",
      dataHex:
        selector("depositForBurn(uint256,uint32,bytes32,address)") +
        uintWord(250_000_000n) + uintWord(0n) +
        word("00".repeat(12) + PAYEE.slice(2).toLowerCase()) +
        addressWord(USDC),
    },
  },
  {
    label: "neutral · a plain payment",
    scam: false,
    claim: "pay",
    note: "Paying a wallet. Nothing to decode, and that is fine.",
    tx: { to: PAYEE, valueUsdc: "25", dataHex: "0x" },
  },
];

function renderExamples() {
  const row = $("examples");
  for (const example of EXAMPLES) {
    row.append(
      h("button", {
        type: "button",
        class: `example${example.scam ? " example--scam" : ""}`,
        title: example.note,
        text: example.label,
        onclick: () => {
          $("tx-to").value = example.tx.to;
          $("tx-value").value = example.tx.valueUsdc;
          $("tx-data").value = example.tx.dataHex;
          $("tx-claim").value = example.claim;
          checkTransaction({
            to: example.tx.to,
            valueWei: parseUnits(example.tx.valueUsdc, 18),
            dataHex: example.tx.dataHex,
            claim: example.claim,
          });
        },
      }),
    );
  }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
function wireTabs() {
  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => {
      for (const t of document.querySelectorAll(".tab")) {
        t.classList.toggle("is-active", t === tab);
        t.setAttribute("aria-selected", String(t === tab));
      }
      for (const p of document.querySelectorAll(".panel")) {
        p.classList.toggle("is-active", p.id === `panel-${tab.dataset.tab}`);
      }
    });
  }
}

function init() {
  wireTabs();
  renderExamples();
  verifyChain();

  $("tx-form").addEventListener("submit", (event) => {
    event.preventDefault();
    let valueWei = 0n;
    try {
      valueWei = parseUnits($("tx-value").value, 18);
    } catch (error) {
      show($("tx-results"), renderError(`Value is not a number: ${error.message}`));
      return;
    }
    checkTransaction({
      to: $("tx-to").value.trim(),
      valueWei,
      dataHex: $("tx-data").value.trim() || "0x",
      claim: $("tx-claim").value,
    });
  });

  $("tx-clear").addEventListener("click", () => {
    $("tx-to").value = "";
    $("tx-value").value = "";
    $("tx-data").value = "";
    $("tx-claim").value = "unknown";
    $("tx-results").replaceChildren();
  });

  $("tx-load").addEventListener("click", () => {
    const hash = $("tx-hash").value.trim();
    if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
      show($("tx-results"), renderError("A transaction hash is 0x followed by 64 hex characters."));
      return;
    }
    loadTransactionByHash(hash);
  });

  $("addr-form").addEventListener("submit", (event) => {
    event.preventDefault();
    checkAddress($("addr-input").value.trim());
  });

  $("link-form").addEventListener("submit", (event) => {
    event.preventDefault();
    checkLink($("link-input").value.trim());
  });
}

init();

export { checkTransaction, checkAddress, checkLink, codeSize };
