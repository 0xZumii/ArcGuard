import { test } from "node:test";
import assert from "node:assert/strict";

import { analyzeAddress, analyzeTransaction, minimalProxyTarget, planLookups } from "../docs/lib/checks.js";
import { selector } from "../docs/lib/keccak.js";
import { MAX_UINT256 } from "../docs/lib/format.js";
import {
  CCTP_TOKEN_MESSENGER_V2,
  PERMIT2,
  USDC,
} from "../docs/lib/registry.js";

const VICTIM = "0x9999999999999999999999999999999999999999";
const ATTACKER = "0x1111111111111111111111111111111111111111";

const word = (hex) => hex.padStart(64, "0");
const addressWord = (a) => word(a.slice(2).toLowerCase());
const uintWord = (v) => word(BigInt(v).toString(16));
const calldata = (sig, ...chunks) => selector(sig) + chunks.join("");

const titles = (result) => result.findings.map((f) => f.title).join(" | ");
const hasLevel = (result, level) => result.findings.some((f) => f.level === level);
const findByTitle = (result, re) => result.findings.find((f) => re.test(f.title));

test("a plain USDC payment to a wallet is quiet, because that is also what a payment looks like", () => {
  const result = analyzeTransaction(
    { to: ATTACKER, valueWei: 50_000_000_000_000_000_000n, dataHex: "0x", claim: "pay" },
    { codes: { [ATTACKER]: "0x" } },
  );
  assert.equal(hasLevel(result, "critical"), false, titles(result));
  assert.ok(findByTitle(result, /Native USDC transfer to a wallet/), titles(result));
  assert.ok(findByTitle(result, /claim matches the transaction/), titles(result));
});

test("the same payment becomes critical once it is called a bridge", () => {
  const result = analyzeTransaction(
    { to: ATTACKER, valueWei: 10n ** 18n, dataHex: "0x", claim: "bridge" },
    { codes: { [ATTACKER]: "0x" } },
  );
  const f = findByTitle(result, /It does not\./);
  assert.ok(f, titles(result));
  assert.equal(f.level, "critical");
  assert.match(f.detail, /depositForBurn/);
  assert.equal(result.claim, "bridge");
});

test("an unknown claim leaves the payment unflagged", () => {
  const result = analyzeTransaction(
    { to: ATTACKER, valueWei: 10n ** 18n, dataHex: "0x" },
    { codes: { [ATTACKER]: "0x" } },
  );
  assert.equal(hasLevel(result, "critical"), false);
  assert.equal(result.claim, "unknown");
});

test("value plus calldata to a wallet says the calldata is discarded", () => {
  const result = analyzeTransaction(
    {
      to: ATTACKER,
      valueWei: 10n ** 18n,
      dataHex: calldata("transfer(address,uint256)", addressWord(VICTIM), uintWord(1000n)),
    },
    { codes: { [ATTACKER]: "0x" } },
  );
  assert.ok(findByTitle(result, /calldata attached/), titles(result));
});

test("a plain native transfer to a contract is only notable", () => {
  const result = analyzeTransaction(
    { to: VICTIM, valueWei: 10n ** 18n, dataHex: "0x" },
    { codes: { [VICTIM]: "0x6080" } },
  );
  assert.equal(hasLevel(result, "critical"), false);
  assert.ok(findByTitle(result, /Sends native USDC to a contract/));
});

test("UNKNOWN contract status is never rendered as an EOA", () => {
  // This is the failure mode that would make the tool untrustworthy: an RPC
  // hiccup must not turn into "this is a wallet address, do not send".
  const result = analyzeTransaction(
    { to: ATTACKER, valueWei: 10n ** 18n, dataHex: "0x" },
    { codes: {} }, // nothing fetched
  );
  assert.equal(hasLevel(result, "critical"), false);
  assert.ok(findByTitle(result, /Contract status not checked/), titles(result));
  assert.equal(result.facts.toIsEoa, null);
});

test("transfer() on the USDC ERC-20 is called out as a payment, not a bridge", () => {
  const data = calldata("transfer(address,uint256)", addressWord(ATTACKER), uintWord(5_000_000n));
  const result = analyzeTransaction({ to: USDC, valueWei: 0n, dataHex: data }, { codes: { [USDC]: "0x60" } });
  const f = findByTitle(result, /plain USDC transfer, not a bridge/);
  assert.ok(f, titles(result));
  assert.equal(f.level, "high");
  assert.match(f.detail, /depositForBurn/);
  assert.match(f.detail, new RegExp(CCTP_TOKEN_MESSENGER_V2));
});

test("a USDC transfer called a bridge is critical", () => {
  const data = calldata("transfer(address,uint256)", addressWord(ATTACKER), uintWord(5_000_000n));
  const result = analyzeTransaction(
    { to: USDC, valueWei: 0n, dataHex: data, claim: "bridge" },
    { codes: { [USDC]: "0x60" } },
  );
  const f = findByTitle(result, /You were told this bridges\. It does not\./);
  assert.ok(f, titles(result));
  assert.equal(f.level, "critical");
});

test("a 'rewards claim' is critical even before looking at the calldata", () => {
  const data = calldata("approve(address,uint256)", addressWord(ATTACKER), uintWord(MAX_UINT256));
  const result = analyzeTransaction(
    { to: USDC, valueWei: 0n, dataHex: data, claim: "rewards" },
    { codes: { [USDC]: "0x60", [ATTACKER]: "0x" } },
  );
  const f = findByTitle(result, /Arc has no rewards or airdrop to claim/);
  assert.ok(f, titles(result));
  assert.equal(f.level, "critical");
});

test("'connect my wallet' that moves funds is critical", () => {
  const data = calldata("transfer(address,uint256)", addressWord(ATTACKER), uintWord(1n));
  const result = analyzeTransaction(
    { to: USDC, valueWei: 0n, dataHex: data, claim: "approve" },
    { codes: { [USDC]: "0x60" } },
  );
  const f = findByTitle(result, /Connecting should not move funds/);
  assert.ok(f, titles(result));
  assert.equal(f.level, "critical");
});

test("a bridge claim that does call depositForBurn on the real contract is affirmed", () => {
  const data = calldata(
    "depositForBurn(uint256,uint32,bytes32,address)",
    uintWord(1_000_000n), uintWord(0n), word("00".repeat(12) + ATTACKER.slice(2)),
    addressWord(USDC),
  );
  const result = analyzeTransaction(
    { to: CCTP_TOKEN_MESSENGER_V2, valueWei: 0n, dataHex: data, claim: "bridge" },
    { codes: { [CCTP_TOKEN_MESSENGER_V2]: "0x6080" } },
  );
  assert.equal(hasLevel(result, "critical"), false, titles(result));
  assert.ok(findByTitle(result, /claim matches the transaction/), titles(result));
});

test("an unrecognised claim value falls back to unknown rather than throwing", () => {
  const result = analyzeTransaction(
    { to: USDC, valueWei: 0n, dataHex: "0x", claim: "definitely-not-a-claim" },
    { codes: { [USDC]: "0x60" } },
  );
  assert.equal(result.claim, "unknown");
});

test("transfer() on an unrecognised token raises the no-public-token fact", () => {
  const fakeArc = "0xdead000000000000000000000000000000000001";
  const data = calldata("transfer(address,uint256)", addressWord(ATTACKER), uintWord(1n));
  const result = analyzeTransaction({ to: fakeArc, valueWei: 0n, dataHex: data }, { codes: { [fakeArc]: "0x6080" } });
  const f = findByTitle(result, /Token transfer on an unrecognised contract/);
  assert.ok(f, titles(result));
  assert.match(f.detail, /not publicly tradable|not publicly|not Circle's ARC/);
});

test("an approval whose spender is a wallet is critical", () => {
  const data = calldata("approve(address,uint256)", addressWord(ATTACKER), uintWord(1_000_000n));
  const result = analyzeTransaction(
    { to: USDC, valueWei: 0n, dataHex: data },
    { codes: { [USDC]: "0x60", [ATTACKER]: "0x" } },
  );
  const f = findByTitle(result, /approval target is not a contract/);
  assert.ok(f, titles(result));
  assert.equal(f.level, "critical");
});

test("an unlimited approval warns about persistence", () => {
  const data = calldata("approve(address,uint256)", addressWord(ATTACKER), uintWord(MAX_UINT256));
  const result = analyzeTransaction(
    { to: USDC, valueWei: 0n, dataHex: data },
    { codes: { [USDC]: "0x60", [ATTACKER]: "0x6080" } },
  );
  assert.ok(findByTitle(result, /Unlimited approval/));
  assert.ok(findByTitle(result, /Prefer a exact allowance/));
});

test("an approval to the real Permit2 is recognised as normal", () => {
  const data = calldata("approve(address,uint256)", addressWord(PERMIT2), uintWord(1_000_000n));
  const result = analyzeTransaction(
    { to: USDC, valueWei: 0n, dataHex: data },
    { codes: { [USDC]: "0x60", [PERMIT2]: "0x6080" } },
  );
  assert.ok(findByTitle(result, /Spender is the real Permit2/), titles(result));
});

test("a TESTNET address presented on mainnet is critical", () => {
  const testnetMessenger = "0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA";
  const result = analyzeTransaction(
    { to: testnetMessenger, valueWei: 0n, dataHex: "0x" },
    { codes: { [testnetMessenger.toLowerCase()]: "0x6080" }, network: "mainnet" },
  );
  const f = findByTitle(result, /TESTNET address/);
  assert.ok(f, titles(result));
  assert.equal(f.level, "critical");
  assert.equal(result.facts.isTestnetAddress, true);
});

test("the real CCTP TokenMessenger is recognised", () => {
  const result = analyzeTransaction(
    { to: CCTP_TOKEN_MESSENGER_V2, valueWei: 0n, dataHex: "0x" },
    { codes: { [CCTP_TOKEN_MESSENGER_V2]: "0x6080" } },
  );
  assert.equal(result.facts.isOfficial, true);
  assert.match(titles(result), /Recognised Arc contract: CCTP TokenMessengerV2/);
});

test("depositForBurn aimed at the wrong contract is critical", () => {
  const wrong = "0x2222222222222222222222222222222222222222";
  const data = calldata(
    "depositForBurn(uint256,uint32,bytes32,address)",
    uintWord(1_000_000n), uintWord(0n), word("00".repeat(12) + ATTACKER.slice(2)),
    addressWord(USDC),
  );
  const result = analyzeTransaction({ to: wrong, valueWei: 0n, dataHex: data }, { codes: { [wrong]: "0x6080" } });
  const f = findByTitle(result, /Bridge call aimed at the wrong contract/);
  assert.ok(f, titles(result));
  assert.equal(f.level, "critical");
});

test("depositForBurn at the real TokenMessenger is affirmed", () => {
  const data = calldata(
    "depositForBurn(uint256,uint32,bytes32,address)",
    uintWord(1_000_000n), uintWord(0n), word("00".repeat(12) + ATTACKER.slice(2)),
    addressWord(USDC),
  );
  const result = analyzeTransaction(
    { to: CCTP_TOKEN_MESSENGER_V2, valueWei: 0n, dataHex: data },
    { codes: { [CCTP_TOKEN_MESSENGER_V2]: "0x6080" } },
  );
  assert.ok(findByTitle(result, /real CCTP TokenMessenger/), titles(result));
  assert.equal(hasLevel(result, "critical"), false);
});

test("on-chain reports on the recipient escalate the verdict", () => {
  const result = analyzeTransaction(
    { to: ATTACKER, valueWei: 10n ** 18n, dataHex: "0x" },
    { codes: { [ATTACKER]: "0x6080" }, registryReports: 4 },
  );
  const f = findByTitle(result, /4 public report/);
  assert.ok(f, titles(result));
  assert.equal(f.level, "critical");
});

test("planLookups asks for the recipient and every counterparty in the calldata", () => {
  const data = calldata("approve(address,uint256)", addressWord(ATTACKER), uintWord(1n));
  const lookups = planLookups({ to: USDC, dataHex: data });
  assert.ok(lookups.includes(USDC));
  assert.ok(lookups.includes(ATTACKER));
});

test("minimal proxy detection finds the implementation address", () => {
  const impl = "1234567890abcdef1234567890abcdef12345678";
  const code = "0x363d3d373d3d3d363d73" + impl + "5af43d82803e903d91602b57fd5bf3";
  assert.equal(minimalProxyTarget(code), "0x" + impl);
  assert.equal(minimalProxyTarget("0x6080"), null);
});

test("address mode: a fresh minimal proxy is flagged and the implementation named", () => {
  const impl = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";
  const code = "0x363d3d373d3d3d363d73" + impl + "5af43d82803e903d91602b57fd5bf3";
  const result = analyzeAddress({ address: ATTACKER, codeHex: code });
  const f = findByTitle(result, /Minimal proxy/);
  assert.ok(f, titles(result));
  assert.match(f.detail, new RegExp(impl));
});

test("address mode: an EOA claiming to be infrastructure is high", () => {
  const result = analyzeAddress({ address: ATTACKER, codeHex: "0x" });
  const f = findByTitle(result, /No contract code/);
  assert.ok(f);
  assert.equal(f.level, "high");
});

test("address mode: an unreadable address is 'not checked', never 'clean'", () => {
  const result = analyzeAddress({ address: ATTACKER });
  assert.equal(result.facts.isContract, null);
  assert.ok(findByTitle(result, /Could not read the code/));
});

test("the headline never claims safety", () => {
  const result = analyzeTransaction(
    { to: USDC, valueWei: 0n, dataHex: "0x" },
    { codes: { [USDC]: "0x60" } },
  );
  assert.match(result.headline, /not the same as safe/);
});
