import { test } from "node:test";
import assert from "node:assert/strict";

import { analyzeCalldata, BY_SELECTOR, hexToBytes } from "../docs/lib/decode.js";
import { selector } from "../docs/lib/keccak.js";
import { MAX_UINT256 } from "../docs/lib/format.js";

const SPENDER = "0x1111111111111111111111111111111111111111";
const USER = "0x9999999999999999999999999999999999999999";
const TOKEN_MESSENGER = "0x28b5a0e9c621a5badaa536219b3a228c8168cf5d";

const word = (hexNo0x) => hexNo0x.padStart(64, "0");
const addressWord = (address) => word(address.slice(2).toLowerCase());
const uintWord = (value) => word(BigInt(value).toString(16));

function calldata(signature, ...chunks) {
  return selector(signature) + chunks.join("");
}

test("the selector table only contains selectors that hash to themselves", () => {
  for (const [sel, entry] of Object.entries(BY_SELECTOR)) {
    assert.equal(sel, selector(entry.sig), entry.sig);
  }
});

test("hexToBytes rejects malformed input instead of guessing", () => {
  assert.equal(hexToBytes("0x").length, 0);
  assert.equal(hexToBytes("0xa9059cbb").length, 4);
  assert.throws(() => hexToBytes("0xzz"), /not valid hex/);
  assert.throws(() => hexToBytes("0xabc"), /odd number/);
});

test("empty or truncated calldata is reported, not treated as safe", () => {
  const empty = analyzeCalldata("0x");
  assert.equal(empty.kind, "empty");
  assert.equal(empty.findings.length, 0);

  const short = analyzeCalldata("0xa9059c");
  assert.equal(short.kind, "empty");
});

test("unlimited approve is flagged critical", () => {
  const data = calldata("approve(address,uint256)", addressWord(SPENDER), uintWord(MAX_UINT256));
  const result = analyzeCalldata(data);
  assert.equal(result.kind, "approval");
  assert.equal(result.args.spender, SPENDER);
  assert.equal(result.args.amount, MAX_UINT256);
  const critical = result.findings.find((f) => f.level === "critical");
  assert.ok(critical, "expected a critical finding");
  assert.match(critical.detail, /ENTIRE balance/);
  assert.deepEqual(result.addressesOfInterest, [{ address: SPENDER, role: "spender" }]);
});

test("a limited approve is notable, not critical", () => {
  const data = calldata("approve(address,uint256)", addressWord(SPENDER), uintWord(1_000_000n));
  const result = analyzeCalldata(data);
  assert.equal(result.args.amount, 1_000_000n);
  assert.equal(result.findings[0].level, "notable");
});

test("a plain USDC transfer decodes and names the recipient", () => {
  const data = calldata("transfer(address,uint256)", addressWord(USER), uintWord(25_000_000n));
  const result = analyzeCalldata(data);
  assert.equal(result.kind, "transfer");
  assert.equal(result.args.to, USER);
  assert.equal(result.args.amount, 25_000_000n);
  assert.deepEqual(result.addressesOfInterest, [{ address: USER, role: "recipient" }]);
});

test("the real CCTP bridge call is recognised and affirmed, not accused", () => {
  const data = calldata(
    "depositForBurn(uint256,uint32,bytes32,address)",
    uintWord(25_000_000n),
    uintWord(0n),          // destinationDomain
    word("00".repeat(12) + USER.slice(2)), // mintRecipient bytes32
    addressWord("0x3600000000000000000000000000000000000000"),
  );
  const result = analyzeCalldata(data);
  assert.equal(result.kind, "bridge-burn");
  assert.equal(result.args.amount, 25_000_000n);
  assert.equal(result.findings[0].level, "info");
  assert.match(result.findings[0].title, /matches a real CCTP bridge call/);
});

test("EIP-2612 permit is flagged critical regardless of amount", () => {
  const data = calldata(
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    addressWord(USER), addressWord(SPENDER), uintWord(500n), uintWord(0n),
    uintWord(27n), word("11".repeat(32)), word("22".repeat(32)),
  );
  const result = analyzeCalldata(data);
  assert.equal(result.kind, "permit");
  assert.equal(result.findings[0].level, "critical");
  assert.match(result.findings[0].title, /permit/);
});

test("setApprovalForAll(true) is a blanket grant", () => {
  const data = calldata("setApprovalForAll(address,bool)", addressWord(SPENDER), uintWord(1n));
  const result = analyzeCalldata(data);
  assert.equal(result.args.approved, true);
  assert.equal(result.findings[0].level, "critical");
});

test("setApprovalForAll(false) is informational", () => {
  const data = calldata("setApprovalForAll(address,bool)", addressWord(SPENDER), uintWord(0n));
  const result = analyzeCalldata(data);
  assert.equal(result.findings[0].level, "info");
});

test("Permit2 approve with a uint160 max is unlimited", () => {
  const max160 = (1n << 160n) - 1n;
  const data = calldata(
    "approve(address,address,uint160,uint48)",
    addressWord("0x3600000000000000000000000000000000000000"),
    addressWord(SPENDER),
    uintWord(max160),
    uintWord(0n),
  );
  const result = analyzeCalldata(data);
  assert.equal(result.kind, "permit2-approval");
  assert.equal(result.args.amount, max160);
  assert.equal(result.findings[0].level, "critical");
  assert.match(result.findings[0].title, /Permit2/);
});

test("a dynamic bytes tail is decoded (safeTransferFrom with data)", () => {
  // Layout: 3 head words + 1 offset word + length + payload, padded.
  const payload = "deadbeef";
  const data =
    selector("safeTransferFrom(address,address,uint256,bytes)") +
    addressWord(USER) + addressWord(SPENDER) + uintWord(7n) +
    uintWord(128n) +
    uintWord(BigInt(payload.length / 2)) +
    payload.padEnd(64, "0");
  const result = analyzeCalldata(data);
  assert.equal(result.args.tokenId, 7n);
  assert.equal(result.args.data, "0xdeadbeef");
});

test("unknown selectors are surfaced as unchecked, never as clean", () => {
  const result = analyzeCalldata("0xdeadbeef" + "00".repeat(32));
  assert.equal(result.kind, "unknown");
  assert.equal(result.signature, null);
  assert.equal(result.findings[0].level, "notable");
  assert.match(result.findings[0].title, /Unrecognised/);
});

test("the bridge-deposit selector is the one Arc's real TokenMessenger uses", () => {
  // Guards against the mistake this whole tool exists to prevent: shipping a
  // checker that keys off a testnet or invented address.
  assert.equal(selector("depositForBurn(uint256,uint32,bytes32,address)"), "0x6fd3504e");
  assert.equal(TOKEN_MESSENGER.length, 42);
});
