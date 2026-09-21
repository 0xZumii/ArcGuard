import { test } from "node:test";
import assert from "node:assert/strict";

import { keccak256, keccak256Hex, selector } from "../docs/lib/keccak.js";

// These are the vectors that catch the classic mistake: implementing SHA3-256
// (NIST padding) instead of Keccak-256 (Ethereum padding). They differ only in
// the domain-separation byte, and produce completely different digests.
test("keccak256 matches known vectors", () => {
  assert.equal(
    keccak256Hex(""),
    "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    "empty input",
  );
  assert.equal(
    keccak256Hex("abc"),
    "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    "abc",
  );
});

test("keccak256 is not SHA3-256", () => {
  // SHA3-256("") is a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a.
  // If this ever equals that, the padding byte was wrong.
  assert.notEqual(
    keccak256Hex(""),
    "0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
  );
});

test("keccak256 handles inputs longer than one rate block", () => {
  // 136 bytes is exactly one rate block, so 136 and 200 exercise the padding
  // boundary and the multi-block absorb path.
  const a = keccak256(new Uint8Array(136));
  const b = keccak256(new Uint8Array(200));
  assert.equal(a.length, 32);
  assert.equal(b.length, 32);
  assert.notDeepEqual(a, b);
});

// Every selector here was independently derived with evm-audit's pure-Python
// Keccak. If the JS port drifts, these fail.
const SELECTOR_VECTORS = {
  "approve(address,uint256)": "0x095ea7b3",
  "increaseAllowance(address,uint256)": "0x39509351",
  "transfer(address,uint256)": "0xa9059cbb",
  "transferFrom(address,address,uint256)": "0x23b872dd",
  "setApprovalForAll(address,bool)": "0xa22cb465",
  "safeTransferFrom(address,address,uint256)": "0x42842e0e",
  "safeTransferFrom(address,address,uint256,bytes)": "0xb88d4fde",
  "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)": "0xd505accf",
  "approve(address,address,uint160,uint48)": "0x87517c45",
  "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)": "0x2b67b570",
  "depositForBurn(uint256,uint32,bytes32,address)": "0x6fd3504e",
  "depositForBurnWithHook(uint256,uint32,bytes32,address,bytes)": "0xbe37adbc",
  "receiveMessage(bytes,bytes)": "0x57ecfd28",
  "balanceOf(address)": "0x70a08231",
  "decimals()": "0x313ce567",
  "withdraw(uint256)": "0x2e1a7d4d",
};

test("selector derivation matches known on-chain selectors", () => {
  for (const [signature, expected] of Object.entries(SELECTOR_VECTORS)) {
    assert.equal(selector(signature), expected, signature);
  }
});
