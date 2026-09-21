import { test } from "node:test";
import assert from "node:assert/strict";

import { LEVELS, countByLevel, finding, sortFindings, worstLevel } from "../docs/lib/findings.js";

const f = (level) => finding(level, `${level} title`, "detail");

test("finding rejects an unknown level rather than silently accepting it", () => {
  assert.throws(() => finding("severe", "x", "y"), /unknown level/);
  for (const level of Object.keys(LEVELS)) {
    assert.equal(finding(level, "t", "d").level, level);
  }
});

/**
 * Regression test. An earlier implementation returned ORDER[worst] where worst
 * was already a level string, so worstLevel always came back undefined and every
 * headline silently degraded to "nothing alarming". The page test caught it;
 * this keeps it caught.
 */
test("worstLevel returns the most severe level, not undefined", () => {
  assert.equal(worstLevel([]), "info");
  assert.equal(worstLevel([f("info")]), "info");
  assert.equal(worstLevel([f("info"), f("notable")]), "notable");
  assert.equal(worstLevel([f("notable"), f("critical"), f("high")]), "critical");
  assert.equal(worstLevel([f("high"), f("notable")]), "high");
});

test("worstLevel is defined for every level", () => {
  for (const level of Object.keys(LEVELS)) {
    const result = worstLevel([f(level)]);
    assert.equal(typeof result, "string", level);
    assert.ok(result in LEVELS, `${level} -> ${result}`);
  }
});

test("sortFindings is most severe first and leaves the input alone", () => {
  const input = [f("info"), f("critical"), f("notable"), f("high")];
  const sorted = sortFindings(input);
  assert.deepEqual(sorted.map((x) => x.level), ["critical", "high", "notable", "info"]);
  assert.deepEqual(input.map((x) => x.level), ["info", "critical", "notable", "high"], "input mutated");
});

test("countByLevel counts every level, including zeros", () => {
  const counts = countByLevel([f("critical"), f("critical"), f("info")]);
  assert.deepEqual(counts, { critical: 2, high: 0, notable: 0, info: 1 });
});

test("findings carry extra evidence through the model", () => {
  const withEvidence = finding("high", "t", "d", { source: "on-chain", why: "because" });
  assert.equal(withEvidence.source, "on-chain");
  assert.equal(withEvidence.why, "because");
});
