import { test } from "node:test";
import assert from "node:assert/strict";

import { analyzeDomain, editDistance, extractHost } from "../docs/lib/domains.js";

const titles = (r) => r.findings.map((f) => f.title).join(" | ");
const top = (r) => r.findings[0];

test("extractHost normalises URLs, ports, defanged forms and case", () => {
  assert.equal(extractHost("https://ARC.IO/path?q=1"), "arc.io");
  assert.equal(extractHost("arc.io:443"), "arc.io");
  assert.equal(extractHost("governance-arc[.]com"), "governance-arc.com");
  assert.equal(extractHost("  Example.COM. "), "example.com");
  assert.equal(extractHost("https://user:pw@arc.io/x"), "arc.io");
  assert.equal(extractHost("notadomain"), null);
  assert.equal(extractHost(""), null);
});

test("editDistance catches single-character typosquats", () => {
  assert.equal(editDistance("arc.io", "arrc.io"), 1);
  assert.equal(editDistance("arc.io", "arc.io"), 0);
  assert.equal(editDistance("a", "abc"), 2);
});

test("official and official-subdomain hosts pass cleanly", () => {
  for (const host of ["arc.io", "docs.arc.io", "portal.arc.io", "explorer.arc.io"]) {
    const result = analyzeDomain(host);
    assert.equal(result.official, true, host);
    assert.equal(top(result).level, "info", host);
  }
});

test("the documented drainer domain is named and flagged critical", () => {
  const result = analyzeDomain("https://governance-arc.com/vote");
  assert.equal(result.knownDrainer, true);
  assert.equal(top(result).level, "critical");
  assert.match(titles(result), /Known Arc drainer domain/);
});

test("brand plus lure word is critical even for unknown domains", () => {
  const result = analyzeDomain("arc-claim.com");
  const f = result.findings.find((x) => /Brand \+ lure word/.test(x.title));
  assert.ok(f, titles(result));
  assert.equal(f.level, "critical");
  assert.match(f.detail, /not publicly tradable|no airdrop/);
});

test("a lookalike of the real domain is critical", () => {
  const result = analyzeDomain("arrc.io");
  const f = result.findings.find((x) => /Lookalike/.test(x.title));
  assert.ok(f, titles(result));
  assert.equal(f.level, "critical");
});

test("a brand mention without an official domain is high", () => {
  const result = analyzeDomain("arc.io.evil.com");
  assert.equal(result.official, false);
  assert.ok(result.findings.some((f) => f.level === "high"), titles(result));
});

test("punycode homoglyph hosts are flagged", () => {
  const result = analyzeDomain("xn--rce-eka.io");
  assert.ok(result.findings.some((f) => /Punycode/.test(f.title)), titles(result));
});

test("an ordinary unrelated domain is only 'not official'", () => {
  const result = analyzeDomain("example.com");
  assert.equal(result.official, false);
  assert.equal(result.knownDrainer, false);
  assert.deepEqual(result.findings.map((f) => f.level), ["notable"]);
});

test("a non-domain input is rejected with guidance, not a verdict", () => {
  const result = analyzeDomain("hello world");
  assert.equal(result.host, null);
  assert.match(top(result).title, /Not a domain/);
});
