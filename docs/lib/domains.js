/**
 * Domain checking.
 *
 * This layer exists because the documented Arc drainer (governance-arc.com) never
 * touches a malicious *contract* — it clones the real Arc front end and drains on
 * wallet connection. No amount of bytecode inspection catches that. What does
 * catch it is recognising that the domain is not Arc's, and that the thing it
 * offers does not exist.
 *
 * The list is a seed, not a feed, and the UI says so. Edit KNOWN_DRAINER_DOMAINS
 * in registry.js to extend it.
 */

import {
  KNOWN_DRAINER_DOMAINS,
  LURE_WORDS,
  OFFICIAL_DOMAINS,
  isKnownDrainerDomain,
  isOfficialDomain,
} from "./registry.js";
import { finding } from "./findings.js";

/** Accepts a URL, a bare host, or a defanged form like "governance-arc[.]com". */
export function extractHost(input) {
  if (typeof input !== "string") return null;
  let value = input.trim().toLowerCase();
  if (!value) return null;
  value = value.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".").replace(/\s+/g, "");
  value = value.replace(/^[a-z]+:\/\//, "");
  value = value.split("/")[0].split("?")[0].split("#")[0];
  value = value.replace(/^[^@]*@/, ""); // strip user:pass@
  value = value.split(":")[0]; // strip port
  value = value.replace(/\.$/, "");
  if (!value.includes(".")) return null;
  return value;
}

/**
 * The words a hostname is built from, excluding the TLD. Splits on hyphens as
 * well as dots, because the lure is usually the hyphenated half: "arc-claim.com"
 * is ["arc", "claim"], not ["arc-claim"].
 */
function labels(host) {
  const parts = host.split(".");
  const registrable = parts.slice(0, Math.max(1, parts.length - 1)).join(".");
  return registrable.split(/[.-]/).filter(Boolean);
}

/** True if the host is, or is a subdomain of, an official domain. */
function coversOfficial(host) {
  return OFFICIAL_DOMAINS.some((official) => host === official || host.endsWith(`.${official}`));
}

/** Levenshtein distance, small strings only. Used to catch arc.io lookalikes. */
export function editDistance(a, b) {
  const rows = a.length + 1;
  const cols = b.length + 1;
  let prev = Array.from({ length: cols }, (_, i) => i);
  for (let i = 1; i < rows; i++) {
    const curr = [i, ...new Array(cols - 1).fill(0)];
    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    prev = curr;
  }
  return prev[cols - 1];
}

/**
 * Brand and lure fused into a single label: "arcclaim", "airdroparc",
 * "arcrewards". Scammers concatenate to dodge the hyphen/word-boundary rules,
 * and those forms were previously only reported as "not an official domain".
 *
 * Precision matters more than recall here. The rule requires the label to be
 * *exactly* brand + lure (tolerating a trailing plural "s"):
 *
 *   arcclaim    -> "claim" removed -> "arc"      -> flagged
 *   airdroparc  -> "airdrop" removed -> "arc"    -> flagged
 *   arcaderewards -> "rewards" removed -> "arcade" -> NOT flagged
 *   arcscan / arcguard                           -> no lure -> NOT flagged
 *
 * That last pair is the point: arcscan.app appears in Arc's own docs, and a
 * tool that flagged it would be crying wolf.
 */
function compoundBrandLure(host) {
  const parts = host.split(".");
  const words = parts.slice(0, Math.max(1, parts.length - 1)).join(".").split(/[.-]/).filter(Boolean);
  for (const label of words) {
    for (const lure of LURE_WORDS) {
      if (!label.includes(lure)) continue;
      const remainder = label.replace(lure, "").replace(/s$/, "");
      if (remainder === "arc" || remainder === "circle") {
        return { label, lure };
      }
    }
  }
  return null;
}

export function analyzeDomain(input) {
  const host = extractHost(input);
  if (!host) {
    return {
      host: null,
      findings: [finding("info", "Not a domain",
        "Enter a hostname (for example: arc.io) or a full URL to check where a link really points.")],
    };
  }

  const findings = [];
  const lureHits = LURE_WORDS.filter((word) => labels(host).includes(word));
  const mentionsBrand = /(^|[^a-z])(arc|circle)([^a-z]|$)/.test(host.replace(/\./g, "-"));
  const fused = compoundBrandLure(host);

  if (host.startsWith("xn--") || host.includes(".xn--")) {
    findings.push(finding("high", "Punycode domain",
      "This hostname contains punycode (xn--). It renders as different characters than it actually is, " +
      "which is a standard homoglyph trick. Read the raw form, not the pretty one."));
  }

  if (isOfficialDomain(host) || coversOfficial(host)) {
    findings.push(finding("info", "Official Arc/Circle domain",
      `${host} is on the official list. Note that even this is not a promise about a specific transaction — ` +
      `only that the domain is the real one.`));
    return { host, findings, official: true, knownDrainer: false };
  }

  if (isKnownDrainerDomain(host)) {
    findings.push(finding("critical", "Known Arc drainer domain",
      `${host} is a documented Arc drainer: it clones the Arc front end and offers a fake "Community Rewards" ` +
      `vote, then drains the wallet on connection. Do not connect. If you already did, revoke approvals and ` +
      `move remaining funds with a fresh wallet.`));
    return { host, findings, official: false, knownDrainer: true };
  }

  findings.push(finding("notable", "Not an official Arc domain",
    `${host} is not on the Arc/Circle official list. That is expected for third-party apps, but ` +
    `it means nobody here can vouch for it. Verify it against the project's own docs before connecting a wallet.`));

  if (mentionsBrand && lureHits.length > 0) {
    findings.push(finding("critical", "Brand + lure word in the hostname",
      `The hostname combines Arc/Circle branding with "${lureHits.join('", "')}". ` +
      `Worth knowing: Circle has announced no rewards programme and no airdrop for Arc, and the ARC asset ` +
      `is not publicly tradable, so a site asking you to ` +
      `claim, vote or stake on those terms is describing something that does not exist. ` +
      `governance-arc.com is the documented example.`));
  } else if (fused) {
    findings.push(finding("critical", "Brand fused with a lure word in the hostname",
      `"${fused.label}" is Arc/Circle branding welded onto "${fused.lure}" — no hyphen, so the word-boundary ` +
      `check does not see it. This is a deliberate dodge, and it is what "arcclaim", "arcrewards" and ` +
      `"airdroparc" style domains look like. Circle has announced no airdrop and no rewards programme for ` +
      `Arc, and the ARC asset is not publicly tradable, so anything these offer you does not exist.`));
  } else if (mentionsBrand) {
    findings.push(finding("high", "Uses the Arc/Circle name without being official",
      `"${host}" references Arc or Circle but is not an official domain. The real Arc domains are: ` +
      `${OFFICIAL_DOMAINS.slice(0, 6).join(", ")}. Verify every link against docs.arc.io, never against ` +
      `a link someone sent you.`));
  } else if (lureHits.length > 0) {
    findings.push(finding("notable", "Offers something Arc does not have",
      `The hostname mentions "${lureHits.join('", "')}". Circle has announced no airdrop and no rewards ` +
      `programme for Arc, so check whether the offer depends on one.`));
  }

  // Typosquats of the real thing: arc.io, circle.com, portal.arc.io, ...
  const nearMisses = ["arc.io", "circle.com", "portal.arc.io"].filter(
    (brand) => host !== brand && editDistance(host, brand) <= 2,
  );
  if (nearMisses.length > 0) {
    findings.push(finding("critical", "Lookalike of an official domain",
      `${host} is one or two characters from ${nearMisses.join(", ")}. Typosquat domains are registered ` +
      `in bulk around launches and are the cheapest part of this attack.`));
  }

  return { host, findings, official: false, knownDrainer: false, knownDrainerList: KNOWN_DRAINER_DOMAINS };
}
