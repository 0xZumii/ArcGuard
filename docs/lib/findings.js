/**
 * One finding model, shared by every checker so the UI renders a single shape.
 *
 * A finding is an observation for a human, never a verdict. The tool this grew
 * out of (evm-audit) made that a rule, and it holds here: `level` describes how
 * much attention something deserves, not whether a transaction is "safe".
 */

export const LEVELS = Object.freeze({
  critical: 4,
  high: 3,
  notable: 2,
  info: 1,
});

/**
 * @param {"critical"|"high"|"notable"|"info"} level
 * @param {string} title short, scannable
 * @param {string} detail what was actually observed, in plain language
 * @param {object} [extra] optional { evidence, source, why }
 */
export function finding(level, title, detail, extra = {}) {
  if (!(level in LEVELS)) throw new Error(`unknown level: ${level}`);
  return { level, title, detail, ...extra };
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) => LEVELS[b.level] - LEVELS[a.level]);
}

export function worstLevel(findings) {
  if (!findings.length) return "info";
  // NOTE: reduce returns a level *string*; indexing ORDER by it would yield
  // undefined and silently downgrade every headline. Verified by
  // test/findings.test.js and scripts/test-page.mjs.
  return findings.reduce((worst, f) => (LEVELS[f.level] > LEVELS[worst] ? f.level : worst), "info");
}

export function countByLevel(findings) {
  const counts = { critical: 0, high: 0, notable: 0, info: 0 };
  for (const f of findings) counts[f.level] += 1;
  return counts;
}
