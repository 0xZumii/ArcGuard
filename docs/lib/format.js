/** Small formatting helpers. Kept apart from logic so they stay testable. */

export const MAX_UINT256 = (1n << 256n) - 1n;
export const MAX_UINT160 = (1n << 160n) - 1n;
export const MAX_UINT48 = (1n << 48n) - 1n;

/** Format a base-unit integer as a decimal string. BigInt in, string out. */
export function formatUnits(value, decimals) {
  if (value === null || value === undefined) return "-";
  const v = BigInt(value);
  const negative = v < 0n;
  const abs = negative ? -v : v;
  const base = 10n ** BigInt(decimals);
  const whole = abs / base;
  const frac = abs % base;
  let out = whole.toString();
  if (frac > 0n) {
    out += "." + frac.toString().padStart(decimals, "0").replace(/0+$/, "");
  }
  return (negative ? "-" : "") + out;
}

/** Parse a decimal string like "12.5" into base units. Inverse of formatUnits. */
export function parseUnits(input, decimals) {
  if (input === null || input === undefined) return 0n;
  const s = String(input).trim().replace(/,/g, "");
  if (s === "") return 0n;
  if (!/^\d*\.?\d*$/.test(s)) throw new Error(`"${s}" is not a number`);
  const [whole = "0", frac = ""] = s.split(".");
  const padded = (frac + "0".repeat(decimals)).slice(0, decimals);
  return BigInt(whole || "0") * 10n ** BigInt(decimals) + BigInt(padded || "0");
}

export function formatAddress(address, chars = 4) {
  if (typeof address !== "string" || address.length < 2 + chars * 2) return address ?? "-";
  return `${address.slice(0, 2 + chars)}…${address.slice(-chars)}`;
}

export function formatInt(value) {
  if (value === null || value === undefined) return "-";
  return BigInt(value).toLocaleString("en-US");
}

/** "unlimited" reads better than a 78-digit number in a warning. */
export function describeAmount(value, decimals, maxValues) {
  const maxes = (maxValues ?? [MAX_UINT256]).map(BigInt);
  if (maxes.includes(BigInt(value))) return "UNLIMITED (max uint)";
  return formatUnits(value, decimals);
}

export function shortHex(hex, head = 10) {
  if (typeof hex !== "string") return "-";
  return hex.length <= head + 3 ? hex : `${hex.slice(0, head)}…`;
}
