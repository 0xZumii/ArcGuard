/**
 * Calldata decoding: what is this transaction actually asking you to authorise?
 *
 * Selectors are DERIVED with keccak256 at load time, not pasted in as constants.
 * tests/decode.test.js asserts each derived selector equals the value already
 * known on-chain (e.g. transfer(address,uint256) -> 0xa9059cbb), so a bug in the
 * hashing code cannot silently make the tool point at the wrong function.
 *
 * The decoder is deliberately small: it handles static head words plus one
 * dynamic `bytes` tail, which covers every function we care about here.
 */

import { selector } from "./keccak.js";
import { finding } from "./findings.js";
import { MAX_UINT256, MAX_UINT160 } from "./format.js";

/**
 * kind drives the security logic in checks.js:
 *   approval | operator | transfer | transfer-from | permit
 *   permit2-approval | permit2-permit | bridge-burn | bridge-receive | other
 */
const SIGNATURES = {
  "transfer(address,uint256)": {
    label: "ERC-20 transfer", kind: "transfer", risk: "notable",
    params: ["address", "uint256"], names: ["to", "amount"],
  },
  "transferFrom(address,address,uint256)": {
    label: "ERC-20 transferFrom", kind: "transfer-from", risk: "notable",
    params: ["address", "address", "uint256"], names: ["from", "to", "amount"],
  },
  "approve(address,uint256)": {
    label: "ERC-20 approve", kind: "approval", risk: "high",
    params: ["address", "uint256"], names: ["spender", "amount"],
  },
  "increaseAllowance(address,uint256)": {
    label: "ERC-20 increaseAllowance", kind: "approval", risk: "high",
    params: ["address", "uint256"], names: ["spender", "amount"],
  },
  "setApprovalForAll(address,bool)": {
    label: "ERC-721/1155 setApprovalForAll", kind: "operator", risk: "high",
    params: ["address", "bool"], names: ["operator", "approved"],
  },
  "safeTransferFrom(address,address,uint256)": {
    label: "ERC-721 safeTransferFrom", kind: "transfer", risk: "notable",
    params: ["address", "address", "uint256"], names: ["from", "to", "tokenId"],
  },
  "safeTransferFrom(address,address,uint256,bytes)": {
    label: "ERC-721 safeTransferFrom (with data)", kind: "transfer", risk: "notable",
    params: ["address", "address", "uint256", "bytes"], names: ["from", "to", "tokenId", "data"],
  },
  "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)": {
    label: "EIP-2612 permit", kind: "permit", risk: "high",
    params: ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
    names: ["owner", "spender", "value", "deadline", "v", "r", "s"],
  },
  "approve(address,address,uint160,uint48)": {
    label: "Permit2 approve", kind: "permit2-approval", risk: "high",
    params: ["address", "address", "uint160", "uint48"],
    names: ["token", "spender", "amount", "expiration"],
  },
  "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)": {
    label: "Permit2 permit (signature)", kind: "permit2-permit", risk: "high",
    params: ["address", "address", "uint160", "uint48", "uint48", "address", "uint256", "bytes"],
    names: ["owner", "token", "amount", "expiration", "nonce", "spender", "sigDeadline", "signature"],
  },
  // --- CCTP: the function a REAL Arc bridge calls. Recognising it is the point. ---
  "depositForBurn(uint256,uint32,bytes32,address)": {
    label: "CCTP depositForBurn", kind: "bridge-burn", risk: "notable",
    params: ["uint256", "uint32", "bytes32", "address"],
    names: ["amount", "destinationDomain", "mintRecipient", "burnToken"],
  },
  "depositForBurnWithHook(uint256,uint32,bytes32,address,bytes)": {
    label: "CCTP depositForBurnWithHook", kind: "bridge-burn", risk: "notable",
    params: ["uint256", "uint32", "bytes32", "address", "bytes"],
    names: ["amount", "destinationDomain", "mintRecipient", "burnToken", "hookData"],
  },
  "receiveMessage(bytes,bytes)": {
    label: "CCTP receiveMessage", kind: "bridge-receive", risk: "notable",
    params: ["bytes", "bytes"], names: ["message", "attestation"],
  },
};

/** @type {Record<string, {sig:string} & Record<string, unknown>>} */
export const BY_SELECTOR = Object.fromEntries(
  Object.entries(SIGNATURES).map(([sig, meta]) => [selector(sig), { sig, ...meta }]),
);

/** Exposed so tests can check the table against known on-chain selectors. */
export const SIGNATURE_TABLE = SIGNATURES;

const STATIC = new Set(["address", "bool", "bytes32", "uint8", "uint32", "uint48", "uint160", "uint256"]);

export function hexToBytes(hex) {
  if (typeof hex !== "string") throw new Error("calldata must be a string");
  const clean = hex.trim().replace(/^0x/i, "");
  if (clean === "") return new Uint8Array(0);
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error("calldata is not valid hex");
  if (clean.length % 2 !== 0) throw new Error("calldata has an odd number of hex digits");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function wordAt(data, index) {
  const slice = data.slice(index * 32, index * 32 + 32);
  return slice.length < 32 ? null : slice;
}

function decodeWord(type, word) {
  let value = 0n;
  for (const byte of word) value = (value << 8n) | BigInt(byte);
  switch (type) {
    case "address":
      return "0x" + [...word.slice(12)].map((b) => b.toString(16).padStart(2, "0")).join("");
    case "bool":
      return value !== 0n;
    case "bytes32":
      return "0x" + [...word].map((b) => b.toString(16).padStart(2, "0")).join("");
    default:
      return value; // uintN -> BigInt
  }
}

export function decodeArgs(types, data) {
  const values = [];
  for (let i = 0; i < types.length; i++) {
    const type = types[i];
    const word = wordAt(data, i);
    if (!word) { values.push(null); continue; }

    if (STATIC.has(type)) { values.push(decodeWord(type, word)); continue; }

    // Dynamic tail: a 32-byte offset, then a 32-byte length, then the payload.
    let offset = 0n;
    for (const byte of word) offset = (offset << 8n) | BigInt(byte);
    const start = Number(offset);
    if (start + 32 > data.length) { values.push(null); continue; }
    const length = Number(decodeWord("uint256", data.slice(start, start + 32)));
    const raw = data.slice(start + 32, start + 32 + length);
    values.push(type === "string" ? new TextDecoder().decode(raw) : "0x" + [...raw].map((b) => b.toString(16).padStart(2, "0")).join(""));
  }
  return values;
}

/**
 * Addresses the caller should look up on-chain before drawing conclusions,
 * with the role each one plays.
 */
function addressesOfInterest(kind, args) {
  const out = [];
  const push = (address, role) => {
    if (typeof address === "string" && /^0x[0-9a-f]{40}$/.test(address)) out.push({ address, role });
  };
  switch (kind) {
    case "approval":
    case "permit":
      push(args.spender, "spender");
      break;
    case "operator":
      push(args.operator, "operator");
      break;
    case "permit2-approval":
    case "permit2-permit":
      push(args.spender, "spender");
      push(args.token, "token");
      break;
    case "transfer":
      push(args.to, "recipient");
      break;
    case "transfer-from":
      push(args.from, "sender");
      push(args.to, "recipient");
      break;
    default:
      break;
  }
  return out;
}

function findingsFor(entry, args, decimals) {
  const findings = [];
  const { kind } = entry;

  if (kind === "approval") {
    const amount = args.amount;
    if (amount === MAX_UINT256) {
      findings.push(finding("critical", "Unlimited approval",
        `Approves ${args.spender} to move your ENTIRE balance of this token, now and in the future. ` +
        `If this address is not a protocol you trust, it can empty the token without asking you again.`));
    } else if (typeof amount === "bigint") {
      findings.push(finding("notable", "Token approval",
        `Grants ${args.spender} an allowance of ${amount} base units. An approval is not a payment — ` +
        `it is permission to take a payment later.`));
    }
  }

  if (kind === "operator") {
    if (args.approved === true) {
      findings.push(finding("critical", "Blanket operator approval",
        `Grants ${args.operator} control over ALL of your tokens in this collection. This is the strongest ` +
        `permission an ERC-721/1155 contract can give and it is a common drainer step.`));
    } else {
      findings.push(finding("info", "Operator approval revoked", `Removes ${args.operator} as an operator.`));
    }
  }

  if (kind === "permit") {
    const unlimited = args.value === MAX_UINT256;
    findings.push(finding("critical", "Signature-based approval (EIP-2612 permit)",
      `${unlimited ? "Unlimited. " : ""}This is a signature, not a transaction: it authorises ${args.spender} ` +
      `to move this token with no further confirmation from you. The signature is the payment — you do not ` +
      `get a second prompt.`));
  }

  if (kind === "permit2-approval" || kind === "permit2-permit") {
    const unlimited = args.amount === MAX_UINT160 || args.amount === MAX_UINT256;
    findings.push(finding(unlimited ? "critical" : "high", "Permit2 approval",
      `${unlimited ? "Unlimited. " : ""}Permit2 (0x0000…8BA3, the real one) lets ${args.spender} pull ` +
      `${args.token} using a signature. Confirm the spender is the protocol you think it is.`));
  }

  if (kind === "transfer-from") {
    findings.push(finding("info", "Moves tokens that are already approved",
      `Transfers from ${args.from} to ${args.to}. If ${args.from} is your address and you did not start ` +
      `this, an earlier approval is being spent.`));
  }

  if (kind === "bridge-burn") {
    findings.push(finding("info", "This matches a real CCTP bridge call",
      `depositForBurn on the CCTP TokenMessenger is how USDC legitimately leaves Arc. This is the shape ` +
      `you want to see — but confirm the transaction is sent TO the official TokenMessenger address, ` +
      `not to an address that merely asks for the same calldata.`));
  }

  return findings;
}

/**
 * @param {string} dataHex 0x-prefixed calldata
 * @param {number} [decimals] token decimals for human-readable amounts (default 6 = USDC ERC-20)
 */
export function analyzeCalldata(dataHex, decimals = 6) {
  const data = hexToBytes(dataHex ?? "0x");
  if (data.length < 4) {
    return {
      selector: null, signature: null, label: null, kind: "empty", risk: null,
      args: [], findings: [], addressesOfInterest: [], raw: "0x", byteLength: data.length,
    };
  }
  const sel = "0x" + [...data.slice(0, 4)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const entry = BY_SELECTOR[sel];

  if (!entry) {
    return {
      selector: sel, signature: null, label: null, kind: "unknown", risk: null,
      args: [], addressesOfInterest: [], byteLength: data.length, raw: dataHex,
      findings: [finding("notable", "Unrecognised function selector",
        `The first four bytes (${sel}) are not in this tool's table. Unknown approvals and permits are ` +
        `exactly what drainers hide behind, so treat this as unchecked rather than harmless.`)],
    };
  }

  const values = entry.params ? decodeArgs(entry.params, data.slice(4)) : [];
  const names = entry.names ?? entry.params ?? [];
  const args = {};
  const argList = [];
  for (let i = 0; i < (entry.params?.length ?? 0); i++) {
    args[names[i]] = values[i];
    argList.push({ name: names[i], type: entry.params[i], value: values[i] });
  }

  return {
    selector: sel,
    signature: entry.sig,
    label: entry.label,
    kind: entry.kind,
    risk: entry.risk,
    args,
    argList,
    addressesOfInterest: addressesOfInterest(entry.kind, args),
    findings: findingsFor(entry, args, decimals),
    byteLength: data.length,
    raw: dataHex,
  };
}
