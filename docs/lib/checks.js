/**
 * The pre-flight opinion.
 *
 * Everything here is a pure function of (what you are about to sign) x (facts
 * fetched from Arc). Keeping the fetching in arc.js and the judgement here means
 * the rules are unit-testable without a network, which is the only way to trust
 * a security tool you wrote in a weekend.
 *
 * The tool never returns "safe". It returns observations and a headline that
 * says how much attention the transaction deserves.
 */

import {
  CCTP_TOKEN_MESSENGER_V2,
  MAINNET_CONTRACTS,
  PERMIT2,
  TESTNET_CONTRACTS,
  USDC,
  lookupContract,
  normalizeAddress,
} from "./registry.js";
import { analyzeCalldata } from "./decode.js";
import { MAX_UINT256, formatUnits } from "./format.js";
import { finding, sortFindings, worstLevel } from "./findings.js";

const EIP1167_PREFIX = "363d3d373d3d3d363d73";
const EIP1167_SUFFIX = "5af43d82803e903d91602b57fd5bf3";

/**
 * The verified position on ARC, stated precisely — because "there is no ARC
 * token" is *not* accurate and a security tool that overstates loses the right
 * to be believed.
 *
 * What Circle actually said at the Arc mainnet launch (16 Sep 2026): it had
 * completed a genesis mint of 10 billion ARC, and described that as "not a
 * commitment to publicly launch ARC, but an important technical milestone".
 * ARC is not tradable, not stakable, and not used for gas, fees or governance;
 * no public sale or listing has been announced; and Circle sold 807.5m ARC
 * privately beforehand.
 *
 * So the honest warning is about what you can buy, not about whether an ARC
 * contract exists on-chain.
 */
export const ARC_TOKEN_FACTS =
  "An ARC asset exists on-chain (Circle genesis-minted 10 billion at launch) but it is not publicly " +
  "tradable. Circle called the mint a technical milestone rather than a public launch, and ARC is not " +
  "used for gas, staking or governance, with no public sale announced. So any ARC you can actually buy " +
  "is not Circle's ARC — and anyone selling it is using a real fact about Arc to reach a conclusion " +
  "that does not follow from it.";

/** Detect an EIP-1167 minimal proxy and return the implementation address. */
export function minimalProxyTarget(codeHex) {
  if (typeof codeHex !== "string") return null;
  const code = codeHex.toLowerCase().replace(/^0x/, "");
  // 10-byte prefix + 20-byte implementation + 15-byte suffix = 45 bytes = 90 hex.
  if (code.length !== 90) return null;
  if (!code.startsWith(EIP1167_PREFIX) || !code.endsWith(EIP1167_SUFFIX)) return null;
  return "0x" + code.slice(EIP1167_PREFIX.length, EIP1167_PREFIX.length + 40);
}

export function isEoa(codeHex) {
  return typeof codeHex !== "string" || codeHex === "0x" || codeHex === "0x0" || codeHex === "";
}

/** Addresses whose code the caller must fetch before analyzeTransaction is meaningful. */
export function planLookups(tx = {}) {
  const targets = new Set();
  const to = normalizeAddress(tx.to);
  if (to) targets.add(to);
  for (const { address } of analyzeCalldata(tx.dataHex ?? "0x").addressesOfInterest) {
    targets.add(address.toLowerCase());
  }
  return [...targets];
}

function isOfficialToken(address) {
  const hit = lookupContract(address, MAINNET_CONTRACTS);
  return hit && hit.kind === "token" ? hit : null;
}

/**
 * The heart of the tool: a scam is a mismatch between what you were told a
 * transaction does and what it actually does.
 *
 * A transaction alone often cannot be called good or bad. Sending USDC to a
 * wallet is a payment or a theft depending entirely on what you were promised,
 * and a `transfer()` call is ordinary right up until someone calls it a bridge.
 * So we take the claim as an input and flag the disagreement. That is the whole
 * trick, and it is why this needs no classifier.
 */
export const CLAIMS = Object.freeze(["unknown", "bridge", "pay", "approve", "rewards", "swap"]);

export const CLAIM_LABELS = Object.freeze({
  unknown: "Not sure / I was not told",
  bridge: "Bridge my USDC to another chain",
  pay: "Pay someone",
  approve: "Connect my wallet / approve a token",
  rewards: "Claim rewards or an airdrop",
  swap: "Swap tokens",
});

function claimFindings({ claim, decoded, to, toIsEoa, toIsContract, valueWei }) {
  const findings = [];
  if (claim === "unknown") return findings;

  const isValueToWallet = toIsEoa && valueWei > 0n;
  const isUsdcTransfer =
    (decoded.kind === "transfer" || decoded.kind === "transfer-from") && to === USDC;
  const isApproval = ["approval", "permit", "permit2-approval", "permit2-permit", "operator"].includes(decoded.kind);
  const isRealBridge = decoded.kind === "bridge-burn" && to === CCTP_TOKEN_MESSENGER_V2;

  if (claim === "bridge") {
    if (isRealBridge) {
      findings.push(finding("info", "The claim matches the transaction",
        "You were told this bridges, and it calls CCTP's depositForBurn on the real Arc TokenMessenger. " +
        "Now check the destination domain and the mintRecipient bytes32 really are your intended " +
        "destination, because the burn cannot be undone."));
    } else if (isValueToWallet) {
      findings.push(finding("critical", "You were told this bridges. It does not.",
        `This sends ${formatUnits(valueWei, 18)} USDC to ${to}, which has no contract code. No bridge is ` +
        `involved, nothing is minted on any other chain, and the transfer is final the moment it lands. ` +
        `Real Arc bridging calls depositForBurn on ${CCTP_TOKEN_MESSENGER_V2}. This is the documented Arc ` +
        `bridge scam: the site can cite the real whitepaper, the real raise and the real mainnet, and still ` +
        `be asking you to send USDC to a wallet.`));
    } else if (isUsdcTransfer) {
      findings.push(finding("critical", "You were told this bridges. It does not.",
        `It calls transfer() on the USDC ERC-20, moving USDC straight to ${decoded.args?.to}. Bridging ` +
        `burns USDC on the TokenMessenger (${CCTP_TOKEN_MESSENGER_V2}) and mints it on the far side; it ` +
        `never simply forwards your USDC to an address.`));
    } else if (isApproval) {
      findings.push(finding("critical", "You were told this bridges. It grants permission instead.",
        "Nothing is bridged. An approval is a standing permission the spender can exercise later, " +
        "without asking you again."));
    } else if (toIsEoa) {
      findings.push(finding("critical", "You were told this bridges. There is no contract to bridge with.",
        `${to} has no contract code, so no bridge exists at that address regardless of what the site shows.`));
    } else if (toIsContract) {
      findings.push(finding("high", "This does not look like an Arc bridge",
        `You were told this bridges. Real Arc bridging calls depositForBurn on ` +
        `${CCTP_TOKEN_MESSENGER_V2}. This transaction does not call that function on that contract, so ` +
        `whatever it does, it is not the standard Circle bridge.`));
    }
  }

  if (claim === "pay") {
    if (isValueToWallet || isUsdcTransfer) {
      findings.push(finding("info", "The claim matches the transaction",
        "You expected a payment and this is a payment. Confirm the recipient address character by " +
        "character — address-poisoning scams rely on you not doing that."));
    } else if (isApproval) {
      findings.push(finding("high", "You expected a payment, but this grants permission",
        "Approvals do not move money now; they let the spender move it later. If a counterparty asked you " +
        "to approve or connect in order to pay you, the direction of the permission is the problem."));
    } else {
      findings.push(finding("notable", "This does not look like a plain payment",
        "Read what the calldata does before signing."));
    }
  }

  if (claim === "approve") {
    if (isApproval) {
      findings.push(finding("info", "The claim matches the transaction",
        "You expected an approval and this is one. The remaining question is the spender, above."));
    } else if (isValueToWallet || isUsdcTransfer) {
      findings.push(finding("critical", "Connecting should not move funds",
        "You were told this connects your wallet or approves a token, but this transaction moves USDC " +
        "immediately. Connecting never needs to transfer your balance. `permit` and Permit2 make it worse: " +
        "they authorise movement with a signature, so there is no second confirmation to catch it."));
    } else {
      findings.push(finding("high", "Not the approval you were expecting",
        "You were told this approves something, but the calldata is not an approval, permit or operator " +
        "grant. Check what it actually calls."));
    }
  }

  if (claim === "rewards") {
    const costs = isValueToWallet || isUsdcTransfer || isApproval;
    findings.push(finding(costs ? "critical" : "high", "Arc has no rewards or airdrop to claim",
      "You were told this claims rewards or an airdrop. Circle has announced no rewards programme and no " +
      "airdrop for Arc, and the ARC asset is not publicly tradable, so there is nothing for a claim to pay " +
      "out. " +
      (costs
        ? "This transaction also asks for funds or permissions — that is the half that actually costs you."
        : "Whatever this transaction does, the reward it offers does not exist.")));
  }

  if (claim === "swap") {
    if (isValueToWallet) {
      findings.push(finding("critical", "A swap does not send funds to a wallet",
        `You were told this swaps tokens. It sends USDC to ${to}, which has no contract. A swap settles ` +
        `against a contract; this is a transfer to a person.`));
    } else if (toIsContract) {
      findings.push(finding("info", "Consistent with a swap",
        "A swap against a contract looks like this. Verify the contract and the amounts, since slippage " +
        "and routing are where swap losses actually happen."));
    }
  }

  return findings;
}

/**
 * @param {object} tx
 * @param {string} [tx.to]          0x recipient (empty = contract creation)
 * @param {bigint|string} [tx.valueWei] native USDC in base units (18 decimals)
 * @param {string} [tx.dataHex]     calldata
 * @param {string} [tx.claim]       what you were told this does; see CLAIMS
 * @param {object} facts
 * @param {Record<string,string>} [facts.codes]  lowercase address -> runtime bytecode
 * @param {number|null} [facts.registryReports]  count from the on-chain registry
 * @param {"mainnet"|"testnet"} [facts.network]
 */
export function analyzeTransaction(tx = {}, facts = {}) {
  const network = facts.network ?? "mainnet";
  const codes = {};
  for (const [key, value] of Object.entries(facts.codes ?? {})) codes[key.toLowerCase()] = value;

  const to = normalizeAddress(tx.to ?? "");
  const claim = CLAIMS.includes(tx.claim) ? tx.claim : "unknown";
  const valueWei = tx.valueWei === undefined || tx.valueWei === null ? 0n : BigInt(tx.valueWei);
  const dataHex = tx.dataHex && tx.dataHex !== "0x" ? tx.dataHex : "0x";
  const findings = [];

  const decoded = analyzeCalldata(dataHex);
  const toCode = to ? (codes[to] ?? null) : null;
  // null means "not fetched", and must never be treated as "no code". Reporting
  // a contract as a wallet because the RPC call failed would be a false alarm of
  // exactly the kind this tool exists to avoid.
  const toCodeKnown = to ? toCode !== null : false;
  const toIsEoa = toCodeKnown ? isEoa(toCode) : false;
  const toIsContract = toCodeKnown ? !isEoa(toCode) : false;

  // ---- 1. Recipient identity -------------------------------------------------
  let mainnetHit = null;
  let testnetHit = null;
  if (to) {
    mainnetHit = lookupContract(to, MAINNET_CONTRACTS);
    testnetHit = lookupContract(to, TESTNET_CONTRACTS);

    if (!mainnetHit && testnetHit) {
      findings.push(finding("critical", "This is an Arc TESTNET address",
        `${testnetHit.name} exists on Arc testnet (chain 5042002), not on mainnet. Testnet assets are ` +
        `valueless and the address has no role on mainnet. Passing a testnet address off as a mainnet ` +
        `bridge is one of the documented scams around this launch — and the testnet CCTP addresses look ` +
        `nothing like the mainnet ones (${CCTP_TOKEN_MESSENGER_V2} is the real mainnet TokenMessenger).`));
    } else if (mainnetHit) {
      findings.push(finding("info", `Recognised Arc contract: ${mainnetHit.name}`,
        `${mainnetHit.note ?? ""}`.trim() || "Listed in Circle's published Arc mainnet addresses."));
    } else if (toIsContract) {
      findings.push(finding("info", "Unlisted contract on Arc mainnet",
        `${to} has bytecode but is not one of Circle's published system contracts. That is normal for ` +
        `third-party apps — it just means this tool cannot vouch for it. Confirm it against the project's ` +
        `own docs and explorer.arc.io.`));
    }
  }

  // ---- 2. The community registry --------------------------------------------
  if (to && typeof facts.registryReports === "number" && facts.registryReports > 0) {
    findings.push(finding("critical", `${facts.registryReports} public report(s) on this address`,
      `The on-chain ArcGuardRegistry holds ${facts.registryReports} report(s) for ${to}. Reports are ` +
      `uncurated and can be wrong, so read them (and who filed them) before deciding — but if you were ` +
      `about to sign something, stop and look.`));
  }

  // ---- 3. Where the money actually goes ------------------------------------
  if (!to) {
    if (dataHex !== "0x") {
      findings.push(finding("notable", "This deploys a contract",
        "With no recipient address, this transaction creates a new contract. Newly deployed contracts are " +
        "the ones nobody has reviewed."));
    }
  } else if (!toCodeKnown) {
    findings.push(finding("info", "Contract status not checked",
      `This tool could not read the code at ${to}, so it cannot say whether that address is a contract. ` +
      `Treat that as missing evidence, not as a clean result, and re-run once the RPC answers.`));
  } else if (toIsEoa) {
    if (valueWei > 0n && dataHex === "0x") {
      findings.push(finding("info", "Native USDC transfer to a wallet",
        `There is no contract at ${to}. ${formatUnits(valueWei, 18)} USDC moves straight into an ordinary ` +
        `wallet. On Arc that is final in under a second, with no chargeback and no contract in the middle ` +
        `to reverse it. Paying a person looks exactly like this — and so does being robbed by one, which ` +
        `is why the claim check matters.`));
    } else if (valueWei > 0n) {
      findings.push(finding("notable", "USDC sent to a wallet with calldata attached",
        `There is no contract at ${to}, so the calldata is ignored by the EVM entirely. Only the ` +
        `${formatUnits(valueWei, 18)} USDC moves. Calldata that does nothing is not how a protocol behaves.`));
    } else if (dataHex !== "0x") {
      findings.push(finding("notable", "Calldata addressed to a wallet",
        `${to} has no contract code, so this calldata does nothing at all. A function call that silently ` +
        `does nothing is not how a real protocol behaves.`));
    }
  } else if (valueWei > 0n) {
    findings.push(finding("notable", "Sends native USDC to a contract",
      `${formatUnits(valueWei, 18)} USDC goes to ${to} alongside the call. If you expected a token ` +
      `transfer instead, this is not one.`));
  }

  if (valueWei > 0n && dataHex === "0x" && toIsContract) {
    findings.push(finding("info", "Native USDC to a contract with no calldata",
      "Value with empty calldata is a bare deposit. Make sure the contract has a receive/fallback that " +
      "does what you expect."));
  }

  // ---- 4. What the calldata authorises --------------------------------------
  findings.push(...decoded.findings);

  const recipientArg = decoded.args?.to;
  const tokenAtTo = to ? isOfficialToken(to) : null;

  if (decoded.kind === "transfer" || decoded.kind === "transfer-from") {
    if (to === USDC) {
      findings.push(finding("high", "This is a plain USDC transfer, not a bridge",
        `It calls ${decoded.signature} on the USDC ERC-20 directly, sending to ${recipientArg}. ` +
        `That is a payment, and it is irreversible. Real Arc bridging does not look like this: CCTP calls ` +
        `depositForBurn on the TokenMessenger at ${CCTP_TOKEN_MESSENGER_V2}. A page that calls itself a ` +
        `bridge and asks you to approve a transfer to a wallet address is the documented Arc bridge scam.`));
    } else if (!tokenAtTo && to) {
      findings.push(finding("high", "Token transfer on an unrecognised contract",
        `This calls ${decoded.signature} on ${to}, which is not one of Circle's published Arc tokens. ` +
        `If you were told this contract is "ARC", then: ${ARC_TOKEN_FACTS}`));
    }
  }

  // Approvals: the spender is what matters, so check whether it is even a contract.
  const spender = decoded.args?.spender ?? decoded.args?.operator;
  if (spender && ["approval", "permit", "permit2-approval", "permit2-permit", "operator"].includes(decoded.kind)) {
    const spenderKey = normalizeAddress(spender);
    const spenderCode = codes[spenderKey];
    if (spenderCode !== undefined && isEoa(spenderCode)) {
      findings.push(finding("critical", "The approval target is not a contract",
        `${spender} has no contract code. An allowance granted to a wallet address is simply a standing ` +
        `instruction that whoever holds that wallet's key can take your tokens whenever they like. ` +
        `Legitimate protocols are contracts. There is no reason for a "router" to be a plain wallet.`));
    } else if (spenderKey === PERMIT2) {
      findings.push(finding("info", "Spender is the real Permit2",
        `${spender} is the canonical Permit2 deployment. That is expected for signature-based approvals — ` +
        `the risk is in the nested spender inside the signature, not in Permit2 itself.`));
    } else if (spenderCode !== undefined && !isEoa(spenderCode)) {
      const hit = lookupContract(spenderKey, MAINNET_CONTRACTS);
      findings.push(finding("info", "The approval target is a contract",
        `${spender} has bytecode${hit ? ` and is ${hit.name}` : " but is not one of Circle's published contracts"}. ` +
        `An approval is permission, not payment — it persists until you revoke it.`));
    }
    if (decoded.kind === "approval" && decoded.args.amount === MAX_UINT256) {
      findings.push(finding("high", "Prefer a exact allowance",
        `Unlimited approvals survive this transaction. Set the allowance to what this action needs, so a ` +
        `later compromise of ${spender} cannot drain the whole balance.`));
    }
  }

  // The inverse of the bridge scam: a genuine bridge call pointed somewhere wrong.
  if (decoded.kind === "bridge-burn") {
    if (to === CCTP_TOKEN_MESSENGER_V2) {
      findings.push(finding("info", "Sent to the real CCTP TokenMessenger",
        "This is the shape of a legitimate Arc bridge-out. Confirm the destination domain and the " +
        "mintRecipient bytes32 are what you intend, because once burned, the mint on the far side is " +
        "whoever that bytes32 decodes to."));
    } else {
      findings.push(finding("critical", "Bridge call aimed at the wrong contract",
        `This uses CCTP's depositForBurn — the real bridge function — but sends it to ${to}, not to Arc's ` +
        `TokenMessenger (${CCTP_TOKEN_MESSENGER_V2}). Copying a real function signature into a fake ` +
        `contract is exactly how a "bridge" can look correct in a wallet preview and still take the USDC.`));
    }
  }

  // ---- 5. Does it do what you were told it does? ---------------------------
  findings.push(...claimFindings({ claim, decoded, to, toIsEoa, toIsContract, valueWei }));

  // ---- 6. Bytecode shape of the destination ---------------------------------
  if (to && toIsContract) {
    const proxy = minimalProxyTarget(toCode);
    if (proxy && !mainnetHit) {
      findings.push(finding("notable", "Destination is a minimal proxy",
        `${to} is a 45-byte EIP-1167 forwarder whose logic lives at ${proxy}. The code at the address you ` +
        `are shown is not the code that runs. Fresh proxies are cheap to deploy and common in drainer ` +
        `campaigns; look at the implementation before trusting the front.`));
    }
  }

  const sorted = sortFindings(findings);
  return {
    network,
    claim,
    decoded,
    facts: {
      to: to || null,
      toIsEoa: to ? (toCodeKnown ? toIsEoa : null) : null,
      toCodeSize: toCode ? (toCode.length - 2) / 2 : null,
      isOfficial: Boolean(mainnetHit),
      officialName: mainnetHit?.name ?? null,
      isTestnetAddress: Boolean(testnetHit) && !mainnetHit,
      registryReports: facts.registryReports ?? null,
      registryChecked: facts.registryReports !== undefined && facts.registryReports !== null,
    },
    findings: sorted,
    headline: headlineFor(sorted),
  };
}

function headlineFor(findings) {
  const worst = worstLevel(findings);
  if (worst === "critical") return "Do not sign this until you have explained every critical item below.";
  if (worst === "high") return "Something here does not match what a legitimate version of this action looks like.";
  if (worst === "notable") return "Nothing decisive, but read the notes before signing.";
  return "Nothing alarming in what this tool can see. That is not the same as safe.";
}

/**
 * Address-only inspection: the "is this address what it claims to be?" mode.
 */
export function analyzeAddress({ address, codeHex, registryReports, network = "mainnet" } = {}) {
  const findings = [];
  const key = normalizeAddress(address);
  if (!key) {
    return {
      address: null,
      findings: [finding("info", "Not an address",
        "Enter a 0x-prefixed 40-character address to inspect. You can get one from explorer.arc.io.")],
      facts: null,
      headline: "Nothing to inspect.",
    };
  }

  const mainnetHit = lookupContract(key, MAINNET_CONTRACTS);
  const testnetHit = lookupContract(key, TESTNET_CONTRACTS);
  const codeKnown = typeof codeHex === "string" && codeHex !== "";
  const eoa = codeKnown && isEoa(codeHex);

  if (mainnetHit) {
    findings.push(finding("info", `Recognised Arc contract: ${mainnetHit.name}`, mainnetHit.note ?? ""));
  } else if (testnetHit) {
    findings.push(finding("critical", "Arc TESTNET address",
      `${testnetHit.name} is a testnet contract. It holds no value and has no mainnet role.`));
  } else if (!codeKnown) {
    findings.push(finding("info", "Could not read the code at this address",
      `The RPC did not answer, so this tool cannot say whether ${key} is a contract. That is missing ` +
      `evidence, not a clean result.`));
  } else if (eoa) {
    findings.push(finding("high", "No contract code — this is a wallet",
      `${key} is an ordinary account, not a contract. Any site describing it as a bridge, router, ` +
      `exchange, faucet or protocol contract is describing something that is not there. USDC sent here ` +
      `is a plain transfer: final, and to whoever controls the key.`));
  } else {
    findings.push(finding("notable", "Contract not in Circle's published list",
      `${key} has ${(codeHex.length - 2) / 2} bytes of code but is not one of Arc's published system ` +
      `contracts. Third-party contracts are expected here — this only means nobody in this tool vouches ` +
      `for it. Check explorer.arc.io for verification status.`));
    const proxy = minimalProxyTarget(codeHex);
    if (proxy) {
      findings.push(finding("notable", "Minimal proxy (EIP-1167)",
        `Logic lives at ${proxy}. The address you are shown is a forwarder; the behaviour is at the ` +
        `implementation. Inspect ${proxy} too.`));
    }
  }

  if (codeKnown && !eoa && !mainnetHit && !testnetHit) {
    const proxy = minimalProxyTarget(codeHex);
    if (!proxy && (codeHex.length - 2) / 2 < 120) {
      findings.push(finding("notable", "Very small contract",
        `Only ${(codeHex.length - 2) / 2} bytes. Legitimate protocols are rarely this small; short ` +
        `contracts are often single-purpose sweeps.`));
    }
  }

  if (typeof registryReports === "number" && registryReports > 0) {
    findings.push(finding("critical", `${registryReports} public report(s)`,
      `The community registry holds ${registryReports} report(s) for this address. Read them on-chain, ` +
      `including who filed them, before acting.`));
  }

  const sorted = sortFindings(findings);
  return {
    address: key,
    findings: sorted,
    facts: {
      isContract: codeKnown ? !eoa : null,
      codeSize: codeKnown ? (eoa ? 0 : (codeHex.length - 2) / 2) : null,
      isOfficial: Boolean(mainnetHit),
      officialName: mainnetHit?.name ?? null,
      isTestnetAddress: Boolean(testnetHit) && !mainnetHit,
      minimalProxyTarget: codeKnown && !eoa ? minimalProxyTarget(codeHex) : null,
      registryReports: registryReports ?? null,
      registryChecked: typeof registryReports === "number",
    },
    headline: headlineFor(sorted),
  };
}
