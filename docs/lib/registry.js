/**
 * The ground truth this tool checks against: the addresses Circle actually
 * publishes for Arc, and the domains that are actually Arc's.
 *
 * Every mainnet address below was copied from docs.arc.io/arc/references/
 * contract-addresses (and cross-checked by calling eth_getCode on Arc mainnet —
 * see tests/live.check.mjs). Addresses are stored lowercase and compared
 * case-insensitively so a checksummed paste never causes a false "unknown".
 *
 * The testnet list exists for one reason: the single most effective Arc scam
 * right now is passing a TESTNET address off as a mainnet bridge. A mainnet
 * tool that cannot recognise a testnet address cannot catch that.
 */

export const MAINNET_CHAIN_ID = 5042;
export const TESTNET_CHAIN_ID = 5042002;

export const MAINNET_RPC = "https://rpc.mainnet.arc.io";
export const MAINNET_RPC_FALLBACKS = [
  "https://rpc.blockdaemon.mainnet.arc.io",
  "https://rpc.drpc.mainnet.arc.io",
  "https://rpc.quicknode.mainnet.arc.io",
];
export const TESTNET_RPC = "https://rpc.testnet.arc.io";

export const EXPLORER = {
  mainnet: "https://explorer.arc.io",
  testnet: "https://explorer.testnet.arc.io",
};

// Native USDC is 18 decimals at the protocol level; the ERC-20 interface below
// is 6 decimals. Mixing them up is a 10^12 error, and it is Arc-specific.
export const NATIVE_DECIMALS = 18;
export const USDC_ERC20_DECIMALS = 6;

function c(address, name, kind, note) {
  return { address: address.toLowerCase(), name, kind, note };
}

/** Circle-published Arc MAINNET contracts. Source: docs.arc.io (see header). */
export const MAINNET_CONTRACTS = [
  c("0x3600000000000000000000000000000000000000", "USDC (ERC-20 interface)", "token",
    "USDC is Arc's native gas asset. This address is the optional ERC-20 view of the same balance (6 decimals). There is no wrapped USDC on Arc."),
  c("0xbEf5f6d51CB62b58e6A8f77868681825C6fe21c1", "EURC", "token", "Circle's euro stablecoin (6 decimals)."),
  c("0x8a5D989Bbb96929F689B0200f435f53dA42bF490", "USYC", "token", "Tokenised money-market fund shares (6 decimals)."),
  c("0xb69ecb156Dc0028198028c501340d5367845ca72", "USYC Entitlements", "system", "Allowlist for permissioned USYC access."),
  c("0x51A8CE47dC08ba5CD19c7aa84EA6fD6664f60f9b", "USYC Teller", "system", "Mints/redeems USYC against USDC."),

  c("0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d", "CCTP TokenMessengerV2", "bridge",
    "THE real Arc bridge entry point. Legitimate USDC bridging out of Arc calls depositForBurn here. If a site calls itself a bridge and does not route through this contract, it is not bridging anything."),
  c("0x81D40F21F12A8F0E3252Bccb954D722d4c464B64", "CCTP MessageTransmitterV2", "bridge", "CCTP message receive/attestation."),
  c("0xfd78EE919681417d192449715b2594ab58f5D002", "CCTP TokenMinterV2", "bridge", "CCTP token minting."),
  c("0xec546b6B005471ECf012e5aF77FBeC07e0FD8f78", "CCTP MessageV2", "bridge", "CCTP message storage."),

  c("0x77777777Dcc4d5A8B6E418Fd04D8997ef11000eE", "Gateway Wallet", "system", "Circle Gateway unified USDC balance."),
  c("0x2222222d7164433c4C09B0b0D809a9b52C04C205", "Gateway Minter", "system", "Circle Gateway minting."),

  c("0xe2E5F173576B513d994073CCbDaCBE027d43DFe6", "StableFX FxEscrow", "system", "Escrow for StableFX RFQ settlement."),
  c("0x5294E9927c3306DcBaDb03fe70b92e01cCede505", "Memo", "predeploy", "Attaches memos to calls."),
  c("0x522fAf9A91c41c443c66765030741e4AaCe147D0", "Multicall3From", "predeploy",
    "Batches calls while preserving msg.sender, so a tx routed through it can appear to come from you."),

  c("0xcA11bde05977b3631167028862bE2a173976CA11", "Multicall3", "common", "Standard batched reads."),
  c("0x000000000022D473030F116dDEE9F6B43aC78BA3", "Permit2", "common",
    "Signature-based approvals. An approval here can be exercised later without another confirmation."),
  c("0x4e59b44847b379578588920cA78FbF26c0B4956C", "CREATE2 Factory", "common", "Deterministic deploys."),
];

/** Circle-published Arc TESTNET contracts. A mainnet tool must recognise these. */
export const TESTNET_CONTRACTS = [
  c("0x3600000000000000000000000000000000000000", "USDC (ERC-20 interface)", "token", "Testnet USDC ERC-20 view."),
  c("0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a", "EURC", "token", "Testnet EURC."),
  c("0xe9185F0c5F296Ed1797AaE4238D26CCaBEadb86C", "USYC", "token", "Testnet USYC."),
  c("0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA", "CCTP TokenMessengerV2 (TESTNET)", "bridge", "Testnet only."),
  c("0xE737e5cEBEEBa77EFE34D4aa090756590b1CE275", "CCTP MessageTransmitterV2 (TESTNET)", "bridge", "Testnet only."),
  c("0xb43db544E2c27092c107639Ad201b3dEfAbcF192", "CCTP TokenMinterV2 (TESTNET)", "bridge", "Testnet only."),
  c("0xbaC0179bB358A8936169a63408C8481D582390C4", "CCTP MessageV2 (TESTNET)", "bridge", "Testnet only."),
  c("0x0077777d7EBA4688BDeF3E311b846F25870A19B9", "Gateway Wallet (TESTNET)", "system", "Testnet only."),
  c("0x0022222ABE238Cc2C7Bb1f21003F0a260052475B", "Gateway Minter (TESTNET)", "system", "Testnet only."),
  c("0x867650F5eAe8df91445971f14d89fd84F0C9a9f8", "StableFX FxEscrow (TESTNET)", "system", "Testnet only."),
];

/**
 * Domains that are actually Arc/Circle. Anything else is a third party, and a
 * third party asking for a wallet connection deserves scrutiny.
 */
export const OFFICIAL_DOMAINS = [
  "arc.io",
  "docs.arc.io",
  "portal.arc.io",
  "explorer.arc.io",
  "testnet.arc.io",
  "explorer.testnet.arc.io",
  "faucet.circle.com",
  "circle.com",
  "developers.circle.com",
  "support.circle.com",
  "help.circle.com",
];

/**
 * Documented Arc-related drainer domains. Seed list, not a feed — the UI says so.
 * governance-arc.com is a cloned Arc front end offering a fake "Community
 * Rewards" vote; connecting a wallet runs a drainer. Reported by pcrisk and
 * MalwareTips, September 2026.
 */
export const KNOWN_DRAINER_DOMAINS = ["governance-arc.com"];

/**
 * Words that, combined with "arc"/"circle", describe things the real Arc does
 * not offer. Circle has announced no airdrop and no rewards programme for Arc,
 * and the ARC asset is not publicly tradable, so any domain asking you to
 * claim/vote/bridge on those premises is inventing them.
 */
export const LURE_WORDS = [
  "governance", "rewards", "reward", "airdrop", "claim", "claiming", "faucet",
  "bridge", "bridging", "stake", "staking", "migrate", "migration", "bonus",
  "giveaway", "presale", "prelaunch", "vote", "portal",
];

// The three addresses the Arc-specific checks key off, named so the logic reads
// clearly. All lowercase; compare with normalizeAddress().
export const USDC = "0x3600000000000000000000000000000000000000";
export const CCTP_TOKEN_MESSENGER_V2 = "0x28b5a0e9c621a5badaa536219b3a228c8168cf5d";
export const PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3";

export function normalizeAddress(address) {  if (typeof address !== "string") return "";
  const trimmed = address.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(trimmed)) return "";
  return trimmed.toLowerCase();
}

export function isValidAddress(address) {
  return normalizeAddress(address) !== "";
}

export function lookupContract(address, list) {
  const key = normalizeAddress(address);
  if (!key) return null;
  return list.find((entry) => entry.address === key) ?? null;
}

/** Look an address up on both networks. Returns { mainnet, testnet }. */
export function lookupAnyContract(address) {
  return {
    mainnet: lookupContract(address, MAINNET_CONTRACTS),
    testnet: lookupContract(address, TESTNET_CONTRACTS),
  };
}

export function isOfficialDomain(host) {
  if (!host) return false;
  const clean = host.toLowerCase().replace(/\.$/, "");
  return OFFICIAL_DOMAINS.includes(clean);
}

export function isKnownDrainerDomain(host) {
  if (!host) return false;
  const clean = host.toLowerCase().replace(/\.$/, "");
  return KNOWN_DRAINER_DOMAINS.includes(clean);
}
