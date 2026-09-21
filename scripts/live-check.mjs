/**
 * Live check against Arc mainnet and testnet.
 *
 * This is the test that matters most: the whole tool keys off a list of
 * addresses copied out of documentation, and a single wrong character turns the
 * checker into the thing it is supposed to catch. So we ask the chains directly.
 *
 * Run manually (it needs the network):
 *   npm run check:live
 *
 * Exits non-zero if any published address has no code where it should, or if
 * USDC's decimals() is not the value the tool assumes.
 */

import { ArcRpc, createMainnetRpc, createTestnetRpc } from "../docs/lib/arc.js";
import {
  CCTP_TOKEN_MESSENGER_V2,
  MAINNET_CHAIN_ID,
  MAINNET_CONTRACTS,
  TESTNET_CHAIN_ID,
  TESTNET_CONTRACTS,
  USDC,
} from "../docs/lib/registry.js";
import { selector } from "../docs/lib/keccak.js";

let failures = 0;
const fail = (message) => { failures++; console.log(`  FAIL  ${message}`); };
const pass = (message) => console.log(`  ok    ${message}`);
const skip = (message) => console.log(`  skip  ${message}`);

const codeSize = (code) => (code && code !== "0x" ? (code.length - 2) / 2 : 0);

async function checkNetwork(label, rpc, expectedChainId, contracts) {
  console.log(`\n${label}`);
  let chainId;
  try {
    chainId = await rpc.chainId();
  } catch (error) {
    fail(`RPC unreachable: ${error.message}`);
    return;
  }
  if (chainId !== expectedChainId) {
    fail(`chain id ${chainId}, expected ${expectedChainId}`);
  } else {
    pass(`chain id ${chainId}`);
  }

  for (const entry of contracts) {
    try {
      const code = await rpc.getCode(entry.address);
      const size = codeSize(code);
      if (size > 0) pass(`${entry.name.padEnd(38)} ${size} bytes  ${entry.address}`);
      else fail(`${entry.name} has NO code at ${entry.address}`);
    } catch (error) {
      fail(`${entry.name}: ${error.message}`);
    }
  }
}

async function main() {
  const mainnet = createMainnetRpc();
  const testnet = createTestnetRpc();

  await checkNetwork("Arc mainnet (5042)", mainnet, MAINNET_CHAIN_ID, MAINNET_CONTRACTS);
  await checkNetwork("Arc testnet (5042002)", testnet, TESTNET_CHAIN_ID, TESTNET_CONTRACTS);

  console.log("\nbehaviour the tool depends on");
  try {
    // Native USDC balance is 18-decimal; the ERC-20 view must report 6.
    const result = await mainnet.callContract(USDC, selector("decimals()"));
    const decimals = Number(BigInt(result));
    if (decimals === 6) pass(`USDC ERC-20 decimals() == 6 (native is 18)`);
    else fail(`USDC decimals() returned ${decimals}, expected 6`);
  } catch (error) {
    fail(`decimals() call failed: ${error.message}`);
  }

  try {
    // A regular account must return no code, or the EOA heuristic is worthless.
    const code = await mainnet.getCode("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    if (codeSize(code) === 0) pass("a known account returns 0x (EOA detection works)");
    else fail("expected no code for a known account");
  } catch (error) {
    fail(`EOA probe failed: ${error.message}`);
  }

  try {
    const testnetOnly = "0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA";
    const onMainnet = codeSize(await mainnet.getCode(testnetOnly));
    const onTestnet = codeSize(await testnet.getCode(testnetOnly));
    if (onMainnet === 0 && onTestnet > 0) {
      pass("testnet TokenMessenger has code on testnet and none on mainnet");
    } else {
      fail(`testnet/mainnet address expectations broke (mainnet=${onMainnet}, testnet=${onTestnet})`);
    }
  } catch (error) {
    fail(`cross-network probe failed: ${error.message}`);
  }

  console.log("\nconfiguration sanity");
  if (CCTP_TOKEN_MESSENGER_V2 === CCTP_TOKEN_MESSENGER_V2.toLowerCase()) pass("bridge address is stored lowercase");
  else fail("bridge address is not lowercase");

  console.log(`\n${failures === 0 ? "All live checks passed." : `${failures} live check(s) FAILED.`}`);
  if (failures > 0) process.exitCode = 1;
  if (!mainnet || !testnet || !ArcRpc) skip("unreachable");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
