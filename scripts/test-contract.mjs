/**
 * Contract tests that run without Foundry.
 *
 *   npm run test:contract
 *
 * Compiles ArcGuardRegistry with solc, deploys it to an in-process EVM (ganache)
 * and exercises the bond / report / retract behaviour, including the swap-and-pop
 * path that silently corrupts state if the index bookkeeping is wrong.
 *
 * contracts/test/ArcGuardRegistry.t.sol is the same suite for Foundry, so the
 * contract is verified either way.
 */

import { compileRegistry } from "./compile.mjs";

let failures = 0;
let checks = 0;

function ok(condition, label) {
  checks++;
  if (condition) console.log(`  ok    ${label}`);
  else {
    failures++;
    console.log(`  FAIL  ${label}`);
  }
}

async function expectRevert(promise, label) {
  checks++;
  try {
    await promise;
    failures++;
    console.log(`  FAIL  ${label} (expected a revert, call succeeded)`);
  } catch (error) {
    const message = String(error?.shortMessage ?? error?.message ?? error);
    console.log(`  ok    ${label}  [${message.split("\n")[0].slice(0, 70)}]`);
  }
}

const BOND = 10n ** 18n;
const Tag = { Drainer: 1, FakeBridge: 2, FakeToken: 3, PhishingSite: 4, TestnetMislabel: 5, Other: 6 };

async function main() {
  const artifact = await compileRegistry();
  console.log(`solc ${artifact.compiler} — compiled cleanly`);

  const { default: ganache } = await import("ganache");
  const { ethers } = await import("ethers");

  const eip1193 = ganache.provider({
    logging: { quiet: true },
    wallet: { totalAccounts: 4, defaultBalance: 1000 },
  });
  const provider = new ethers.BrowserProvider(eip1193);
  const signers = await provider.listAccounts();
  const [alice, bob, carol] = await Promise.all(signers.slice(0, 3).map((s) => s.getAddress()));
  const aliceSigner = signers[0];
  const bobSigner = signers[1];
  const carolSigner = signers[2];
  const scam = "0x000000000000000000000000000000000000dead";

  // Ethers caches the "latest" block for a moment, which makes a balance read
  // immediately after a transaction return the pre-transaction value. Ask the
  // node directly so the refund assertion is actually testing the refund.
  const rawBalance = async (address) =>
    BigInt(await eip1193.request({ method: "eth_getBalance", params: [address, "latest"] }));

  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, aliceSigner);
  const registry = await factory.deploy();
  await registry.waitForDeployment();
  const address = await registry.getAddress();
  console.log(`deployed to in-process EVM at ${address}\n`);

  console.log("bond rules");
  await expectRevert(
    registry.report.staticCall(scam, Tag.Drainer, "underpaid", { value: BOND - 1n }),
    "a report below the bond reverts",
  );
  const tx = await registry.report(scam, Tag.FakeBridge, "pretends to be CCTP", { value: BOND });
  await tx.wait();
  ok((await registry.reportCount(scam)) === 1n, "reportCount increments");
  ok(await registry.hasReported(scam, alice), "hasReported records the reporter");

  const reports = await registry.getReports(scam);
  ok(reports[0].reporter === alice, "report is attributed to the reporter");
  ok(Number(reports[0].tag) === Tag.FakeBridge, "tag is stored");
  ok(reports[0].deposit === BOND, "deposit is stored for exact refunds");
  ok(reports[0].note === "pretends to be CCTP", "note is stored");

  console.log("\none report per reporter");
  await expectRevert(
    registry.report.staticCall(scam, Tag.Drainer, "again", { value: BOND }),
    "a second report from the same reporter reverts",
  );

  console.log("\nmultiple reporters and the swap-and-pop");
  await (await registry.connect(bobSigner).report(scam, Tag.FakeToken, "b", { value: BOND })).wait();
  await (await registry.connect(carolSigner).report(scam, Tag.Drainer, "c", { value: BOND })).wait();
  ok((await registry.reportCount(scam)) === 3n, "three reporters accumulate");

  const before = await rawBalance(bob);
  await (await registry.connect(bobSigner).retract(scam)).wait();
  const after = await rawBalance(bob);
  ok(after > before, "retracting refunds the bond (gas aside)");
  ok((await registry.reportCount(scam)) === 2n, "one report removed");

  const remaining = await registry.reporters(scam);
  ok(remaining[0] === alice && remaining[1] === carol, "survivors keep their index after removal");

  // The survivors must still be retractable; a broken index map shows up here.
  await (await registry.retract(scam)).wait();
  await (await registry.connect(carolSigner).retract(scam)).wait();
  ok((await registry.reportCount(scam)) === 0n, "all reports can be retracted");

  await expectRevert(registry.retract.staticCall(scam), "retracting with no report reverts");

  console.log("\nper-target isolation");
  ok((await registry.reportCount("0x00000000000000000000000000000000000000be")) === 0n,
    "a different address has no reports");

  console.log(`\n${checks - failures}/${checks} checks passed.`);

  // ganache bundles a µWS binary that is incompatible with Node 24 and forces a
  // non-zero exit even when every assertion passed (verified: a bare
  // `ganache.provider()` in this environment exits 1 with no error raised).
  // Since the assertions are what matter, set the exit code ourselves.
  const code = failures > 0 ? 1 : 0;
  await new Promise((resolve) => setTimeout(resolve, 100)); // let stdout flush
  try {
    await eip1193.disconnect?.();
  } catch {
    /* teardown only */
  }
  process.exit(code);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
