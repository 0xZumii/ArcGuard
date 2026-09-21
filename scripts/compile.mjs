/** Shared solc compilation for the build and test scripts. */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

export const CONTRACT_PATH = fileURLToPath(
  new URL("../contracts/src/ArcGuardRegistry.sol", import.meta.url),
);
export const SOURCE_NAME = "ArcGuardRegistry.sol";

export async function compileRegistry() {
  let solc;
  try {
    ({ default: solc } = await import("solc"));
  } catch {
    throw new Error(
      "solc is not installed. Run `npm install` first, or use Foundry: `forge build`.",
    );
  }

  const source = await readFile(CONTRACT_PATH, "utf8");
  const input = {
    language: "Solidity",
    sources: { [SOURCE_NAME]: { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      // Paris keeps the bytecode runnable on every EVM Arc supports *and* on
      // local test EVMs (ganache predates MCOPY). This contract needs no
      // Cancun-only opcodes, so maximal compatibility costs nothing here.
      evmVersion: "paris",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors ?? []).filter((e) => e.severity === "error");
  if (errors.length) {
    throw new Error("solc failed:\n" + errors.map((e) => e.formattedMessage).join("\n"));
  }
  const warnings = (output.errors ?? []).filter((e) => e.severity !== "error").map((e) => e.formattedMessage);

  const contract = output.contracts?.[SOURCE_NAME]?.ArcGuardRegistry;
  if (!contract) throw new Error("compiled output did not contain ArcGuardRegistry");

  return {
    contractName: "ArcGuardRegistry",
    compiler: solc.version(),
    abi: contract.abi,
    bytecode: "0x" + contract.evm.bytecode.object,
    warnings,
  };
}
