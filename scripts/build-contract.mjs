/**
 * Compile ArcGuardRegistry and write the artifact the browser deploy page reads.
 *
 *   npm install && npm run build:contract
 *
 * Needs no Foundry. The artifact is committed so the site works without a build.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

import { compileRegistry } from "./compile.mjs";

const outPath = fileURLToPath(new URL("../contracts/artifacts/ArcGuardRegistry.json", import.meta.url));
// GitHub Pages serving from /docs cannot reach ../contracts, so the site gets
// its own copy. Same bytes; regenerate both with this script.
const sitePath = fileURLToPath(new URL("../docs/artifacts/ArcGuardRegistry.json", import.meta.url));

const artifact = await compileRegistry();
const payload = {
  contractName: artifact.contractName,
  compiler: artifact.compiler,
  abi: artifact.abi,
  bytecode: artifact.bytecode,
};
const json = JSON.stringify(payload, null, 2) + "\n";

for (const path of [outPath, sitePath]) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, json, "utf8");
}

for (const warning of artifact.warnings) console.log("warning:", warning.split("\n")[0]);
console.log(`solc ${artifact.compiler}`);
console.log(`ABI entries : ${artifact.abi.length}`);
console.log(`bytecode    : ${(artifact.bytecode.length - 2) / 2} bytes`);
console.log(`wrote       : contracts/artifacts/ArcGuardRegistry.json`);
console.log(`wrote       : docs/artifacts/ArcGuardRegistry.json`);
