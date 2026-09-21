/**
 * Static smoke test for the deployed site.
 *
 *   npm run serve          # in one terminal
 *   node scripts/smoke-site.mjs
 *
 * Fetches every local asset the pages reference, so a typo in a script path or a
 * missing artifact fails loudly here instead of silently in a reviewer's browser.
 * Also checks the deploy artifact actually contains a deployable contract.
 */

const BASE = process.env.BASE ?? "http://localhost:5173";

let failures = 0;
const ok = (message) => console.log(`  ok    ${message}`);
const fail = (message) => { failures++; console.log(`  FAIL  ${message}`); };

const LOCAL_REF = /(?:src|href)="(\.\/[^"]+)"/g;

async function get(path) {
  const response = await fetch(new URL(path, BASE));
  const body = await response.text();
  return { status: response.status, type: response.headers.get("content-type") ?? "", body };
}

async function checkPage(path, markers) {
  console.log(`\n${path}`);
  const page = await get(path);
  if (page.status !== 200) {
    fail(`${path} returned ${page.status}`);
    return [];
  }
  ok(`${path} 200 (${page.type})`);
  for (const marker of markers) {
    if (page.body.includes(marker)) ok(`contains ${JSON.stringify(marker)}`);
    else fail(`missing ${JSON.stringify(marker)}`);
  }

  const refs = [...page.body.matchAll(LOCAL_REF)].map((m) => m[1]);
  for (const ref of refs) {
    const asset = await get(ref);
    if (asset.status === 200 && asset.body.length > 0) ok(`${ref} 200 (${asset.body.length} bytes)`);
    else fail(`${ref} -> ${asset.status}, ${asset.body.length} bytes`);
  }
  return refs;
}

const indexRefs = await checkPage("/", ["Arc Guard", "id=\"tx-form\"", "id=\"addr-form\"", "id=\"link-form\""]);
const deployRefs = await checkPage("/deploy.html", ["ArcGuardRegistry", "id=\"deploy\""]);

// The library graph the app imports (app.js pulls these in at runtime).
console.log("\nlibrary modules");
for (const path of [
  "/lib/keccak.js",
  "/lib/decode.js",
  "/lib/checks.js",
  "/lib/domains.js",
  "/lib/registry.js",
  "/lib/format.js",
  "/lib/findings.js",
  "/lib/arc.js",
  "/config.js",
]) {
  const asset = await get(path);
  if (asset.status === 200 && asset.body.length > 0) ok(`${path} 200 (${asset.body.length} bytes)`);
  else fail(`${path} -> ${asset.status}`);
}

console.log("\ndeploy artifact");
const artifact = await get("/artifacts/ArcGuardRegistry.json");
if (artifact.status !== 200) {
  fail(`artifact returned ${artifact.status}`);
} else {
  try {
    const parsed = JSON.parse(artifact.body);
    if (parsed.contractName === "ArcGuardRegistry") ok("contractName is ArcGuardRegistry");
    else fail(`unexpected contractName: ${parsed.contractName}`);
    if (Array.isArray(parsed.abi) && parsed.abi.length > 0) ok(`abi has ${parsed.abi.length} entries`);
    else fail("abi is empty");
    if (typeof parsed.bytecode === "string" && parsed.bytecode.startsWith("0x") && parsed.bytecode.length > 100) {
      ok(`bytecode is deployable (${(parsed.bytecode.length - 2) / 2} bytes)`);
    } else {
      fail("bytecode looks wrong");
    }
    const required = ["reportCount(address)", "report(address,uint8,string)", "retract(address)"];
    for (const signature of required) {
      const found = parsed.abi.some((entry) => {
        if (entry.type !== "function") return false;
        return `${entry.name}(${entry.inputs.map((i) => i.type).join(",")})` === signature;
      });
      if (found) ok(`abi exposes ${signature}`);
      else fail(`abi is missing ${signature}`);
    }
  } catch (error) {
    fail(`artifact is not valid JSON: ${error.message}`);
  }
}

console.log("\nunused refs sanity");
if (indexRefs.includes("./app.js")) ok("index.html loads app.js as a module");
else fail("index.html does not reference ./app.js");
if (deployRefs.includes("./deploy.js")) ok("deploy.html loads deploy.js as a module");
else fail("deploy.html does not reference ./deploy.js");

console.log(`\n${failures === 0 ? "Site smoke test passed." : `${failures} failure(s).`}`);
process.exit(failures === 0 ? 0 : 1);
