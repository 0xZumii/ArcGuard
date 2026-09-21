/**
 * Browser deploy for ArcGuardRegistry.
 *
 * Uses raw EIP-1193 calls rather than an SDK, so there is no bundler and no
 * dependency in the deployed page. The transaction is signed by the user's own
 * wallet; this script never sees a key.
 */

const ARC_CHAIN_ID = 5042;
const ARC_CHAIN_ID_HEX = "0x" + ARC_CHAIN_ID.toString(16); // 0x13b2

const ARC_CHAIN_PARAMS = {
  chainId: ARC_CHAIN_ID_HEX,
  chainName: "Arc",
  nativeCurrency: { name: "USDC", symbol: "USDC", decimals: 18 },
  rpcUrls: ["https://rpc.mainnet.arc.io"],
  blockExplorerUrls: ["https://explorer.arc.io"],
};

const $ = (id) => document.getElementById(id);

let artifact = null;
let account = null;

function setStatus(text, kind) {
  $("chain-text").textContent = text;
  $("chain-status").querySelector(".dot").className = `dot dot--${kind}`;
}

function note(title, body, kind = "info") {
  const div = document.createElement("div");
  div.className = `verdict verdict--${kind}`;
  const h = document.createElement("h2");
  h.textContent = title;
  const p = document.createElement("p");
  p.textContent = body;
  div.append(h, p);
  return div;
}

function show(...nodes) {
  $("deploy-results").replaceChildren(...nodes);
}

async function loadArtifact() {
  const response = await fetch("./artifacts/ArcGuardRegistry.json", { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json();
}

async function refreshAccount() {
  const accounts = await window.ethereum.request({ method: "eth_accounts" });
  account = accounts?.[0] ?? null;
  if (!account) {
    $("account-info").textContent = "No account connected.";
    $("deploy").disabled = true;
    return;
  }
  const balanceHex = await window.ethereum.request({ method: "eth_getBalance", params: [account, "latest"] });
  const balance = Number(BigInt(balanceHex)) / 1e18;
  $("account-info").textContent = `${account} — ${balance.toFixed(6)} USDC (gas)`;
  $("deploy").disabled = !(await onArc());
}

async function currentChainId() {
  return Number(BigInt(await window.ethereum.request({ method: "eth_chainId" })));
}

async function onArc() {
  try {
    const chainId = await currentChainId();
    if (chainId === ARC_CHAIN_ID) {
      setStatus("Arc mainnet · chain 5042", "ok");
      $("switch").disabled = true;
      return true;
    }
    setStatus(`wrong chain: ${chainId}`, "bad");
    $("switch").disabled = false;
    return false;
  } catch {
    return false;
  }
}

async function switchToArc() {
  try {
    await window.ethereum.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: ARC_CHAIN_ID_HEX }],
    });
  } catch (error) {
    // 4902 = unknown chain; add it, then the wallet switches on its own.
    if (error?.code === 4902) {
      await window.ethereum.request({
        method: "wallet_addEthereumChain",
        params: [ARC_CHAIN_PARAMS],
      });
    } else {
      throw error;
    }
  }
  await refreshAccount();
}

async function waitForReceipt(hash) {
  for (let attempt = 0; attempt < 90; attempt++) {
    const receipt = await window.ethereum.request({
      method: "eth_getTransactionReceipt",
      params: [hash],
    });
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("timed out waiting for the receipt");
}

async function deploy() {
  const button = $("deploy");
  button.disabled = true;
  try {
    if (!(await onArc())) throw new Error("Wallet is not on Arc mainnet. Use Switch to Arc first.");
    show(note("Waiting for your wallet", "Confirm the deployment transaction. It contains only the contract bytecode.", "notable"));

    const hash = await window.ethereum.request({
      method: "eth_sendTransaction",
      params: [{ from: account, data: artifact.bytecode, value: "0x0" }],
    });

    show(note("Transaction sent", `${hash} — waiting for the receipt. Arc finalises in about a second.`, "notable"));
    const receipt = await waitForReceipt(hash);

    if (!receipt.contractAddress) {
      show(note("Deployment failed", `No contract address in the receipt. Status: ${receipt.status}`, "critical"));
      return;
    }

    const info = note("Deployed", `${receipt.contractAddress}`, "info");
    const steps = document.createElement("p");
    steps.innerHTML =
      "Next: put this address in <code>docs/config.js</code> as <code>registryAddress</code>, " +
      "then commit. The checker picks it up on the next load.";
    info.append(steps);
    show(info);
  } catch (error) {
    show(note("Could not deploy", String(error?.message ?? error), "critical"));
  } finally {
    button.disabled = false;
  }
}

async function init() {
  try {
    artifact = await loadArtifact();
    $("artifact-info").textContent =
      `${artifact.contractName} · solc ${artifact.compiler} · ${(artifact.bytecode.length - 2) / 2} bytes of bytecode`;
  } catch (error) {
    $("artifact-info").textContent = `Could not load the artifact (${error.message}). Run "npm run build:contract".`;
    return;
  }

  if (!window.ethereum) {
    setStatus("no wallet detected", "bad");
    $("account-info").textContent =
      "No injected wallet found. Install one, or use the Foundry route at the bottom of this page.";
    return;
  }

  await refreshAccount();
  await onArc();

  $("connect").addEventListener("click", async () => {
    try {
      await window.ethereum.request({ method: "eth_requestAccounts" });
      await refreshAccount();
      await onArc();
    } catch (error) {
      show(note("Connection rejected", String(error?.message ?? error), "critical"));
    }
  });
  $("switch").addEventListener("click", () => switchToArc().catch((error) =>
    show(note("Could not switch network", String(error?.message ?? error), "critical"))));
  $("deploy").addEventListener("click", deploy);

  window.ethereum.on?.("chainChanged", () => { onArc(); });
  window.ethereum.on?.("accountsChanged", () => { refreshAccount().then(onArc); });
}

init();
