/**
 * Arc JSON-RPC client.
 *
 * Uses the platform `fetch`, so the same module runs in the browser (where the
 * checker is deployed) and in Node (where the live tests run). No SDK, no build
 * step, no API key.
 *
 * Verified reachable and CORS-open from a browser origin: Arc's public mainnet
 * RPC echoes the request Origin, so a static page can query mainnet directly.
 * See tests/live.check.mjs.
 */

import {
  MAINNET_CHAIN_ID,
  MAINNET_RPC,
  MAINNET_RPC_FALLBACKS,
  TESTNET_CHAIN_ID,
  TESTNET_RPC,
} from "./registry.js";
import { selector } from "./keccak.js";

export const REPORT_COUNT_SELECTOR = selector("reportCount(address)");

export class RpcError extends Error {}

/** Minimal JSON-RPC over fetch, with endpoint fallback. */
export class ArcRpc {
  /**
   * @param {object} [options]
   * @param {"mainnet"|"testnet"} [options.network]
   * @param {string} [options.url] force a single endpoint (Vite/proxy, Alchemy, ...)
   * @param {number} [options.timeoutMs]
   */
  constructor({ network = "mainnet", url = null, timeoutMs = 15000 } = {}) {
    this.network = network;
    this.expectedChainId = network === "mainnet" ? MAINNET_CHAIN_ID : TESTNET_CHAIN_ID;
    this.timeoutMs = timeoutMs;
    this.urls = url
      ? [url]
      : network === "mainnet"
        ? [MAINNET_RPC, ...MAINNET_RPC_FALLBACKS]
        : [TESTNET_RPC];
    this._id = 0;
  }

  async call(method, params = []) {
    let lastError = null;
    for (const url of this.urls) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const response = await fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: ++this._id, method, params }),
          signal: controller.signal,
        });
        if (!response.ok) throw new RpcError(`${url} returned HTTP ${response.status}`);
        const body = await response.json();
        if (body.error) throw new RpcError(`${url}: ${body.error.message ?? JSON.stringify(body.error)}`);
        return body.result;
      } catch (error) {
        lastError = error;
      } finally {
        clearTimeout(timer);
      }
    }
    throw new RpcError(`all Arc RPC endpoints failed for ${method}: ${lastError?.message ?? "unknown error"}`);
  }

  async chainId() {
    return Number(BigInt(await this.call("eth_chainId")));
  }

  /** Runtime bytecode. "0x" means no contract is deployed there (an EOA). */
  async getCode(address) {
    return (await this.call("eth_getCode", [address, "latest"])) ?? "0x";
  }

  /** Native USDC balance in base units (18 decimals at the protocol level). */
  async getBalance(address) {
    return BigInt((await this.call("eth_getBalance", [address, "latest"])) ?? "0x0");
  }

  /** Read-only contract call. */
  async callContract(to, data) {
    return await this.call("eth_call", [{ to, data }, "latest"]);
  }

  async getTransaction(hash) {
    return await this.call("eth_getTransactionByHash", [hash]);
  }

  async getBlockNumber() {
    return Number(BigInt(await this.call("eth_blockNumber")));
  }

  /**
   * How many public reports the on-chain registry holds for an address.
   * Returns null when no registry is configured, so the UI can say "not checked"
   * rather than silently implying "clean".
   */
  async getReportCount(registryAddress, target) {
    if (!registryAddress) return null;
    const word = target.toLowerCase().replace(/^0x/, "").padStart(64, "0");
    const result = await this.callContract(registryAddress, REPORT_COUNT_SELECTOR + word);
    if (!result || result === "0x") return 0;
    return Number(BigInt(result));
  }
}

export function createMainnetRpc(options = {}) {
  return new ArcRpc({ network: "mainnet", ...options });
}

export function createTestnetRpc(options = {}) {
  return new ArcRpc({ network: "testnet", ...options });
}

export function codeSize(codeHex) {
  if (typeof codeHex !== "string" || !codeHex.startsWith("0x")) return 0;
  return (codeHex.length - 2) / 2;
}
