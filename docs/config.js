/**
 * Deployment configuration.
 *
 * The only value you must edit after deploying ArcGuardRegistry to Arc mainnet
 * is REGISTRY_ADDRESS. Until it is set, the checker still runs every offline and
 * on-chain-RPC check; it simply reports the community registry as "not deployed
 * yet" instead of pretending it looked.
 */

export const CONFIG = {
  /** Arc mainnet by default — this is a mainnet safety tool. */
  network: "mainnet",

  /**
   * Address of the deployed ArcGuardRegistry contract on Arc mainnet.
   * Leave empty to disable registry lookups. Set it after:
   *   forge script script/Deploy.s.sol --rpc-url https://rpc.mainnet.arc.io --broadcast
   */
  registryAddress: "",

  /** Override the RPC (e.g. your own Alchemy key). Empty = public endpoints. */
  rpcUrl: "",

  /**
   * The canonical URL this tool is published at, once you have a custom domain.
   * Leave empty while on GitHub Pages: the site still shows the non-affiliation
   * notice, and simply omits the "this is the only address" line.
   *   canonicalUrl: "https://arcguard.dev/",
   */
  canonicalUrl: "",

  /**
   * Chain ID the checker insists on. If the RPC answers with anything else the
   * tool refuses to give findings, because analysing the wrong chain is itself a
   * way to be misled.
   */
  requiredChainId: 5042,
};
