# Arc Guard

**Check what a transaction does before you sign it — on Arc mainnet.**

Arc Guard is a pre-flight checker for Arc, Circle's USDC-native L1. Paste a
transaction (or a hash, or an address, or a link) and it tells you what you are
actually about to authorise, in plain language, using facts read live from Arc
mainnet.

It is built for the specific scams that appeared around the Arc launch, and it
never says "safe".

---

## The idea, in one paragraph

The scams around Arc are built on true statements with false conclusions:
Arc is real, Circle raised real money, the mainnet is live, USDC is the gas
token. Then: *so send your USDC here to bridge it.* The transaction itself is
the tell. A **real** Arc bridge calls `depositForBurn` on the CCTP TokenMessenger
at `0x28b5…cf5d`. A fake one asks you to send USDC to a wallet, or calls
`transfer()` on the USDC contract and calls it bridging. So this tool reads the
transaction, reads the destination on-chain, and compares both against **what you
were told it does**:

> A transaction on its own is often neutral. Sending USDC to a wallet is a
> payment or a theft depending on what you were promised — and a `transfer()`
> call is ordinary until somebody calls it a bridge.

That is why there is no classifier here. The mismatch is the signal.

---

## What it checks

**A transaction.** Decodes the calldata (selectors are derived with Keccak-256
at runtime, not hardcoded), then checks:

| Check | Why it matters on Arc |
| :--- | :--- |
| Is the recipient a contract at all? | A "bridge deposit address" with no code is a scam. `eth_getCode` settles it. |
| Is the address a **testnet** contract? | The single most effective trick is passing a testnet address off as a mainnet bridge. Arc's testnet CCTP addresses look nothing like mainnet's. |
| Does a `transfer()`/`transferFrom()` on USDC claim to be a bridge? | Real bridging burns on the TokenMessenger; it never forwards your USDC to an address. |
| Is an approval's spender a wallet with no code? | An allowance to an EOA is just a standing instruction that whoever holds that key can take your tokens. |
| Unlimited approvals, `permit`, Permit2, `setApprovalForAll` | Permission persists after the transaction. These are the modern drain vectors (signature phishing), not bytecode. |
| `depositForBurn` sent to the **wrong** contract | Copying the real function into a fake contract makes a wallet preview look correct. |
| Is the destination a fresh EIP-1167 minimal proxy? | The code at the address you are shown is a 45-byte forwarder; the behaviour is elsewhere. |
| Native vs ERC-20 USDC confusion | Arc exposes USDC twice — 18 decimals natively, 6 through the ERC-20 interface at `0x3600…0000`. Mixing them is a 10¹² error unique to Arc. |

**An address.** Is this what you were told it is? Compares against Circle's
published Arc contracts, reports testnet addresses, walks minimal proxies to
their implementation.

**A link.** The documented Arc drainer (`governance-arc.com`) clones the real
front end and drains on wallet connect. No bytecode check catches that. Domain
checking does: official-domain comparison, a documented-drainer list, brand +
lure-word detection (`arc-claim.com`), typosquat distance, and punycode.

**A community registry**, deployed on Arc mainnet: an append-only, ownerless
contract where anyone can file a public report against an address, with a small
USDC bond that is returned if they retract. Reports are attributed on-chain, so a
cluster of reports from one funder is visible as a cluster. The tool surfaces the
count; it does not treat it as a verdict.

---

## Verified, not assumed

Every address this tool trusts is checked against the live chain by
`npm run check:live`. That command asks Arc **mainnet and testnet** for the code
at each published address and fails if any is missing, and confirms USDC's
ERC-20 `decimals()` is 6 while the native balance is 18.

All 17 mainnet and 10 testnet addresses currently verify. Two facts the tool
relies on were wrong in the material it grew out of, and the live check is what
caught them:

- The `0x8FE6…` / `0xE737…` CCTP addresses circulating as "Arc's bridge" are
  **testnet**. Mainnet is `0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d`.
- It was not CCTP that Arc restricted during the private phase, it was the public
  RPC and Gateway front end. Mainnet CCTP is live.

---

## Quick start

No build step, no backend, no API key. The Arc public RPC is reachable from a
browser (it echoes the request `Origin`, so a static page can query mainnet
directly).

```bash
npm run serve      # http://localhost:5173
```

Or just open `docs/index.html`.

Online: **https://0xZumii.github.io/ArcGuard/** ← the link for the grant
submission.

---

## Deploying

### 1. The site (GitHub Pages)

Push this repo, then **Settings → Pages → Deploy from a branch → `main` / `/docs`**.
`docs/` is self-contained: the app, the libraries, and the contract artifact.

**Why the root has an `index.html` that only redirects.** GitHub Pages runs
Jekyll by default, and Jekyll's rule is that a directory with no `index.html`
gets its `README.md` rendered as the homepage. If Pages is pointed at the
repository root, visitors therefore see this README instead of the checker —
which looks like a broken deployment but is just Jekyll's fallback. Two things
prevent it:

- `index.html` at the root redirects to `./docs/`, so the site works whichever
  folder Pages is pointed at.
- `docs/.nojekyll` stops Jekyll from processing the app directory at all.

Once Pages is set to `/docs`, the root `index.html` is redundant and can be
deleted.

### 2. The registry contract (Arc mainnet)

The contract is already compiled and committed at
`contracts/artifacts/ArcGuardRegistry.json`, so you can deploy **without
Foundry**:

1. Open `docs/deploy.html` (linked from the site footer).
2. Connect a wallet that holds a little USDC on Arc. Gas is about a cent.
3. Click deploy, then copy the printed address into `docs/config.js`:

```js
registryAddress: "0x…",
```

Commit and push. Until that address is set, the app says the registry is "not
deployed yet" rather than implying it looked and found nothing.

With Foundry, if you prefer:

```bash
forge install foundry-rs/forge-std
export PRIVATE_KEY=0x...
forge script script/Deploy.s.sol --rpc-url arc --broadcast
```

**The contract is ownerless on purpose.** No admin, no upgrade path, no
withdrawal. There is nothing to seize or phish, and equally nobody who can delete
a false report. Bonds attached to reports that are never retracted stay in the
contract forever, because there is no owner to sweep them. That trade is stated
here rather than hidden.

---

## Testing

```bash
npm test              # 62 unit tests: keccak vectors, decoding, checks, domains
npm run test:contract # compiles and tests the Solidity on an in-process EVM
npm run test:page     # drives the real page in a real DOM against live Arc mainnet
npm run check:live    # verifies every published Arc address on mainnet + testnet
npm run smoke:site    # every asset the pages reference resolves
```

Three of these are worth explaining, because they are where the confidence comes
from:

- **`npm test` derives every selector with Keccak-256 and asserts it equals the
  value already known on-chain** (`transfer(address,uint256)` → `0xa9059cbb`).
  A bug in the hashing code cannot silently make the tool point at the wrong
  function.
- **`npm run test:page` imports the real `docs/app.js` into a jsdom document and
  clicks the real buttons.** It asserts what a user would see. It is how the
  false-positive on plain payments was found: the tool had been flagging a
  normal USDC payment as critical, which is the failure mode that destroys a
  security tool's credibility.
- **`npm run check:live`** is the only check that can catch a mistyped address in
  the registry, which is the one bug that would make this tool say "safe" about
  the thing it is warning you about.

CI runs all of it on Node 20 and 22.

---

## Honest limitations

- It is **not an oracle**. It reports observations and what it could not see.
  "Nothing alarming" is not "safe".
- It recognises the **documented** Arc patterns, not novel ones.
- The registry is **uncurated public reports**, not a verified blocklist. It can
  be wrong, and anyone can file. A report against an address Circle publishes is
  almost certainly a false-flag campaign; the contract is deliberately dumb and
  the front end is where that is handled.
- The domain list is a **seed, not a feed**. Extend `KNOWN_DRAINER_DOMAINS`.
- Bytecode reading is heuristic. **Decompiled intent is not intent.**
- It cannot see inside `permit` signatures for a spender nested in typed data
  beyond flattening the payload.
- Arc's native asset is USDC, so `msg.value` and the ERC-20 balance are the same
  underlying money at different precisions. Getting that wrong is the most likely
  way to misread an amount, and the tool warns about it rather than hiding it.

---

## Why this fits the Arc Microgrants brief

The brief asks for "tiny apps, proofs of concept, prototypes, demos, hackathon
continuations, experimental infrastructure", deployed and working on Arc mainnet,
with a public repo. This is a working deployment, not a demo: it reads Arc
mainnet on load, verifies chain 5042 before it will give findings, and ships an
ownerless contract deployed to mainnet.

It also does the thing the brief's own ecosystem needs. Arc launched with
institutional validators and a brand-new, less-experienced user base — which is
exactly the population a structured, repetitive scam campaign targets. The
defence that fits is small, boring and specific: check the transaction against
the claim.

## Layout

```
docs/                 the site (GitHub Pages root)
  index.html          the checker
  deploy.html         browser deploy for the registry
  app.js              DOM wiring only; no judgement lives here
  lib/
    checks.js         the pre-flight logic + the claim-mismatch engine
    decode.js         calldata decoding; selectors derived via keccak
    domains.js        domain / typosquat / lure-word analysis
    registry.js       Circle's published Arc addresses, mainnet + testnet
    keccak.js         Keccak-256 from scratch (browser + Node)
    arc.js            JSON-RPC client with endpoint fallback
    findings.js       one finding model, shared by every checker
contracts/            Solidity, Foundry tests, compiled artifact
scripts/              live checks, contract build/test, page test, dev server
test/                 unit tests (node:test)
```

## Sources

- Arc mainnet parameters, contract addresses, CCTP and the USDC dual-interface
  model: <https://docs.arc.io>
- The `governance-arc.com` drainer: PCrisk and MalwareTips advisories, Sep 2026
- The ARC genesis mint being "not a commitment to publicly launch ARC":
  Circle's launch announcement and the ARC whitepaper

MIT licensed. Not affiliated with Circle or Arc.
