# Arc Microgrants submission

Copy/paste-ready. Replace the three `<…>` placeholders once the repo is pushed
and the registry is deployed.

---

**Project name:** Arc Guard

**One line:** A pre-flight checker for Arc mainnet that tells you what a
transaction actually does before you sign it.

**Live link:** https://0xZumii.github.io/ArcGuard/

**Public repo:** https://github.com/0xZumii/ArcGuard

**Builder profile:** https://github.com/0xZumii

**Deployed on Arc mainnet:** ArcGuardRegistry at `0x…` —
`https://explorer.arc.io/address/0x…`
(deploy it via `docs/deploy.html`, then replace both `0x…` above with the real
address; nothing else on this page needs editing)

---

## What it does

Paste a transaction (or a hash, an address, or a link) and Arc Guard reports what
you are about to authorise, in plain language, read live from Arc mainnet.

It targets the scams that appeared around the Arc launch, which all share one
shape: a true statement about Arc followed by a false conclusion. Arc is real,
USDC is the gas token, the mainnet is live — *so send your USDC here to bridge
it.*

The transaction is the tell. A real Arc bridge calls `depositForBurn` on Circle's
CCTP TokenMessenger at `0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d`. A fake one
asks you to send USDC to a wallet, or calls `transfer()` on the USDC contract and
calls that bridging. So the tool reads the transaction, reads the destination
address on-chain, and compares both against **what you were told it does**:

- A "bridge" that only moves USDC to a wallet → critical.
- A `transfer()` on USDC presented as a bridge → critical.
- A testnet CCTP address presented as a mainnet bridge → critical.
- A "rewards claim" that is actually an unlimited approval → critical. Arc has no
  airdrop and no rewards programme, so the premise itself is false.
- A legitimate `depositForBurn` to the real TokenMessenger → recognised and not
  condemned, which matters as much as the catches.

Because a transaction alone is often neutral, the claim is an input. That is the
whole design: no classifier, one mismatch.

The site is a static page with no backend and no API key — it queries Arc's
public mainnet RPC directly from the browser, which is possible because that RPC
is CORS-open.

## What it uses Arc for

- Reads Arc mainnet state (`eth_getCode`, `eth_getBalance`, `eth_call`,
  `eth_getTransactionByHash`) to decide whether an address is a contract, whether
  it is one of Circle's published contracts, and whether it is a testnet address
  being passed off as mainnet.
- Verifies chain ID 5042 before it will give findings at all — analysing the
  wrong chain is itself a way to be misled.
- Runs an ownerless registry contract on Arc mainnet where users can file public,
  attributed reports about drainer addresses. It costs a small USDC bond to
  report, returned on retraction, so a drive-by false accusation is not free.
- Handles Arc's USDC dual-interface model explicitly (18 decimals natively, 6
  through the ERC-20 interface at `0x3600…0000`) — the most common way to misread
  an amount on Arc.

## How it is verified

- `npm test` — 62 unit tests. Every function selector is derived with a
  from-scratch Keccak-256 and asserted against the value already known on-chain,
  so the tool cannot silently point at the wrong function.
- `npm run check:live` — asks Arc mainnet **and** testnet for the code at every
  address the tool trusts. All 17 mainnet and 10 testnet addresses verify. This
  caught two errors in the material the project started from: the widely-circulated
  CCTP addresses are testnet, and mainnet CCTP is live (it was the public RPC and
  Gateway front end that were restricted during the private phase).
- `npm run test:contract` — compiles the Solidity with solc and exercises it on an
  in-process EVM, including the swap-and-pop path that silently corrupts state if
  the index bookkeeping is wrong.
- `npm run test:page` — imports the real `app.js` into a jsdom document and clicks
  the real buttons against live mainnet. This is how a false positive was caught:
  the tool had been flagging an ordinary USDC payment as critical, which is the
  failure mode that destroys a security tool's credibility. The claim-mismatch
  design came out of fixing it.

## Honest scope

This is a heuristic checker, not drainer analysis or a classifier. It recognises
the documented Arc patterns, not novel ones. It never says "safe" — it reports
what it observed and what it could not see. The community registry is uncurated
public reports, not a verified blocklist, and the drainer-domain list is a seed
rather than a feed.

It is $500 and a credential, not a research contribution. It is the first thing
that genuinely connects to the goal of keeping people safe in this space: one
working tool that catches the scam pattern that is actually happening on the
chain it was excited about.
