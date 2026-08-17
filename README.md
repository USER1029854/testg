# Exploited-contract regression corpus (BNB Smart Chain, 2026)

Real, verified on-chain source for five DeFi projects exploited on BNB Smart Chain
(chain id 56) in 2026, assembled as a regression-test corpus for a security-audit
pipeline: run the audit tool against `source/` in each target and check whether it
flags the bug described in that target's `BUG.md`.

## Layout

Each target is a folder under `targets/`:

```
targets/<TARGET>/
  source/    real verified Solidity, pulled from the block explorer's own
             getsourcecode API, reconstructed at its original file paths.
             Nothing here was retyped, summarized, or reconstructed from a
             post-mortem's code excerpt.
  raw/       the raw API/RPC responses (getsourcecode, storage-slot reads,
             tx/block lookups) that back every claim in PROVENANCE.md.
  PROVENANCE.md   which contract(s) were exploited and why, exploit tx,
                  how the address was found and cross-checked, proxy /
                  upgradeability analysis, and an explicit pre-hack verdict.
  BUG.md          ANSWER KEY. Kept out of source/ on purpose so source/ can be
                  handed to a test subject (human or audit tool) without also
                  handing them the answer. Function, defect, exploit path,
                  cited to public post-mortems.
```

## Method (applied per target)

1. Find the real exploited contract address(es) and exploit tx — from post-mortems
   (SlowMist, PeckShield, BlockSec, CertiK, TenArmor, press) and, where one exists,
   a DeFiHackLabs (`SunWeb3Sec/DeFiHackLabs`) Foundry PoC, which hardcodes the real
   addresses and a mainnet fork block.
2. Cross-check the address independently before trusting it — at least one of:
   an on-chain fact a wrong address couldn't satisfy (e.g. a decoded constructor
   argument linking two contracts), a second independent source, or decoding the
   actual exploit transaction's logs/calldata.
3. Pull verified source via the Etherscan V2 unified API
   (`api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode`),
   save the raw response, reconstruct every file at its original relative path.
4. Determine upgradeability. If the contract is an EIP-1967 proxy, read the
   implementation slot at a block before the exploit and pull *that*
   implementation's source, not today's. If it's not a proxy, deployed bytecode
   is immutable, so current verified source is exploit-time source by
   construction — stated explicitly rather than left implicit.
5. Write up the bug from the pulled source plus cited public post-mortems, in a
   file kept separate from `source/`.

Where any step couldn't be completed — address unconfirmed, source unverified,
proxy check blocked by API limits — that is stated explicitly in the target's
`PROVENANCE.md`/`BUG.md` rather than papered over. Two targets' initial one-line
leads (given as a starting point, not verified fact) turned out not to match what
the pulled source actually shows; both are corrected in place with the discrepancy
explained, not silently overwritten.

## Per-target status

| Target | Address(es) confirmed | Source pulled | Proxy check | Pre-hack verdict |
|---|---|---|---|---|
| [MOKE](targets/MOKE/) | Yes, 4 contracts (token, release, LP manager, dividend) | Yes, all 4 | Non-proxy, confirmed via public-RPC EIP-1967 slot read + byte-identical bytecode pre/post exploit | **Confirmed pre-hack** |
| [LULA](targets/LULA/) | Yes, LULA token; two independent public sources cited a *wrong* address, caught and ruled out | Yes, LULA token. Rental contract (holds the actual attacker-facing claim entrypoint) is unverified on-chain | Non-proxy, confirmed via slot read + byte-identical bytecode pre/post exploit | **Confirmed pre-hack** for the LULA token; Rental contract's code is simply unavailable (unverified) |
| [Crypto DAO / Pro token](targets/CryptoDAO-Pro/) | Yes, ProToken + 2 PancakeSwap pairs + USDT | Yes, all 4 | Non-proxy, confirmed via slot read | **Confirmed pre-hack** |
| [LOOPSDAO / LpdFi](targets/LOOPSDAO-LpdFi/) | Yes, both `Lpd` and `LpdFi` | Yes, both, full multi-file trees | Non-proxy, confirmed via slot read + `eth_getCode` diff pre/post exploit | **Confirmed pre-hack** |
| [42DAO / Balance Protocol](targets/42DAO-BalanceProtocol/) | Partial. `Vat` and `Dog` confirmed (cross-linked on-chain via a decoded constructor argument); the **Median Oracle and Spotter contracts named in every post-mortem as the actual entry point could not be confirmed on mainnet** | `Vat`, `Dog`, `Blc`, `FTD` only — Median/Spotter explicitly NOT included, since no verifiable mainnet address was found | Non-proxy per `getsourcecode`'s own field; the independent EIP-1967 slot cross-check specified by the method **could not be run** — this session's API key rejected `module=proxy`/`block`/`account` calls for chain 56, and the Blockscout BSC fallback was unreachable | Vat/Dog: high confidence, not full-strength proof (see gap above). Median/Spotter: **not established, code not included** |

Read each target's own `PROVENANCE.md` for the full evidence trail before treating
any of the above as more certain than it's stated to be — the table is a summary,
not a substitute.

## Known gaps (see individual PROVENANCE.md/BUG.md for detail)

- **42DAO/Balance Protocol**: the Median Oracle and mainnet Spotter — the contracts
  actually named as the exploit's entry point — were not found as verifiable
  mainnet source. Only the downstream `Vat`/`Dog` contracts they fed a bad price
  into are included. A regression test against this target can only exercise the
  "no validation on an authorized price write" / "no liquidation delay" surface in
  `Vat`/`Dog`, not the oracle-manipulation step itself.
- **LULA**: the `Rental` contract, which holds the attacker-facing
  `claimReward()`/`claimTeamReward()` entrypoint the exploit actually called, is
  unverified on the block explorer — its bytecode exists on-chain but no source is
  available to pull. Only the LULA token contract (which contains `recycle()`) is
  included.
- **MOKE** and **Crypto DAO / Pro token**: in both cases, the one-line bug
  description used to kick off research didn't hold up against the pulled source
  (MOKE's `claim()` does have an entitlement check; Pro's vault functions are all
  properly access-controlled). Both `BUG.md` files document the corrected
  mechanism, reconstructed from decoded on-chain exploit-tx logs and cross-checked
  against a matching DeFiHackLabs PoC, rather than silently keeping the wrong lead
  or silently swapping it without explanation.
- This session's Etherscan V2 API key returned `"Free API access is not supported
  for this chain"` for most non-`getsourcecode` modules on chain 56 (`proxy`,
  `block`, `account`, `logs`) for at least the 42DAO target; other targets worked
  around this via direct JSON-RPC calls to a public BSC node instead (documented
  per-target in `raw/`). The Blockscout BSC instance (`bsc.blockscout.com`) was
  unreachable (404) from this environment for the one target that tried it as a
  fallback.

## Repository note

This branch (`claude/clever-shannon-ej53l1`) was pushed to a previously-empty
repository and became its default branch — there is no separate base branch to
open a pull request against.
