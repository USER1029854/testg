# PROVENANCE — 42DAO / Balance Protocol (BLC) exploit, BNB Smart Chain, 22 Jul 2026

## Chain

BNB Smart Chain (BSC) mainnet, chain id **56**.

## Incident summary (from public reporting)

- Protocol: **42DAO**, the DAO/team behind **Balance Protocol**, a MakerDAO-style CDP system on BSC issuing the stablecoin **BLC ("Balance Coin")**, collateralized primarily by BTCB.
- Date: **22 Jul 2026**. Loss estimated at **~$912K (SlowMist)** / **~$915K (PeckShield / most press)**.
- Reported vector (per SlowMist TI alert and multiple press reports): an attacker fed an abnormally low BTCB price into the protocol's **Median Oracle**, which was propagated with no validation through the **Spotter** contract's `poke()` into the **Vat** ledger's `ilks[ilk].spot`, and then consumed with no independent validation or delay by the **Dog** liquidation module's `bark()`, allowing multiple BTCB vaults to be liquidated far below fair value in a single transaction. Reporting also describes unbacked BLC being minted "from a null address" via a **GemJoin** contract and swapped on PancakeSwap V2 for BSC-USD and BTCB, in two waves roughly two hours apart. BLC depegged from ~$1 to ~$0.001–0.0025 (>99%) within hours.
- BLC fell from ~$0.9954 to ~$0.001358 the same day (Balance Coin / BLC).

## Exploit transaction

- Hash (from search-engine indexing of a BscScan tx-page title, format-valid 32-byte hex): `0xe7abe6416e386332b41d63cf5f16903251dc178942cd79bf080fe61058587628`
  - BscScan link: https://bscscan.com/tx/0xe7abe6416e386332b41d63cf5f16903251dc178942cd79bf080fe61058587628
  - **This session could not independently query this transaction.** The Etherscan V2 API key provided for this task returns `"Free API access is not supported for this chain"` for every module except `module=contract` (`getsourcecode`, `getabi`) on chainid=56 — `module=proxy` (`eth_getTransactionByHash`, `eth_call`, `eth_getStorageAt`), `module=account` (`txlist`, `txlistinternal`, `tokentx`, `balance`), `module=block` (`getblocknobytime`), `module=logs` (`getLogs`), and `module=contract&action=getcontractcreation` all failed with that error. Direct HTTPS fetches of bscscan.com (via curl and via WebFetch) return Cloudflare 403/challenge pages. `bsc.blockscout.com` (the fallback suggested for this task) returned `404 default backend` on every path tried (`/api/v2/smart-contracts/...`, `/api/v2/blocks`), including with the supplied Blockscout API key as both a query param and an `Authorization` header — the domain appears unreachable/decommissioned from this environment (independent sanity check: `eth.blockscout.com` responded normally with `HTTP 200`, so this is specific to the BSC instance, not a general network block). `explorer.bnbchain.org` (BNB Beacon Chain explorer, not BSC/EVM) loaded but showed no data for these addresses. **Net effect: the tx hash above is a plausible, well-formed lead corroborated by multiple news outlets citing the same short hash prefix `0xe7abe6416e...`, but it was not independently confirmed on-chain in this session.**
- Reporting describes a second, near-identical transaction ~2 hours later (mint of ~5,900 BLC vs. ~4.5M BLC in the first). No hash for the second transaction was found.

## Contracts investigated, and verdicts

All source pulled via:
```
curl "https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=<ADDR>&apikey=<KEY>"
```
Raw JSON saved under `raw/`. Reconstructed file trees under `source/<ContractName>_<address>/...` at their original relative paths exactly as returned in the `sources` map of the multi-file bundle (no flattening, no retyping).

### CONFIRMED — pulled from chain, cross-linked on-chain, and named in press/SlowMist reporting

| Role (per reporting) | Contract | Address | Verified source | Proxy? |
|---|---|---|---|---|
| CDP ledger / core accounting ("Vat") | `Vat` | `0xfa7cea82f8a6254ccebad71350125aa6171b8a84` | Yes — `src/0.5.12/vat.sol` | No (`Proxy:"0"` in getsourcecode) |
| Liquidation module ("Dog"/`bark`) | `Dog` | `0x00101ae4467d72e83ef68df447c41de0c71f634e` | Yes — `src/0.6.12/Dog.sol` | No (`Proxy:"0"`) |
| Stablecoin token | `Blc` (BLC) | `0x5343b4586a3f2a3365df92ee705c3bf446c54668` | Yes — `src/0.5.12/Token/BLC.sol` + `src/0.5.12/lib/lib.sol` | No (`Proxy:"0"`) |
| DAO governance token (project-identity confirmation only, not in the exploit path) | `FTDToken` (FTD) | `0x653062e37D7A52d465A8570a5daA46cA4e0Bd3d9` | Yes — flattened `FTDToken.sol` | No (`Proxy:"0"`) |

BscScan links:
- https://bscscan.com/address/0xfa7cea82f8a6254ccebad71350125aa6171b8a84
- https://bscscan.com/address/0x00101ae4467d72e83ef68df447c41de0c71f634e
- https://bscscan.com/address/0x5343b4586a3f2a3365df92ee705c3bf446c54668
- https://bscscan.com/address/0x653062e37D7A52d465A8570a5daA46cA4e0Bd3d9

**How Vat and Dog were found and cross-validated:**
1. WebSearch for `"42dao" OR "balanceprotocol" bscscan GemJoin contract address` and related queries surfaced an X/SlowMist alert (https://x.com/SlowMist_Team/status/2079759793192132810) whose *indexed title text* is the literal SlowMist TI-alert copy ("Attackers exploited an abnormally low BTCB oracle price from Median Oracle via Spotter `poke` and Dog `bark`... The dog module then used this updated spot without any liquidation delay or oracle price validation..."). A separate synthesized answer from the same tool call additionally asserted specific addresses for "Spotter," "Dog," "Attacker," and "Victim" that were **not** present in that literal snippet text — flagged as a possible hallucination risk per this task's own warning.
2. Each asserted address was independently checked on-chain via `getsourcecode`:
   - The asserted **Dog** address (`0x00101ae4467d72e83ef68df447c41de0c71f634e`) resolved to a real, verified contract named `Dog`, source file `src/0.6.12/Dog.sol`, with a **custom** `VatLike.ilks()` signature carrying non-stock `taxRate1`/`taxRate2` fields (i.e. not a copy-paste of vanilla MakerDAO's `Dog.sol`, which has no tax fields) — meaning this is a bespoke fork, not a generic template match.
   - Its constructor argument (`ConstructorArguments` in the raw JSON) decodes to a single `address vat_` = `0xfa7cea82f8a6254ccebad71350125aa6171b8a84`.
   - That address independently resolved to a real, verified contract named `Vat`, source file `src/0.5.12/vat.sol`, whose `Ilk` struct also carries the same bespoke `taxRate1`/`taxRate2` fields — an exact structural match to what `Dog.sol` expects from `VatLike`.
   - **This Dog→Vat link is a real on-chain relationship (decoded constructor bytes), not a search-engine claim** — a hallucinated address pair could not independently satisfy it. This is the strongest evidence in this dossier.
   - A second, independent WebSearch (querying the raw address `0x00101ae4467d72e83ef68df447c41de0c71f634e` directly, with no other context) also returned it associated with "the Dog contract (a vulnerable contract from the 42DAO incident)," corroborating from a second angle.
   - The asserted **Spotter** address from the same original answer (`0x849dc2416cbe54995a1d725afe526c0e38829228`) returned an **empty `SourceCode`/`ContractName`** from `getsourcecode` — indistinguishable via this API between "wrong/hallucinated address" and "real but unverified contract," because `eth_getCode` was not reachable to check for the presence of bytecode. **This address is NOT used anywhere in this dossier and is not asserted to be the real Spotter.** Its raw (empty) API response is saved for the record at `raw/getsourcecode_0x849dc241_Spotter_candidate_EMPTY_UNCONFIRMED.json`.
3. `Blc` (BLC token, `0x5343b4586a3f2a3365df92ee705c3bf446c54668`) and `FTDToken` (`0x653062e37D7A52d465A8570a5daA46cA4e0Bd3d9`) were found via WebSearch results whose *titles themselves* are BscScan's own first-party public address-name tags: **"42DAO: BLC Token"** and **"42DAO: FTD Token"** respectively — i.e., BscScan itself (not a summarizer) labels these addresses as belonging to 42DAO. FTD is additionally named on 42DAO's CertiK Skynet audit page (https://skynet.certik.com/projects/forty-two-dao). Both resolved to real verified source. `Blc`'s file path (`src/0.5.12/Token/BLC.sol`) shares the same `src/0.5.12/...` project layout as the confirmed `Vat` (`src/0.5.12/vat.sol`), consistent with (but not proof of) originating from the same compiled monorepo. `FTDToken` compiles with a different toolchain (Solidity 0.8.0, MIT license, no path metadata) and is almost certainly the separate DAO governance token — included here only as project-identity corroboration, **not** as part of the exploited price/liquidation path.

### INVESTIGATED AND REJECTED — real contract, but does not belong to this system

- `GemJoin` at `0xf72f07b96d4ee64d1065951cafac032b63c767bb` (BscScan: https://bscscan.com/address/0xf72f07b96d4ee64d1065951cafac032b63c767bb) — found via WebSearch for a 42DAO GemJoin contract. It IS a real, verified, stock MakerDAO `join.sol`-style `GemJoin` contract. However its decoded constructor arguments are `vat_ = 0x713c28b2ef6f89750bdf97f7bbf307f6f949b3ff`, `ilk_ = "STKCAKE-A"`, `gem_ = 0xb50acf6195f97177d33d132a3e5617b934c351d3` — **a different Vat address than the confirmed 42DAO Vat above, and a collateral type ("STKCAKE," i.e. staked CAKE) that has nothing to do with the BTCB oracle exploit being investigated.** This is almost certainly a GemJoin belonging to an unrelated Maker-fork deployment on BSC that happens to reuse the same generic contract name. **Excluded from `source/`.** Raw evidence kept at `raw/getsourcecode_0xf72f07b9_GemJoin_UNRELATED_ilk_mismatch.json` to document the negative result.
- `0x42f1eec10cdab5cacae297db045063edd8b5c176` — surfaced by a WebSearch for 42DAO/GemJoin/BSC; resolved to a verified contract named `FlorkCoin`. Unrelated; discarded without saving.
- `0x4ef392fa185676dfe81c48c027f262388ad877bd` — surfaced by a WebSearch for "42dao Spotter.sol"; resolved to a verified contract named `MasterChef`. Unrelated; discarded without saving.

### NOT FOUND — Median Oracle and (mainnet, exploit-time) Spotter

Despite the task's method-2 requirement to identify at minimum the Median oracle and the Spotter, **this session could not confirm a mainnet BSC address for either**, and per this task's own instructions ("If you cannot get real source for something, leave it out and say so"), no Median or mainnet Spotter source is included in `source/`.

What was tried and why it fell short of the bar for inclusion:
- No DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs) PoC exists for 42DAO/Balance Protocol/BLC as of this session — `src/test/2026-07/` and `src/test/2026-08/` were checked directly and contain no matching file (confirmed by listing both directories; also confirmed no hits for `42DAO` when searching GitHub).
- rekt.news, DeFiLlama's hack list, and hacked.slowmist.io (checked directly) do not appear to have a page for this incident as indexed/reachable in this session.
- The one candidate Spotter address surfaced by a WebSearch summary (`0x849dc2416cbe54995a1d725afe526c0e38829228`) returned empty source from `getsourcecode` and could not be corroborated by any second, independent source (a targeted follow-up search for that literal address string returned nothing related). **Not used.**
- A contract literally named `Spotter` (`contracts/spot.sol`) was found and verified on **BSC testnet (chainid 97)** at `0xca52b26945FB42BB7fC3bc7d9B8DAec0aa1E60aB` (raw response saved at `raw/getsourcecode_chain97_0xca52b269_Spotter_TESTNET_UNCONFIRMED.json`), confirming that "Spotter" is a real contract name 42DAO/testers used somewhere in this project's history. **This is testnet, not mainnet, was not exploited, uses a different source-path convention (`contracts/spot.sol` vs. the confirmed mainnet contracts' `src/0.5.12/...`) than the confirmed mainnet Vat/BLC, and is explicitly NOT claimed to be the same bytecode as whatever ran on mainnet at exploit time. It is not included in `source/` and should not be treated as evidence of the exploited code — it is only weak circumstantial context.**
- No Median oracle address (mainnet or testnet) was found by any method attempted (targeted address-pattern searches, "Oracle | Address" BscScan-title searches, CertiK audit page, 42DAO GitBook docs pages, X/Twitter via x.com, r.jina.ai reader proxy [blocked, rate-limited], and nitter/xcancel mirrors [anti-bot challenge, no content]).

## Proxy / upgradeability verdict

For all four confirmed contracts (`Vat`, `Dog`, `Blc`, `FTDToken`), the `getsourcecode` API response itself reports **`"Proxy":"0"`** and an empty `Implementation` field — i.e. BscScan's own verification metadata does not consider any of them an EIP-1967/similar proxy.

**This verdict could NOT be independently cross-checked by reading the EIP-1967 implementation storage slot** (`eth_getStorageAt` at `0x360894a1...`), as instructed by the task, because `module=proxy` calls are rejected by the API key/environment for chainid=56 with `"Free API access is not supported for this chain"` (see the "Exploit transaction" section above for the full list of blocked modules/endpoints attempted). The same restriction blocked `getblocknobytime` (needed to find the pre-exploit block) and `getcontractcreation` (needed to sanity-check a single creation event per address), so the historical-implementation-slot comparison and the single-creation sanity check described in the task's method could not be performed either.

Given that constraint, the verdict here rests on: (a) BscScan's own `Proxy:"0"` field for all four addresses, and (b) the architectural prior that MakerDAO-style `Vat`/`Dog`/collateral-token contracts are conventionally deployed as plain, non-upgradeable contracts (this is true of vanilla MakerDAO `dss` and was true of every other BSC "Maker-fork" contract encountered during this investigation — `GemJoin`, `MasterChef`, `FlorkCoin`, testnet `Spotter` — none reported as a proxy either). Consistent with the task's own guidance: **for a non-proxy contract, deployed bytecode is immutable, so current verified source == exploit-time source.**

**Verdict: `source/Vat_.../vat.sol`, `source/Dog_.../Dog.sol`, `source/BLC_Token_.../*.sol`, and `source/FTD_Token_.../FTDToken.sol` are treated as pre-hack == exploit-time code on the strength of (a) above, with the historical-slot cross-check from the task's method explicitly NOT performed due to API restrictions in this environment (documented above), not because it was judged unnecessary.** This is a genuine evidentiary gap, not an oversight, and should be read as "high confidence, not full-strength proof."

## Gaps / honesty summary

1. Exploit tx hash `0xe7abe6416e386332b41d63cf5f16903251dc178942cd79bf080fe61058587628` is unconfirmed on-chain in this session (API/network restrictions — see above). It is corroborated only by matching short-hash prefixes across multiple secondary news sources, not fetched directly.
2. **Median oracle: no address found at all.** Not represented in `source/`.
3. **Spotter (mainnet, exploit-time): no confirmed address.** Not represented in `source/`. A single unconfirmed candidate and a testnet contract of the same name are documented above and in `raw/`, but explicitly not trusted or used.
4. `GemJoin`: a real contract with that name was found but proven (via constructor-arg decoding) to belong to a different, unrelated deployment — excluded.
5. Proxy verdict rests on BscScan's self-reported `Proxy` field only; the task's prescribed independent storage-slot cross-check and historical-block comparison could not be executed because this environment's Etherscan V2 key rejects `module=proxy`/`module=block`/`module=account` calls for chain 56, and the suggested Blockscout fallback (`bsc.blockscout.com`) is unreachable (404 on every path, including with the supplied API key) from this environment.
6. No internal-transaction / call-trace data for the exploit tx could be retrieved (blocked API + blocked bscscan.com direct access), so the exact sequence of contracts touched by the exploit tx is inferred from press/SlowMist reporting (Median Oracle → Spotter.poke → Vat → Dog.bark), not observed directly.
