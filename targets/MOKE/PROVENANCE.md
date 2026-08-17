# PROVENANCE — MOKE / MokeRelease exploit (BNB Smart Chain, chain id 56)

## 1. Chain / incident identification

- **Chain:** BNB Smart Chain, chain id **56**.
- **Reported loss:** ~$907.7K (TenArmor alert, reported via [CryptoTimes, "MOKE Suffers $907K Exploit in Suspected BNB Chain Attack", 2026-08-03](https://www.cryptotimes.io/2026/08/03/moke-suffers-907k-exploit-in-suspected-bnb-chain-attack/)). That article names the **MokeLPManager** contract and PancakeSwap V2 pools as involved, gives no contract addresses or tx hash, and explicitly states "the exact vulnerability behind the exploit remains unknown" — **it is not a technical post-mortem**.
- **No official MOKE-team or major-security-firm (SlowMist/PeckShield/CertiK/BlockSec) technical post-mortem was found** despite targeted searches (rekt.news, X/Twitter alert searches, "MOKE hack post-mortem", etc.). See BUG.md for the full list of queries tried and the sourcing caveat this implies.
- **Primary technical source used:** [SunWeb3Sec/DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) Foundry PoC, `src/test/2026-07/MOKE_exp.sol` (indexed in the repo's README under "20260802 MOKE"), cloned locally from `https://github.com/SunWeb3Sec/DeFiHackLabs` (commit at clone time: shallow clone, main branch, 2026-08-17). The PoC file's own header states it was written **without** an official root-cause writeup, "recovered by tracing the exploit tx from scratch" — i.e. it is itself independent forensic reconstruction, not an authoritative post-mortem. Everything from it is treated as a *lead* below and cross-checked against raw chain data (see §4).

## 2. Exploit transaction

- **Tx hash:** `0x0776048b1b58064fb31b6513721811e7b44d6bdbe7bf5833158b241ca6756a8f`
  BscScan: https://bscscan.com/tx/0x0776048b1b58064fb31b6513721811e7b44d6bdbe7bf5833158b241ca6756a8f
- **Block:** 113,652,609 (`0x6c63381`), transaction index 26 (`0x1a`).
- **Block timestamp:** `1785703811` = **2026-08-02 20:50:11 UTC**.
- Independently confirmed via a direct JSON-RPC call to a public BSC full node (`https://bsc-mainnet.public.blastapi.io`), **not** taken on faith from DeFiHackLabs:
  - `eth_getTransactionByHash` → raw/`rpc_tx_by_hash.json`. Confirms `from == to == 0xe454a9bac1a44868e4a9cbe1a4b5ac231d0dcf8a`, `transactionIndex = 0x1a`, `blockNumber = 0x6c63381`, `chainId = 0x38` (56), and `input` starting `0x20402f14...` containing the embedded addresses `0x684d722ebf8980f49492f631f56765dd4fb302a7` (release contract) and `0xacabe59b2fb33b895a58891231f5e18582b86f33` (LP manager) — matches the DeFiHackLabs PoC's hardcoded calldata byte-for-byte.
  - `eth_getBlockByNumber(0x6c63381)` → raw/`rpc_block.json`. Confirms block number 113652609 and the UTC timestamp above.
  - `eth_getTransactionReceipt` → raw/`rpc_tx_receipt.json`. `status = 0x1` (success), 256 logs emitted across 16 distinct contract addresses. Fully decoded in BUG.md.
- Etherscan V2 unified API (`api.etherscan.io/v2/api?chainid=56`) was **not usable** for tx/proxy/block lookups with the supplied free-tier key — every `module=proxy`, `module=account`, `module=block`, `module=logs`, `module=stats` call returned `{"status":"0","message":"NOTOK","result":"Free API access is not supported for this chain..."}` (see raw/`tx_by_hash.json`, `tx_receipt.json`, `txlist_release.json`, `logs_release_at_exploit.json`). Only `module=contract&action=getsourcecode` worked on this key for chain 56. Blockscout's BSC instance (`bsc.blockscout.com`) returned HTTP 404 "default backend" for both the REST v2 endpoint and the base page (raw/`blockscout_tx_info.json`) — it appears to no longer be live/routed for BSC. **All tx/block/storage-slot evidence below therefore comes directly from a public BSC RPC node via raw JSON-RPC, not from a block-explorer convenience API.**

## 3. Exploited/relevant contract addresses

| Role | Address | Contract name (verified) | BscScan link |
|---|---|---|---|
| **Vulnerable contract** — `MokeToken.releaseContract`, exposes the abused `claim()`/`settle()` logic | `0x684D722EbF8980f49492f631f56765DD4Fb302A7` | `MokeRelease` | https://bscscan.com/address/0x684D722EbF8980f49492f631f56765DD4Fb302A7 |
| Token contract, holds the reserve pool drained by `releaseFromPair`/`addReleasedBalance`; gates those two functions to `releaseContract` only | `0x1A35C16cE21903Bc17Fd020c4ED73fEdC70c1b2A` | `MokeToken` | https://bscscan.com/address/0x1A35C16cE21903Bc17Fd020c4ED73fEdC70c1b2A |
| LP manager used in the cash-out leg (`removeLiquidity`) | `0xaCABE59B2FB33b895a58891231f5e18582B86F33` | `MokeLPManager` | https://bscscan.com/address/0xaCABE59B2FB33b895a58891231f5e18582B86F33 |
| Dividend vault used in the cash-out leg (`distributeDividend`/`claimDividend`, 131 log entries in the exploit tx) | `0x5ae569d8a0539a6A603E96A26ac8CaEA7CEba377` | `MokeLPDividend` | https://bscscan.com/address/0x5ae569d8a0539a6A603E96A26ac8CaEA7CEba377 |
| Attacker EOA — carries an EIP-7702 delegation designator to its own exploit bytecode at the exploit block (`to == from` in the exploit tx) | `0xE454a9BAC1a44868e4A9Cbe1a4B5ac231D0DCF8a` | n/a (EOA) | https://bscscan.com/address/0xE454a9BAC1a44868e4A9Cbe1a4B5ac231D0DCF8a |
| Attacker's EIP-7702 delegation target / exploit implementation contract | `0xC7fDEA027FEb41C8f3a45eC284280ce68f4e6Ff7` | **unverified** | https://bscscan.com/address/0xC7fDEA027FEb41C8f3a45eC284280ce68f4e6Ff7 |
| WBNB (adjacent, not exploited — standard token) | `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` | `WBNB` | https://bscscan.com/address/0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c |

**How each address was found/confirmed:**
1. DeFiHackLabs PoC (`MOKE_exp.sol`) hardcodes all of the above as named `constant`s with a comment explaining each one's role, plus the exact original exploit calldata as a `bytes constant`.
2. Independently re-derived the same two addresses (release contract + LP manager) by raw-decoding the `input` field of the real on-chain transaction fetched by `eth_getTransactionByHash` from a public BSC RPC (§2) — the calldata bytes match the PoC's hardcoded `EXPLOIT_CALLDATA` exactly, and the addresses fall at the expected ABI-encoding offsets.
3. Confirmed `MokeToken` and `MokeRelease` are linked on-chain: `MokeToken.sol` (verified source, see `source/MOKE_.../project/contracts/MokeToken.sol`) declares `address public releaseContract;` and gates `releaseFromPair`/`addReleasedBalance` with `require(msg.sender == releaseContract, ...)`. `MokeRelease.claim()` (verified source, `source/RELEASE_.../project/contracts/MokeRelease.sol`) calls `IMokeToken(address(mokeToken)).releaseFromPair(...)` and `.addReleasedBalance(...)` — i.e. `MokeRelease` at `0x684D72...` really is the `releaseContract` the task's lead referred to (`MokeToken.releaseContract()`), confirmed structurally, not just by the PoC comment asserting it.
4. Confirmed via the exploit tx's decoded event log (raw/`rpc_tx_receipt.json`, decoded in BUG.md) that the `MokeRelease` and `MokeLPDividend` addresses actually emitted events (`Claimed`, `PriceSettled`, `DynamicReward` from `0x684d722e...`; 131 dividend-related log entries from `0x5ae569d8...`) during this exact transaction — i.e. these contracts were not merely named in a PoC comment but demonstrably participated on-chain in this tx.
5. Cross-checked the $907.7K/loss-scale claim against the independently-decoded `Claimed` event amounts and against CryptoTimes' independent $907,700 figure (different source, same order of magnitude) — see BUG.md §"Independently decoded on-chain evidence".

## 4. Proxy / upgradeability determination

**Verdict: none of the four project contracts (MokeRelease, MokeToken, MokeLPManager, MokeLPDividend) are EIP-1967 proxies.** They are plain, non-upgradeable contracts.

Evidence, all in `raw/`:

- Etherscan's own `getsourcecode` analysis: every one of the four `getsourcecode_*.json` responses has `"Proxy":"0"` and `"Implementation":""`.
- **Independent confirmation**, since Etherscan's `module=proxy` calls were not usable on this key (§2): queried the canonical EIP-1967 implementation storage slot (`0x360894a1...d382bb`) directly against a public BSC RPC node for all four addresses, both at `latest` and at block `0x6c63380` (113,652,608 — one block **before** the exploit block). Result for all four: the slot is `0x0` (empty) at both blocks (`raw/proxy_slot_checks.json`) — consistent with non-proxy, not with an unset/misread proxy.
- **Bytecode immutability check**: fetched `eth_getCode` for all four addresses at block `0x6c63380` (pre-exploit) and at `latest`, and hashed both (`raw/code_pre_*.json`, `raw/code_latest_*.json`). All four contracts' deployed bytecode is **byte-identical** pre-exploit vs. latest (SHA-256 match confirmed for each). Since these are non-proxy contracts, deployed bytecode is immutable by construction (no `SELFDESTRUCT`+redeploy was observed either, consistent with the matching bytecode), so:

  **The verified source in `source/` is confirmed to be the exact code that ran at exploit time** (block 113,652,609) — not a later-modified version. This is the strongest form of provenance available short of matching compiled bytecode hash-for-hash against the on-chain runtime code (not attempted here, but Etherscan's verification process already does this at the time of verification, and we've shown the on-chain code hasn't changed since before the exploit).
- Could not independently run `module=contract&action=getcontractcreation` (also blocked on this key) to double-confirm "only one CREATE at this address ever" as an extra belt-and-suspenders check; the bytecode-immutability check above (pre-exploit vs. current) is considered sufficient given it directly brackets the exploit block.

## 5. Contract-by-contract source verdict

| Address | Verified? | ContractName | Compiler | Files reconstructed | Path |
|---|---|---|---|---|---|
| `0x684D722EbF8980f49492f631f56765DD4Fb302A7` (RELEASE) | **Yes** | MokeRelease | v0.8.28+commit.7893614a, cancun, optimizer runs=200 | 16 (incl. project sources + OZ 5.6.1 deps) | `source/RELEASE_0x684D722EbF8980f49492f631f56765DD4Fb302A7/` |
| `0x1A35C16cE21903Bc17Fd020c4ED73fEdC70c1b2A` (MOKE) | **Yes** | MokeToken | v0.8.28+commit.7893614a, cancun | 14 | `source/MOKE_0x1A35C16cE21903Bc17Fd020c4ED73fEdC70c1b2A/` |
| `0xaCABE59B2FB33b895a58891231f5e18582B86F33` (LP_MANAGER) | **Yes** | MokeLPManager | v0.8.28+commit.7893614a, cancun | 13 | `source/LP_MANAGER_0xaCABE59B2FB33b895a58891231f5e18582B86F33/` |
| `0x5ae569d8a0539a6A603E96A26ac8CaEA7CEba377` (DIVIDEND) | **Yes** | MokeLPDividend | v0.8.28+commit.7893614a, cancun | 13 | `source/DIVIDEND_0x5ae569d8a0539a6A603E96A26ac8CaEA7CEba377/` |
| `0xC7fDEA027FEb41C8f3a45eC284280ce68f4e6Ff7` (attacker's EIP-7702 delegation target) | **No — unverified.** `SourceCode` is empty in `raw/getsourcecode_ATTACKER_IMPL_0xC7fDEA027FEb41C8f3a45eC284280ce68f4e6Ff7.json`. Not included in `source/`. This is the attacker's own exploit contract, not a project contract — its absence does not weaken the pre-hack-source verdict for the four project contracts above. | — | — | — | — |

All four verified `SourceCode` payloads were double-brace-wrapped Etherscan multi-file JSON bundles (`{{ "language": "Solidity", "sources": {...}, "settings": {...} }}`). Each was parsed by stripping one outer brace layer, and every entry in `sources` was written to disk at its exact original relative path (e.g. `project/contracts/MokeRelease.sol`, `npm/@openzeppelin/contracts@5.6.1/access/Ownable.sol`) under the corresponding `source/<LABEL>_<address>/` folder — nothing was flattened, retyped, or reconstructed from a post-mortem snippet. The compiler `settings` object (minus `sources`) from each bundle was also saved as `_compiler_settings.json` alongside the reconstructed tree, for completeness (this is real API-response data, not derived/fabricated).

## 6. Which contracts the exploit actually touched vs. adjacent

From the exploit tx's decoded log addresses (`raw/rpc_tx_receipt.json`, 256 logs total across 16 addresses) — full breakdown and event-level decode in BUG.md:

- **Directly exploited / central to the bug:** `MokeRelease` (0x684d722e…, 21 logs incl. 4× `Claimed`, 1× `PriceSettled`, many `DynamicReward`).
- **Directly touched as part of the cash-out path (functioning as designed, not themselves buggy as far as could be determined):** `MokeLPDividend` (0x5ae569d8…, 131 logs — `distributeDividend`/`claimDividend` fan-out across ~100 pre-registered addresses), `MokeToken` (0x1a35c16c…, 20 logs — `releaseFromPair`/`addReleasedBalance`/transfers), `MokeLPManager` (0xacabe59b…, 1 log — `removeLiquidity`).
- **Adjacent infrastructure used for working capital, not MOKE-project contracts:** WBNB (0xbb4cdb9c…, 14 logs), a Cake-LP pair (0xba6a49a9…, 9 logs, appears as `cakeLP` param in the exploit calldata), Moolah/Lista Lending and Venus-protocol contracts (flash loan + BTCB/BNB leverage legs — addresses `0x8f73b65b…` etc. — **not pulled into `source/`**, they are third-party BSC money-market infrastructure, not MOKE contracts, and are out of scope for this deliverable).

## 7. Overall verdict

- **Real verified source, confirmed pre-hack:** YES, for all four MOKE-project contracts (`MokeRelease`, `MokeToken`, `MokeLPManager`, `MokeLPDividend`). None are proxies; their deployed bytecode is proven byte-identical between the block immediately before the exploit and the current chain head, so the Etherscan-verified source in `source/` is the exact code that executed during the exploit transaction.
- **Gap:** the attacker's own EIP-7702 delegation-target contract is unverified and is not part of the deliverable (nor should it be — it's attacker code, not a MOKE contract).
- **Gap:** no official MOKE-team or named-security-firm technical post-mortem exists publicly as of this writing (2026-08-17); the technical narrative in BUG.md is built from (a) the DeFiHackLabs PoC's own tracing-based reconstruction, cited as such, and (b) this session's independent decode of the real transaction receipt's event logs, cross-checked line-by-line against the verified `MokeRelease.sol` source. Confidence in the *addresses, tx hash, and pre-hack-source* claims is high (multiple independent on-chain confirmations, listed above with source URLs). Confidence in the *narrative framing* of the root cause should be read per the caveats in BUG.md.
