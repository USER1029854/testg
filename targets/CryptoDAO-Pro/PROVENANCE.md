# Provenance — Crypto DAO / Pro Token exploit (BNB Smart Chain, chain id 56)

## Summary verdict

- **Project identified:** Yes, with high confidence. "Crypto DAO" (X/Twitter handle `@CryptoDAOGlobal`), token ticker **Pro** (`Pro Token`, 9 decimals), on **BNB Smart Chain (chain id 56)**.
- **Exploited contract (primary):** Pro Token — `0x8D65744527f55d0b2338350912d5C99A81ddF0e2`
- **Directly-involved contracts:** USDT/Pro PancakeSwap pair (drained) `0x63844BD4BFad910B1643713302a1cC1ed20d50c3`; a second Pro liquidity pair used as the flash-loan source `0x86ac451a0C0bCac5B74116Ae90832e89e9c630df`; BSC-USD (USDT) `0x55d398326f99059fF775485246999027B3197955`.
- **Exploit tx (this PoC/reproduction):** `0xaaea183bdb5d7e4fd3c8da1d5bfe7edcb2e1db2458cef9a3adac54db6a7793d1`, block **112654014**, timestamp **2026-07-28 15:58:10 UTC** (independently confirmed by direct RPC query, see below). This single tx drains ~605K USDT; press reports put the **cumulative** campaign total at ~$8.2M across ~13 similar transactions.
- **Proxy status:** Pro Token is **NOT** an EIP-1967 proxy. Confirmed two independent ways (see §4). Deployed bytecode is immutable, so the verified source in `source/` is the same code that ran at exploit time.
- **Pre-hack verdict:** `source/` is **CONFIRMED pre-hack / exploit-time code** for the Pro Token contract, the two PancakeSwap pair contracts, and the USDT contract (all non-proxy, so current verified source == exploit-time source). See caveats below.

---

## 1. How the project/incident was identified

Search leads (WebSearch) converged on the same incident from three independent outlets:

- CryptoTimes, "Crypto DAO Drained for $8.2M on BNB Chain via Access-Control Bug" (2026-07-29): https://www.cryptotimes.io/2026/07/29/crypto-dao-drained-for-8-2m-on-bnb-chain-via-access-control-bug/
  - Names the exploiter wallet `0x427671b2C8e91034A91FE698F9B7259b2345F45D`, the token "Pro" tied to "Crypto DAO", ~$8.2M USDT drained, and describes the root cause as "a vault function anyone could call" / "a publicly callable state-changing function with no access control", amplified by a flash loan.
- The Merkle, "Blockaid Flags $8.2M Exploit On Pro Token - H1 Report Indicates Nobody's Safe From Attacks": https://themerkle.com/blockaid-flags-82m-exploit-on-pro-token-h1-report-indicates-nobodys-safe-from-attacks
  - Independently corroborates: Blockaid flagged an "ongoing exploit targeting the Pro token", project account `@CryptoDAOGlobal`, $8.2M USDT.
- `@CryptoDAOGlobal` on X: https://x.com/CryptoDAOGlobal — confirms the project's own handle, matching "Crypto DAO".

These two independent outlets (CryptoTimes and The Merkle) agree on the token name ("Pro"), project name ("Crypto DAO" / `CryptoDAOGlobal`), amount (~$8.2M USDT), chain (BNB Chain), and approximate date (reported July 28–29, 2026), which is the cross-check required before trusting an address.

**DeFiHackLabs GitHub repo** (`github.com/SunWeb3Sec/DeFiHackLabs`) contains a matching, already-committed Foundry PoC that reproduces this exact exploit:
- File: `src/test/2026-07/ProToken_exp.sol` (cloned from `https://github.com/SunWeb3Sec/DeFiHackLabs`, commit `2c99b565ae24ea2006adf181da20c4419b3edc30`)
- README entry: `### 20260725 Pro Token - Reward-on-transfer self-dealing winner drain` / `### Lost: ~605K USDT (single tx; ~$8.2M cumulative across ~13 txs)`
- This PoC file hardcodes: attacker EOA, an attacker "helper" contract, the Pro token address, the USDT/Pro pair address, USDT address, three "winner" addresses, the exploit block number (112,654,014), and the exact exploit-tx calldata.

**Note on the date discrepancy:** the DeFiHackLabs README heading says "20260725" (25 July) while the reproduced transaction's on-chain timestamp (confirmed below) is **2026-07-28 15:58:10 UTC**, matching the CryptoTimes/Merkle reporting date. This is consistent with the PoC comment's own statement that the $8.2M is "cumulative... across ~13 such transactions" — i.e. the campaign likely started around July 25 and this specific reproduced tx is a later (July 28) transaction in the same multi-day drain campaign. This is called out explicitly rather than silently reconciled.

## 2. Independent on-chain verification (not just trusting the PoC file or the news)

All of the following were queried live against BNB Smart Chain via public RPC (`https://bsc-dataseed.binance.org`) and the Etherscan V2 unified API, independent of the DeFiHackLabs file's claims:

- **Exploit tx exists and matches exactly.** `eth_getTransactionByHash` on `0xaaea183bdb5d7e4fd3c8da1d5bfe7edcb2e1db2458cef9a3adac54db6a7793d1` returns `from = 0x427671b2c8e91034a91fe698f9b7259b2345f45d` (the attacker EOA reported by CryptoTimes), `to = 0xf00bc28d22d71be74bc8ab0d11fe77f6d77850ac` (the PoC's "helper" contract), `blockNumber = 0x6b6f6be` (112,654,014), and `input` starting `0x452ae331...` — byte-for-byte identical to the calldata hardcoded in the PoC file. Saved: `raw/exploit_tx_publicrpc.json`.
- **Block timestamp.** `eth_getBlockByNumber(0x6b6f6be)` → `timestamp = 1785254290` = **2026-07-28 15:58:10 UTC**. Saved: `raw/exploit_block_info_publicrpc.json`.
- **Transaction succeeded and its full event log was pulled and decoded.** `eth_getTransactionReceipt` → `status = 0x1` (success), 1843 logs. Saved: `raw/exploit_tx_receipt_publicrpc.json`. Decoding the `Transfer`/`Swap` events (done locally, not sourced from any post-mortem) shows:
  - `0x86ac451a...` (Pro paired with a third token) flash-lends ~14,702 Pro to the helper contract, which is repaid (~14,738.86 Pro, i.e. ~0.25% fee) at the very end of the tx — a standard Uniswap-V2-style flash swap used purely to bootstrap the attack with zero starting capital.
  - The helper then drives ~300 loop iterations, each transferring 50 Pro from an attacker-controlled address (`0xc44f2acc...`, the PoC's "CLONE_A"/"player") toward the `0x63844bd4...` USDT/Pro pair. Each transfer is split by Pro Token's own sell-tax logic into a 1.25 Pro (2.5%) fee to the fee receiver and 48.75 Pro forwarded to the pair.
  - The pair is then swapped against directly (not through the router), and each iteration pays out roughly 2,016 USDT to one of three rotating "winner" addresses (`0x4e94c21C...`, `0xD9c854ED...`, `0xc3994bFF...`), plus one very large single swap early in the loop. Total USDT drained from the pair in this one tx: ~604,888 USDT (matches the PoC's `assertApproxEqAbs` target almost exactly).
  - This fund-flow pattern is consistent with the DeFiHackLabs classification ("reward-on-transfer self-dealing winner drain") but was derived independently from raw receipt logs, not copied from the PoC's prose. See `BUG.md` for the full mechanism and an explicit discussion of where it does/doesn't match the press's "missing access control" framing.
- **Verified source pulled directly from Etherscan V2** (`module=contract&action=getsourcecode`, chainid=56) for all four addresses touched by the exploit. Raw JSON saved under `raw/`; reconstructed files under `source/`. See §3.

## 3. Source code obtained

| Contract | Address | Verified? | Format | Saved to |
|---|---|---|---|---|
| Pro Token (`Token`, ERC20) | `0x8D65744527f55d0b2338350912d5C99A81ddF0e2` | Yes | Multi-file JSON (Etherscan standard-json-input), 7 files incl. OpenZeppelin deps | `source/ProToken_0x8D65744527f55d0b2338350912d5C99A81ddF0e2/` |
| USDT/Pro PancakeSwap pair (drained) | `0x63844BD4BFad910B1643713302a1cC1ed20d50c3` | Yes | Flattened single file, `PancakePair` | `source/PancakePair_0x63844BD4BFad910B1643713302a1cC1ed20d50c3/PancakePair.sol` |
| Secondary Pro liquidity pair (flash-loan source) | `0x86ac451a0C0bCac5B74116Ae90832e89e9c630df` | Yes | Flattened single file, `PancakePair` | `source/PancakePair_0x86ac451a0C0bCac5B74116Ae90832e89e9c630df/PancakePair.sol` |
| BSC-USD (USDT) | `0x55d398326f99059fF775485246999027B3197955` | Yes | Flattened single file, `BEP20USDT` | `source/BEP20USDT_0x55d398326f99059fF775485246999027B3197955/BEP20USDT.sol` |
| Attacker "helper" contract (`attack(address,uint256,uint256)`, selector `0x452ae331`) | `0xf00bC28D22d71Be74Bc8aB0d11Fe77F6D77850ac` | **No — unverified.** `getsourcecode` returns empty `SourceCode`/`ABI: "Contract source code not verified"`. Has real deployed bytecode (5,846 bytes via `eth_getCode`, confirmed live). This is the **attacker's own exploit contract**, not a Crypto DAO contract — its selector `0x452ae331` resolves in the public 4byte signature directory to the generic `attack(address,uint256,uint256)`, consistent with an attacker-authored PoC/exploit contract rather than a project contract. Not fabricated or reconstructed — left out per instructions since no real source is available. | (not included — unverified) |

Raw API responses backing every row above are in `raw/` (`pro_token_getsourcecode.json`, `lp_pair_getsourcecode.json`, `secondary_pair_getsourcecode.json`, `usdt_getsourcecode.json`, `helper_getsourcecode.json`).

**Which contract the exploit actually touched:** the exploit's fund-drain path runs entirely through the **Pro Token contract's `_update` (transfer) logic** and **direct calls to the two PancakeSwap pair contracts' `swap()`**. There is no separate "vault" or "treasury" contract in the touched-address set (confirmed by enumerating every unique log-emitting address in the exploit tx's receipt — only Pro Token, USDT, and the two pairs appear). Pro Token's own `treasury` state variable exists (gates `mint()`) but the `treasury` address was never involved in this transaction's logs. See `BUG.md` for why the press's "vault function" framing does not map cleanly onto a specific unprotected function in the verified Pro Token source.

## 4. Proxy determination

Two independent checks, both agreeing Pro Token is **not** a proxy:

1. **`getsourcecode` API field.** `raw/pro_token_getsourcecode.json` → `"Proxy": "0"`, `"Implementation": ""`.
2. **EIP-1967 implementation slot read directly.** Etherscan V2's `module=proxy&action=eth_getStorageAt` returned `"Free API access is not supported for this chain"` for this key/tier (saved as-is: `raw/pro_token_impl_slot.json`), so the check was performed independently against a public BSC RPC node instead:
   ```
   eth_getStorageAt(0x8D65744527f55d0b2338350912d5C99A81ddF0e2,
                     0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bb, "latest")
   → 0x0000000000000000000000000000000000000000000000000000000000000000
   ```
   Saved: `raw/pro_token_impl_slot_publicrpc.json`. An all-zero implementation slot confirms no EIP-1967 implementation is set — this is not a transparent/UUPS proxy.

Because it is **not** a proxy, deployed bytecode at this address is immutable from the moment of deployment, so **current verified source == exploit-time source** for the Pro Token contract, by construction (no upgrade path exists). The same "current == exploit-time" reasoning applies to the two PancakeSwap pair contracts and BSC-USD, none of which are proxies (standard, long-since-deployed, immutable PancakeSwap/Binance-Peg contracts).

**Gap/caveat on the sanity check for "single contract creation":** the task's suggested sanity check (`module=contract&action=getcontractcreation`) returned `"Free API access is not supported for this chain. Please upgrade your api plan"` under the provided API key for chain 56 (saved as-is: `raw/pro_token_creation.json`), and the legacy `api.bscscan.com` v1 endpoint is fully deprecated (`raw/exploit_tx_internal_bscscanapi.json` — redirects callers to Etherscan V2). `module=account&action=txlist`/`txlistinternal` were likewise premium-gated (`raw/pro_token_first_tx.json`, `raw/exploit_tx_internal_etherscanv2.json`). A `debug_traceTransaction` call-trace was attempted against several free public RPC endpoints to independently verify the internal call structure; all either lack archive state (`"missing trie node"`) or don't expose the `debug`/`trace` namespace at all (saved as-is: `raw/exploit_tx_calltrace_publicrpc.json`). **This is disclosed as an explicit gap**: the contract-creation-event sanity check and a full internal call-trace could not be obtained with the available free-tier credentials. This does not change the proxy verdict (which rests on the EIP-1967 slot read, a strong independent signal on its own) but it does mean the exact internal call structure of the exploit (e.g. exactly which function on the pair the helper called, in what order, relative to the callback) is reconstructed from the transaction's *log events* (which are complete and were fully decoded, see §2 and `BUG.md`) rather than from a verified opcode-level trace.

## 5. Files in this directory

- `source/` — real verified Solidity source, exactly as returned by Etherscan V2 `getsourcecode`, reconstructed at original relative paths (multi-file JSON bundle for Pro Token; flattened single files for the two PancakeSwap pairs and USDT, since that is the format Etherscan returned for those).
- `raw/` — every raw API/RPC response used as evidence, saved as-is, including the ones that came back empty/blocked (kept as evidence of what was and wasn't obtainable under this API key/tier).
- `PROVENANCE.md` — this file.
- `BUG.md` — vulnerability writeup (see file; starts with the required "ANSWER KEY" banner).

## 6. Explicit pre-hack confirmation verdict

**CONFIRMED PRE-HACK.** Pro Token, the two PancakeSwap pairs, and USDT are all non-proxy contracts with immutable bytecode; the EIP-1967 slot read (§4) independently rules out a hidden upgrade path. The verified source pulled "as of today" (2026-08-17) via Etherscan V2 is therefore necessarily identical to what was deployed and executing on 2026-07-28 at block 112,654,014. The one contract in the exploit path that is **not** included is the attacker's own unverified helper contract, which is correctly excluded rather than fabricated.
