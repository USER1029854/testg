# PROVENANCE — LULA (BNB Smart Chain, exploited ~28-29 Jul 2026)

## Chain

BNB Smart Chain, **chain id 56**.

## Exploited / relevant addresses

| Role | Address | Explorer link | Verified? |
|---|---|---|---|
| **LULA token** (holds the vulnerable `recycle()`) | `0xF5d7029eb6751d170dcF0Bb1c87Af6f93d5A2e9a` | https://bscscan.com/address/0xF5d7029eb6751d170dcF0Bb1c87Af6f93d5A2e9a#code | Yes — source in `source/` |
| **LULA/USDT PancakeSwap V2 pair** (victim pool, drained) | `0xF0b36389a12A28be1280c0ec2A4bbc76889D6a96` | https://bscscan.com/address/0xF0b36389a12A28be1280c0ec2A4bbc76889D6a96#code | Yes, but it is a **stock, unmodified PancakeSwap V2 `PancakePair`** (compiler v0.5.16, `SimilarMatch: 0x804678fa97d91b974ec2af3c843270886528a9e6`, i.e. BscScan matched it to a byte-identical known Pancake pair implementation). Not vendored into `source/` per the task's instruction to skip stock, non-customized Pancake contracts; raw response kept in `raw/getsourcecode_LULA_USDT_LP_0xF0b3638.json` as evidence of this determination. |
| **Rental contract** (the only address `recycle()` will accept as caller; holds `claimReward()`/`claimTeamReward()`) | `0x377a015f44c3fdf71060e94648edc9e0316c7f1a` | https://bscscan.com/address/0x377a015f44c3fdf71060e94648edc9e0316c7f1a#code | **No — unverified.** `getsourcecode` returns empty `SourceCode`/`ABI` (raw/getsourcecode_RENTAL_0x377a015f.json). This is a gap: the exact logic of the public claim function that drives `recycle()` is not available as verified source. |
| Attacker EOA | `0x2677806d48325Ced7533C54B86eD5e99b129a4ED` | https://bscscan.com/address/0x2677806d48325Ced7533C54B86eD5e99b129a4ED | n/a (EOA) |
| Attacker helper contract (executes the whole flash-loan/claim/recycle loop) | `0x5E506Ba06Fa6C61D1069B0E68d7013DE35AFA816` | https://bscscan.com/address/0x5E506Ba06Fa6C61D1069B0E68d7013DE35AFA816#code | No — unverified (expected for an attacker-deployed contract; raw/getsourcecode_HELPER_0x5E506Ba.json) |
| USDT (BEP-20, standard, not vendored) | `0x55d398326f99059fF775485246999027B3197955` | https://bscscan.com/address/0x55d398326f99059fF775485246999027B3197955 | Standard token, out of scope |

## Exploit transaction

- **Tx hash:** `0xa219ab9d57e520e5235b15a8801f4ebac8cc45551be0430ce4e49caea0411d7c`
- **Link:** https://bscscan.com/tx/0xa219ab9d57e520e5235b15a8801f4ebac8cc45551be0430ce4e49caea0411d7c (also https://app.blocksec.com/phalcon/explorer/tx/bsc/0xa219ab9d57e520e5235b15a8801f4ebac8cc45551be0430ce4e49caea0411d7c)
- **Block:** 112,655,390 (`0x6b6fc1e`)
- **Block timestamp:** 2026-07-28 16:08:29 UTC (`raw/exploit_block_112655390.json`) — public reporting on 29 Jul 2026 is consistent with this UTC time landing on 29 Jul in Asia-Pacific timezones.
- **Status:** success (`0x1`), gasUsed 3,810,877, 243 logs (`raw/exploit_tx_receipt.json`)
- `from` = attacker EOA, `to` = attacker helper contract, `value` = 1e10 wei, `input` selector `0x763a0e5b` with argument `15,000,000` (`raw/exploit_tx_by_hash.json`) — a single top-level call from the attacker's own EOA into its own pre-deployed helper, which internally runs the flash-loan + swap + repeated-`recycle()` sequence.
- Loss: reported ~$578,100 (578,295 USDT), drained from the LULA/USDT PancakeSwap V2 pair's USDT reserve.

## How the address/tx were found and cross-checked (every source cited)

1. **News/analyst leads (initial, treated as unverified):**
   - CryptoTimes: https://www.cryptotimes.io/2026/07/29/lula-token-on-bsc-exploited-for-578k-in-reserve-manipulation-attack/ — cited LULA token address `0x72ad494fda63d2b91b9d7290737e8ef1194a0c47` and tx `0x392fc1d6cb1b3c832983c7eabb94a96b895c2f1c16c472a15930d4d7c4efc52d`.
   - BlockSec Weekly blog: https://blocksec.com/blog/web3-security-coldcard-entropy-lula-exploits — also linked `LULA.recycle()` to `https://bscscan.com/address/0x72ad494fda63d2b91b9d7290737e8ef1194a0c47#code`, but its own "Attack Analysis" section is explicitly built around a **different** transaction, `0xa219ab9d57e520e5235b15a8801f4ebac8cc45551be0430ce4e49caea0411d7c` (Phalcon link: https://app.blocksec.com/phalcon/explorer/tx/bsc/0xa219ab9d57e520e5235b15a8801f4ebac8cc45551be0430ce4e49caea0411d7c), citing Phalcon's X post https://x.com/Phalcon_xyz/status/2082298859481608516. Both articles' raw HTML saved in `raw/article_*.html`.
   - These two leads disagreed with each other (different tx hashes) and, per the task's instruction to cross-check rather than trust a single source, both address citations were independently tested rather than assumed correct.

2. **DeFiHackLabs Foundry PoC (primary corroborating source):** https://github.com/SunWeb3Sec/DeFiHackLabs, file `src/test/2026-07/LULA_exp.sol` (cloned locally, commit `2c99b565ae24ea2006adf181da20c4419b3edc30`; copy saved at `raw/DeFiHackLabs_LULA_exp.sol`). This PoC hardcodes: LULA token `0xF5d7029eb6751d170dcF0Bb1c87Af6f93d5A2e9a`, victim LP `0xF0b36389a12A28be1280c0ec2A4bbc76889D6a96`, attacker EOA `0x2677806d48325Ced7533C54B86eD5e99b129a4ED`, helper `0x5E506Ba06Fa6C61D1069B0E68d7013DE35AFA816`, exploit block `112,655,390`, and the exact tx hash `0xa219ab9d57e520e5235b15a8801f4ebac8cc45551be0430ce4e49caea0411d7c` — matching BlockSec's tx hash, **not** the CryptoTimes/BlockSec-hyperlink address.

3. **Direct on-chain verification (decisive):** the two candidate addresses were disambiguated by pulling `getsourcecode` for `0x72ad494fda63d2b91b9d7290737e8ef1194a0c47` — it turned out to be a **generic, unmodified Binance `BEP20Token` boilerplate** (constructor sets `_name="LULA COIN"`, `_symbol="LULA"`, fixed supply, **no `recycle`, no `Rental`, no reward/tax logic of any kind**) — see `raw/getsourcecode_RULEDOUT_0x72ad494_wrong_lead.json`. This is inconsistent with the reported vulnerability, so it was **ruled out** as a same-ticker, unrelated "LULA" token rather than the exploited contract.
   By contrast, `0xF5d7029eb6751d170dcF0Bb1c87Af6f93d5A2e9a`'s verified source (`raw/getsourcecode_LULA_0xF5d7029.json`) contains exactly the reported mechanism: a `recycle()` function gated to a `rentalContract` address that pulls LULA straight out of the PancakeSwap pair and calls `sync()`.
   Final, conclusive proof: the actual exploit tx's receipt logs (`raw/exploit_tx_receipt.json`) were parsed — of 23 unique contract addresses that emitted logs, **`0xF5d7029eb6751d170dcF0Bb1c87Af6f93d5A2e9a` emitted 82 events, the pair `0xF0b36389a12A28be1280c0ec2A4bbc76889D6a96` emitted 53, and the Rental contract `0x377a015f44c3fdf71060e94648edc9e0316c7f1a` emitted 4 — while `0x72ad494fda63d2b91b9d7290737e8ef1194a0c47` (the news-article address) emitted zero events and does not appear anywhere in the transaction.** The pair's logs include 46 `Sync(uint112,uint112)` events and the token's logs include 41 `Transfer(pair → rentalContract)` events during this single transaction, matching the post-mortems' description of `recycle()` being invoked repeatedly to drain the pair before the final swap.
   `rentalContract()` and `uniswapV2Pair()` were also read live via `eth_call` against the LULA contract (`raw/eth_call_rentalContract.json`, `raw/eth_call_uniswapV2Pair.json`), returning `0x377a015f44c3fdf71060e94648edc9e0316c7f1a` and `0xf0b36389a12a28be1280c0ec2a4bbc76889d6a96` respectively — matching the values above and the PoC's `VICTIM_LP`.

**Verdict on address/tx identity:** `0xF5d7029eb6751d170dcF0Bb1c87Af6f93d5A2e9a` is the real exploited LULA token contract and `0xa219ab9d57e520e5235b15a8801f4ebac8cc45551be0430ce4e49caea0411d7c` is the real exploit transaction, confirmed by three independent angles (DeFiHackLabs PoC, BlockSec's own tx citation, and direct on-chain log analysis). The address `0x72ad494fda63d2b91b9d7290737e8ef1194a0c47` repeated by two news sources is a **false lead** (an unrelated, unmodified boilerplate token that happens to share the LULA COIN/LULA name/symbol) and was **not** used for anything in `source/`.

## Proxy determination

- `getsourcecode` for `0xF5d7029eb6751d170dcF0Bb1c87Af6f93d5A2e9a` reports `"Proxy":"0"`, `"Implementation":""`.
- Independently confirmed by reading the EIP-1967 implementation slot (`0x360894a1...382bb`) directly via BSC JSON-RPC (Etherscan V2 `module=proxy`/`module=block` actions returned `"Free API access is not supported for this chain"` for the provided key on chain 56, so this and the block/creation checks below were done via the public BSC RPC `https://bsc-mainnet.public.blastapi.io` instead — the same archive endpoint used by the DeFiHackLabs PoC itself): the slot reads all-zero at `latest` (`raw/eip1967_impl_slot_latest.json`) — no implementation address stored, confirming this is not an EIP-1967 proxy.
- The verified source itself corroborates this structurally: `totalSupply`, `uniswapV2Pair`, and `distributor` are Solidity `immutable`s set in the constructor, `balanceOf`/`allowance` are ordinary declared mappings (not EIP-1967-style storage), and there is no `fallback`/`delegatecall` anywhere in `LULA.sol` — i.e. the contract is architecturally incapable of being a delegate-call proxy.
- **Bytecode identity check:** `eth_getCode` for the LULA token was read at block 112,655,389 (one block before the exploit) and at `latest`, and the two returned byte-for-byte identical bytecode (`raw/getcode_LULA_at_block_112655389.json` vs `raw/getcode_LULA_latest.json`, both 13,042 hex-chars, `identical bytecode: True`).

**Verdict:** The LULA token contract is **not a proxy**. Deployed bytecode is immutable and confirmed unchanged from before the exploit block through to today, so the current verified source in `source/` **is confirmed to be the exact pre-hack (and exploit-time) code** — not merely "presumed" from non-upgradeability, but positively checked against the historical block.

The PancakeSwap pair (`0xF0b36389a12A28be1280c0ec2A4bbc76889D6a96`) is also reported non-proxy (`"Proxy":"0"`) and, per its `SimilarMatch`, is stock Pancake bytecode — standard AMM pairs of this vintage are not upgradeable either.

The Rental contract (`0x377a015f44c3fdf71060e94648edc9e0316c7f1a`) could not be checked this way because it is unverified; no proxy/non-proxy claim is made about it.

## Multi-contract exploit path

The exploit crosses three project-relevant contracts:
1. **LULA token** (`0xF5d7029eb6751d170dcF0Bb1c87Af6f93d5A2e9a`) — holds `recycle()`. Verified source vendored in `source/`.
2. **Rental contract** (`0x377a015f44c3fdf71060e94648edc9e0316c7f1a`) — the only address authorized to call `recycle()`; per post-mortems, its public `claimReward()`/`claimTeamReward()` is the attacker-reachable entry point that triggers `recycle()`. **Unverified — not in `source/`.** This is the key gap in this evidence set.
3. **LULA/USDT PancakeSwap V2 pair** (`0xF0b36389a12A28be1280c0ec2A4bbc76889D6a96`) — confirmed stock/unmodified PancakeSwap V2 pair, not vendored (per task instructions).

Also involved but out of scope to vendor: USDT token (standard BEP-20) and the numerous third-party lending/flash-loan sources named in BlockSec's writeup (Moolah/Lista, Aave V3, Venus, PancakeSwap V3, PancakeSwap Vault, Uniswap V4 PoolManager, Uniswap V3) and the attacker's own unverified helper contract — none of these are LULA-project-owned/customized code.

## Explicit verdict: is `source/` confirmed pre-hack?

**Yes, for the LULA token contract** (`source/LULA_token_0xF5d7029eb6751d170dcF0Bb1c87Af6f93d5A2e9a/`): non-proxy, bytecode verified byte-identical between one block pre-exploit and latest, so the currently-verified source is the exploit-time source.

**No source obtained for the Rental contract** — it is unverified on BscScan. Its role (privileged caller gate) is described only by public post-mortems (cited in `BUG.md`), not by source code in this evidence set.

**No custom source needed for the PancakeSwap pair** — confirmed to be stock Pancake bytecode, not a customized fork.
