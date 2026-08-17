# PROVENANCE — LOOPSDAO / LpdFi exploit (BNB Smart Chain, chain id 56)

## 1. Chain and identity

- **Chain:** BNB Smart Chain (BSC), chain id 56.
- **Project:** "LOOPSDAO" — the token's on-chain `name()` is literally `"LOOPSDAO"`, `symbol()` is `"LPD"`. The lending/staking front-end is called "LpdFi".
- **Exploit date:** 2026-08-02, UTC. Two attacker transactions, consecutive blocks, exactly 1 second apart.
- **Amount:** attacker net gain ≈ **573,034.79 USDC** (the ~690K/700K headline figures reported in press are the *gross* terminal USDC inflow from the claim transaction before subtracting the attacker's own 116,495 USDC stake used to fund the setup transaction; net profit is ~$573K). Both figures are in the same incident.

## 2. Exploited addresses (both confirmed real, non-proxy, verified source obtained)

| Role | Address | BscScan link | Contract name (verified) |
|---|---|---|---|
| Vulnerable lending/interest contract (`buy`, `claimInterest`, `removeLp`) | `0xcE6A6e4413D85A136bBaC8AaE6fB46eAa77F295e` | https://bscscan.com/address/0xcE6A6e4413D85A136bBaC8AaE6fB46eAa77F295e | `LpdFi` |
| Price-source / LPD token contract (`price()`) | `0x38763EebE58a69C9CC91876947D9fB83e1273604` | https://bscscan.com/address/0x38763EebE58a69C9CC91876947D9fB83e1273604 | `Lpd` |
| LPD/USDC PancakeSwap pair (spot-price source read by `Lpd.price()`) | `0x85346d31743796F7d00D675629e32783A968F210` | https://bscscan.com/address/0x85346d31743796F7d00D675629e32783A968F210 | `PancakePair` (stock PancakeSwap V2 pair, not project code) |
| Attacker EOA | `0x5d289266d85EF671561bA3F253FB79327C193f33` | https://bscscan.com/address/0x5d289266d85EF671561bA3F253FB79327C193f33 | — (EOA, no code) |
| Attacker's pre-deployed executor contract | `0x7f5AD0A998Dcb3f5006F0D152BEBC055979EF711` | https://bscscan.com/address/0x7f5AD0A998Dcb3f5006F0D152BEBC055979EF711 | **unverified** — see §6 gap |
| BSC USDC (18 decimals) | `0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d` | https://bscscan.com/address/0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d | stock BEP-20 token, not project code |

**Answering the "one or two contracts" question:** they are **two different deployed contracts**.
- `Lpd` (`0x3876...3604`) is the LOOPSDAO/LPD ERC-20 token and it *also* hosts the `price()` function that reads the raw PancakeSwap reserves with no TWAP.
- `LpdFi` (`0xcE6A...295e`) is the separate lending/staking contract that holds `buy()`, `claimInterest()`, and the private `removeLp()` helper.
- `LpdFi.sol` imports and references `Lpd` (`Lpd public immutable token`), and `LpdFi.buy()` / `LpdFi.claimInterest()` both call `token.price()` directly — so the two contracts are tightly coupled but are not the same deployment. Confirmed by diffing the `Lpd.sol` file bundled inside the `LpdFi` verified-source bundle against the `Lpd.sol` obtained by fetching the `Lpd` address directly: **byte-for-byte identical** (see `source/LpdFi/project/contracts/Lpd.sol` vs `source/Lpd/project/contracts/Lpd.sol`).

## 3. Exploit transactions

| | Tx hash | Block | Timestamp (UTC) | Status | Link |
|---|---|---|---|---|---|
| Setup (spot-price manipulation + inflated `buy()`) | `0xbb5b8573d7203e00f8fb9d4839dbeea46a8efd367eac8bed81e4ece2341c3588` | 113,613,923 | 2026-08-02 15:59:59 | success | https://bscscan.com/tx/0xbb5b8573d7203e00f8fb9d4839dbeea46a8efd367eac8bed81e4ece2341c3588 |
| Claim (`claimInterest` drains protocol-owned Cake-LP) | `0x70bbe0aa3c7ef149ecb6128a06025885deaa8fef3f393a505d447d28ab3315d6` | 113,613,924 | 2026-08-02 16:00:00 | success | https://bscscan.com/tx/0x70bbe0aa3c7ef149ecb6128a06025885deaa8fef3f393a505d447d28ab3315d6 |

Both transactions are plain EOA→contract calls from the attacker EOA into the attacker's pre-deployed executor (`to != from`, no EIP-7702 delegation). The executor then calls the permissionless public entrypoints `LpdFi.buy(uint256)` and `LpdFi.claimInterest(uint256)`.

## 4. How the address was found and independently confirmed

1. **Lead source:** `SunWeb3Sec/DeFiHackLabs` GitHub repo, file `src/test/2026-08/LpdFi_exp.sol` (commit `2c99b565ae24ea2006adf181da20c4419b3edc30`, dated 2026-08-10). https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2026-08/LpdFi_exp.sol — this Foundry PoC hardcodes all six addresses above, the two tx hashes, block numbers, timestamps, and the exact original calldata bytes for both transactions, and states it verified the root cause "by tracing the two on-chain txs from scratch," attributing the root-cause writeup to "DarkNavy." A local copy of this file, as cloned, is saved at `raw/DeFiHackLabs_LpdFi_exp.sol`.
2. **Independent secondary confirmation (press):** Coinfomania, "LpdFi Exploit Exposed: $700K Lost in Flash Loan Attack" — https://coinfomania.com/pt/lpdfi-exploit-exposed-700k-lost-in-flash-loan-attack-pt/ — reports the LpdFi protocol lost ~$700K around 2026-08-03 via a flash-loan attack that inflated the LPD token price (~71x) to open a ~$140M fraudulent collateral/deposit position, citing Hexagate/Chainalysis. This matches the PoC's mechanics (140,324,732 USDC nominal principal in `buy()`) and rough dollar magnitude, from a source independent of the DeFiHackLabs repo.
3. **Independent primary confirmation (this session, direct to chain — not sourced from the PoC file):** queried a public BSC full node (`https://bsc-dataseed.binance.org`) directly with `eth_getTransactionByHash`, `eth_getTransactionReceipt`, and `eth_getBlockByNumber` for both tx hashes:
   - Both txs exist on-chain, `status: 0x1` (success), `from` = the attacker EOA, `to` = the executor contract.
   - `input` calldata returned by the node is **byte-for-byte identical** to the PoC's `SETUP_CALLDATA` / `CLAIM_CALLDATA` constants.
   - `blockNumber` fields decode to exactly 113,613,923 and 113,613,924.
   - Block timestamps decode to exactly `1785686399` (2026-08-02 15:59:59 UTC) and `1785686400` (2026-08-02 16:00:00 UTC) — i.e. the claim really did land exactly one second after setup, in the very next block, matching the PoC's "issue index rolls 18→19" narrative.
   - Raw JSON saved: `raw/rpc_getTransactionByHash_setup.json`, `raw/rpc_getTransactionByHash_claim.json`, `raw/rpc_getTransactionReceipt_setup.json`, `raw/rpc_getTransactionReceipt_claim.json`, `raw/rpc_getBlockByNumber_setup.json`, `raw/rpc_getBlockByNumber_claim.json`.
   - This RPC cross-check is *primary on-chain data fetched independently by this session*, not a re-statement of the PoC file, and it corroborates the PoC's addresses/tx hashes/blocks/timestamps in full.
4. Etherscan V2 `getsourcecode` was then called directly against the two contract addresses named in the PoC and returned substantial (203KB / 33KB decompressed) real, compilable, multi-file verified Solidity source for both — see §5.

Between (1) DeFiHackLabs PoC, (2) an independent press report citing Hexagate/Chainalysis, and (3) this session's own direct BSC RPC queries, the exploited addresses, tx hashes, and exploit mechanics are corroborated by at least two sources independent of each other, one of which is primary on-chain data.

## 5. Verified source retrieval

Etherscan V2 unified API, `module=contract&action=getsourcecode`, `chainid=56`:

```
https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=<ADDR>&apikey=...
```

| Contract | Raw JSON saved at | Result |
|---|---|---|
| `LpdFi` (`0xcE6A...295e`) | `raw/getsourcecode_LPDFI_0xcE6A6e4413D85A136bBaC8AaE6fB46eAa77F295e.json` | Verified. `SourceCode` is a double-brace-wrapped Solidity Standard-JSON-Input bundle, 30 files (project contracts + OpenZeppelin 5.6.1 + PancakeSwap interfaces/library). Compiler `v0.8.28+commit.7893614a`, optimizer on (200 runs), EVM version `cancun`. Reconstructed at original relative paths under `source/LpdFi/`. |
| `Lpd` (`0x3876...3604`) | `raw/getsourcecode_LPD_0x38763EebE58a69C9CC91876947D9fB83e1273604.json` | Verified. Same JSON-bundle format, 10 files. Same compiler/settings. Reconstructed under `source/Lpd/`. |
| `PancakePair` (`0x8534...8210`) | `raw/getsourcecode_PAIR_0x85346d31743796F7d00D675629e32783A968F210.json` | Verified, but this is the **stock PancakeSwap V2 pair contract** (`ContractName: PancakePair`, compiler `v0.5.16`), not project-owned code. Per the task instructions ("anything else the PoC calls that isn't a standard vendored library or a stock PancakeSwap contract"), this was **not** reconstructed into `source/` — the raw JSON is kept in `raw/` as evidence that it is indeed the unmodified stock contract, but no `source/PancakePair/` tree was created. |
| Executor (`0x7f5A...F711`) | `raw/getsourcecode_EXECUTOR_0x7f5AD0A998Dcb3f5006F0D152BEBC055979EF711.json` | **Not verified** (`SourceCode: ""`, `ABI: "Contract source code not verified"`). This is the attacker's own exploit contract, not project code — no source is claimed or fabricated for it. See §6. |

`source/` tree actually written (all content traced to the two `getsourcecode_*` JSON files above, no hand-typed or memory-reconstructed Solidity):

```
source/LpdFi/project/contracts/LpdFi.sol         <- claimInterest(), removeLp(), buy(), getOrder()
source/LpdFi/project/contracts/Lpd.sol           <- price() (byte-identical to source/Lpd/project/contracts/Lpd.sol)
source/LpdFi/project/contracts/LpdBasic.sol
source/LpdFi/project/contracts/Binding.sol
source/LpdFi/project/contracts/interface/*.sol
source/LpdFi/project/contracts/library/PancakeLibrary.sol
source/LpdFi/npm/@openzeppelin/contracts@5.6.1/...   (vendored OZ 5.6.1, part of the verified bundle)
source/Lpd/project/contracts/Lpd.sol             <- price(), standalone fetch
source/Lpd/project/contracts/interface/*.sol
source/Lpd/project/contracts/library/PancakeLibrary.sol
source/Lpd/npm/@openzeppelin/contracts@5.6.1/...
```

## 6. Proxy / upgradeability determination

Both exploited contracts are **NOT proxies**:

- `getsourcecode` reported `"Proxy": "0"`, `"Implementation": ""` for both `LpdFi` and `Lpd`.
- Independently confirmed by reading the EIP-1967 implementation slot (`0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bb`) at `latest` directly against a public BSC RPC node (Etherscan's own `module=proxy` and `module=contract&action=getcontractcreation` endpoints returned `"Free API access is not supported for this chain"` on the provided API key/plan, so the check was done via `https://bsc-dataseed.binance.org` instead — raw responses in `raw/eip1967_slot_LPDFI_latest_publicrpc.json` and `raw/eip1967_slot_LPD_latest_publicrpc.json`). Both return `0x000...000` — no implementation address stored, confirming these are plain (non-proxy) contracts, consistent with the `getsourcecode` `Proxy` flag.
- Both contracts' constructors (`Lpd(address,address,address)`, `LpdFi(address,address,address,address,address,address)`) set every collaborator address as `immutable`, which is a strong additional structural signal against an upgradeable/proxy design — immutables are baked into the runtime bytecode at deploy time and cannot be changed post-deploy.
- Attempted a direct pre/post bytecode diff (`eth_getCode` at the pre-exploit block `113,613,922` vs `latest`) as an extra empirical check; the public RPC node returned `"missing trie node"` for the historical block (it does not retain state that far back — only ~15 days of history at time of this research, and the node is not an archive node). This specific extra check could not be completed, but is not required to reach a verdict: for a **non-proxy** contract, the EVM guarantees deployed bytecode is immutable for the life of the address (barring `SELFDESTRUCT` + redeploy at the same address via `CREATE2`, for which there is no evidence — the DeFiHackLabs PoC itself forks at block `113,613,922` and successfully replays the original calldata against these same addresses using their contemporary on-chain state, which would not work if the code had since changed or the address were freshly redeployed).

**Verdict: `source/` is confirmed pre-hack code.** Because both `LpdFi` and `Lpd` are ordinary (non-proxy) contracts, their deployed bytecode has been immutable since original deployment (which necessarily predates the 2026-08-02 exploit block, since the exploit transactions executed successfully against fully-initialized state — `orders`, `investedUAmount`, the PancakeSwap pair, etc. — at that address). The verified source pulled from Etherscan today is therefore the same source that compiled to the bytecode that ran during the exploit. This is stated explicitly per the task's instructions, not left implicit.

## 7. Gaps / things NOT fabricated

- The attacker's **executor contract** (`0x7f5AD0A998Dcb3f5006F0D152BEBC055979EF711`) is unverified on the block explorer. Its exact logic (how it computed the manipulation amounts, its transient-storage flash-liquidity trick) is known only from the DeFiHackLabs PoC's *comments* and its own re-derivation of calldata/behavior — not from real verified source, because none exists publicly. No executor Solidity file is included in `source/`.
- `PancakePair` (`0x85346d31743796F7d00D675629e32783A968F210`) verified source was fetched (`raw/getsourcecode_PAIR_...json`) but deliberately **not** placed under `source/` since it is stock, unmodified PancakeSwap V2 code, per the task's scope instructions.
- Etherscan V2's `module=proxy` (`eth_getStorageAt`, `eth_getTransactionByHash`) and `module=contract&action=getcontractcreation` calls were rejected by the given API key's plan tier for chain 56 ("Free API access is not supported for this chain"). Where this happened, the equivalent data was obtained instead from a public BSC JSON-RPC node (`bsc-dataseed.binance.org`) and saved under `raw/rpc_*.json` — noted here so the substitution is explicit, not hidden.
- A dedicated DarkNavy write-up for this specific incident (referenced by name inside the DeFiHackLabs PoC's comments) could not be located directly on darknavy.org during this research (the site's `/web3/exploits/` index returned HTTP 503 during this session, and a site-scoped search did not surface an LpdFi/LOOPSDAO-titled report). BUG.md therefore cites the DeFiHackLabs PoC itself (which states it independently re-derived the root cause from the raw transaction trace) plus the Coinfomania/Hexagate press report as its public sources, and does not claim a DarkNavy report was read.
