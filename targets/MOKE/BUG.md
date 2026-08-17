ANSWER KEY — DO NOT SHIP WITH SOURCE HANDED TO A TEST SUBJECT

# MOKE / MokeRelease — root cause writeup

**Chain:** BNB Smart Chain (56). **Exploit tx:** `0x0776048b1b58064fb31b6513721811e7b44d6bdbe7bf5833158b241ca6756a8f`, block 113,652,609, 2026-08-02 20:50:11 UTC. **Vulnerable contract:** `MokeRelease` at `0x684D722EbF8980f49492f631f56765DD4Fb302A7` — this is the `releaseContract` referenced by `MokeToken` (`0x1A35C16cE21903Bc17Fd020c4ED73fEdC70c1b2A`). Full provenance and address-confirmation chain: see `PROVENANCE.md`.

## Sourcing note — read this before trusting the framing below

The task's lead described this as *"an unprotected/public `claim()` function ... that lacked access control."* Independent verification (this file) shows that framing is **imprecise**: `MokeRelease.claim()` is indeed a public/external function with no `onlyOwner`/allowlist modifier, but it is *not* a bare "anyone can call it and get paid" bug — it does check `ur.pendingUsdt > 0` and a per-user claim interval. The real, more specific bug is a **broken access check on the price-oracle-update function `settle()`, combined with `claim()` trusting that oracle price with no manipulation resistance** — which lets *any* caller convert a small, legitimately-vested USDT-denominated entitlement into an enormously inflated MOKE payout. This is corroborated by:

1. **[SunWeb3Sec/DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs)**, `src/test/2026-07/MOKE_exp.sol` (README anchor "20260802 MOKE — Unprotected claim() drained via EIP-7702 self-delegation") — a Foundry reproduction whose header explicitly states it was built by **tracing the raw exploit transaction from scratch**, because *"No public root-cause writeup at build time."* Its comment describes the symptom (`claim()` "with NO check that the caller is entitled to that allocation") without walking through *why* — i.e. it doesn't identify the `settle()` access-control bug or the price-manipulation mechanism explicitly, though its cash-out-path description (flash loans → price move → claim → LP/dividend unwind) is consistent with what's derived below.
2. **[CryptoTimes, "MOKE Suffers $907K Exploit in Suspected BNB Chain Attack"](https://www.cryptotimes.io/2026/08/03/moke-suffers-907k-exploit-in-suspected-bnb-chain-attack/)** (2026-08-03) — confirms the ~$907.7K loss figure and TenArmor's detection, names `MokeLPManager` and PancakeSwap V2 pools, but **explicitly states the exact vulnerability mechanism is unknown** and gives no contract addresses, tx hash, or technical detail. This is not a post-mortem; it's a loss-alert news writeup.
3. **No SlowMist/PeckShield/CertiK/BlockSec/rekt.news technical writeup was found** despite multiple targeted searches (queries logged: "MOKE token exploit August 2026 BNB", "MokeToken releaseContract claim exploit post-mortem", "rekt.news MOKE exploit BNB Chain 2026", `"MOKE" hack BSC "settle" OR "price manipulation" OR "vesting" August 2026`, "MOKE token BNB Chain exploit CertiK OR PeckShield OR SlowMist OR BlockSec"). As of 2026-08-17 this incident appears to have no public technical post-mortem from the project or a named security firm.

**Given that gap, the mechanism below is derived independently in this session** by (a) reading the verified `MokeRelease.sol` source line-by-line (`source/RELEASE_.../project/contracts/MokeRelease.sol`), and (b) decoding the *actual* event log of the real exploit transaction's receipt (fetched fresh from a public BSC RPC node, not copied from any writeup — raw data in `raw/rpc_tx_receipt.json`). This is stronger evidence than the DeFiHackLabs comment alone (which is itself an inferred reconstruction), but it is still **this session's own analysis, not a confirmed/published root-cause finding** — treat the specific numeric claims below as independently reproducible from the cited raw data, and the causal narrative as the most plausible reading of that data, not as an official verdict.

## The vulnerable code

`source/RELEASE_0x684D722EbF8980f49492f631f56765DD4Fb302A7/project/contracts/MokeRelease.sol`

### Bug 1 — `settle()`'s "authorized OR EOA" check is not an access control at all

```solidity
function settle() external override {
    require(
        isSettler[msg.sender] || msg.sender == owner() || msg.sender == tx.origin,
        "Only authorized or EOA"
    );
    require(
        block.timestamp >= lastSettleTime + settleMinInterval,
        "Settle cooldown"
    );
    _trySettle();
    uint256 price = getMokeUsdtPrice();
    if (price > 0) {
        settledMokePrice = price;
        lastSettleTime = block.timestamp;
        emit PriceSettled(price);
    }
}
```

The third disjunct, `msg.sender == tx.origin`, is true for **every directly-initiated EOA call**, regardless of whether that address is an authorized settler. The condition was presumably meant to mean "or it's a trusted keeper bot calling directly" but as written it means "or the caller is not going through an intermediate contract" — which is not a permission check, it's a call-shape check. Any EOA can call `settle()` directly (subject only to the 600-second `settleMinInterval` cooldown) and force `settledMokePrice` to be recomputed from **live** PancakeSwap reserves via `getMokeUsdtPrice()`:

```solidity
function getMokeUsdtPrice() public view returns (uint256) {
    ...
    uint256 mokeBnbPrice = _getPriceFromPair(mokeBnbPair, address(mokeToken));
    uint256 bnbUsdtPrice = _getPriceFromPair(bnbUsdtPair, wbnb);
    ...
    return mokeBnbPrice * bnbUsdtPrice / PRECISION;
}
```

`_getPriceFromPair` reads a PancakeSwap V2 pair's **instantaneous, spot** reserves (`getReserves()`) with no TWAP, no minimum liquidity check, and no staleness/multi-block averaging. A single large swap in the same transaction moves this price arbitrarily.

**The EIP-7702 angle:** the attacker's EOA (`0xE454a9BAC1a44868e4A9Cbe1a4B5ac231D0DCF8a`) had an on-chain EIP-7702 delegation designator pointing at its own exploit bytecode (`0xC7fDEA027FEb41C8f3a45eC284280ce68f4e6Ff7`) installed before the exploit block. Because EIP-7702 makes the delegated code execute *as* the EOA's own address, a top-level transaction with `to == from == attacker` still has `tx.origin == msg.sender == attacker` for every call the delegated logic makes — so the naive `msg.sender == tx.origin` check keeps passing even though the "EOA" is really running attacker-authored contract logic that performs a flash-loan-funded swap, then calls `settle()`, then immediately calls `claim()`, all inside one atomic transaction. (Note: this bug does **not require** EIP-7702 — any EOA calling `settle()` directly, then a contract-mediated swap-then-claim in a *separate* transaction, or a plain multi-step bot script, would trip the same `tx.origin` loophole. EIP-7702 just let the attacker package the whole sequence atomically from a single externally-owned-looking address.)

### Bug 2 — `claim()`'s price-deviation guard is defeated because it checks the price against *itself*

```solidity
function claim() external payable override nonReentrant whenNotPaused {
    require(msg.value >= claimFee, "Insufficient claim fee");
    _trySettle();
    _snapshotUser(msg.sender);

    UserRelease storage ur = userRelease[msg.sender];
    require(ur.pendingUsdt > 0, "Nothing to claim");
    require(block.timestamp >= ur.lastClaimTime + claimInterval, "Claim interval not reached");
    ...
    uint256 pendingUsdt = ur.pendingUsdt;
    require(settledMokePrice > 0, "Price not settled");

    uint256 livePrice = getMokeUsdtPrice();
    if (livePrice > 0) {
        uint256 deviation = livePrice > settledMokePrice
            ? (livePrice - settledMokePrice) * BASIS_POINTS / settledMokePrice
            : (settledMokePrice - livePrice) * BASIS_POINTS / settledMokePrice;
        require(deviation <= maxPriceDeviation, "Price deviation too high"); // maxPriceDeviation = 2000 (20%)
    }

    uint256 mokeAmount = pendingUsdt * PRECISION / settledMokePrice;
    ...
    uint256 mokeBalBefore = mokeToken.balanceOf(xMokePair);
    require(mokeBalBefore >= mokeAmount, "Insufficient MOKE in reserve pool");
    ur.pendingUsdt = 0;
    ur.claimedUsdt += pendingUsdt;
    ur.lastClaimTime = block.timestamp;

    IMokeToken(address(mokeToken)).releaseFromPair(msg.sender, mokeAmount);       // pulls MOKE from the reserve pool
    ...
    IMokeToken(address(mokeToken)).addReleasedBalance(msg.sender, mokeAmount);    // credits it to the caller
    ...
}
```

The `deviation` check is meant to stop `claim()` from being called against a stale/manipulated `settledMokePrice`. But because `settle()` (Bug 1) can be called permissionlessly moments earlier **in the same transaction**, the attacker sets `settledMokePrice` to the exact manipulated `livePrice` right before calling `claim()` — so at the point `claim()` re-reads `livePrice`, it is comparing the manipulated price to itself: `deviation ≈ 0`, and the guard passes trivially. `mokeAmount = pendingUsdt * PRECISION / settledMokePrice` then converts the user's small, legitimately-accrued USDT-denominated vesting entitlement into a MOKE amount inflated by however much the price was crashed. `MokeToken.releaseFromPair` (gated to `msg.sender == releaseContract`, see `MokeToken.sol`) pulls that inflated amount straight from the protocol's `xMokePair` reserve pool.

So the actual missing control isn't "an entitlement check on `claim()`" (that check exists and is intact) — it's **manipulation-resistance on the price oracle `claim()` relies on to convert USDT-value entitlement into a token amount**, gated behind an access check (`settle()`) that doesn't actually restrict who can update the oracle.

## Independently decoded on-chain evidence (this session, from the real exploit tx)

Fetched `eth_getTransactionReceipt` for the exploit tx from a public BSC RPC node (`raw/rpc_tx_receipt.json`) and decoded every log emitted by the `MokeRelease` contract (`0x684d722e...`), using locally-computed event-signature hashes (not copied from any writeup):

- **One `PriceSettled(uint256)` event** (log index `0x86`), value `0x00000000000000000000000000000000000000000000000000021c5e30999a7f` = **594,140,821,297,791 wei-scaled = 0.000594140821297791 USDT per MOKE.** This is the `settle()` call locking in a manipulated price.
- **Four `Claimed(address indexed user, uint256 mokeAmount, uint256 usdtValue)` events**, for **four different addresses** (not just the attacker EOA — three additional pre-funded/"sybil" accounts also called `claim()` within the same atomic transaction, consistent with the DeFiHackLabs comment's mention of pre-seeded holder accounts):

  | Claimant | mokeAmount | usdtValue (pendingUsdt spent) |
  |---|---|---|
  | `0xE454a9BAC1a44868e4A9Cbe1a4B5ac231D0DCF8a` (attacker EOA) | 41,684,057.23 MOKE | 24,766.2 USDT |
  | `0x8c8bd7018dba1c4c23a999a0dba74a72a117f5fa` | 1,110,847.76 MOKE | 660.0 USDT |
  | `0xd2d29da97ec789bf8ae3acdd3a993956883822f2` | 1,009,861.60 MOKE | 600.0 USDT |
  | `0xec6b16576ecac384d40df8af4522fc9614f67ea2` | 55,542.39 MOKE | 33.0 USDT |
  | **Total** | **≈ 43,860,309 MOKE** | **≈ 26,059.2 USDT** |

  i.e. ~26,059 USDT worth of *nominally legitimate* vesting entitlement (across 4 accounts) was converted into ~43.86M MOKE tokens because the divisor (`settledMokePrice`) had just been crashed to ~$0.000594/MOKE by the same transaction.
- Dozens of `DynamicReward(address indexed referrer, address indexed downline, uint256 layer, uint256 acAmount)` events interleaved between the `Claimed` events — the referral-reward cascade (`_distributeDynamicReward`) firing for each claimant across multiple upline layers, confirming the four claimants were linked into a pre-built referral tree.
- Separately, `MokeLPDividend` (`0x5ae569d8...`) emitted **131 log entries** in the same transaction — consistent with `distributeDividend()` (converts the vault's now-inflated MOKE balance to BNB) followed by `claimDividend()` run across a large batch of pre-registered LP-holding addresses (the DeFiHackLabs comment's "100 seeded holder accounts"), which is how the inflated MOKE was ultimately converted into BNB that the attacker kept. `MokeLPManager` (`0xacabe59b...`) emitted 1 log, consistent with a single `removeLiquidity()` unwind of a pre-seeded LP position.

These numbers were decoded directly from the raw receipt in this session (method: `python3` + `pycryptodome` to compute `keccak256("Claimed(address,uint256,uint256)")` etc. and slice the log `data` fields) — see `raw/rpc_tx_receipt.json` for the source data; the decode script's logic is reproducible from the event signatures quoted above and the `MokeRelease.sol` event declarations.

## Exploit path (synthesized)

1. Attacker's EOA carries a pre-installed EIP-7702 delegation to attacker-controlled exploit bytecode.
2. Within one atomic transaction (`to == from == attacker EOA`): flash-loan WBNB + BTCB from Moolah (Lista Lending); use Venus to lever BTCB into more BNB — working capital for the price move.
3. Swap through the MOKE-BNB / BNB-USDT PancakeSwap V2 pools to crash the pool-implied MOKE/USDT price.
4. Call `MokeRelease.settle()` — permissionless in practice due to the `msg.sender == tx.origin` loophole (Bug 1) — locking the crashed price into `settledMokePrice`.
5. Call `MokeRelease.claim()` from the attacker EOA and from 3 other pre-funded/pre-vested addresses. Each passes the now-meaningless deviation check (Bug 2) and receives a MOKE payout wildly disproportionate to its small USDT-denominated vesting entitlement, pulled from the `xMokePair` reserve via `MokeToken.releaseFromPair`/`addReleasedBalance`.
6. Launder the inflated MOKE to BNB using the project's own plumbing: feed it through `MokeLPDividend.distributeDividend()` (swaps vault MOKE → BNB, bumps `totalDividendPerLP`), then `claimDividend()` across the pre-registered LP-holder set to pull the BNB out; `MokeLPManager.removeLiquidity()` unwinds the attacker's own pre-seeded LP position.
7. Repay the flash loans and Venus borrow within the same transaction; keep the net BNB profit (~1,546 BNB per the DeFiHackLabs PoC's `assertApproxEqAbs` assertion, ≈ $907.7K at ~$587/BNB — matching CryptoTimes' independently-reported loss figure).

## Fix sketch (not from any source — this session's own assessment)

- `settle()` must be gated to a genuinely trusted keeper/multisig set (drop the `msg.sender == tx.origin` disjunct entirely — it provides no security value).
- The price feed `settle()`/`claim()` rely on should not be a single-block spot read of a PancakeSwap V2 pair; use a TWAP, a Chainlink-style oracle, or at minimum require the settlement price to be sourced from a block prior to the one containing `claim()` so it cannot be moved and consumed atomically.
- `claim()`'s deviation check should compare the *settlement-time* price against an independently-sourced *current* price (e.g. a separate oracle), not against a `livePrice` read from the same manipulable spot source that `settle()` itself just wrote from.
