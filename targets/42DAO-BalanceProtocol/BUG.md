ANSWER KEY — DO NOT SHIP WITH SOURCE HANDED TO A TEST SUBJECT

# BUG — 42DAO / Balance Protocol oracle-to-liquidation exploit (BSC, 22 Jul 2026, ~$912K–915K)

## Status of this writeup

The vulnerable **Median Oracle** and **Spotter** contracts (the pieces named directly in every public post-mortem as the entry point) could **not** be retrieved as verified mainnet source in this session — see `PROVENANCE.md` for the full account of what was tried and why. What follows is therefore in two tiers:

- **Directly confirmed from pulled, verified, pre-hack source code** (`Vat.sol`, `Dog.sol` — see `source/`): how the bad price, once it lands in `Vat`, mechanically enables under-collateralized liquidation with zero additional checks. This part is not speculation — it is read straight off the contracts in this dossier.
- **Reported but not independently source-verified** (Median Oracle, Spotter): the specific missing checks are stated by SlowMist's public TI alert and cited press coverage, not observed in code we hold. Flagged explicitly below.

## Reported root cause (per SlowMist TI alert, PeckShield, and press coverage — not independently source-verified in this dossier)

> "Attackers exploited an abnormally low BTCB oracle price from Median Oracle via Spotter `poke` and Dog `bark`. The spotter lacked price deviation checks, max drawdown limits, and minimum price protections, allowing immediate write of the low spot into Vat. The dog module then used this updated spot without any liquidation delay or oracle price validation, enabling instant liquidation of multiple BTCB vaults."
> — SlowMist TI Alert, https://x.com/SlowMist_Team/status/2079759793192132810 (quoted in, e.g., https://www.tftc.io/balance-coin-42dao-exploit-blc-crash-99-percent and https://www.cryptotimes.io/2026/07/22/42daos-blc-stablecoin-depegs-to-near-zero-after-912k-oracle-exploit/)

Additional detail from press: a falsified/near-zero BTCB price was accepted by the Median Oracle with, per reporting, "no sanity check and no circuit breaker" (https://www.cryptonexa.com/42dao-oracle-exploit-drains-915k-and-sends-blc-to-near-zero, https://crypto-economy.com/oracle-attack-sent-balance-stablecoin-collapse/, which additionally states 42DAO lacked a MakerDAO-style Oracle Security Module / OSM delay). Reporting also describes unbacked BLC being minted from a null address via a `GemJoin`-style contract and immediately swapped for BSC-USD/BTCB on PancakeSwap V2 in two waves ~2 hours apart (https://www.techtimes.com/articles/321253/20260722/stablecoin-blc-loses-dollar-peg-after-oracle-attack-drains-915k-42dao-protocol.htm), though the exact relationship between that minting and the oracle/liquidation path has not been technically confirmed by a source-level post-mortem that this session could locate (one outlet, https://www.tftc.io/balance-coin-42dao-exploit-blc-crash-99-percent, explicitly notes "the root cause of the null-address minting has not been confirmed by a technical post-mortem").

## What the pulled source actually shows (Vat + Dog, confirmed non-proxy, pre-hack == current bytecode — see PROVENANCE.md)

### 1. `Vat.file(bytes32 ilk, bytes32 what, uint data)` — no validation on the price it accepts

`source/Vat_0xfa7cea82f8a6254ccebad71350125aa6171b8a84/src/0.5.12/vat.sol`:

```solidity
function file(bytes32 ilk, bytes32 what, uint data) external note auth {
    require(live == 1, "Vat/not-live");
    if (what == "spot") ilks[ilk].spot = data;
    else if (what == "line") ilks[ilk].line = data;
    else if (what == "dust") ilks[ilk].dust = data;
    else if (what == "taxRate1") ilks[ilk].taxRate1 = data;
    else if (what == "taxRate2") ilks[ilk].taxRate2 = data;
    else revert("Vat/file-unrecognized-param");
}
```

This is the function the Spotter's `poke()` calls to write a freshly-observed collateral price into the ledger (`ilks[ilk].spot`). The **only** guard is `auth` (caller must be a `ward`, i.e. an address the Vat's owner has `rely`'d — normally just the Spotter). There is:
- no minimum value check,
- no maximum-deviation-from-previous-value check,
- no rate-of-change / max-drawdown limit,
- no delay/timelock between write and use.

Any `data` value — including a price near zero — is accepted immediately and used by every downstream consumer on the very next call. This is the "Spotter lacked price deviation checks, max drawdown limits, and minimum price protections... allowing immediate write of the low spot into Vat" step from the SlowMist alert, confirmed at the `Vat` layer: **even if `Spotter.poke()` had wanted to add a check, `Vat` itself provides no backstop** — the ledger will accept whatever an authorized caller tells it.

### 2. `Dog.bark(bytes32 ilk, address urn, address kpr)` — liquidates purely off `Vat.ilks[ilk].spot`, no delay, no second opinion

`source/Dog_0x00101ae4467d72e83ef68df447c41de0c71f634e/src/0.6.12/Dog.sol`:

```solidity
function bark(bytes32 ilk, address urn, address kpr) external returns (uint256 id) {
    require(live == 1, "Dog/not-live");

    (uint256 ink, uint256 art) = vat.urns(ilk, urn);
    Ilk memory milk = ilks[ilk];
    uint256 dart;
    uint256 rate;
    uint256 dust;
    {
        uint256 spot;
        (,rate,,, spot,, dust) = vat.ilks(ilk);
        require(spot > 0 && mul(ink, spot) < mul(art, rate), "Dog/not-unsafe");
        ...
```

The entire "is this vault unsafe / liquidatable" decision is the single inequality `mul(ink, spot) < mul(art, rate)`, where `spot` is read live, in the same call, straight out of `Vat.ilks[ilk].spot` — the value `Vat.file(..., "spot", ...)` just wrote. There is:
- no check that `spot` moved by a plausible amount since the last observation,
- no liquidation delay (no block/time buffer between a price update and it being usable to `bark()`),
- no independent price source or second oracle consulted,
- no circuit breaker / pause tied to price volatility.

The **only** requirement is `spot > 0` — so literally any positive-but-near-zero price satisfies it. This directly confirms the SlowMist claim that "the dog module... used this updated spot without any liquidation delay or oracle price validation, enabling instant liquidation of multiple BTCB vaults": the code we pulled shows there is structurally nothing else `bark()` could check even if it wanted to — `spot` is trusted completely, in the same transaction it was written.

Once `bark()` decides a vault is unsafe, it immediately calls `vat.grab(...)` to seize the collateral (`ink`) and hand it to a `Clipper`/liquidation-auction contract at a discount (`chop`), and the caller (`kpr`, the liquidation keeper — in this case, the attacker) can receive a liquidation incentive. With `spot` crashed to near zero, `mul(ink, spot) < mul(art, rate)` is true for essentially every BTCB vault regardless of its real health, so **every** BTCB vault becomes liquidatable in the same transaction that corrupted the price — matching the reported "instant liquidation of multiple BTCB vaults" in one transaction.

## Exploit path (as reported; steps 1–2 not independently source-verified — see Status above)

1. **Attacker manipulates the Median Oracle's reported BTCB price down to a near-zero value** in a single transaction (reported mechanism: the Median Oracle accepted the value with no sanity/deviation check and no circuit breaker; source of the Median contract could not be obtained in this session, so the exact manipulation primitive — e.g. a directly-writable feed, a manipulable AMM-derived median, or a missing minimum-quorum check on price submitters — is not confirmed here).
2. **Attacker (or anyone) calls `Spotter.poke(ilk)`** for the BTCB collateral type. Per SlowMist, Spotter had no price deviation checks, no max-drawdown limit, and no minimum-price floor, so it accepts the Median's bad reading and forwards it to `Vat.file(ilk, "spot", badValue)` — confirmed above to be an unguarded write once `poke()`/Spotter passes the `auth` check on `Vat`.
3. **`Vat.ilks["BTCB-A"].spot` is now near zero**, effective immediately (confirmed: `Vat.file` has no delay/queue).
4. **Attacker calls `Dog.bark("BTCB-A", urn, attacker)` against multiple BTCB vaults.** Confirmed above: `bark()`'s sole safety check, `mul(ink, spot) < mul(art, rate)`, is trivially true for real vaults once `spot` is near zero, so every one of them is now "unsafe" and gets liquidated in the same transaction, with the attacker acting as `kpr` (keeper) to capture the liquidation-auction / incentive flow.
5. **Reported (not independently verified):** unbacked BLC is minted from the null address via a GemJoin-style contract and swapped through PancakeSwap V2 for BSC-USD and BTCB, in a first wave (~4.5M BLC) and a second, near-identical wave ~2 hours later (~5,900 BLC), for a combined ~$912K–915K extracted. BLC depegs from ~$1 to ~$0.001–0.0025 (>99%) within hours as the market reacts.

## What MakerDAO's real design has that this fork's confirmed code does not

Reporting (https://crypto-economy.com/oracle-attack-sent-balance-stablecoin-collapse/) attributes the root cause to the absence of a MakerDAO-style **Oracle Security Module (OSM)** — a component that buffers oracle price updates for a delay period (in vanilla Maker, ~1 hour) before `Spotter.poke()` can consume them, so that a manipulated single-block price cannot be used for liquidation until it has had time to be noticed/contested. The `Vat.file` and `Dog.bark` code pulled in this dossier confirms there is **no such delay anywhere downstream of the price write** — a price written to `Vat` is usable by `Dog.bark()` in the very same transaction. Whether the missing delay lived in the (unrecovered) Median/Spotter contracts, or was simply architecturally absent from this fork entirely, could not be pinned down further without their source.

## Sources

- SlowMist TI Alert (primary technical claim, quoted above): https://x.com/SlowMist_Team/status/2079759793192132810
- https://www.tftc.io/balance-coin-42dao-exploit-blc-crash-99-percent
- https://www.cryptotimes.io/2026/07/22/42daos-blc-stablecoin-depegs-to-near-zero-after-912k-oracle-exploit/
- https://www.cryptonexa.com/42dao-oracle-exploit-drains-915k-and-sends-blc-to-near-zero
- https://crypto-economy.com/oracle-attack-sent-balance-stablecoin-collapse/
- https://www.techtimes.com/articles/321253/20260722/stablecoin-blc-loses-dollar-peg-after-oracle-attack-drains-915k-42dao-protocol.htm
- https://intellectia.ai/news/crypto/42dao-exploit-leads-to-99-plummet-of-blc-token
- Pulled verified source (this dossier): `source/Vat_0xfa7cea82f8a6254ccebad71350125aa6171b8a84/src/0.5.12/vat.sol`, `source/Dog_0x00101ae4467d72e83ef68df447c41de0c71f634e/src/0.6.12/Dog.sol` — see `PROVENANCE.md` for retrieval method and proxy/pre-hack verdict.
