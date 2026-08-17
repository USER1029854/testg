# Exploited-contract regression corpus (BNB Smart Chain, 2026)

Real, verified on-chain source for five DeFi projects exploited on BNB Smart Chain
(chain id 56) in 2026, assembled as a blind regression-test corpus for a
security-audit pipeline: point the audit tool at each `targets/<TARGET>/source/`
and check whether it independently flags a real vulnerability, with no hints
about what that vulnerability is or where it lives.

## Layout

```
targets/<TARGET>/source/   real verified Solidity for the contract(s) touched by
                            that target's exploit, pulled from the block
                            explorer's own getsourcecode API and reconstructed at
                            original file paths. Nothing here was retyped,
                            summarized, or reconstructed from a post-mortem.
```

That's the whole tree. Provenance notes, the exploit write-up, and raw API/RPC
evidence were deliberately removed from the working tree after the source was
verified, so this corpus can be used as a blind test without leaking the answer
into the same package. That material still exists in this branch's git history
if it's ever needed again (e.g. to re-confirm an address or re-derive the
pre-hack verdict) — it isn't lost, just not shipped alongside the source.

## Targets

- MOKE
- LULA
- Crypto DAO / Pro token
- LOOPSDAO / LpdFi
- 42DAO / Balance Protocol

All five: BNB Smart Chain (chain id 56), exploited in 2026.

## Repository note

This branch (`claude/clever-shannon-ej53l1`) was pushed to a previously-empty
repository and became its default branch — there is no separate base branch to
open a pull request against.
