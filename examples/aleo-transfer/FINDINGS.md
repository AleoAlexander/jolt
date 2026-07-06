# Phase 0 Findings: Aleo Crypto Inlines for Jolt

*July 6, 2026 · fork of a16z/jolt @ b092110, branch `aleo/inlines`, tag `phase0-complete`*
*Spec: sparkVM `docs/superpowers/specs/2026-07-06-phase0-inlines-benchmark-design.md`*

## Executive summary

**The central finding is negative and definitive: guest-side inline sequences
cannot meaningfully accelerate Aleo's 253-bit field arithmetic in Jolt.** The
advice-quotient inline we built is correct, sound, and proven end-to-end — and
19% *slower* than the software it was meant to replace. The ≤4M-cycle target
for `transfer_private` is unreachable from the guest side. The path to the
5-10× win is prover-side field acceleration (a `field-inline` analog for
BLS12-377 Fr), which is upstream-collaboration scope. That is the input the
Aleo→Jolt roadmap's Phase 0 existed to produce.

## Scorecard (Apple M4 Pro, 14 cores, 24 GB, LTO off)

| Run | transfer_private | full trace | prover | peak RSS | proof | verify |
|---|---|---|---|---|---|---|
| baseline-plain (junk Poseidon consts) | 17.59M† | 21.20M | ~178K cyc/s | 4.79 GB | 90,303 B | 85 ms |
| baseline-field-inline | identical | identical | — | — | — | — |
| inline chain (1000 field ops) | — | 310,464 | — | — | — | — |
| arkworks control (1000 field ops) | — | 252,714 | — | — | — | — |

† with real snarkVM Poseidon parameters (M1). Earlier junk-constant model: 15.7M.

## What was built and verified

1. **`aleo-vectors-gen`** (sparkVM repo): generates Poseidon2 parameters
   (8 full + 31 partial rounds, α=17, t=3), domain separator, and test vectors
   directly from snarkVM v4.7 — nothing hand-transcribed.
2. **Bit-exact snarkVM Poseidon in a Jolt guest** (M1): `poseidon2_hash`
   reproduces `N::hash_psd2` exactly — verified against 8 snarkVM-generated
   vectors on the host build *and* inside the RISC-V guest. The sponge
   convention (state `[capacity, rate0, rate1]`, preimage `[domain, len, ...]`,
   squeeze `rate[0]` post-permute) is documented in the guest source.
3. **`jolt-inlines/edwards-bls12`** (M3/M4): FQMUL/FQSQR/FQDIV advice-quotient
   inlines with the w·p accumulation generalized to a 4-limb negated modulus;
   canonical-limb `Fq` SDK with add/sub/inverse; extended twisted-Edwards
   (a=-1, d=3021) point add/double/neg/to_affine. 9 differential tests vs
   arkworks (1000-case random + edge cases + 20-step chain agreement).
   **Proven end-to-end**: `fqmul-test` traces, proves, and verifies
   (`valid: true`, 2.92s) — the M3 soundness gate passed.
4. **Scorecard harness** (`scripts/aleo-scorecard.sh`) + `RESULTS.md` history.

## The negative results, precisely

- **Approach 3 (existing `field-inline` feature): zero effect.** It is BN254-
  specific and never engages for `ark-ed-on-bls12-377` guest code.
- **Approach 1 (advice-quotient inlines): 0.81× — a slowdown.** The identity
  `ab + wp = 2^256·w + c` needs the full 4×4 `w·p` product because
  `p = 2^256 − q` has four significant limbs for a 253-bit `q`. Total ≈ 64 limb
  products per op vs Montgomery's ≈ 48, and the a16z arkworks fork already
  emits ~252-cycle Montgomery multiplication on RV64. secp256k1's inlines win
  only because their negated moduli are 1-2 limbs. **No sequence-level trick
  escapes this: verified foreign-field mul at 253 bits is product-count parity
  with direct computation.**

## Recommendation (Approach-2 escalation, upstream scope)

1. **Do not invest further in guest-side sequences for field mul.** The crate
   stays as proven infrastructure (div-by-advice may still pay — inversion via
   Fermat costs ~250 muls in software vs 1 verified div — useful for batch
   affine conversions; measure before relying on it).
2. **Take the field-acceleration case upstream.** Jolt already special-cases
   its native BN254 field (`field-inline`). The concrete, evidence-backed ask:
   generalize prover-side field acceleration to guest-declared moduli (or add
   BLS12-377 Fr as a second supported field). This aligns with LayerZero's
   interests (any chain with non-BN254 crypto hits the same wall) and is
   precisely the roadmap's WS-0.1 upstream-seat agenda.
3. **Software wins still on the table** (not executed, per scope decision):
   the benchmark guest converts ~470 Poseidon constants to Montgomery form per
   permutation (`fq_from_limbs` in the perm loop); hoisting to static
   Montgomery-form constants is a ~2× hashing win. Windowed/wNAF scalar mult
   tuning may yield another ~1.5× on curve ops. Realistic software-only floor:
   ~10-13M cycles — still far from 4M, reinforcing conclusion (2).

## Cost model implications for the Aleo→Jolt roadmap

At today's ~19M cycles and measured prover throughput (~180K cyc/s laptop,
~1M cyc/s server-class per a16z), a delegated transfer_private proof is
~20-100s CPU — viable for a delegated-prover service only with GPU proving
(LayerZero's stack) or the upstream field acceleration. Client-side proving
additionally needs the streaming prover (RAM). Neither changes the roadmap's
Phase-1 (coprocessor) viability — public-compute guests using standard hashes
(sha2/keccak inlines exist) are unaffected by this finding.
