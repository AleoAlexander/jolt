# Field-Acceleration Prototype (branch aleo/field-accel-prototype)

**Purpose:** evidence for the RFC "prover-side foreign-field acceleration
(guest-declared modulus)" — NOT for merge. Originally built on a16z/jolt @
b092110; rebased onto upstream main 552ba6192 (2026-08-17) with all gates
re-run green and numbers re-measured (see RESULTS.md `rebase-20260817`).

## What this branch demonstrates
- B0: advice-only field ops (jolt-inlines/edwards-bls12): 41 cyc/op vs 252
  software; Aleo transfer_private model 17.59M → 3.09M cycles (5.7x).
- B1: batched non-native-mul sumcheck (crates/jolt-prover-legacy/src/zkvm/
  field_accel/): 46K-op transfer log proved in 0.179s, verified <0.1ms;
  tamper tests reject corrupted logs; muldiv regression green.

## Deliberately unsound / incomplete (the `// PROTOTYPE:` inventory)
1. Advice results are unbound in the main proof (B0 ops verify nothing
   in-trace); binding = the gadget, which is a *side proof* here.
2. Gadget final evals are sent in the clear — no PCS commitment binding.
3. No range checks on limb columns (bounds derived in field_accel/
   CARRY_BOUNDS.md; enforcement is Track C).
4. Invocation log via host thread-local, not witness-gen plumbing.
5. Non-ZK mode only; no BlindFold synchronization; no Akita path.
6. Transcript draws tau/alpha before any column commitment is absorbed —
   grindable in a bound design; the real design must absorb commitments
   (and the record count) first.
7. Division records: the b = 0, a = 0 cell accepts an arbitrary quotient;
   the real design needs an in-gadget divisor-nonzero witness.
8. num_records/log_n are trusted inputs, not transcript-bound.

## Known implementation gaps (round-2 code review, July 2026)
Distinct from the protocol-design requirements above — these are code-level:
- **from_canonical uses debug_assert** (sdk.rs): compiled out in release, so
  non-canonical operands are accepted at the input boundary. Load-bearing
  because Fq derives Eq on raw limbs and add()/the overflow argument assume
  < q. Real (small) soundness crack in release; fix = reduce or spoil_proof
  instead of debug_assert. Present at phase0-complete and HEAD.
- **load_fq ...unwrap_or(0)** — FIXED by the 2026-08-17 rebase: upstream's
  InlineAdviceContext API returns Result, so a failed memory load now surfaces
  as InlineAdviceError instead of silently becoming limb 0. (Was: latent
  desync once B1 binds the log to the trace.)
- **add() debug_assert!(!carry)** (sdk.rs): drops carry-out in release;
  reachable only via non-canonical inputs (same root as from_canonical).
- **FIELD_OP_LOG thread-local**: correct single-pass for the published
  RESULTS.md counts (verified: usdcx/credits = 3.19× matches the 3.2× op
  ratio; no double-count), but drain-ordering is fragile and a future
  worker-thread tracer would silently under-log. Fix = thread the log through
  ProgramSummary, not a thread_local!.
- **FieldOpRecord::new panics** on malformed logs (assert/expect): fine for an
  honest tracer, a DoS vector for any service building witnesses from
  untrusted logs. Fix = return Result before service use.
- **scalar_mul branches on scalar bits**: leaks Hamming weight / bit-length via
  trace shape. Fine for public scalars; the "branches cost cycles, not privacy"
  comment is an assumption, not a fact, for secret scalars.

Cleared by the review (checked, not exploitable): carry-counter overflow, the
tail LTE-after-ADD wrap checks, spoil_proof unsatisfiability, and the
guest canonicity comparison — all sound.

An internal adversarial review (July 2026, two rounds) confirmed the
arithmetization and carry bounds are sound (|S_k| < 2^175, ~79 bits of margin)
and produced the soundness-requirements list now in the RFC; items 1-8 above
are the prototype-side design manifestations, the list here is the code-side.

## Reproduce
`export CARGO_PROFILE_RELEASE_LTO=off; cargo build --release --bin jolt`
- Numbers: `PATH="$PWD/target/release:$PATH" ./scripts/aleo-scorecard.sh <label>`
  and `cargo run --release -p fqmul-test` (B1 gate at the end).
- Tests: `cargo nextest run -p jolt-inlines-edwards-bls12 --features host`
  and `cargo nextest run -p jolt-prover-legacy field_accel --features host`.
- History: examples/aleo-transfer/{RESULTS.md,FINDINGS.md}; Phase 0 verified
  sequences at tag `phase0-complete`.
