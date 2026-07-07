# Field-Acceleration Prototype (branch aleo/field-accel-prototype)

**Purpose:** evidence for the RFC "prover-side foreign-field acceleration
(guest-declared modulus)" — NOT for merge. Base: fork of a16z/jolt @ b092110.

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

## Reproduce
`export CARGO_PROFILE_RELEASE_LTO=off; cargo build --release --bin jolt`
- Numbers: `PATH="$PWD/target/release:$PATH" ./scripts/aleo-scorecard.sh <label>`
  and `cargo run --release -p fqmul-test` (B1 gate at the end).
- Tests: `cargo nextest run -p jolt-inlines-edwards-bls12 --features host`
  and `cargo nextest run -p jolt-prover-legacy field_accel --features host`.
- History: examples/aleo-transfer/{RESULTS.md,FINDINGS.md}; Phase 0 verified
  sequences at tag `phase0-complete`.
