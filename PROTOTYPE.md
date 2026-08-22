# Field-Acceleration Prototype (branch aleo/field-accel-prototype)

**Purpose:** evidence for the RFC "prover-side foreign-field acceleration
(guest-declared modulus)" — NOT for merge. Originally built on a16z/jolt @
b092110; rebased onto upstream main 552ba6192 (2026-08-17) with all gates
re-run green and numbers re-measured (see RESULTS.md `rebase-20260817`).

## What this branch demonstrates
- B0: advice-only field ops (jolt-inlines/edwards-bls12): 41 cyc/op vs 252
  software. (The July "transfer_private 17.59M → 3.09M (5.7x)" figure used
  the withdrawn per-use-reconversion software methodology — see the
  fair-baseline note below; the per-op number is the one that stands.)
- B1: batched non-native-mul sumcheck (crates/jolt-prover-legacy/src/zkvm/
  field_accel/) — superseded by the B2 schema below.
- **B2 (2026-08-18): the SOUND, fully bound gadget.** Guest welds every op
  to its 16-word record block in the committed untrusted-advice region
  (bind.rs; tampered blob ⇒ main proof fails); the gadget proves the
  64-bit-word identity with committed offset carries + 2-bit digit range
  checks, Dory-bound evaluations, and a header-anchored record count
  (bound.rs). Measured: fqmul 87 cyc/op bound (vs 45 unbound / 252
  software); usdcx FAIR-BASELINE numbers (2026-08-22, software twin
  KAT-pinned to the accelerated output, Montgomery constants hoisted the
  way real software keeps them): 48.86M software / 13.95M unbound (3.5x)
  / 19.58M bound (2.5x). Earlier 5.8x/4.3x entries used a software twin
  that re-converted constant tables per use — withdrawn as unfair; the
  per-op 6.1x (252 vs 41 cyc) stands. Bound gadget proves the 46,056-op
  log in ~9.5s, verifies in ~0.15s; mult_bench bound end-to-end (welds + sidecar + commitment
  equality) passes. Composition is a sidecar sharing the main proof's
  advice commitment object — in-pipeline integration is upstream's call
  (RFC question 2).

## B2 status (2026-08-18): the binding gaps are CLOSED

The original unsoundness inventory (kept below for history) is resolved by
the B2 bound design (`field_accel/bound.rs`, `jolt-inlines/edwards-bls12/
src/bind.rs`, spec Rev 3):

1. **Advice results bound**: every field op's (x, y, z) words are welded
   in-circuit (`bind::weld` + `spoil_proof`) to the op's 16-word record
   block in the committed untrusted-advice region; `bind::finalize`
   forbids unwelded tails. Tampered blob ⇒ the MAIN proof fails
   (fqmul-test weld gate, negative verified).
2. **PCS binding**: the gadget's word evaluations are openings of the
   committed `UntrustedAdvice` polynomial; carries/digits are committed
   as one aux polynomial; corner claims collapse to single Dory openings
   via random-point interpolation. No clear final evals remain in the
   bound path.
3. **Range checks**: carries are committed in offset form and
   range-checked by 2-bit-digit columns (validity + recomposition
   constraint families); word ranges are inherited from the committed
   region's byte construction and the RAM-checked weld.
4. Invocation log (host thread-local) is now pass-1 tooling only — the
   proof's witness source is the committed region, never the log.
5. **Transcript ordering**: both commitments are absorbed before τ/α/γ.
6. **Counts**: the record count is derived from the region's own header
   word (opened at the all-zero point) under the same pad rule the guest
   enforces — no trusted num_records/log_n/offsets.
7. Division b = 0 cannot reach the gadget: the guest spoils on
   division-by-zero before welding (sdk.rs), so no valid proof contains
   a zero-divisor record.

The commitment bridge lives in the library:
`verify_field_accel_bound_bridged` checks the sidecar's advice commitment
equals the main proof's `untrusted_advice_commitment` before verifying the
gadget — integrators use that entry point, not a hand-rolled equality.

Measurement note: guests built with the `field-accel-bind` feature pay a
~4 cyc/op no-op weld check even when unbound (fqmul unbound reads 45
cyc/op under the feature vs 41 clean). The AUTHORITATIVE unbound usdcx
number is the fair-baseline 13.95M (feature-on, same binary as the other
columns); older 14.56M feature-off entries predate the build-time
constant tables and are superseded.

Still open, explicitly: non-ZK only (no BlindFold sync), no Akita path,
and the SIDECAR COMPOSITION — the gadget proof shares the main proof's
advice commitment object but not its transcript; in-pipeline integration
(shared transcript, stage-8 batched openings) is upstream's design call
(RFC question 2). Guest-side canonicity posture unchanged (below).

## Deferred from the Aug 21 code review (recorded, not fixed)

An 8-angle adversarial code review (36 candidates, 10 verified findings)
confirmed the B2 cryptography sound and its findings were fixed at
891cabae0, except these five, each deferred with cause:

1. **Curve-agnostic weld module.** bind.rs is modulus-generic but lives in
   the edwards-bls12 crate with singleton static-mut state: a second
   accelerated curve would copy-paste it, and one guest can never weld two
   accelerated fields (interleaved block streams). Fix = a per-stream bind
   module in jolt-inlines-sdk — API design work owed to the in-pipeline
   integration, needed only when a second curve exists.
2. **Shared blob-schema module.** The record-blob wire format (varint
   header, pad rule, 128-byte blocks) has four hand-written
   implementations: guest (bind.rs), host encoder (sequence_builder.rs),
   prover/verifier parser (bound.rs), test encoder. A schema change must
   hit all four or guest and verifier silently disagree. Fix = one shared
   no_std schema crate spanning guest and prover sides — a new common
   dependency that in-pipeline integration may obsolete (the blob format
   itself disappears under cycle-indexed binding).
3. **Sumcheck/eq dedup.** zero_check_verify and eq_at re-implement
   ClearSumcheckProof::verify / EqPolynomial::mle. Swapping them changes
   transcript byte-sequences (compressed round polys, challenge
   derivation) for zero functional gain now; do it when the gadget adopts
   the shared sumcheck infrastructure during integration.
4. **Vendored-MSM thread churn.** The arkworks fork builds a thread pool
   PER MSM CHUNK and pool drops don't join threads — at 2^24-element
   commitments the churn outruns thread reaping and hits the OS cap
   (EAGAIN). pcs_pool here is a caller-side cap (2 threads, 64 MB stacks)
   that leaves commitment throughput on the table; the real fix belongs in
   the vendored MSM (use the ambient pool) and should be reported
   upstream — it bites any large-commitment caller.
5. **Feature-split baselines.** field-accel-bind compiles a ~4 cyc/op
   no-op weld check into unbound guests (see Measurement note above).
   A clean fix needs per-provable-fn feature control the #[jolt::provable]
   macro doesn't offer. Since the fair-baseline correction, the RFC's
   headline row is measured feature-ON in one binary (the authoritative
   13.95M unbound number carries the ~4 cyc/op tax and is reported as
   such); this item now covers only the residual tax, not the baseline
   methodology.

## Historical inventory (pre-B2, resolved as described above)
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
- **from_canonical uses debug_assert** — FIXED (2026-08-22): the
  constructor now spoils (guest) / panics (host) on non-canonical limbs
  and Fq's Deserialize validates, making canonicity a type invariant.
  (History: the debug-only check let release builds construct e >= q,
  with per-method divergent behavior — see the add() entry.)
- **load_fq ...unwrap_or(0)** — FIXED by the 2026-08-17 rebase: upstream's
  InlineAdviceContext API returns Result, so a failed memory load now surfaces
  as InlineAdviceError instead of silently becoming limb 0. (Was: latent
  desync once B1 binds the log to the trace.)
- **add() debug_assert!(!carry)** (sdk.rs): drops carry-out in release;
  reachable only via non-canonical inputs. RESOLVED at the root
  (2026-08-22): from_canonical now spoils/panics on non-canonical limbs
  and Deserialize validates, so no code past construction can observe a
  non-canonical Fq — the per-method divergence family (div/inverse
  spoils, silent add/sub corruption, host-vs-guest reduction) is closed
  at one choke point. Raw-.insn guests bypassing the SDK remain outside
  this invariant AND outside the weld (they never call bind::init, so
  weld/finalize are no-ops): the raw-insn surface is unprotected by B2
  by construction; closing it means load_fq rejecting non-canonical
  limbs for all three ops (see sequence_builder.rs's DIVQ comment).
- **FIELD_OP_LOG thread-local**: correct single-pass for the published
  RESULTS.md counts (verified: usdcx/credits = 3.19× matches the 3.2× op
  ratio; no double-count), but drain-ordering is fragile and a future
  worker-thread tracer would silently under-log. Fix = thread the log through
  ProgramSummary, not a thread_local!. B2 note: the log is now pass-1
  blob-building tooling only — proof soundness no longer depends on it
  (an under-logged blob simply fails the weld, spoiling the proof).
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
  and `cargo nextest run -p jolt-prover-legacy field_accel --features host`
  (includes the B2 bound roundtrip + negative suite: tampered corners,
  forged header count, wrong commitment, false record).
- B2 e2e gates: `cargo run --release -p fqmul-test` (weld gate + bound
  gate + negatives) and the aleo-transfer run (usdcx bound cycles,
  transfer-scale bound gadget, mult_bench bound e2e).
- History: examples/aleo-transfer/{RESULTS.md,FINDINGS.md}; Phase 0 verified
  sequences at tag `phase0-complete`.
