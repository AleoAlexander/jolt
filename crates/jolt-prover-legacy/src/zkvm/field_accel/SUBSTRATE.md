# B2 substrate verification (plan Task 1)

Facts verified against branch HEAD (post-552ba6192 rebase), with citations.

## (a) What is committed, and how

- `UntrustedAdvice` the committed polynomial is built from
  `program_io.untrusted_advice` — the **untrusted-advice input region**
  of guest memory — NOT from the tracer's advice tape
  (`zkvm/prover.rs:822-846`): `populate_memory_states` packs the byte
  blob into u64 words in order, `MultilinearPolynomial::from(words)`,
  Dory-committed and absorbed into the transcript in the preamble
  (`append_serializable(b"untrusted_advice", ...)`). **Word k of the
  region is multilinear index k** — the 16-word block layout maps
  directly onto the low 4 index bits.
- The per-cycle `VirtualAdvice`/`AdviceLD` values come from the tracer's
  FIFO tape (`tracer/src/emulator/cpu.rs:17-90`,
  `tracer/src/instruction/advice_ld.rs`) and are **free witness** —
  nothing commits the tape. The Rev 2 assumption that the tape is the
  committed polynomial was FALSE; design revised (spec Rev 3).
- Guest reads of the region are ordinary RAM loads at
  `memory_layout.untrusted_advice_start + offset`
  (`common/src/jolt_device.rs:145,170`); region contents enter RAM
  initial state, tied to the committed polynomial via the stage-6
  advice claim reduction (`zkvm/prover.rs:2181,2211`; cf.
  `ram::reconstruct_full_eval` note in CLAUDE.md).

## (b) The weld primitive

- `jolt_platform::spoil_proof()` (`jolt-platform/src/spoil.rs:5-20`)
  emits the B-format assert opcode 0x5B/funct3 001 with rs1=0,rs2=1 and
  imm≠0: the tracer warns and continues (`virtual_assert_eq.rs` exec,
  spoil branch), the proof becomes unsatisfiable. Established guest
  pattern: `jolt-inlines/edwards-bls12/src/sdk.rs:133,153,207`.
- Therefore the operand weld is **ordinary guest code** (load region
  word, compare, `spoil_proof()` on mismatch) — no inline-sequence
  changes, no new virtual instructions, register budget moot.

## (c) Opening accumulator / SumcheckId

- Stage-7 claim reductions append precommitted-polynomial openings via
  `ProverOpeningAccumulator` with a `SumcheckId`
  (`claim_reductions/advice.rs` imports; `zkvm/prover.rs:2211,2339`
  route `CommittedPolynomial::UntrustedAdvice` claims into the stage-8
  batch, with `opening_proof_hints` at `prover.rs:486`). Task 4 adds
  `SumcheckId::FieldAccel` and appends (i) the single UntrustedAdvice
  claim at `(ρ ‖ r_row)` and (ii) the gadget aux-column claims. Exact
  append call signatures to be lifted from `advice.rs` at Task 4 start.

## (d) Register budget

- Moot — no inline-sequence changes (see (b)).

## (e) Prover access at stage 7.5

- `self.advice.untrusted_advice_polynomial: Option<MultilinearPolynomial>`
  is populated at commitment time (`prover.rs:842`) and available
  through stage 8. The gadget witness (carries/digits) derives from the
  same region words.

## Two-pass flow

- Upstream's `#[jolt::advice]` macro is dual-build: `compute_advice`
  feature executes the body and writes the tape; without it, reads
  (`jolt-sdk/macros/src/lib.rs:1425+`). Our record-blob flow mirrors
  this: pass 1 = collect build (weld disabled, thread-local log as
  today) produces the blob; pass 2 = the proven guest takes the blob as
  an `UntrustedAdvice<T>`-marked input (`jolt-sdk/src/lib.rs:191`) and
  always welds. Only the pass-2 bytecode matters for soundness, and it
  welds unconditionally.
