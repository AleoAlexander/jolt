## baseline-plain — 2026-07-06 — 7dc159e3
```
"record_decrypt": 2788874 RV64IMAC cycles + 43127 virtual instructions = 2832001 total cycles
"serial_number": 2026410 RV64IMAC cycles + 29347 virtual instructions = 2055757 total cycles
"schnorr_verify": 2830445 RV64IMAC cycles + 31878 virtual instructions = 2862323 total cycles
"output_record_1": 4898137 RV64IMAC cycles + 70949 virtual instructions = 4969086 total cycles
"output_record_2": 4801818 RV64IMAC cycles + 70180 virtual instructions = 4871998 total cycles
"transfer_total": 17345748 RV64IMAC cycles + 245481 virtual instructions = 17591229 total cycles
total trace length (cycles): 21204400
trace length (cycles): 1697589
2026-07-06T18:57:36.593300Z  INFO jolt_prover_legacy::zkvm::prover: 1674734 raw RISC-V instructions + 22855 virtual instructions = 1697589 total cycles
prover time: 9.54s  (177980 cycles/s)
proof size: 90303 bytes
verify time: 0.085s, valid: true
4790091776  maximum resident set size
```

## baseline-field-inline — 2026-07-06 — 7dc159e3 — features: guest/field-inline
```
"record_decrypt": 2788874 RV64IMAC cycles + 43127 virtual instructions = 2832001 total cycles
"serial_number": 2026410 RV64IMAC cycles + 29347 virtual instructions = 2055757 total cycles
"schnorr_verify": 2830445 RV64IMAC cycles + 31878 virtual instructions = 2862323 total cycles
"output_record_1": 4898137 RV64IMAC cycles + 70949 virtual instructions = 4969086 total cycles
"output_record_2": 4801818 RV64IMAC cycles + 70180 virtual instructions = 4871998 total cycles
"transfer_total": 17345748 RV64IMAC cycles + 245481 virtual instructions = 17591229 total cycles
total trace length (cycles): 21204400
trace length (cycles): 1697589
2026-07-06T18:58:42.860428Z  INFO jolt_prover_legacy::zkvm::prover: 1674734 raw RISC-V instructions + 22855 virtual instructions = 1697589 total cycles
prover time: 10.54s  (161120 cycles/s)
proof size: 90303 bytes
verify time: 0.083s, valid: true
4979113984  maximum resident set size
```

**Finding (baseline-field-inline):** identical trace length to baseline-plain (21,204,400).
The SDK's `field-inline` feature does not engage for `ark-ed-on-bls12-377` guest code
(BN254-oriented; the guest build via the jolt CLI compiles without it — see the
`unexpected cfg` warning). Approach-3 ceiling for Aleo primitives is therefore zero:
a dedicated edwards-bls12 inline crate is the only path to the ≤4M target.

## control-experiment — 2026-07-06 — inline vs a16z-optimized arkworks
```
fqmul_chain (EDBLS inline):   310,464 cycles / 1000 field ops = 310 cycles/op
ark_chain (software control): 252,714 cycles / 1000 field ops = 252 cycles/op
inline "speedup": 0.81x  (the inline is 19% SLOWER)
```
**Finding:** the advice-quotient inline pattern does not pay for a 253-bit modulus.
The verification identity ab + wp = 2^256*w + c requires the full 4x4 w*p product
(32 limb products) on top of a*b (32 products) = 64 products per op. secp256k1's
inline wins only because its negated modulus is 1-2 limbs (~40 products total vs
Montgomery's ~48). The a16z arkworks fork (dev/twist-shout) already emits
well-scheduled ~252-cycle CIOS Montgomery mults on RV64. Verified foreign-field
mul at 253 bits is instruction-count-parity with direct computation; no
sequence-level trick changes this. Reaching >=5x per-op requires prover-side
support (dedicated lookups / field-inline-style acceleration for this field) —
upstream-collaboration scope, not fork-only scope.
## B0-advice-only — 2026-07-07 — 1cbe251a
```
"record_decrypt": 427452 RV64IMAC cycles + 44560 virtual instructions = 472012 total cycles
"serial_number": 333802 RV64IMAC cycles + 35440 virtual instructions = 369242 total cycles
"schnorr_verify": 491481 RV64IMAC cycles + 54152 virtual instructions = 545633 total cycles
"output_record_1": 769389 RV64IMAC cycles + 80752 virtual instructions = 850141 total cycles
"output_record_2": 768665 RV64IMAC cycles + 80896 virtual instructions = 849561 total cycles
"transfer_total": 2790819 RV64IMAC cycles + 295800 virtual instructions = 3086619 total cycles
total trace length (cycles): 3848359
trace length (cycles): 305808
2026-07-07T15:01:09.741958Z  INFO jolt_prover_legacy::zkvm::prover: 275556 raw RISC-V instructions + 30252 virtual instructions = 305808 total cycles
prover time: 2.99s  (102284 cycles/s)
proof size: 85905 bytes
verify time: 0.074s, valid: true
1749630976  maximum resident set size
```

**B0 gate analysis (3.086M vs the ≤3M criterion, +2.9%):** the field-op-share
assumption held — the 5.7x reduction matches the 1.5-3M projection band. The
overage is attributable, not structural: (a) the SDK wrapper costs ~41
cycles/op, of which ~16 is the canonicity comparison after every advice op —
a batched-check or trusted-advice design cuts this; (b) scalar mult is plain
double-and-add (~375 point ops); a 4-bit window removes ~90 adds/mult. Both
are Track C design choices, not prototype blockers. mult_bench proof: 306K
cycles, 2.99s prove, 1.75GB RSS (was 5.3GB), 85.9KB proof, 74ms verify.
## B1-gadget — 2026-07-07 — field-accel prototype complete
```
transfer_private trace:        3,086,619 cycles (B0, unchanged)
field-accel invocation log:    46,056 records
gadget sumcheck prove:         0.179 s
gadget sumcheck verify:        <0.1 ms
mult_bench main proof:         2.99 s / 85,905 B / 73 ms verify / 1.75 GB RSS
```
**B1 summary:** the verification work removed from the trace (46K ops x ~269
cycles = ~12.4M cycles = ~2 minutes of proving at measured throughput) is
performed by one batched sumcheck in 0.179 s — a ~700x reduction for the
verification portion, at ~4 microseconds per field op. Final evals are clear
(unbound); PCS binding, range checks (CARRY_BOUNDS.md), and BlindFold sync
are Track C. Tamper tests confirm the gadget rejects corrupted logs.
## usdcx-model — 2026-07-07 — usdcx_stablecoin.aleo transfer_private (B0 advice mode)
```
usdcx_total:            12,927,849 cycles   (vs 3,086,619 credits-model)
  merkle_proofs:         8,962,739 cycles   (69% — 2 x 16-level psd4 proofs, 68 t=5 perms)
  record_decrypt:          474,931
  output_token_1/2 + output_compliance: ~2.5M (3 records vs 2)
field-accel gadget:     146,766 records, prove 0.687s
poseidon4 (t=5, rate 4): vendored from snarkVM, vector-exact vs hash_psd4
```
**Findings:** modeled from the on-chain program source: usdcx consumes 1 Token
record, verifies TWO 16-level Merkle proofs in-circuit (hash.psd4), and emits
THREE records. Even advice-accelerated it is 4.2x a plain credits transfer,
and Merkle compliance checking dominates (t=5 perm ≈ 132K cycles ≈ 3,200 field
ops). Software-only extrapolation (x~6 per field op): ~70M cycles. The gadget
absorbs the 3.2x-larger invocation log (147K vs 46K records) in 0.69s.
Implication: compliant-stablecoin workloads strengthen the field-acceleration
case — they are ~4x heavier than credits transfers, almost entirely in
Poseidon hashing.
## usdcx-soft-direct — 2026-07-07 — software baseline measured (same binary)
```
usdcx_transfer_private (software, ark):   84,354,251 cycles  (merkle: 61,621,175)
usdcx_transfer_private (advice-backed):   14,558,905 cycles  (merkle:  8,962,739)
field acceleration factor:                5.8x   (merkle component: 6.9x)
```
Note: adding the ark software twin to the guest binary shifted the SDK-path
total from 12.93M to 14.56M (codegen/inlining differences only — virtual
instruction count identical); the 5.8x compares both paths in one binary.
The earlier 3.4x "linear floor" estimate was too conservative: real software
carries per-constant Montgomery conversions the per-op model misses. Measured
factor matches the credits transfer's 5.7x almost exactly.
