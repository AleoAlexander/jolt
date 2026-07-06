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

