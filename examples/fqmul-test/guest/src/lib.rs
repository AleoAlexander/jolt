//! Toy guest exercising the edwards-bls12 FQMUL/FQSQR inlines: the M3
//! prove+verify gate for the Phase 0 inline work.

#![cfg_attr(feature = "guest", no_std)]
#![no_main]

use jolt_inlines_edwards_bls12::sdk::Fq;

/// 500 iterations of x = x^2 * 3 — 1000 inline field ops.
#[jolt::provable(stack_size = 131072, heap_size = 262144, max_trace_length = 524288)]
fn fqmul_chain(seed: u64) -> [u64; 4] {
    let three = Fq::from_u64(3);
    let mut x = Fq::from_u64(seed);
    for _ in 0..500 {
        x = x.square().mul(&three);
    }
    x.to_canonical()
}
