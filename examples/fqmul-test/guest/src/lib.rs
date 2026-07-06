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

/// Control: identical chain in pure-software arkworks, for an honest
/// like-for-like cycles/op comparison against the inline path.
#[jolt::provable(stack_size = 131072, heap_size = 262144, max_trace_length = 4194304)]
fn ark_chain(seed: u64) -> [u64; 4] {
    use ark_ff::{BigInt, Field, PrimeField};
    let three = ark_ed_on_bls12_377::Fq::new(BigInt::new([3, 0, 0, 0]));
    let mut x = ark_ed_on_bls12_377::Fq::new(BigInt::new([seed, 0, 0, 0]));
    for _ in 0..500 {
        x = x.square() * three;
    }
    x.into_bigint().0
}
