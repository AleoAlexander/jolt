// Performance model of an Aleo `credits.aleo/transfer_private` client-side
// workload, executed inside a Jolt guest on the edwards-bls12 SDK types
// (advice-backed field ops on branch aleo/field-accel-prototype).
//
// Poseidon2 is the real snarkVM hash: vendored parameters (generated from
// snarkVM by aleo-vectors-gen) used directly as canonical limbs — zero
// Montgomery conversion cost — and the exact sponge convention (state =
// [capacity, rate0, rate1]; preimage = [domain, len, ...inputs]; permute
// between rate-chunks; squeeze rate0 after a final permute). Verified against
// snarkVM-produced vectors in the host test suite.
//
// The record/transition structure is approximated (same op counts as a real
// transfer: 8 full-width scalar mults + 19 Poseidon permutations).

#![cfg_attr(feature = "guest", no_std)]
#![no_main]

mod vendored;

use jolt::{end_cycle_tracking, start_cycle_tracking};
use jolt_inlines_edwards_bls12::sdk::{EdwardsPoint, Fq};

const _: () = assert!(vendored::POSEIDON2_ALPHA == 17, "sbox17 hardcodes alpha = 17");
const _: () = assert!(vendored::POSEIDON2_T == 3, "state layout hardcodes t = 3");

// x^17 = ((((x^2)^2)^2)^2) * x
fn sbox17(x: Fq) -> Fq {
    x.square().square().square().square().mul(&x)
}

fn mds_row(row: &[[u64; 4]; 3], state: &[Fq; 3]) -> Fq {
    let mut acc = Fq::ZERO;
    for (m, s) in row.iter().zip(state.iter()) {
        acc = acc.add(&Fq::from_canonical(*m).mul(s));
    }
    acc
}

pub fn poseidon_perm(state: &mut [Fq; 3]) {
    let full = vendored::POSEIDON2_FULL_ROUNDS;
    let partial = vendored::POSEIDON2_PARTIAL_ROUNDS;
    let partial_range = (full / 2)..(full / 2 + partial);
    for round in 0..(full + partial) {
        for (s, c) in state.iter_mut().zip(vendored::POSEIDON2_ARK[round].iter()) {
            *s = s.add(&Fq::from_canonical(*c));
        }
        if partial_range.contains(&round) {
            state[0] = sbox17(state[0]);
        } else {
            for s in state.iter_mut() {
                *s = sbox17(*s);
            }
        }
        let new_state = [
            mds_row(&vendored::POSEIDON2_MDS[0], state),
            mds_row(&vendored::POSEIDON2_MDS[1], state),
            mds_row(&vendored::POSEIDON2_MDS[2], state),
        ];
        *state = new_state;
    }
}

/// snarkVM `N::hash_psd2`: sponge over state [capacity, rate0, rate1].
pub fn poseidon2_hash(inputs: &[Fq]) -> Fq {
    let mut state = [Fq::ZERO; 3];
    state[1] = state[1].add(&Fq::from_canonical(vendored::POSEIDON2_DOMAIN));
    state[2] = state[2].add(&Fq::from_u64(inputs.len() as u64));
    let mut chunks = inputs.chunks(2).peekable();
    if chunks.peek().is_some() {
        // header chunk is followed by input chunks
        poseidon_perm(&mut state);
        while let Some(chunk) = chunks.next() {
            state[1] = state[1].add(&chunk[0]);
            if chunk.len() == 2 {
                state[2] = state[2].add(&chunk[1]);
            }
            if chunks.peek().is_some() {
                poseidon_perm(&mut state);
            }
        }
    }
    poseidon_perm(&mut state); // absorb -> squeeze transition
    state[1]
}

fn xorshift(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x
}

// Full-width (~250-bit) scalar limbs; masked below the group order so the
// double-and-add walks the real bit-length.
fn full_scalar(s: &mut u64) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for limb in limbs.iter_mut() {
        *limb = xorshift(s);
    }
    limbs[3] &= (1u64 << 58) - 1; // < 2^250 < r
    limbs
}

/// In-guest witness that the vendored Poseidon matches snarkVM: hashes a
/// single field element exactly as `N::hash_psd2(&[input])`.
#[jolt::provable(stack_size = 262144, heap_size = 1048576, max_trace_length = 2097152)]
fn poseidon_hash_bench(input: u64) -> [u64; 4] {
    poseidon2_hash(&[Fq::from_u64(input)]).to_canonical()
}

// Small provable workload: 1 full-width scalar mult + 1 Poseidon perm, for
// end-to-end prover throughput measurement.
#[jolt::provable(stack_size = 262144, heap_size = 1048576, max_trace_length = 2097152)]
fn mult_bench(seed: u64) -> u64 {
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let g = EdwardsPoint::generator();

    let (px, py) = g.scalar_mul(&full_scalar(&mut s)).to_affine();
    let mut state = [Fq::from_canonical(px), Fq::from_canonical(py), Fq::from_u64(2)];
    poseidon_perm(&mut state);
    state[0].add(&state[1]).to_canonical()[0]
}

#[jolt::provable(stack_size = 262144, heap_size = 1048576, max_trace_length = 67108864)]
fn transfer_private(seed: u64) -> u64 {
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let g = EdwardsPoint::generator();

    // "Transaction-supplied" points (sender pk, recipient address, record
    // nonce). Computed outside the markers — the prover receives these, it
    // doesn't compute them.
    let pk = g.scalar_mul(&full_scalar(&mut s));
    let addr_pt = g.scalar_mul(&full_scalar(&mut s));
    let nonce_pt = g.scalar_mul(&full_scalar(&mut s));

    let mut acc = Fq::ZERO;
    let mut state = [Fq::from_u64(seed), Fq::from_u64(1), Fq::from_u64(2)];

    start_cycle_tracking("transfer_total");

    // 1. Input record decryption: view-key ECDH + KDF/decrypt
    start_cycle_tracking("record_decrypt");
    let vk = full_scalar(&mut s);
    let (sx, sy) = nonce_pt.scalar_mul(&vk).to_affine();
    state[0] = state[0].add(&Fq::from_canonical(sx));
    state[1] = state[1].add(&Fq::from_canonical(sy));
    for _ in 0..4 {
        poseidon_perm(&mut state);
    }
    acc = acc.add(&state[0]);
    end_cycle_tracking("record_decrypt");

    // 2. Serial number / nullifier for the consumed record
    start_cycle_tracking("serial_number");
    for _ in 0..2 {
        poseidon_perm(&mut state);
    }
    let (snx, _) = g.scalar_mul(&full_scalar(&mut s)).to_affine();
    acc = acc.add(&Fq::from_canonical(snx)).add(&state[0]);
    end_cycle_tracking("serial_number");

    // 3. Request authorization (Schnorr verify): R' = z*G + e*PK
    start_cycle_tracking("schnorr_verify");
    poseidon_perm(&mut state);
    let e = full_scalar(&mut s);
    let z = full_scalar(&mut s);
    let (rx, _) = g.scalar_mul(&z).add(&pk.scalar_mul(&e)).to_affine();
    acc = acc.add(&Fq::from_canonical(rx));
    end_cycle_tracking("schnorr_verify");

    // 4+5. Two output records: ephemeral key + ECDH, then KDF/encrypt + commitment
    for label in ["output_record_1", "output_record_2"] {
        start_cycle_tracking(label);
        let esk = full_scalar(&mut s);
        let eph = g.scalar_mul(&esk);
        let (ephx, ephy) = eph.to_affine();
        let (sox, _) = addr_pt.scalar_mul(&esk).to_affine();
        state[0] = state[0].add(&Fq::from_canonical(ephx));
        state[1] = state[1].add(&Fq::from_canonical(sox));
        for _ in 0..6 {
            poseidon_perm(&mut state);
        }
        acc = acc.add(&state[0]).add(&Fq::from_canonical(ephy));
        end_cycle_tracking(label);
    }

    end_cycle_tracking("transfer_total");

    acc = acc.add(&state[1]).add(&state[2]);
    acc.to_canonical()[0]
}
