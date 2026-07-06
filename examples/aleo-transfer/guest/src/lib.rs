// Performance model of an Aleo `credits.aleo/transfer_private` client-side
// workload, executed as pure software inside a Jolt guest.
//
// Poseidon2 here is the real snarkVM hash: vendored parameters (ARK/MDS/domain
// generated from snarkVM by aleo-vectors-gen) and the exact sponge convention
// (state = [capacity, rate0, rate1]; preimage = [domain, len, ...inputs];
// permute between rate-chunks; squeeze rate0 after a final permute). Verified
// against snarkVM-produced vectors in the host test suite.
//
// The record/transition structure is still approximated (same op counts as a
// real transfer: 8 full-width scalar mults + 19 Poseidon permutations), so
// cycle totals are representative, not consensus-accurate.

#![cfg_attr(feature = "guest", no_std)]
#![no_main]

mod vendored;

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::fields::Field;
use ark_ff::{BigInt, PrimeField, Zero};
use jolt::{end_cycle_tracking, start_cycle_tracking};

use ark_ed_on_bls12_377::{EdwardsProjective, Fq, Fr};

const _: () = assert!(vendored::POSEIDON2_ALPHA == 17, "sbox17 hardcodes alpha = 17");
const _: () = assert!(vendored::POSEIDON2_T == 3, "state layout hardcodes t = 3");

pub fn fq_from_limbs(limbs: &[u64; 4]) -> Fq {
    Fq::from_bigint(BigInt::new(*limbs)).expect("vendored constant exceeds modulus")
}

// x^17 = ((((x^2)^2)^2)^2) * x
fn sbox17(x: Fq) -> Fq {
    let x2 = x.square();
    let x4 = x2.square();
    let x8 = x4.square();
    let x16 = x8.square();
    x16 * x
}

fn mds_row(row: &[[u64; 4]; 3], state: &[Fq; 3]) -> Fq {
    let mut acc = Fq::zero();
    for (m, s) in row.iter().zip(state.iter()) {
        acc += fq_from_limbs(m) * s;
    }
    acc
}

pub fn poseidon_perm(state: &mut [Fq; 3]) {
    let full = vendored::POSEIDON2_FULL_ROUNDS;
    let partial = vendored::POSEIDON2_PARTIAL_ROUNDS;
    let partial_range = (full / 2)..(full / 2 + partial);
    for round in 0..(full + partial) {
        for (s, c) in state.iter_mut().zip(vendored::POSEIDON2_ARK[round].iter()) {
            *s += fq_from_limbs(c);
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
    let mut state = [Fq::zero(); 3];
    state[1] += fq_from_limbs(&vendored::POSEIDON2_DOMAIN);
    state[2] += Fq::from(inputs.len() as u64);
    let mut chunks = inputs.chunks(2).peekable();
    if chunks.peek().is_some() {
        // header chunk is followed by input chunks
        poseidon_perm(&mut state);
        while let Some(chunk) = chunks.next() {
            state[1] += chunk[0];
            if chunk.len() == 2 {
                state[2] += chunk[1];
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

// Full-width (mod-order) scalar, so scalar mults cost the real ~251 bits.
fn full_scalar(s: &mut u64) -> Fr {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&xorshift(s).to_le_bytes());
    }
    Fr::from_le_bytes_mod_order(&bytes)
}

/// In-guest witness that the vendored Poseidon matches snarkVM: hashes a
/// single field element exactly as `N::hash_psd2(&[input])`.
#[jolt::provable(stack_size = 262144, heap_size = 1048576, max_trace_length = 2097152)]
fn poseidon_hash_bench(input: u64) -> [u64; 4] {
    let out = poseidon2_hash(&[Fq::from(input)]);
    out.into_bigint().0
}

// Small provable workload (~1.5M cycles): 1 full-width scalar mult + 1 Poseidon
// perm. Sized so an end-to-end proof fits in laptop RAM, to measure real prover
// throughput and extrapolate to the full transfer.
#[jolt::provable(stack_size = 262144, heap_size = 1048576, max_trace_length = 2097152)]
fn mult_bench(seed: u64) -> u64 {
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let g = EdwardsProjective::generator();

    let p = (g * full_scalar(&mut s)).into_affine();
    let mut state = [p.x, p.y, Fq::from(2u64)];
    poseidon_perm(&mut state);
    (state[0] + state[1]).into_bigint().0[0]
}

#[jolt::provable(stack_size = 262144, heap_size = 1048576, max_trace_length = 67108864)]
fn transfer_private(seed: u64) -> u64 {
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let g = EdwardsProjective::generator();

    // "Transaction-supplied" points (sender pk, recipient address, record
    // nonce). Computed outside the markers — the prover receives these, it
    // doesn't compute them.
    let pk = g * full_scalar(&mut s);
    let addr_pt = g * full_scalar(&mut s);
    let nonce_pt = g * full_scalar(&mut s);

    let mut acc = Fq::zero();
    let mut state = [Fq::from(seed), Fq::from(1u64), Fq::from(2u64)];

    start_cycle_tracking("transfer_total");

    // 1. Input record decryption: view-key ECDH + KDF/decrypt (~3 ciphertext field elements)
    start_cycle_tracking("record_decrypt");
    let vk = full_scalar(&mut s);
    let shared = (nonce_pt * vk).into_affine();
    state[0] += shared.x;
    state[1] += shared.y;
    for _ in 0..4 {
        poseidon_perm(&mut state);
    }
    acc += state[0];
    end_cycle_tracking("record_decrypt");

    // 2. Serial number / nullifier for the consumed record
    start_cycle_tracking("serial_number");
    for _ in 0..2 {
        poseidon_perm(&mut state);
    }
    let sn_pt = (g * full_scalar(&mut s)).into_affine();
    acc += sn_pt.x + state[0];
    end_cycle_tracking("serial_number");

    // 3. Request authorization (Schnorr verify): R' = z*G + e*PK
    start_cycle_tracking("schnorr_verify");
    poseidon_perm(&mut state);
    let e = full_scalar(&mut s);
    let z = full_scalar(&mut s);
    let r_prime = (g * z + pk * e).into_affine();
    acc += r_prime.x;
    end_cycle_tracking("schnorr_verify");

    // 4+5. Two output records: ephemeral key + ECDH, then KDF/encrypt + commitment
    for label in ["output_record_1", "output_record_2"] {
        start_cycle_tracking(label);
        let esk = full_scalar(&mut s);
        let eph = (g * esk).into_affine();
        let shared_out = (addr_pt * esk).into_affine();
        state[0] += eph.x;
        state[1] += shared_out.x;
        for _ in 0..6 {
            poseidon_perm(&mut state);
        }
        acc += state[0] + eph.y;
        end_cycle_tracking(label);
    }

    end_cycle_tracking("transfer_total");

    acc += state[1] + state[2];
    acc.into_bigint().0[0]
}
