// Performance model of an Aleo `credits.aleo/transfer_private` client-side
// workload, executed as pure software inside a Jolt guest.
//
// This is NOT cryptographically valid Aleo code: Poseidon round constants and
// the MDS matrix are pseudo-random junk, and the record structure is
// approximated. It IS arithmetically faithful: the same curve
// (twisted Edwards over the BLS12-377 scalar field, i.e. Aleo's Edwards-BLS12),
// full-width (251-bit) scalar multiplications, and Poseidon permutations with
// snarkVM's shape for this field (width 3, alpha = 17, 8 full + 31 partial
// rounds). Montgomery field arithmetic is data-independent, so junk constants
// cost the same cycles as real ones.
//
// Modeled workload (all inside cycle markers):
//   record_decrypt   1 var-base scalar mult (view-key ECDH) + 4 Poseidon perms
//   serial_number    1 scalar mult + 2 perms
//   schnorr_verify   2 scalar mults + 1 perm (request authorization)
//   output_record x2 2 scalar mults (ephemeral + ECDH) + 6 perms each
// Total: 8 full-width scalar mults, 19 Poseidon permutations.

#![cfg_attr(feature = "guest", no_std)]
#![no_main]

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::fields::Field;
use ark_ff::PrimeField;
use jolt::{end_cycle_tracking, start_cycle_tracking};

use ark_ed_on_bls12_377::{EdwardsProjective, Fq, Fr};

const T: usize = 3;
const R_F: usize = 8;
const R_P: usize = 31;
const N_ROUNDS: usize = R_F + R_P;

struct PoseidonParams {
    rc: [[Fq; T]; N_ROUNDS],
    mds: [[Fq; T]; T],
}

fn xorshift(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x
}

fn gen_params(seed: u64) -> PoseidonParams {
    let mut s = seed | 1;
    let mut rc = [[Fq::from(0u64); T]; N_ROUNDS];
    for round in rc.iter_mut() {
        for c in round.iter_mut() {
            *c = Fq::from(xorshift(&mut s));
        }
    }
    let mut mds = [[Fq::from(0u64); T]; T];
    for row in mds.iter_mut() {
        for c in row.iter_mut() {
            *c = Fq::from(xorshift(&mut s));
        }
    }
    PoseidonParams { rc, mds }
}

// x^17 = ((((x^2)^2)^2)^2) * x — 4 squarings + 1 mul, snarkVM's alpha for this field
fn sbox17(x: Fq) -> Fq {
    let x2 = x.square();
    let x4 = x2.square();
    let x8 = x4.square();
    let x16 = x8.square();
    x16 * x
}

fn mds_mul(state: &mut [Fq; T], mds: &[[Fq; T]; T]) {
    let mut out = [Fq::from(0u64); T];
    for (i, row) in mds.iter().enumerate() {
        let mut acc = Fq::from(0u64);
        for (j, m) in row.iter().enumerate() {
            acc += *m * state[j];
        }
        out[i] = acc;
    }
    *state = out;
}

fn poseidon_perm(state: &mut [Fq; T], p: &PoseidonParams) {
    let half = R_F / 2;
    let mut round = 0;
    for _ in 0..half {
        for (x, c) in state.iter_mut().zip(p.rc[round].iter()) {
            *x += c;
        }
        for x in state.iter_mut() {
            *x = sbox17(*x);
        }
        mds_mul(state, &p.mds);
        round += 1;
    }
    for _ in 0..R_P {
        for (x, c) in state.iter_mut().zip(p.rc[round].iter()) {
            *x += c;
        }
        state[0] = sbox17(state[0]);
        mds_mul(state, &p.mds);
        round += 1;
    }
    for _ in 0..half {
        for (x, c) in state.iter_mut().zip(p.rc[round].iter()) {
            *x += c;
        }
        for x in state.iter_mut() {
            *x = sbox17(*x);
        }
        mds_mul(state, &p.mds);
        round += 1;
    }
}

// Full-width (mod-order) scalar, so scalar mults cost the real ~251 bits.
fn full_scalar(s: &mut u64) -> Fr {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&xorshift(s).to_le_bytes());
    }
    Fr::from_le_bytes_mod_order(&bytes)
}

// Small provable workload (~1.5M cycles): 1 full-width scalar mult + 1 Poseidon
// perm. Sized so an end-to-end proof fits in laptop RAM, to measure real prover
// throughput and extrapolate to the full transfer.
#[jolt::provable(stack_size = 262144, heap_size = 1048576, max_trace_length = 2097152)]
fn mult_bench(seed: u64) -> u64 {
    let params = gen_params(seed);
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let g = EdwardsProjective::generator();

    let p = (g * full_scalar(&mut s)).into_affine();
    let mut state = [p.x, p.y, Fq::from(2u64)];
    poseidon_perm(&mut state, &params);
    (state[0] + state[1]).into_bigint().0[0]
}

#[jolt::provable(stack_size = 262144, heap_size = 1048576, max_trace_length = 67108864)]
fn transfer_private(seed: u64) -> u64 {
    let params = gen_params(seed);
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let g = EdwardsProjective::generator();

    // "Transaction-supplied" points (sender pk, recipient address, record
    // nonce). Computed outside the markers — the prover receives these, it
    // doesn't compute them.
    let pk = g * full_scalar(&mut s);
    let addr_pt = g * full_scalar(&mut s);
    let nonce_pt = g * full_scalar(&mut s);

    let mut acc = Fq::from(0u64);
    let mut state = [Fq::from(seed), Fq::from(1u64), Fq::from(2u64)];

    start_cycle_tracking("transfer_total");

    // 1. Input record decryption: view-key ECDH + KDF/decrypt (~3 ciphertext field elements)
    start_cycle_tracking("record_decrypt");
    let vk = full_scalar(&mut s);
    let shared = (nonce_pt * vk).into_affine();
    state[0] += shared.x;
    state[1] += shared.y;
    for _ in 0..4 {
        poseidon_perm(&mut state, &params);
    }
    acc += state[0];
    end_cycle_tracking("record_decrypt");

    // 2. Serial number / nullifier for the consumed record
    start_cycle_tracking("serial_number");
    for _ in 0..2 {
        poseidon_perm(&mut state, &params);
    }
    let sn_pt = (g * full_scalar(&mut s)).into_affine();
    acc += sn_pt.x + state[0];
    end_cycle_tracking("serial_number");

    // 3. Request authorization (Schnorr verify): R' = z*G + e*PK
    start_cycle_tracking("schnorr_verify");
    poseidon_perm(&mut state, &params);
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
            poseidon_perm(&mut state, &params);
        }
        acc += state[0] + eph.y;
        end_cycle_tracking(label);
    }

    end_cycle_tracking("transfer_total");

    acc += state[1] + state[2];
    acc.into_bigint().0[0]
}
