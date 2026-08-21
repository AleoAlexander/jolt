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

const _: () = assert!(
    vendored::POSEIDON2_ALPHA == 17,
    "sbox17 hardcodes alpha = 17"
);
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
fn mult_bench_body(seed: u64) -> u64 {
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let g = EdwardsPoint::generator();

    let (px, py) = g.scalar_mul(&full_scalar(&mut s)).to_affine();
    let mut state = [
        Fq::from_canonical(px),
        Fq::from_canonical(py),
        Fq::from_u64(2),
    ];
    poseidon_perm(&mut state);
    state[0].add(&state[1]).to_canonical()[0]
}

#[jolt::provable(stack_size = 262144, heap_size = 1048576, max_trace_length = 2097152)]
fn mult_bench(seed: u64) -> u64 {
    mult_bench_body(seed)
}

/// B2 bound variant: every field op welded to its record block in the
/// committed untrusted-advice region.
#[jolt::provable(
    stack_size = 262144,
    heap_size = 1048576,
    max_trace_length = 2097152,
    max_untrusted_advice_size = 1048576
)]
fn mult_bench_bound(seed: u64, records: jolt::UntrustedAdvice<&[u8]>) -> u64 {
    jolt_inlines_edwards_bls12::bind::init(&records);
    let out = mult_bench_body(seed);
    jolt_inlines_edwards_bls12::bind::finalize();
    out
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

// --- usdcx_stablecoin.aleo transfer_private model ---------------------------
//
// Modeled from the on-chain program source (fetched 2026-07-07): consumes one
// Token record, verifies TWO 16-level Merkle proofs in-circuit via hash.psd4
// (Poseidon rate 4, t = 5), and produces THREE records (two Token + one
// ComplianceRecord with 4 fields). Same modeling fidelity as transfer_private:
// faithful op counts and real snarkVM parameters, approximated structure.

mod vendored4;

const _: () = assert!(
    vendored4::POSEIDON4_ALPHA == 17,
    "sbox17_5 hardcodes alpha = 17"
);
const _: () = assert!(vendored4::POSEIDON4_T == 5, "state layout hardcodes t = 5");

fn sbox17_5(x: Fq) -> Fq {
    x.square().square().square().square().mul(&x)
}

fn mds_row5(row: &[[u64; 4]; 5], state: &[Fq; 5]) -> Fq {
    let mut acc = Fq::ZERO;
    for (m, s) in row.iter().zip(state.iter()) {
        acc = acc.add(&Fq::from_canonical(*m).mul(s));
    }
    acc
}

pub fn poseidon4_perm(state: &mut [Fq; 5]) {
    let full = vendored4::POSEIDON4_FULL_ROUNDS;
    let partial = vendored4::POSEIDON4_PARTIAL_ROUNDS;
    let partial_range = (full / 2)..(full / 2 + partial);
    for round in 0..(full + partial) {
        for (s, c) in state.iter_mut().zip(vendored4::POSEIDON4_ARK[round].iter()) {
            *s = s.add(&Fq::from_canonical(*c));
        }
        if partial_range.contains(&round) {
            state[0] = sbox17_5(state[0]);
        } else {
            for s in state.iter_mut() {
                *s = sbox17_5(*s);
            }
        }
        let new_state = [
            mds_row5(&vendored4::POSEIDON4_MDS[0], state),
            mds_row5(&vendored4::POSEIDON4_MDS[1], state),
            mds_row5(&vendored4::POSEIDON4_MDS[2], state),
            mds_row5(&vendored4::POSEIDON4_MDS[3], state),
            mds_row5(&vendored4::POSEIDON4_MDS[4], state),
        ];
        *state = new_state;
    }
}

/// snarkVM `N::hash_psd4`: rate-4 sponge, state [capacity, rate0..rate3].
pub fn poseidon4_hash(inputs: &[Fq]) -> Fq {
    let mut state = [Fq::ZERO; 5];
    state[1] = state[1].add(&Fq::from_canonical(vendored4::POSEIDON4_DOMAIN));
    state[2] = state[2].add(&Fq::from_u64(inputs.len() as u64));
    let mut chunks = inputs.chunks(4).peekable();
    if chunks.peek().is_some() {
        poseidon4_perm(&mut state);
        while let Some(chunk) = chunks.next() {
            for (i, v) in chunk.iter().enumerate() {
                state[1 + i] = state[1 + i].add(v);
            }
            if chunks.peek().is_some() {
                poseidon4_perm(&mut state);
            }
        }
    }
    poseidon4_perm(&mut state);
    state[1]
}

fn fq_rand(s: &mut u64) -> Fq {
    let mut limbs = [0u64; 4];
    for limb in limbs.iter_mut() {
        *limb = xorshift(s);
    }
    limbs[3] &= (1u64 << 58) - 1;
    Fq::from_canonical(limbs)
}

/// 16-level Merkle membership: leaf hash + 16 sibling hashes via psd4.
fn merkle_verify_16(leaf: Fq, s: &mut u64) -> Fq {
    let mut node = poseidon4_hash(&[leaf]);
    for _ in 0..16 {
        let sibling = fq_rand(s);
        let bit = xorshift(s) & 1 == 1;
        node = if bit {
            poseidon4_hash(&[sibling, node])
        } else {
            poseidon4_hash(&[node, sibling])
        };
    }
    node
}

fn usdcx_transfer_private_body(seed: u64) -> u64 {
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let g = EdwardsPoint::generator();
    let pk = g.scalar_mul(&full_scalar(&mut s));
    let addr_pt = g.scalar_mul(&full_scalar(&mut s));
    let nonce_pt = g.scalar_mul(&full_scalar(&mut s));

    let mut acc = Fq::ZERO;
    let mut state = [Fq::from_u64(seed), Fq::from_u64(1), Fq::from_u64(2)];

    start_cycle_tracking("usdcx_total");

    // 1. Input Token record decryption
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

    // 2. Serial number
    start_cycle_tracking("serial_number");
    for _ in 0..2 {
        poseidon_perm(&mut state);
    }
    let (snx, _) = g.scalar_mul(&full_scalar(&mut s)).to_affine();
    acc = acc.add(&Fq::from_canonical(snx)).add(&state[0]);
    end_cycle_tracking("serial_number");

    // 3. Request authorization
    start_cycle_tracking("schnorr_verify");
    poseidon_perm(&mut state);
    let e = full_scalar(&mut s);
    let z = full_scalar(&mut s);
    let (rx, _) = g.scalar_mul(&z).add(&pk.scalar_mul(&e)).to_affine();
    acc = acc.add(&Fq::from_canonical(rx));
    end_cycle_tracking("schnorr_verify");

    // 4. TWO 16-level Merkle proofs (usdcx compliance credential checks)
    start_cycle_tracking("merkle_proofs");
    let root1 = merkle_verify_16(fq_rand(&mut s), &mut s);
    let root2 = merkle_verify_16(fq_rand(&mut s), &mut s);
    acc = acc.add(&root1).add(&root2);
    end_cycle_tracking("merkle_proofs");

    // 5. THREE output records: Token x2 (6 perms), ComplianceRecord (7 perms)
    for (label, n_perms) in [
        ("output_token_1", 6usize),
        ("output_token_2", 6),
        ("output_compliance", 7),
    ] {
        start_cycle_tracking(label);
        let esk = full_scalar(&mut s);
        let eph = g.scalar_mul(&esk);
        let (ephx, ephy) = eph.to_affine();
        let (sox, _) = addr_pt.scalar_mul(&esk).to_affine();
        state[0] = state[0].add(&Fq::from_canonical(ephx));
        state[1] = state[1].add(&Fq::from_canonical(sox));
        for _ in 0..n_perms {
            poseidon_perm(&mut state);
        }
        acc = acc.add(&state[0]).add(&Fq::from_canonical(ephy));
        end_cycle_tracking(label);
    }

    end_cycle_tracking("usdcx_total");

    acc = acc.add(&state[1]).add(&state[2]);
    acc.to_canonical()[0]
}

// --- Software (arkworks) twins: direct measurement of the unaccelerated cost.
// Same style as the phase0-complete baseline (ark types, fq_from_limbs
// conversions per vendored constant) so numbers are comparable to the
// recorded 17.59M software transfer.

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::fields::Field as ArkField;
use ark_ff::{BigInt, PrimeField, Zero};
type AFq = ark_ed_on_bls12_377::Fq;
type AProj = ark_ed_on_bls12_377::EdwardsProjective;

fn afq_from_limbs(limbs: &[u64; 4]) -> AFq {
    AFq::from_bigint(BigInt::new(*limbs)).expect("vendored constant exceeds modulus")
}

fn asbox17(x: AFq) -> AFq {
    let x2 = x.square();
    let x4 = x2.square();
    let x8 = x4.square();
    x8.square() * x
}

fn poseidon_perm_soft(state: &mut [AFq; 3]) {
    let full = vendored::POSEIDON2_FULL_ROUNDS;
    let partial = vendored::POSEIDON2_PARTIAL_ROUNDS;
    let partial_range = (full / 2)..(full / 2 + partial);
    for round in 0..(full + partial) {
        for (s, c) in state.iter_mut().zip(vendored::POSEIDON2_ARK[round].iter()) {
            *s += afq_from_limbs(c);
        }
        if partial_range.contains(&round) {
            state[0] = asbox17(state[0]);
        } else {
            for s in state.iter_mut() {
                *s = asbox17(*s);
            }
        }
        let mut new_state = [AFq::zero(); 3];
        for (i, ns) in new_state.iter_mut().enumerate() {
            for (m, s) in vendored::POSEIDON2_MDS[i].iter().zip(state.iter()) {
                *ns += afq_from_limbs(m) * s;
            }
        }
        *state = new_state;
    }
}

fn poseidon4_perm_soft(state: &mut [AFq; 5]) {
    let full = vendored4::POSEIDON4_FULL_ROUNDS;
    let partial = vendored4::POSEIDON4_PARTIAL_ROUNDS;
    let partial_range = (full / 2)..(full / 2 + partial);
    for round in 0..(full + partial) {
        for (s, c) in state.iter_mut().zip(vendored4::POSEIDON4_ARK[round].iter()) {
            *s += afq_from_limbs(c);
        }
        if partial_range.contains(&round) {
            state[0] = asbox17(state[0]);
        } else {
            for s in state.iter_mut() {
                *s = asbox17(*s);
            }
        }
        let mut new_state = [AFq::zero(); 5];
        for (i, ns) in new_state.iter_mut().enumerate() {
            for (m, s) in vendored4::POSEIDON4_MDS[i].iter().zip(state.iter()) {
                *ns += afq_from_limbs(m) * s;
            }
        }
        *state = new_state;
    }
}

fn poseidon4_hash_soft(inputs: &[AFq]) -> AFq {
    let mut state = [AFq::zero(); 5];
    state[1] += afq_from_limbs(&vendored4::POSEIDON4_DOMAIN);
    state[2] += AFq::from(inputs.len() as u64);
    let mut chunks = inputs.chunks(4).peekable();
    if chunks.peek().is_some() {
        poseidon4_perm_soft(&mut state);
        while let Some(chunk) = chunks.next() {
            for (i, v) in chunk.iter().enumerate() {
                state[1 + i] += v;
            }
            if chunks.peek().is_some() {
                poseidon4_perm_soft(&mut state);
            }
        }
    }
    poseidon4_perm_soft(&mut state);
    state[1]
}

fn afr_full(s: &mut u64) -> ark_ed_on_bls12_377::Fr {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&xorshift(s).to_le_bytes());
    }
    ark_ed_on_bls12_377::Fr::from_le_bytes_mod_order(&bytes)
}

fn afq_rand(s: &mut u64) -> AFq {
    let mut limbs = [0u64; 4];
    for limb in limbs.iter_mut() {
        *limb = xorshift(s);
    }
    limbs[3] &= (1u64 << 58) - 1;
    afq_from_limbs(&limbs)
}

fn merkle_verify_16_soft(leaf: AFq, s: &mut u64) -> AFq {
    let mut node = poseidon4_hash_soft(&[leaf]);
    for _ in 0..16 {
        let sibling = afq_rand(s);
        let bit = xorshift(s) & 1 == 1;
        node = if bit {
            poseidon4_hash_soft(&[sibling, node])
        } else {
            poseidon4_hash_soft(&[node, sibling])
        };
    }
    node
}

#[jolt::provable(stack_size = 262144, heap_size = 1048576, max_trace_length = 67108864)]
fn usdcx_transfer_private(seed: u64) -> u64 {
    usdcx_transfer_private_body(seed)
}

/// B2 bound variant: every field op welded to its record block in the
/// committed untrusted-advice region (32 MB capacity for the 146,766-record
/// blob).
#[jolt::provable(
    stack_size = 262144,
    heap_size = 1048576,
    max_trace_length = 67108864,
    max_untrusted_advice_size = 33554432
)]
fn usdcx_transfer_private_bound(seed: u64, records: jolt::UntrustedAdvice<&[u8]>) -> u64 {
    jolt_inlines_edwards_bls12::bind::init(&records);
    let out = usdcx_transfer_private_body(seed);
    jolt_inlines_edwards_bls12::bind::finalize();
    out
}

#[jolt::provable(stack_size = 262144, heap_size = 1048576, max_trace_length = 134217728)]
fn usdcx_transfer_private_soft(seed: u64) -> u64 {
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let g = AProj::generator();
    let pk = g * afr_full(&mut s);
    let addr_pt = g * afr_full(&mut s);
    let nonce_pt = g * afr_full(&mut s);

    let mut acc = AFq::zero();
    let mut state = [AFq::from(seed), AFq::from(1u64), AFq::from(2u64)];

    start_cycle_tracking("usdcx_soft_total");

    let vk = afr_full(&mut s);
    let shared = (nonce_pt * vk).into_affine();
    state[0] += shared.x;
    state[1] += shared.y;
    for _ in 0..4 {
        poseidon_perm_soft(&mut state);
    }
    acc += state[0];

    for _ in 0..2 {
        poseidon_perm_soft(&mut state);
    }
    let sn = (g * afr_full(&mut s)).into_affine();
    acc += sn.x + state[0];

    poseidon_perm_soft(&mut state);
    let e = afr_full(&mut s);
    let z = afr_full(&mut s);
    let rp = (g * z + pk * e).into_affine();
    acc += rp.x;

    start_cycle_tracking("merkle_proofs_soft");
    let root1 = merkle_verify_16_soft(afq_rand(&mut s), &mut s);
    let root2 = merkle_verify_16_soft(afq_rand(&mut s), &mut s);
    acc += root1 + root2;
    end_cycle_tracking("merkle_proofs_soft");

    for n_perms in [6usize, 6, 7] {
        let esk = afr_full(&mut s);
        let eph = (g * esk).into_affine();
        let so = (addr_pt * esk).into_affine();
        state[0] += eph.x;
        state[1] += so.x;
        for _ in 0..n_perms {
            poseidon_perm_soft(&mut state);
        }
        acc += state[0] + eph.y;
    }

    end_cycle_tracking("usdcx_soft_total");

    acc += state[1] + state[2];
    acc.into_bigint().0[0]
}
