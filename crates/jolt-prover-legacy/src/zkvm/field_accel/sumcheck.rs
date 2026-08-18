//! B2 batched verification sumcheck for the field-acceleration prototype,
//! 64-bit word schema.
//!
//! An eq-weighted zero-check over the record rows proving, per row, the
//! α/γ-batched constraint families:
//!
//! - product columns (k = 0..6, degree 2):
//!   `C_k = Σ_{i+j=k, i,j<4} x_i·y_j − Σ_{i+j=k} w_i·q_j − z_k·[k<4]
//!          + (carry'_{k−1} − OFF)·[k≥1] − 2^64·(carry'_k − OFF)·[k≤5]`
//! - carry recomposition (j = 0..5, degree 1):
//!   `R_j = Σ_{d<35} 4^d·digit_{j,d} − carry'_j`
//! - digit validity (210 columns, degree 4):
//!   `D_{j,d} = digit·(digit−1)·(digit−2)·(digit−3)`
//!
//! with `q` the guest-declared modulus WORDS as public constants and
//! `OFF = 2^68` the carry offset. Batching: `Σ_k α^k·C_k + Σ_j α^{7+j}·R_j
//! + α^13·Σ_{j,d} γ^{j·35+d}·D_{j,d}`; the proved statement is
//! `Σ_row eq(τ,row)·batched(row) == 0`. Round messages are degree ≤ 5.
//!
//! Soundness of the integer identity given the field identity relies on the
//! magnitude bounds in CARRY_BOUNDS.md (all column magnitudes ≪ the BN254 Fr
//! modulus, so the field equation cannot wrap), which the digit range checks
//! enforce for the carries; the 16 word columns are u64 by construction of
//! the committed advice region whose blocks they mirror.
//!
//! PROTOTYPE (standalone mode): the final column evaluations are sent in the
//! clear. The bound protocol (plan Task 4) replaces the word evaluations
//! with openings of the committed `UntrustedAdvice` polynomial and the
//! aux-column evaluations with Dory-batched openings.

use super::{
    FieldAccelParams, FieldAccelWitness, CARRY_OFFSET, DIGITS_PER_CARRY, NUM_CARRIES,
    NUM_DIGIT_COLUMNS, NUM_PRODUCT_COLUMNS,
};
use crate::field::JoltField;
use crate::poly::unipoly::UniPoly;
use crate::transcripts::Transcript;

/// Column order: words x0..3 y0..3 z0..3 w0..3, then offset carries 0..6,
/// then digits (j·35 + d).
pub const NUM_WORD_COLUMNS: usize = 16;
pub const NUM_TOTAL_COLUMNS: usize = NUM_WORD_COLUMNS + NUM_CARRIES + NUM_DIGIT_COLUMNS;

const X: usize = 0;
const Y: usize = 4;
const Z: usize = 8;
const W: usize = 12;
const CARRY: usize = NUM_WORD_COLUMNS;
const DIG: usize = NUM_WORD_COLUMNS + NUM_CARRIES;

/// Degree of the row polynomial inside the zero-check (digit validity), so
/// round messages have DEGREE + 1 = 6 evaluations with the eq factor.
const DEGREE: usize = 5;

/// The clear column evaluations at the sumcheck point r (standalone mode).
/// The verifier computes eq(tau, r) itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldAccelEvals<F: JoltField> {
    pub columns: Vec<F>,
}

#[derive(Clone, Debug)]
pub struct FieldAccelProof<F: JoltField> {
    /// One degree-5 univariate message per round (coefficient form).
    pub round_polys: Vec<UniPoly<F>>,
    pub final_evals: FieldAccelEvals<F>,
}

/// Absorb the public statement (row count and modulus) before drawing tau,
/// alpha, and gamma. Prover and verifier must call this identically.
fn bind_statement<T: Transcript>(params: &FieldAccelParams, log_n: usize, transcript: &mut T) {
    transcript.append_label(b"field_accel_b2");
    transcript.append_u64(b"fa_log_n", log_n as u64);
    for limb in params.modulus_limbs {
        transcript.append_u64(b"fa_modulus_limb", limb);
    }
}

/// Lift the witness columns into F. Words are u64; offset carries are
/// < 2^70; digits are < 4. All magnitudes in the batched constraint stay
/// far below the BN254 Fr modulus (CARRY_BOUNDS.md), so the integer
/// identity holds iff the field identity holds.
pub(super) fn witness_columns<F: JoltField>(witness: &FieldAccelWitness) -> Vec<Vec<F>> {
    let mut cols: Vec<Vec<F>> = Vec::with_capacity(NUM_TOTAL_COLUMNS);
    for col in witness.words.iter() {
        cols.push(col.iter().map(|&v| F::from_u64(v)).collect());
    }
    for col in witness.carries.iter() {
        cols.push(col.iter().map(|&v| F::from_u128(v)).collect());
    }
    for col in witness.digits.iter() {
        cols.push(col.iter().map(|&v| F::from_u64(v as u64)).collect());
    }
    cols
}

/// eq table over the hypercube: table[idx] = Π_j (bit_j(idx) ? tau_j : 1−tau_j),
/// little-endian bit/variable pairing; binding the low variable each round
/// consumes tau[0], tau[1], ... in order, matching the verifier's product.
pub(super) fn eq_table<F: JoltField>(tau: &[F]) -> Vec<F> {
    let mut table = vec![F::one()];
    for t in tau {
        let one_minus_t = F::one() - *t;
        let mut next = Vec::with_capacity(table.len() * 2);
        for &e in &table {
            next.push(e * one_minus_t);
        }
        for &e in &table {
            next.push(e * *t);
        }
        table = next;
    }
    table
}

pub struct BatchingChallenges<F: JoltField> {
    /// alpha^0..alpha^13 (13 = 7 product + 6 recomposition; index 13 scales
    /// the digit family).
    pub alpha_pows: [F; 14],
    /// gamma^0..gamma^209 for the digit-validity columns.
    pub gamma_pows: Vec<F>,
}

impl<F: JoltField> BatchingChallenges<F> {
    pub(super) fn draw<T: Transcript>(transcript: &mut T) -> Self {
        let alpha: F = transcript.challenge_scalar();
        let gamma: F = transcript.challenge_scalar();
        let mut alpha_pows = [F::one(); 14];
        for k in 1..14 {
            alpha_pows[k] = alpha_pows[k - 1] * alpha;
        }
        let mut gamma_pows = Vec::with_capacity(NUM_DIGIT_COLUMNS);
        let mut g = F::one();
        for _ in 0..NUM_DIGIT_COLUMNS {
            gamma_pows.push(g);
            g *= gamma;
        }
        BatchingChallenges {
            alpha_pows,
            gamma_pows,
        }
    }
}

/// The batched row constraint at a single (possibly virtual) row.
pub(super) fn constraint_eval<F: JoltField>(
    vals: &[F],
    q_words: &[F; 4],
    ch: &BatchingChallenges<F>,
) -> F {
    let two_64 = F::from_u128(1u128 << 64);
    let offset = F::from_u128(CARRY_OFFSET as u128);
    let mut acc = F::zero();
    // product columns
    for k in 0..NUM_PRODUCT_COLUMNS {
        let mut s = F::zero();
        for i in 0..4usize {
            let Some(j) = k.checked_sub(i) else { continue };
            if j >= 4 {
                continue;
            }
            s += vals[X + i] * vals[Y + j];
            s -= vals[W + i] * q_words[j];
        }
        if k < 4 {
            s -= vals[Z + k];
        }
        if k >= 1 {
            s += vals[CARRY + k - 1] - offset;
        }
        if k <= 5 {
            s -= two_64 * (vals[CARRY + k] - offset);
        }
        acc += ch.alpha_pows[k] * s;
    }
    // carry recomposition
    for j in 0..NUM_CARRIES {
        let mut s = F::zero();
        let mut pow4 = F::one();
        let four = F::from_u64(4);
        for d in 0..DIGITS_PER_CARRY {
            s += pow4 * vals[DIG + j * DIGITS_PER_CARRY + d];
            pow4 *= four;
        }
        s -= vals[CARRY + j];
        acc += ch.alpha_pows[NUM_PRODUCT_COLUMNS + j] * s;
    }
    // digit validity, gamma-batched under alpha^13
    let mut dig_acc = F::zero();
    let (one, two, three) = (F::one(), F::from_u64(2), F::from_u64(3));
    for (idx, gamma_k) in ch.gamma_pows.iter().enumerate() {
        let v = vals[DIG + idx];
        dig_acc += *gamma_k * (v * (v - one) * (v - two) * (v - three));
    }
    acc + ch.alpha_pows[13] * dig_acc
}

/// Bind the lowest variable of a multilinear column to r.
pub(super) fn bind_low<F: JoltField>(v: &mut Vec<F>, r: F) {
    let half = v.len() / 2;
    for i in 0..half {
        let lo = v[2 * i];
        v[i] = lo + r * (v[2 * i + 1] - lo);
    }
    v.truncate(half);
}

pub(super) fn eval_unipoly<F: JoltField>(poly: &UniPoly<F>, r: F) -> F {
    poly.coeffs
        .iter()
        .rev()
        .fold(F::zero(), |acc, c| acc * r + *c)
}

/// Prover core of the eq-weighted zero-check: consumes the columns (binding
/// them in place), appends one degree-5 message per round, and returns the
/// round polynomials plus the row challenges (in native challenge form,
/// little-endian: challenge j binds row-index bit j).
pub(super) fn zero_check_prove<F: JoltField, T: Transcript>(
    cols: &mut [Vec<F>],
    tau: &[F],
    ch: &BatchingChallenges<F>,
    q_words: &[F; 4],
    transcript: &mut T,
) -> (Vec<UniPoly<F>>, Vec<F::Challenge>) {
    let n = cols[0].len();
    debug_assert!(n.is_power_of_two());
    let log_n = n.trailing_zeros() as usize;
    let mut eq = eq_table::<F>(tau);

    let mut round_polys = Vec::with_capacity(log_n);
    let mut r_challenges = Vec::with_capacity(log_n);
    let mut m = n;
    let num_cols = cols.len();
    for _round in 0..log_n {
        m /= 2;
        // Degree-5 message: evaluate Σ_i eq(t, i) · C(t, i) at t = 0..5
        // over the remaining hypercube. Row-parallel; O(6 · 233 · m) work.
        use rayon::prelude::*;
        let evals = (0..m)
            .into_par_iter()
            .fold(
                || (vec![F::zero(); num_cols], vec![F::zero(); num_cols], [F::zero(); DEGREE + 1]),
                |(mut cur, mut diff, mut acc), i| {
                    for ((cur_c, diff_c), col) in
                        cur.iter_mut().zip(diff.iter_mut()).zip(cols.iter())
                    {
                        let lo = col[2 * i];
                        *cur_c = lo;
                        *diff_c = col[2 * i + 1] - lo;
                    }
                    let eq_lo = eq[2 * i];
                    let eq_diff = eq[2 * i + 1] - eq_lo;
                    let mut eq_cur = eq_lo;
                    for (t, eval) in acc.iter_mut().enumerate() {
                        *eval += eq_cur * constraint_eval(&cur, q_words, ch);
                        if t < DEGREE {
                            for (cur_c, diff_c) in cur.iter_mut().zip(diff.iter()) {
                                *cur_c += *diff_c;
                            }
                            eq_cur += eq_diff;
                        }
                    }
                    (cur, diff, acc)
                },
            )
            .map(|(_, _, acc)| acc)
            .reduce(
                || [F::zero(); DEGREE + 1],
                |mut a, b| {
                    for (x, y) in a.iter_mut().zip(b.iter()) {
                        *x += *y;
                    }
                    a
                },
            );
        let poly = UniPoly::from_evals(&evals);
        // Conventional order: message appended, then challenge drawn.
        transcript.append_scalars(b"fa_round_poly", &poly.coeffs);
        let r_c: F::Challenge = transcript.challenge_scalar_optimized::<F>();
        let r: F = r_c.into();
        cols.par_iter_mut().for_each(|col| bind_low(col, r));
        bind_low(&mut eq, r);
        round_polys.push(poly);
        r_challenges.push(r_c);
    }
    (round_polys, r_challenges)
}

/// Verifier core of the zero-check: replays the rounds, returning the row
/// challenges and the running claim to be checked against
/// eq(τ, r) · constraint(final evals).
pub(super) fn zero_check_verify<F: JoltField, T: Transcript>(
    round_polys: &[UniPoly<F>],
    log_rows: usize,
    transcript: &mut T,
) -> Result<(Vec<F::Challenge>, F), &'static str> {
    if round_polys.len() != log_rows {
        return Err("wrong number of sumcheck rounds");
    }
    // Standard sumcheck recurrence: claim_0 = 0 (zero-check);
    // g_j(0) + g_j(1) == claim_j; claim_{j+1} = g_j(r_j).
    let mut claim = F::zero();
    let mut r_vec = Vec::with_capacity(log_rows);
    for poly in round_polys {
        if poly.coeffs.is_empty() || poly.coeffs.len() > DEGREE + 1 {
            return Err("round polynomial has wrong degree");
        }
        if poly.eval_at_zero() + poly.eval_at_one() != claim {
            return Err("sumcheck round claim mismatch");
        }
        transcript.append_scalars(b"fa_round_poly", &poly.coeffs);
        let r_c: F::Challenge = transcript.challenge_scalar_optimized::<F>();
        claim = eval_unipoly(poly, r_c.into());
        r_vec.push(r_c);
    }
    Ok((r_vec, claim))
}

/// eq(τ, r) for little-endian challenge lists.
pub(super) fn eq_at<F: JoltField>(tau: &[F], r: &[F::Challenge]) -> F {
    tau.iter().zip(r.iter()).fold(F::one(), |acc, (t, r)| {
        let r: F = (*r).into();
        acc * (*t * r + (F::one() - *t) * (F::one() - r))
    })
}

pub fn prove_field_accel<F: JoltField, T: Transcript>(
    witness: &FieldAccelWitness,
    params: &FieldAccelParams,
    transcript: &mut T,
) -> FieldAccelProof<F> {
    let n = witness.padded_len();
    debug_assert!(n.is_power_of_two());
    let log_n = n.trailing_zeros() as usize;

    bind_statement(params, log_n, transcript);
    let tau: Vec<F> = transcript.challenge_vector(log_n);
    let ch = BatchingChallenges::draw(transcript);
    let q_words = params.modulus_limbs.map(F::from_u64);

    let mut cols = witness_columns::<F>(witness);
    let (round_polys, _r) = zero_check_prove(&mut cols, &tau, &ch, &q_words, transcript);

    let columns: Vec<F> = cols.iter().map(|col| col[0]).collect();
    FieldAccelProof {
        round_polys,
        // PROTOTYPE (standalone): clear final evaluations; the bound
        // protocol replaces these with committed-polynomial openings.
        final_evals: FieldAccelEvals { columns },
    }
}

pub fn verify_field_accel<F: JoltField, T: Transcript>(
    proof: &FieldAccelProof<F>,
    params: &FieldAccelParams,
    log_num_rows: usize,
    transcript: &mut T,
) -> Result<(), &'static str> {
    bind_statement(params, log_num_rows, transcript);
    let tau: Vec<F> = transcript.challenge_vector(log_num_rows);
    let ch = BatchingChallenges::draw(transcript);

    if proof.final_evals.columns.len() != NUM_TOTAL_COLUMNS {
        return Err("wrong number of final column evaluations");
    }

    let (r_vec, claim) = zero_check_verify(&proof.round_polys, log_num_rows, transcript)?;

    // The verifier computes eq(tau, r) itself.
    let eq_eval = eq_at(&tau, &r_vec);

    let q_words = params.modulus_limbs.map(F::from_u64);
    let c = constraint_eval(&proof.final_evals.columns, &q_words, &ch);

    // PROTOTYPE (standalone): final_evals are unauthenticated clear values;
    // commitment binding is the bound protocol (plan Task 4).
    if claim != eq_eval * c {
        return Err("final sumcheck evaluation check failed");
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::super::{limbs_to_biguint, FieldOpRecord};
    use super::*;
    use crate::transcripts::Blake2bTranscript;
    use ark_bn254::Fr;

    // BLS12-377 Fr — same test modulus as mod.rs; the gadget is modulus-generic.
    const TEST_MODULUS: [u64; 4] = [
        0x0a11800000000001,
        0x59aa76fed0000001,
        0x60b44d1e5c37b001,
        0x12ab655e9a2ca556,
    ];

    fn params() -> FieldAccelParams {
        FieldAccelParams {
            modulus_limbs: TEST_MODULUS,
        }
    }

    fn xorshift(s: &mut u64) -> u64 {
        let mut x = *s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *s = x;
        x
    }

    fn random_element(s: &mut u64) -> [u64; 4] {
        let mut limbs = [0u64; 4];
        for limb in limbs.iter_mut() {
            *limb = xorshift(s);
        }
        limbs[3] &= (1u64 << 58) - 1;
        limbs
    }

    fn mulmod_record(a: [u64; 4], b: [u64; 4]) -> FieldOpRecord {
        let q = params().modulus();
        let z = (limbs_to_biguint(&a) * limbs_to_biguint(&b)) % &q;
        let mut z_limbs = [0u64; 4];
        for (i, chunk) in z.to_bytes_le().chunks(8).enumerate() {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            z_limbs[i] = u64::from_le_bytes(bytes);
        }
        FieldOpRecord::new(a, b, z_limbs, &params())
    }

    fn random_witness(seed: u64, num_records: usize) -> FieldAccelWitness {
        let mut s = seed;
        let records: Vec<_> = (0..num_records)
            .map(|_| mulmod_record(random_element(&mut s), random_element(&mut s)))
            .collect();
        FieldAccelWitness::from_records(&records, &params())
    }

    fn prove(witness: &FieldAccelWitness) -> FieldAccelProof<Fr> {
        let mut transcript = Blake2bTranscript::new(b"field_accel_test");
        prove_field_accel::<Fr, _>(witness, &params(), &mut transcript)
    }

    fn verify(proof: &FieldAccelProof<Fr>, log_num_rows: usize) -> Result<(), &'static str> {
        let mut transcript = Blake2bTranscript::new(b"field_accel_test");
        verify_field_accel::<Fr, _>(proof, &params(), log_num_rows, &mut transcript)
    }

    #[test]
    fn honest_proof_verifies() {
        let witness = random_witness(1234, 5);
        assert_eq!(witness.padded_len(), 8);
        let proof = prove(&witness);
        assert_eq!(proof.round_polys.len(), 3);
        verify(&proof, 3).unwrap();
    }

    #[test]
    fn tampered_word_fails() {
        let mut witness = random_witness(5678, 5);
        witness.words[Z][2] = witness.words[Z][2].wrapping_add(1);
        let proof = prove(&witness);
        assert!(verify(&proof, 3).is_err());
    }

    #[test]
    fn tampered_carry_fails() {
        let mut witness = random_witness(91011, 5);
        // shift carry AND its digits consistently: recomposition holds but
        // the product identity breaks
        witness.carries[1][3] += 4;
        witness.digits[DIGITS_PER_CARRY + 1][3] += 1;
        let proof = prove(&witness);
        assert!(verify(&proof, 3).is_err());
    }

    #[test]
    fn digit_out_of_range_fails() {
        let mut witness = random_witness(121314, 5);
        // move value 4 into one digit and compensate the next so the carry
        // recomposition still holds — only the digit-validity family trips
        let j = 2usize;
        let row = 1usize;
        let d0 = witness.digits[j * DIGITS_PER_CARRY][row];
        let d1 = witness.digits[j * DIGITS_PER_CARRY + 1][row];
        if d1 == 0 {
            // ensure representable: bump carry by 4 consistently first
            witness.carries[j][row] += 4;
            witness.digits[j * DIGITS_PER_CARRY + 1][row] = 1;
        }
        witness.digits[j * DIGITS_PER_CARRY][row] = d0 + 4;
        witness.digits[j * DIGITS_PER_CARRY + 1][row] -= 1;
        // recomposition unchanged: +4·4^0 − 1·4^1 = 0; digit 0 is now ≥ 4
        let proof = prove(&witness);
        assert!(verify(&proof, 3).is_err(), "out-of-range digit must fail");
    }

    #[test]
    fn carry_offset_forgery_fails() {
        let mut witness = random_witness(151617, 5);
        // inconsistent digit tamper: recomposition family must trip
        witness.digits[5][2] = (witness.digits[5][2] + 1) % 4;
        let proof = prove(&witness);
        assert!(verify(&proof, 3).is_err());
    }

    #[test]
    fn tampered_final_evals_fail() {
        let witness = random_witness(181920, 5);
        let mut proof = prove(&witness);
        proof.final_evals.columns[0] += Fr::from_u64(1);
        assert!(verify(&proof, 3).is_err());
    }

    #[test]
    fn zero_records_edge_case() {
        let witness = FieldAccelWitness::from_records(&[], &params());
        assert_eq!(witness.padded_len(), 1);
        let proof = prove(&witness);
        assert!(proof.round_polys.is_empty());
        verify(&proof, 0).unwrap();
    }
}
