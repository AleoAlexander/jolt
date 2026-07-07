//! B1 batched verification sumcheck for the field-acceleration prototype.
//!
//! A STANDALONE side-proof, deliberately NOT wired into the 7-stage pipeline:
//! an eq-weighted zero-check over the invocation log proving that every record
//! satisfies the per-column limb equation
//!
//!   S_k = Σ_{i+j=k, i,j<3} xL_i·yL_j − Σ_{i+j=k} wL_i·qL_j − zL_k·[k<3]
//!         + carry_{k−1} − carry_k·2^86  == 0   for k = 0..4,
//!
//! with carry_{-1} = carry_4 = 0 and qL the guest-declared modulus limbs as
//! public constants. The five columns are batched with a transcript challenge
//! alpha: C(row) = Σ_k alpha^k · S_k(row), and the statement proved is
//! Σ_row eq(tau, row) · C(row) == 0.
//!
//! Soundness of the integer identity given the field identity relies on the
//! magnitude bounds in CARRY_BOUNDS.md (all column magnitudes < 2^250 ≪ the
//! BN254 Fr modulus, so the field equation cannot wrap around), which in turn
//! assume the limb/carry range checks that B2/Track C must enforce.
//!
//! PROTOTYPE: the 16 final column evaluations are sent IN THE CLEAR and are
//! NOT bound by any polynomial commitment. A malicious prover can therefore
//! invent arbitrary final evaluations consistent with its round polynomials.
//! PCS binding of the witness columns (and range checks) is Track C. What B1
//! demonstrates is the sumcheck arithmetization itself: an honest prover over
//! a *tampered* witness log produces a proof that fails verification (see the
//! tamper tests below).

use super::{FieldAccelParams, FieldAccelWitness};
use crate::field::JoltField;
use crate::poly::unipoly::UniPoly;
use crate::transcripts::Transcript;

/// Column order: x_limbs[0..3], y_limbs[0..3], z_limbs[0..3], w_limbs[0..3],
/// carries[0..4].
pub const NUM_COLUMNS: usize = 16;

const X: usize = 0;
const Y: usize = 3;
const Z: usize = 6;
const W: usize = 9;
const CARRY: usize = 12;

/// The 16 clear column evaluations at the sumcheck point r. The verifier
/// computes eq(tau, r) itself, so no 17th evaluation is sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldAccelEvals<F: JoltField> {
    pub columns: [F; NUM_COLUMNS],
}

#[derive(Clone, Debug)]
pub struct FieldAccelProof<F: JoltField> {
    /// One degree-3 univariate message per round (coefficient form).
    pub round_polys: Vec<UniPoly<F>>,
    pub final_evals: FieldAccelEvals<F>,
}

/// Absorb the public statement (row count and modulus) before drawing tau
/// and alpha. Prover and verifier must call this identically.
fn bind_statement<T: Transcript>(params: &FieldAccelParams, log_n: usize, transcript: &mut T) {
    transcript.append_label(b"field_accel_b1");
    transcript.append_u64(b"fa_log_n", log_n as u64);
    for limb in params.modulus_limbs {
        transcript.append_u64(b"fa_modulus_limb", limb);
    }
}

/// Lift the integer witness columns into F.
///
/// Unsigned 86-bit limbs map via `from_u128`; signed carries map via
/// `from_i128` (negative c ↦ −|c| in F). Because every limb is < 2^86 and
/// every carry magnitude is < 2^88 (CARRY_BOUNDS.md), all intermediate column
/// values in the constraint stay below 2^250 in magnitude, far under the
/// BN254 Fr modulus (~2^254), so the integer identity holds iff the field
/// identity holds — no wraparound is possible.
fn witness_columns<F: JoltField>(witness: &FieldAccelWitness) -> Vec<Vec<F>> {
    let mut cols: Vec<Vec<F>> = Vec::with_capacity(NUM_COLUMNS);
    for group in [
        &witness.x_limbs,
        &witness.y_limbs,
        &witness.z_limbs,
        &witness.w_limbs,
    ] {
        for col in group.iter() {
            cols.push(col.iter().map(|&v| F::from_u128(v)).collect());
        }
    }
    for col in witness.carries.iter() {
        cols.push(col.iter().map(|&v| F::from_i128(v)).collect());
    }
    cols
}

/// eq table over the hypercube: table[idx] = Π_j (bit_j(idx) ? tau_j : 1−tau_j),
/// with bit j of the row index (little-endian) paired with tau[j]. Binding the
/// low variable each round (pairs (2i, 2i+1)) then binds tau[j] against the
/// round-j challenge, matching the verifier's product formula.
fn eq_table<F: JoltField>(tau: &[F]) -> Vec<F> {
    let mut table = vec![F::one()];
    for t in tau {
        let one_minus_t = F::one() - *t;
        let mut next = Vec::with_capacity(table.len() * 2);
        // Each new variable becomes the HIGH bit (low half = bit 0, high half
        // = bit 1) so earlier variables keep their lower bit positions and
        // binding the low variable per round consumes tau[0], tau[1], ... in
        // order — matching the verifier's Π_j (tau_j·r_j + (1−tau_j)(1−r_j)).
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

/// C(vals) = Σ_k alpha^k · S_k(vals) — the batched column constraint at a
/// single (possibly virtual) row.
fn constraint_eval<F: JoltField>(
    vals: &[F; NUM_COLUMNS],
    q: &[F; 3],
    alpha_pows: &[F; 5],
    two_86: F,
) -> F {
    let mut acc = F::zero();
    for (k, alpha_k) in alpha_pows.iter().enumerate() {
        let mut s = F::zero();
        for i in 0..3usize {
            let Some(j) = k.checked_sub(i) else { continue };
            if j >= 3 {
                continue;
            }
            s += vals[X + i] * vals[Y + j];
            s -= vals[W + i] * q[j];
        }
        if k < 3 {
            s -= vals[Z + k];
        }
        if k >= 1 {
            s += vals[CARRY + k - 1];
        }
        if k < 4 {
            s -= vals[CARRY + k] * two_86;
        }
        acc += *alpha_k * s;
    }
    acc
}

/// Bind the lowest variable of a multilinear column to r: v'[i] = v[2i] + r·(v[2i+1] − v[2i]).
fn bind_low<F: JoltField>(v: &mut Vec<F>, r: F) {
    let half = v.len() / 2;
    for i in 0..half {
        let lo = v[2 * i];
        v[i] = lo + r * (v[2 * i + 1] - lo);
    }
    v.truncate(half);
}

fn eval_unipoly<F: JoltField>(poly: &UniPoly<F>, r: F) -> F {
    poly.coeffs
        .iter()
        .rev()
        .fold(F::zero(), |acc, c| acc * r + *c)
}

fn alpha_powers<F: JoltField>(alpha: F) -> [F; 5] {
    let mut pows = [F::one(); 5];
    for k in 1..5 {
        pows[k] = pows[k - 1] * alpha;
    }
    pows
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
    let alpha: F = transcript.challenge_scalar();
    let alpha_pows = alpha_powers(alpha);
    let q = params.modulus_limbs_86().map(F::from_u128);
    let two_86 = F::from_u128(1u128 << 86);

    let mut cols = witness_columns::<F>(witness);
    let mut eq = eq_table::<F>(&tau);

    let mut round_polys = Vec::with_capacity(log_n);
    let mut m = n;
    for _round in 0..log_n {
        m /= 2;
        // Degree-3 message: evaluate Σ_i eq(t, i) · C(t, i) at t = 0, 1, 2, 3
        // over the remaining hypercube. O(4 · 17 · m) per round — prototype.
        let mut evals = [F::zero(); 4];
        for i in 0..m {
            let mut cur = [F::zero(); NUM_COLUMNS];
            let mut diff = [F::zero(); NUM_COLUMNS];
            for ((cur_c, diff_c), col) in cur.iter_mut().zip(diff.iter_mut()).zip(cols.iter()) {
                let lo = col[2 * i];
                *cur_c = lo;
                *diff_c = col[2 * i + 1] - lo;
            }
            let eq_lo = eq[2 * i];
            let eq_diff = eq[2 * i + 1] - eq_lo;
            let mut eq_cur = eq_lo;
            for (t, eval) in evals.iter_mut().enumerate() {
                *eval += eq_cur * constraint_eval(&cur, &q, &alpha_pows, two_86);
                if t < 3 {
                    for (cur_c, diff_c) in cur.iter_mut().zip(diff.iter()) {
                        *cur_c += *diff_c;
                    }
                    eq_cur += eq_diff;
                }
            }
        }
        let poly = UniPoly::from_evals(&evals);
        // Conventional order: message appended, then challenge drawn.
        transcript.append_scalars(b"fa_round_poly", &poly.coeffs);
        let r: F = transcript.challenge_scalar();
        for col in cols.iter_mut() {
            bind_low(col, r);
        }
        bind_low(&mut eq, r);
        round_polys.push(poly);
    }

    let mut columns = [F::zero(); NUM_COLUMNS];
    for (out, col) in columns.iter_mut().zip(cols.iter()) {
        *out = col[0];
    }
    FieldAccelProof {
        round_polys,
        // PROTOTYPE: these final evaluations are sent in the clear and are NOT
        // bound by any polynomial commitment — nothing ties them to the
        // committed witness because there is no committed witness yet. PCS
        // binding (Dory openings of the 16 columns) is Track C.
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
    let alpha: F = transcript.challenge_scalar();

    if proof.round_polys.len() != log_num_rows {
        return Err("wrong number of sumcheck rounds");
    }

    // Standard sumcheck recurrence: claim_0 = 0 (zero-check);
    // g_j(0) + g_j(1) == claim_j; claim_{j+1} = g_j(r_j).
    let mut claim = F::zero();
    let mut r_vec = Vec::with_capacity(log_num_rows);
    for poly in &proof.round_polys {
        if poly.coeffs.is_empty() || poly.coeffs.len() > 4 {
            return Err("round polynomial has wrong degree");
        }
        if poly.eval_at_zero() + poly.eval_at_one() != claim {
            return Err("sumcheck round claim mismatch");
        }
        transcript.append_scalars(b"fa_round_poly", &poly.coeffs);
        let r: F = transcript.challenge_scalar();
        claim = eval_unipoly(poly, r);
        r_vec.push(r);
    }

    // The verifier computes eq(tau, r) itself — it is not part of final_evals.
    let eq_eval = tau.iter().zip(r_vec.iter()).fold(F::one(), |acc, (t, r)| {
        acc * (*t * *r + (F::one() - *t) * (F::one() - *r))
    });

    let q = params.modulus_limbs_86().map(F::from_u128);
    let alpha_pows = alpha_powers(alpha);
    let two_86 = F::from_u128(1u128 << 86);
    let c = constraint_eval(&proof.final_evals.columns, &q, &alpha_pows, two_86);

    // PROTOTYPE: final_evals are unauthenticated clear values (no PCS opening
    // ties them to a commitment); this equality is the whole final check. See
    // the module doc — commitment binding is Track C.
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
    fn tampered_z_limb_fails() {
        let mut witness = random_witness(5678, 5);
        witness.z_limbs[0][2] += 1;
        let proof = prove(&witness);
        assert!(verify(&proof, 3).is_err());
    }

    #[test]
    fn tampered_carry_fails() {
        let mut witness = random_witness(91011, 5);
        witness.carries[1][3] += 1;
        let proof = prove(&witness);
        assert!(verify(&proof, 3).is_err());
    }

    #[test]
    fn tampered_final_evals_fail() {
        let witness = random_witness(121314, 5);
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
