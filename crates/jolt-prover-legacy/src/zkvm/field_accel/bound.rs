//! B2 bound gadget proof (plan Task 4): the zero-check of sumcheck.rs with
//! every final evaluation bound to a polynomial commitment.
//!
//! - The 16 word columns are never committed by the gadget: record i's word
//!   j IS region word `16·(i+1) + j` of the committed `UntrustedAdvice`
//!   polynomial (row 0 = the postcard-varint header row, which satisfies the
//!   identity trivially). The 16 word corner claims at the bound row point
//!   are collapsed to ONE advice opening at a random word point ρ via
//!   multilinear interpolation (Schwartz-Zippel over the 4 word variables).
//! - The 216 aux columns (6 offset carries + 210 digits) are committed as a
//!   single interleaved polynomial `aux[row·256 + col]` (columns padded to
//!   256) and collapsed the same way over 8 column variables at σ.
//! - Region word 0 is opened at the all-zero point to recover the postcard
//!   length varint, from which the verifier derives the record count and
//!   block base — no trusted offsets or counts anywhere (the same pad rule
//!   `bind::init` enforces in-circuit).
//! - All commitments are absorbed before any challenge is squeezed.
//!
//! PROTOTYPE composition note: this runs as a SIDECAR proof sharing the
//! main proof's `untrusted_advice_commitment` object (the verifier receives
//! that commitment from the main `JoltProof` and this section's openings
//! verify against it) rather than inside the main transcript. In-pipeline
//! integration — one shared transcript, stage-8 batched openings — is the
//! production form and exactly the integration question the RFC puts to
//! upstream (question 2).

use super::sumcheck::{
    constraint_eval, eq_at, eq_table, zero_check_prove, zero_check_verify, BatchingChallenges,
    NUM_TOTAL_COLUMNS, NUM_WORD_COLUMNS,
};
use super::{FieldAccelParams, FieldAccelWitness, FieldOpRecord, NUM_CARRIES, NUM_DIGIT_COLUMNS};
use crate::field::JoltField;
use crate::poly::commitment::commitment_scheme::CommitmentScheme;
use crate::poly::commitment::dory::{DoryContext, DoryGlobals};
use crate::poly::multilinear_polynomial::MultilinearPolynomial;
use crate::poly::unipoly::UniPoly;
use crate::transcripts::Transcript;

/// Aux columns are padded to 256 = 2^AUX_COL_BITS.
pub const AUX_COL_BITS: usize = 8;
pub const NUM_AUX_COLUMNS: usize = NUM_CARRIES + NUM_DIGIT_COLUMNS;
const WORD_BITS: usize = 4;
const RECORD_WORDS: usize = 16;

#[derive(Clone, Debug)]
pub struct FieldAccelBoundProof<F: JoltField, PCS: CommitmentScheme<Field = F>> {
    pub aux_commitment: PCS::Commitment,
    pub log_rows: usize,
    pub round_polys: Vec<UniPoly<F>>,
    /// Final evaluations of the 16 word columns (claims against the advice
    /// polynomial) and the 216 aux columns (claims against aux_commitment).
    pub word_corner_evals: Vec<F>,
    pub aux_corner_evals: Vec<F>,
    /// Region word 0 (the postcard length varint + head-pad zeros).
    pub header_word: u64,
    pub advice_claim: F,
    pub advice_opening: PCS::Proof,
    pub header_opening: PCS::Proof,
    pub aux_claim: F,
    pub aux_opening: PCS::Proof,
}

/// Decode a postcard/LEB128 varint from the little-endian bytes of the
/// region's word 0; the remaining bytes must be zero (head pad).
pub fn decode_header_word(word: u64) -> Result<(usize, usize), &'static str> {
    let bytes = word.to_le_bytes();
    let mut len: u64 = 0;
    let mut size = 0usize;
    loop {
        if size >= 8 {
            return Err("header varint does not terminate within word 0");
        }
        let b = bytes[size];
        len |= u64::from(b & 0x7f) << (7 * size);
        size += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    if bytes[size..].iter().any(|&b| b != 0) {
        return Err("header word carries non-zero bytes after the varint");
    }
    Ok((len as usize, size))
}

/// Parse the committed region words into record rows (header row included).
/// Enforces the self-anchoring pad rule: pad = 128 − varint_size(len),
/// blocks starting at word 16.
pub fn parse_region_rows(words: &[u64]) -> Result<(usize, Vec<[u64; RECORD_WORDS]>), &'static str> {
    let (len, varint_size) = decode_header_word(words[0])?;
    let pad = 128 - varint_size;
    if len < pad || (len - pad) % 128 != 0 {
        return Err("blob length violates the pad rule");
    }
    // words 1..16 must be the rest of the head pad (zeros)
    if words[1..RECORD_WORDS].iter().any(|&w| w != 0) {
        return Err("head-pad words are not zero");
    }
    let n = (len - pad) / 128;
    if RECORD_WORDS * (n + 1) > words.len() {
        return Err("record blocks exceed the committed region");
    }
    let mut rows = Vec::with_capacity(n + 1);
    for i in 0..=n {
        let mut row = [0u64; RECORD_WORDS];
        row.copy_from_slice(&words[RECORD_WORDS * i..RECORD_WORDS * (i + 1)]);
        rows.push(row);
    }
    Ok((n, rows))
}

fn row_to_record(row: &[u64; RECORD_WORDS]) -> FieldOpRecord {
    let take = |o: usize| -> [u64; 4] { [row[o], row[o + 1], row[o + 2], row[o + 3]] };
    FieldOpRecord {
        x: take(0),
        y: take(4),
        z: take(8),
        w: take(12),
    }
}

/// Big-endian opening point for index = (row << low_bits) + low, where
/// `low` and `row` challenge lists are little-endian (challenge j binds
/// bit j) and the polynomial has `total_vars` variables (high bits zero).
fn be_point<F: JoltField>(
    total_vars: usize,
    row: &[F::Challenge],
    low: &[F::Challenge],
) -> Vec<F::Challenge> {
    let zero = F::Challenge::from(0u128);
    let mut point = vec![zero; total_vars - row.len() - low.len()];
    point.extend(row.iter().rev().copied());
    point.extend(low.iter().rev().copied());
    point
}

/// Multilinear interpolation of corner values at a little-endian challenge
/// vector: h(r) = Σ_j eq(r, j) · v_j (v beyond the given corners = 0).
fn interpolate_corners<F: JoltField>(corners: &[F], r: &[F::Challenge], num_vars: usize) -> F {
    let r_f: Vec<F> = r.iter().map(|c| (*c).into()).collect();
    let table = eq_table::<F>(&r_f);
    debug_assert_eq!(table.len(), 1 << num_vars);
    corners
        .iter()
        .zip(table.iter())
        .map(|(v, e)| *v * *e)
        .sum()
}

/// Build the advice-region word vector exactly as the prover pipeline does
/// (`populate_memory_states` semantics: LE bytes packed into u64 words,
/// zero-padded to max_untrusted_advice_size / 8).
pub fn region_words(advice_bytes: &[u8], max_untrusted_advice_size: usize) -> Vec<u64> {
    let mut words = vec![0u64; max_untrusted_advice_size / 8];
    for (i, chunk) in advice_bytes.chunks(8).enumerate() {
        let mut b = [0u8; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        words[i] = u64::from_le_bytes(b);
    }
    words
}

/// The vendored arkworks MSM builds a thread pool PER CHUNK inside a
/// parallel map; large sidecar commitments would spawn hundreds of pools
/// concurrently and hit the OS thread cap (EAGAIN). Running our PCS work
/// inside one small dedicated pool caps concurrent chunk-pool creation.
fn pcs_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        // 2 threads: inside this pool the vendored MSM sees
        // current_num_threads()/2 = 1 chunk per call, so it churns ONE
        // short-lived chunk pool per row-MSM instead of several concurrent
        // ones — rayon pool drops don't join their threads, and at 2^24
        // commitment scale the faster churn outruns thread reaping and hits
        // the OS thread cap (EAGAIN). 64 MB stacks: Dory/MSM internals
        // overflow rayon's default 2 MB workers at this scale.
        rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .stack_size(64 * 1024 * 1024)
            .build()
            .expect("field-accel PCS pool")
    })
}

/// Commit the advice-region polynomial exactly as the prover pipeline does
/// (word packing + UntrustedAdvice Dory context). Shared by the sidecar
/// prover and by callers recomputing the commitment for the equality check
/// against the main proof.
pub fn commit_advice_region<F, PCS>(
    advice_bytes: &[u8],
    max_untrusted_advice_size: usize,
    setup: &PCS::ProverSetup,
) -> (PCS::Commitment, PCS::OpeningProofHint)
where
    F: JoltField,
    PCS: CommitmentScheme<Field = F>,
{
    let words = region_words(advice_bytes, max_untrusted_advice_size);
    let poly = MultilinearPolynomial::from(words);
    let _guard = DoryGlobals::initialize_context(
        1,
        max_untrusted_advice_size / 8,
        DoryContext::UntrustedAdvice,
        None,
    );
    let _ctx = DoryGlobals::with_context(DoryContext::UntrustedAdvice);
    pcs_pool().install(|| PCS::commit(&poly, setup))
}

fn aux_vector<F: JoltField>(witness: &FieldAccelWitness) -> Vec<F> {
    let rows = witness.padded_len();
    let mut aux = vec![F::zero(); rows << AUX_COL_BITS];
    for row in 0..rows {
        for (c, col) in witness.carries.iter().enumerate() {
            aux[(row << AUX_COL_BITS) + c] = F::from_u128(col[row]);
        }
        for (d, col) in witness.digits.iter().enumerate() {
            aux[(row << AUX_COL_BITS) + NUM_CARRIES + d] = F::from_u64(col[row] as u64);
        }
    }
    aux
}

fn bind_bound_statement<T: Transcript>(
    params: &FieldAccelParams,
    log_rows: usize,
    advice_vars: usize,
    transcript: &mut T,
) {
    transcript.append_label(b"field_accel_b2_bound");
    transcript.append_u64(b"fa_log_rows", log_rows as u64);
    transcript.append_u64(b"fa_advice_vars", advice_vars as u64);
    for limb in params.modulus_limbs {
        transcript.append_u64(b"fa_modulus_limb", limb);
    }
}

/// Prove the bound gadget over the committed advice region. `advice_bytes`
/// is the exact `program_io.untrusted_advice` byte blob of the main proof;
/// the recomputed region commitment MUST equal the main proof's
/// `untrusted_advice_commitment` (the verifier checks against that object).
pub fn prove_field_accel_bound<F, PCS, T>(
    advice_bytes: &[u8],
    max_untrusted_advice_size: usize,
    params: &FieldAccelParams,
    setup: &PCS::ProverSetup,
    transcript: &mut T,
) -> Result<FieldAccelBoundProof<F, PCS>, &'static str>
where
    F: JoltField,
    PCS: CommitmentScheme<Field = F>,
    T: Transcript,
{
    let words = region_words(advice_bytes, max_untrusted_advice_size);
    assert!(words.len().is_power_of_two(), "region word count must be a power of two");
    let advice_vars = words.len().trailing_zeros() as usize;

    let (_n, rows) = parse_region_rows(&words)?;
    let records: Vec<FieldOpRecord> = rows.iter().map(row_to_record).collect();
    let witness = FieldAccelWitness::from_records(&records, params);
    let log_rows = witness.padded_len().trailing_zeros() as usize;
    if RECORD_WORDS << log_rows > words.len() {
        return Err("padded rows exceed the committed region");
    }

    // Commit (advice re-commit for the hint; aux fresh), then absorb both
    // BEFORE any challenge.
    let advice_poly = MultilinearPolynomial::from(words.clone());
    let (advice_commitment, advice_hint) = {
        let _guard =
            DoryGlobals::initialize_context(1, words.len(), DoryContext::UntrustedAdvice, None);
        let _ctx = DoryGlobals::with_context(DoryContext::UntrustedAdvice);
        pcs_pool().install(|| PCS::commit(&advice_poly, setup))
    };
    let aux = aux_vector::<F>(&witness);
    let aux_poly = MultilinearPolynomial::from(aux);
    let (aux_commitment, aux_hint) = {
        let _guard =
            DoryGlobals::initialize_context(1, aux_poly.len(), DoryContext::UntrustedAdvice, None);
        let _ctx = DoryGlobals::with_context(DoryContext::UntrustedAdvice);
        pcs_pool().install(|| PCS::commit(&aux_poly, setup))
    };

    bind_bound_statement(params, log_rows, advice_vars, transcript);
    transcript.append_serializable(b"fa_advice_commitment", &advice_commitment);
    transcript.append_serializable(b"fa_aux_commitment", &aux_commitment);

    let tau: Vec<F> = transcript.challenge_vector(log_rows);
    let ch = BatchingChallenges::draw(transcript);
    let q_words = params.modulus_limbs.map(F::from_u64);

    let mut cols = super::sumcheck::witness_columns::<F>(&witness);
    let (round_polys, r_row) = zero_check_prove(&mut cols, &tau, &ch, &q_words, transcript);

    let word_corner_evals: Vec<F> = cols[..NUM_WORD_COLUMNS].iter().map(|c| c[0]).collect();
    let aux_corner_evals: Vec<F> = cols[NUM_WORD_COLUMNS..].iter().map(|c| c[0]).collect();
    debug_assert_eq!(aux_corner_evals.len(), NUM_AUX_COLUMNS);

    transcript.append_scalars(b"fa_word_corners", &word_corner_evals);
    transcript.append_scalars(b"fa_aux_corners", &aux_corner_evals);

    let rho: Vec<F::Challenge> = transcript.challenge_vector_optimized::<F>(WORD_BITS);
    let sigma: Vec<F::Challenge> = transcript.challenge_vector_optimized::<F>(AUX_COL_BITS);

    // Advice opening at (high zeros ‖ r_row ‖ ρ) — the interpolated claim.
    let advice_point = be_point::<F>(advice_vars, &r_row, &rho);
    let advice_claim = interpolate_corners::<F>(&word_corner_evals, &rho, WORD_BITS);
    // Header opening at the all-zero point (region word 0).
    let header_point = vec![F::Challenge::from(0u128); advice_vars];
    let header_word = words[0];
    // Aux opening at (r_row ‖ σ).
    let aux_vars = log_rows + AUX_COL_BITS;
    let aux_point = be_point::<F>(aux_vars, &r_row, &sigma);
    let aux_claim = interpolate_corners::<F>(&aux_corner_evals, &sigma, AUX_COL_BITS);

    let (advice_opening, header_opening) = {
        let _guard =
            DoryGlobals::initialize_context(1, words.len(), DoryContext::UntrustedAdvice, None);
        let _ctx = DoryGlobals::with_context(DoryContext::UntrustedAdvice);
        let (advice_opening, _) = pcs_pool().install(|| {
            PCS::prove(
                setup,
                &advice_poly,
                &advice_point,
                Some(advice_hint.clone()),
                transcript,
            )
        });
        let (header_opening, _) = pcs_pool()
            .install(|| PCS::prove(setup, &advice_poly, &header_point, Some(advice_hint), transcript));
        (advice_opening, header_opening)
    };
    let aux_opening = {
        let _guard =
            DoryGlobals::initialize_context(1, aux_poly.len(), DoryContext::UntrustedAdvice, None);
        let _ctx = DoryGlobals::with_context(DoryContext::UntrustedAdvice);
        let (aux_opening, _) =
            pcs_pool().install(|| PCS::prove(setup, &aux_poly, &aux_point, Some(aux_hint), transcript));
        aux_opening
    };

    Ok(FieldAccelBoundProof {
        aux_commitment,
        log_rows,
        round_polys,
        word_corner_evals,
        aux_corner_evals,
        header_word,
        advice_claim,
        advice_opening,
        header_opening,
        aux_claim,
        aux_opening,
    })
}

/// Verify the bound gadget against the MAIN proof's untrusted-advice
/// commitment. `max_untrusted_advice_size` is the verifier-known memory
/// layout constant of the guest.
pub fn verify_field_accel_bound<F, PCS, T>(
    proof: &FieldAccelBoundProof<F, PCS>,
    advice_commitment: &PCS::Commitment,
    max_untrusted_advice_size: usize,
    params: &FieldAccelParams,
    setup: &PCS::VerifierSetup,
    transcript: &mut T,
) -> Result<(), &'static str>
where
    F: JoltField,
    PCS: CommitmentScheme<Field = F>,
    T: Transcript,
{
    let region_word_count = max_untrusted_advice_size / 8;
    if !region_word_count.is_power_of_two() {
        return Err("region word count must be a power of two");
    }
    let advice_vars = region_word_count.trailing_zeros() as usize;

    // Derive the record count from the committed header word — no trusted
    // counts. The header opening below authenticates `header_word`.
    let (len, varint_size) = decode_header_word(proof.header_word)?;
    let pad = 128 - varint_size;
    if len < pad || (len - pad) % 128 != 0 {
        return Err("blob length violates the pad rule");
    }
    let n = (len - pad) / 128;
    let expected_rows = (n + 1).max(1).next_power_of_two();
    if proof.log_rows != expected_rows.trailing_zeros() as usize {
        return Err("log_rows does not match the committed record count");
    }
    if RECORD_WORDS << proof.log_rows > region_word_count {
        return Err("padded rows exceed the committed region");
    }
    if proof.word_corner_evals.len() != NUM_WORD_COLUMNS
        || proof.aux_corner_evals.len() != NUM_AUX_COLUMNS
    {
        return Err("wrong number of corner evaluations");
    }

    bind_bound_statement(params, proof.log_rows, advice_vars, transcript);
    transcript.append_serializable(b"fa_advice_commitment", advice_commitment);
    transcript.append_serializable(b"fa_aux_commitment", &proof.aux_commitment);

    let tau: Vec<F> = transcript.challenge_vector(proof.log_rows);
    let ch = BatchingChallenges::draw(transcript);
    let q_words = params.modulus_limbs.map(F::from_u64);

    let (r_row, claim) = zero_check_verify(&proof.round_polys, proof.log_rows, transcript)?;

    // Final zero-check equation from the corner evaluations.
    let mut final_evals = Vec::with_capacity(NUM_TOTAL_COLUMNS);
    final_evals.extend_from_slice(&proof.word_corner_evals);
    final_evals.extend_from_slice(&proof.aux_corner_evals);
    let c = constraint_eval(&final_evals, &q_words, &ch);
    if claim != eq_at(&tau, &r_row) * c {
        return Err("final sumcheck evaluation check failed");
    }

    transcript.append_scalars(b"fa_word_corners", &proof.word_corner_evals);
    transcript.append_scalars(b"fa_aux_corners", &proof.aux_corner_evals);

    let rho: Vec<F::Challenge> = transcript.challenge_vector_optimized::<F>(WORD_BITS);
    let sigma: Vec<F::Challenge> = transcript.challenge_vector_optimized::<F>(AUX_COL_BITS);

    // The corner claims must interpolate to the opened evaluations
    // (Schwartz-Zippel over the word / column variables).
    if interpolate_corners::<F>(&proof.word_corner_evals, &rho, WORD_BITS) != proof.advice_claim {
        return Err("word corner interpolation mismatch");
    }
    if interpolate_corners::<F>(&proof.aux_corner_evals, &sigma, AUX_COL_BITS) != proof.aux_claim {
        return Err("aux corner interpolation mismatch");
    }

    let advice_point = be_point::<F>(advice_vars, &r_row, &rho);
    let header_point = vec![F::Challenge::from(0u128); advice_vars];
    let aux_point = be_point::<F>(proof.log_rows + AUX_COL_BITS, &r_row, &sigma);

    {
        let _guard =
            DoryGlobals::initialize_context(1, region_word_count, DoryContext::UntrustedAdvice, None);
        let _ctx = DoryGlobals::with_context(DoryContext::UntrustedAdvice);
        PCS::verify(
            &proof.advice_opening,
            setup,
            transcript,
            &advice_point,
            &proof.advice_claim,
            advice_commitment,
        )
        .map_err(|_| "advice opening verification failed")?;
        PCS::verify(
            &proof.header_opening,
            setup,
            transcript,
            &header_point,
            &F::from_u64(proof.header_word),
            advice_commitment,
        )
        .map_err(|_| "header opening verification failed")?;
    }
    {
        let aux_len = 1usize << (proof.log_rows + AUX_COL_BITS);
        let _guard =
            DoryGlobals::initialize_context(1, aux_len, DoryContext::UntrustedAdvice, None);
        let _ctx = DoryGlobals::with_context(DoryContext::UntrustedAdvice);
        PCS::verify(
            &proof.aux_opening,
            setup,
            transcript,
            &aux_point,
            &proof.aux_claim,
            &proof.aux_commitment,
        )
        .map_err(|_| "aux opening verification failed")?;
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::poly::multilinear_polynomial::PolynomialEvaluation;
    use ark_bn254::Fr;

    #[test]
    fn be_point_orientation_matches_evaluate() {
        // 3-var poly over indices 0..8; challenge j binds index bit j
        // (little-endian), the BE point lists variables msb-first.
        let v: Vec<u64> = (0..8).map(|i| (i * i + 3) as u64).collect();
        let poly = MultilinearPolynomial::<Fr>::from(v.clone());
        let r: Vec<<Fr as crate::field::JoltField>::Challenge> =
            vec![7u128.into(), 11u128.into(), 13u128.into()];
        let r_f: Vec<Fr> = r.iter().map(|c| (*c).into()).collect();
        let table = eq_table::<Fr>(&r_f);
        let expected: Fr = v
            .iter()
            .zip(table.iter())
            .map(|(val, e)| Fr::from(*val) * *e)
            .sum();
        // BE point = [r2, r1, r0]
        let be: Vec<_> = r.iter().rev().copied().collect();
        assert_eq!(poly.evaluate(&be), expected);
        // all-zero point evaluates to index 0
        let zeros = vec![<Fr as crate::field::JoltField>::Challenge::from(0u128); 3];
        assert_eq!(poly.evaluate(&zeros), Fr::from(v[0]));
    }

    #[test]
    fn header_varint_roundtrip() {
        // len = 128128 (1000 records + pad 125, varint 3 bytes)
        let len = 125usize + 128_000;
        let mut bytes = [0u8; 8];
        let mut v = len;
        let mut i = 0;
        while v >= 0x80 {
            bytes[i] = (v as u8 & 0x7f) | 0x80;
            v >>= 7;
            i += 1;
        }
        bytes[i] = v as u8;
        let word = u64::from_le_bytes(bytes);
        let (decoded, size) = decode_header_word(word).unwrap();
        assert_eq!(decoded, len);
        assert_eq!(size, 3);
        assert_eq!(128 - size, 125);
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod roundtrip_tests {
    use super::super::{limbs_to_biguint, FieldOpRecord};
    use super::*;
    use crate::poly::commitment::dory::DoryCommitmentScheme;
    use crate::transcripts::Blake2bTranscript;
    use ark_bn254::Fr;

    const TEST_MODULUS: [u64; 4] = [
        0x0a11800000000001,
        0x59aa76fed0000001,
        0x60b44d1e5c37b001,
        0x12ab655e9a2ca556,
    ];
    const MAX_ADVICE: usize = 8192; // 1024 region words

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

    fn varint(mut v: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while v >= 0x80 {
            out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
        out
    }

    /// Postcard-framed advice bytes: varint(len) ++ pad zeros ++ blocks,
    /// with the self-anchoring pad rule (blocks at region word 16).
    fn encode_advice(records: &[FieldOpRecord]) -> Vec<u8> {
        let blocks = records.len() * 128;
        let mut pad = 128 - varint(blocks + 8).len();
        loop {
            let candidate = 128 - varint(blocks + pad).len();
            if candidate == pad {
                break;
            }
            pad = candidate;
        }
        let len = pad + blocks;
        let mut bytes = varint(len);
        bytes.extend(std::iter::repeat_n(0u8, pad));
        for rec in records {
            for value in [rec.x, rec.y, rec.z, rec.w] {
                for limb in value {
                    bytes.extend_from_slice(&limb.to_le_bytes());
                }
            }
        }
        bytes
    }

    fn test_records(n: usize) -> Vec<FieldOpRecord> {
        let mut s = 4242u64;
        (0..n)
            .map(|_| mulmod_record(random_element(&mut s), random_element(&mut s)))
            .collect()
    }

    #[test]
    fn bound_roundtrip_and_negatives() {
        let records = test_records(5);
        let advice_bytes = encode_advice(&records);
        let setup = DoryCommitmentScheme::setup_prover(14);
        let verifier_setup = DoryCommitmentScheme::setup_verifier(&setup);

        let mut pt = Blake2bTranscript::new(b"fa_bound_test");
        let proof = prove_field_accel_bound::<Fr, DoryCommitmentScheme, _>(
            &advice_bytes,
            MAX_ADVICE,
            &params(),
            &setup,
            &mut pt,
        )
        .unwrap();

        // the advice commitment the verifier holds (from the main proof, in
        // the e2e flow) — recompute it the same way the prover pipeline does
        let words = region_words(&advice_bytes, MAX_ADVICE);
        let advice_poly = MultilinearPolynomial::<Fr>::from(words);
        let (advice_commitment, _) = {
            let _guard = DoryGlobals::initialize_context(
                1,
                MAX_ADVICE / 8,
                DoryContext::UntrustedAdvice,
                None,
            );
            let _ctx = DoryGlobals::with_context(DoryContext::UntrustedAdvice);
            DoryCommitmentScheme::commit(&advice_poly, &setup)
        };

        let mut vt = Blake2bTranscript::new(b"fa_bound_test");
        verify_field_accel_bound::<Fr, DoryCommitmentScheme, _>(
            &proof,
            &advice_commitment,
            MAX_ADVICE,
            &params(),
            &verifier_setup,
            &mut vt,
        )
        .unwrap();

        // negative: tampered word corner eval
        let mut bad = proof.clone();
        bad.word_corner_evals[3] += Fr::from(1u64);
        let mut vt = Blake2bTranscript::new(b"fa_bound_test");
        assert!(verify_field_accel_bound::<Fr, DoryCommitmentScheme, _>(
            &bad, &advice_commitment, MAX_ADVICE, &params(), &verifier_setup, &mut vt
        )
        .is_err());

        // negative: tampered aux corner eval
        let mut bad = proof.clone();
        bad.aux_corner_evals[7] += Fr::from(1u64);
        let mut vt = Blake2bTranscript::new(b"fa_bound_test");
        assert!(verify_field_accel_bound::<Fr, DoryCommitmentScheme, _>(
            &bad, &advice_commitment, MAX_ADVICE, &params(), &verifier_setup, &mut vt
        )
        .is_err());

        // negative: forged header word (count shift)
        let mut bad = proof.clone();
        bad.header_word = {
            let (len, _) = decode_header_word(proof.header_word).unwrap();
            let v = varint(len + 128);
            let mut b = [0u8; 8];
            b[..v.len()].copy_from_slice(&v);
            u64::from_le_bytes(b)
        };
        let mut vt = Blake2bTranscript::new(b"fa_bound_test");
        assert!(verify_field_accel_bound::<Fr, DoryCommitmentScheme, _>(
            &bad, &advice_commitment, MAX_ADVICE, &params(), &verifier_setup, &mut vt
        )
        .is_err());

        // negative: verifying against a different advice commitment
        let mut other_bytes = advice_bytes.clone();
        let flip = other_bytes.len() - 5;
        other_bytes[flip] ^= 1;
        let other_words = region_words(&other_bytes, MAX_ADVICE);
        let other_poly = MultilinearPolynomial::<Fr>::from(other_words);
        let (other_commitment, _) = {
            let _guard = DoryGlobals::initialize_context(
                1,
                MAX_ADVICE / 8,
                DoryContext::UntrustedAdvice,
                None,
            );
            let _ctx = DoryGlobals::with_context(DoryContext::UntrustedAdvice);
            DoryCommitmentScheme::commit(&other_poly, &setup)
        };
        let mut vt = Blake2bTranscript::new(b"fa_bound_test");
        assert!(verify_field_accel_bound::<Fr, DoryCommitmentScheme, _>(
            &proof, &other_commitment, MAX_ADVICE, &params(), &verifier_setup, &mut vt
        )
        .is_err());

        // negative: false record (z+1) — the honest prover refuses (record
        // constructor asserts), so tamper at the byte level and try to prove
        let mut false_bytes = encode_advice(&records);
        // z words of record 0 start at byte varint + pad + 64
        let (len, vs) = decode_header_word({
            let mut b = [0u8; 8];
            b.copy_from_slice(&false_bytes[..8]);
            u64::from_le_bytes(b)
        })
        .unwrap();
        let pad = 128 - vs;
        assert_eq!(len, false_bytes.len() - vs);
        false_bytes[vs + pad + 64] ^= 1;
        let mut pt = Blake2bTranscript::new(b"fa_bound_test");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_field_accel_bound::<Fr, DoryCommitmentScheme, _>(
                &false_bytes,
                MAX_ADVICE,
                &params(),
                &setup,
                &mut pt,
            )
        }));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "honest prover must refuse a false record"
        );
    }

    #[test]
    fn bound_zero_records() {
        let advice_bytes = encode_advice(&[]);
        let setup = DoryCommitmentScheme::setup_prover(14);
        let verifier_setup = DoryCommitmentScheme::setup_verifier(&setup);
        let mut pt = Blake2bTranscript::new(b"fa_bound_zero");
        let proof = prove_field_accel_bound::<Fr, DoryCommitmentScheme, _>(
            &advice_bytes,
            MAX_ADVICE,
            &params(),
            &setup,
            &mut pt,
        )
        .unwrap();
        let words = region_words(&advice_bytes, MAX_ADVICE);
        let advice_poly = MultilinearPolynomial::<Fr>::from(words);
        let (advice_commitment, _) = {
            let _guard = DoryGlobals::initialize_context(
                1,
                MAX_ADVICE / 8,
                DoryContext::UntrustedAdvice,
                None,
            );
            let _ctx = DoryGlobals::with_context(DoryContext::UntrustedAdvice);
            DoryCommitmentScheme::commit(&advice_poly, &setup)
        };
        let mut vt = Blake2bTranscript::new(b"fa_bound_zero");
        verify_field_accel_bound::<Fr, DoryCommitmentScheme, _>(
            &proof,
            &advice_commitment,
            MAX_ADVICE,
            &params(),
            &verifier_setup,
            &mut vt,
        )
        .unwrap();
    }
}
