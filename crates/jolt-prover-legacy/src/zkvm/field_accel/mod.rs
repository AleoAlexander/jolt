//! PROTOTYPE (branch aleo/field-accel-prototype): foreign-field acceleration
//! witness — the invocation log in the B2 64-bit word schema.
//!
//! Every advice-backed field op contributes one record satisfying
//! `x * y = w * q + z` over the integers (Mul: (a,b,c); Square: (a,a,c);
//! Div normalizes to (c,b,a)). The identity is checked directly over the
//! four 64-bit words of each value — the same words that sit in the
//! committed untrusted-advice region as the record's 16-word block — via
//! seven product columns and six committed offset carries, with 2-bit-digit
//! range checks on the carries (sumcheck.rs). See CARRY_BOUNDS.md.

/// B2 batched verification sumcheck. Gated so the prototype surface is
/// opt-in for consumers, but always compiled for tests.
#[cfg(any(test, feature = "field-accel-prototype"))]
pub mod sumcheck;

/// B2 bound gadget: the zero-check with commitment-bound evaluations
/// (advice-region words + committed aux columns).
#[cfg(any(test, feature = "field-accel-prototype"))]
pub mod bound;

use num_bigint::BigUint;

/// Guest-declared modulus. Not hardcoded to any curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldAccelParams {
    pub modulus_limbs: [u64; 4],
}

impl FieldAccelParams {
    pub fn modulus(&self) -> BigUint {
        limbs_to_biguint(&self.modulus_limbs)
    }
}

/// One field-op invocation, normalized so the verified identity is always
/// `x * y = w * q + z` over the integers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldOpRecord {
    pub x: [u64; 4],
    pub y: [u64; 4],
    pub z: [u64; 4],
    pub w: [u64; 4],
}

impl FieldOpRecord {
    /// Build a record from (x, y, z) with x*y ≡ z (mod q); derives w.
    /// Panics if the identity does not hold exactly (prototype: the tracer
    /// is honest; the gadget is what catches dishonest logs).
    pub fn new(x: [u64; 4], y: [u64; 4], z: [u64; 4], params: &FieldAccelParams) -> Self {
        let q = params.modulus();
        let product = limbs_to_biguint(&x) * limbs_to_biguint(&y);
        let z_big = limbs_to_biguint(&z);
        assert!(product >= z_big, "record does not satisfy x*y >= z");
        let diff = product - z_big;
        assert!(
            (&diff % &q) == BigUint::ZERO,
            "record does not satisfy x*y ≡ z (mod q)"
        );
        let w_big = diff / q;
        Self {
            x,
            y,
            z,
            w: biguint_to_limbs(&w_big),
        }
    }
}

pub fn limbs_to_biguint(limbs: &[u64; 4]) -> BigUint {
    let mut bytes = Vec::with_capacity(32);
    for limb in limbs {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

fn biguint_to_limbs(v: &BigUint) -> [u64; 4] {
    let bytes = v.to_bytes_le();
    assert!(bytes.len() <= 32, "value exceeds 256 bits");
    let mut limbs = [0u64; 4];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut b = [0u8; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        limbs[i] = u64::from_le_bytes(b);
    }
    limbs
}

/// Number of 64-bit product columns: words i + j = k for i, j in 0..4.
pub const NUM_PRODUCT_COLUMNS: usize = 7;
/// Number of carry columns (no carry out of the last column).
pub const NUM_CARRIES: usize = 6;
/// Carries are committed with this offset so the committed value is
/// non-negative: carry' = carry + CARRY_OFFSET. |carry| < 2^67.2 (see
/// CARRY_BOUNDS.md), so carry' < 2^69 fits DIGITS_PER_CARRY 2-bit digits.
pub const CARRY_OFFSET: i128 = 1 << 68;
/// 2-bit digits per committed carry (70 bits ≥ the 69-bit bound).
pub const DIGITS_PER_CARRY: usize = 35;
/// Total committed digit columns.
pub const NUM_DIGIT_COLUMNS: usize = NUM_CARRIES * DIGITS_PER_CARRY;

/// Per-record signed carries balancing the seven 64-bit product columns:
///   S_k = Σ_{i+j=k} x_i·y_j − Σ_{i+j=k} w_i·q_j − z_k·[k<4]
///   S_0 = carry_0·2^64;  S_k + carry_{k−1} = carry_k·2^64 (k=1..5);
///   S_6 + carry_5 = 0.
pub fn column_carries_64(record: &FieldOpRecord, params: &FieldAccelParams) -> [i128; NUM_CARRIES] {
    use num_bigint::BigInt;
    let x = record.x.map(BigInt::from);
    let y = record.y.map(BigInt::from);
    let z = record.z.map(BigInt::from);
    let w = record.w.map(BigInt::from);
    let q = params.modulus_limbs.map(BigInt::from);

    let mut carries = [0i128; NUM_CARRIES];
    let mut carry_in = BigInt::ZERO;
    let two_64 = BigInt::from(1u128 << 64);
    for k in 0..NUM_PRODUCT_COLUMNS {
        let mut s = BigInt::ZERO;
        for i in 0..4usize {
            let Some(j) = k.checked_sub(i) else { continue };
            if j >= 4 {
                continue;
            }
            s += &x[i] * &y[j];
            s -= &w[i] * &q[j];
        }
        if k < 4 {
            s -= &z[k];
        }
        s += &carry_in;
        if k == NUM_PRODUCT_COLUMNS - 1 {
            assert_eq!(s, BigInt::ZERO, "column 6 must balance exactly");
        } else {
            let carry = &s / &two_64;
            assert_eq!(&carry * &two_64, s, "column {k} not divisible by 2^64");
            carries[k] = i128::try_from(&carry).expect("carry exceeds i128");
            carry_in = carry;
        }
    }
    carries
}

/// The committed gadget witness, one entry per record row, padded with
/// all-zero records (which satisfy the identity trivially) to a power of
/// two. `words` are the same values as the record's 16-word block in the
/// committed advice region (order: x0..3, y0..3, z0..3, w0..3); only
/// `carries` (offset) and `digits` are gadget-committed columns in the
/// bound protocol.
#[derive(Clone, Debug)]
pub struct FieldAccelWitness {
    pub words: [Vec<u64>; 16],
    /// Offset carries: carry + CARRY_OFFSET, in [0, 2^69).
    pub carries: [Vec<u128>; NUM_CARRIES],
    /// 2-bit digits of each offset carry, little-endian:
    /// digits[j * DIGITS_PER_CARRY + d][row] = (carries[j][row] >> 2d) & 3.
    pub digits: Vec<Vec<u8>>,
    pub num_records: usize,
}

impl FieldAccelWitness {
    #[expect(
        clippy::expect_used,
        reason = "callers validate records first; a violating record here is a caller bug"
    )]
    pub fn from_records(records: &[FieldOpRecord], params: &FieldAccelParams) -> Self {
        let n = records.len().max(1).next_power_of_two();
        let mut words: [Vec<u64>; 16] = Default::default();
        let mut carries: [Vec<u128>; NUM_CARRIES] = Default::default();
        let mut digits: Vec<Vec<u8>> = (0..NUM_DIGIT_COLUMNS)
            .map(|_| Vec::with_capacity(n))
            .collect();
        for col in words.iter_mut() {
            col.reserve(n);
        }
        for col in carries.iter_mut() {
            col.reserve(n);
        }
        for record in records {
            for (v, value) in [record.x, record.y, record.z, record.w].iter().enumerate() {
                for (i, word) in value.iter().enumerate() {
                    words[v * 4 + i].push(*word);
                }
            }
            let record_carries = column_carries_64(record, params);
            for (j, carry) in record_carries.iter().enumerate() {
                let offset = u128::try_from(carry + CARRY_OFFSET)
                    .expect("offset carry must be non-negative");
                assert!(
                    offset < (1u128 << (2 * DIGITS_PER_CARRY)),
                    "carry out of range"
                );
                carries[j].push(offset);
                for d in 0..DIGITS_PER_CARRY {
                    digits[j * DIGITS_PER_CARRY + d].push(((offset >> (2 * d)) & 3) as u8);
                }
            }
        }
        // zero-pad: the all-zero record satisfies 0*0 = 0*q + 0 with zero
        // carries, whose offset form is CARRY_OFFSET itself.
        let zero_offset = u128::try_from(CARRY_OFFSET).expect("offset positive");
        for col in words.iter_mut() {
            col.resize(n, 0);
        }
        for j in 0..NUM_CARRIES {
            carries[j].resize(n, zero_offset);
            for d in 0..DIGITS_PER_CARRY {
                digits[j * DIGITS_PER_CARRY + d].resize(n, ((zero_offset >> (2 * d)) & 3) as u8);
            }
        }
        FieldAccelWitness {
            words,
            carries,
            digits,
            num_records: records.len(),
        }
    }

    pub fn padded_len(&self) -> usize {
        self.words[0].len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BLS12-377 Fr (the Aleo curve's base field) — used as *a* test modulus;
    // the module itself is modulus-generic.
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

    fn xorshift(s: &mut u64) -> u64 {
        let mut x = *s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *s = x;
        x
    }

    fn random_element(s: &mut u64) -> [u64; 4] {
        // < 2^250 < q
        let mut limbs = [0u64; 4];
        for limb in limbs.iter_mut() {
            *limb = xorshift(s);
        }
        limbs[3] &= (1u64 << 58) - 1;
        limbs
    }

    #[test]
    fn word_column_carries_balance() {
        let mut s = 7u64;
        for _ in 0..100 {
            let (a, b) = (random_element(&mut s), random_element(&mut s));
            let record = mulmod_record(a, b);
            // column_carries_64 panics internally if any column fails to
            // balance; carry magnitudes stay below 2^68 (CARRY_BOUNDS.md)
            let carries = column_carries_64(&record, &params());
            assert!(carries.iter().all(|c| c.unsigned_abs() < (1u128 << 68)));
        }
    }

    #[test]
    fn witness_pads_to_power_of_two_with_valid_zero_records() {
        let mut s = 99u64;
        let records: Vec<_> = (0..5)
            .map(|_| mulmod_record(random_element(&mut s), random_element(&mut s)))
            .collect();
        let w = FieldAccelWitness::from_records(&records, &params());
        assert_eq!(w.padded_len(), 8);
        assert_eq!(w.num_records, 5);
        // padding rows: zero words, offset carries equal to CARRY_OFFSET,
        // digits recompose to the offset
        for col in w.words.iter() {
            assert_eq!(&col[5..], &[0, 0, 0]);
        }
        let zero_offset = u128::try_from(CARRY_OFFSET).unwrap();
        for j in 0..NUM_CARRIES {
            assert_eq!(&w.carries[j][5..], &[zero_offset; 3]);
            for row in 5..8 {
                let recomposed: u128 = (0..DIGITS_PER_CARRY)
                    .map(|d| (w.digits[j * DIGITS_PER_CARRY + d][row] as u128) << (2 * d))
                    .sum();
                assert_eq!(recomposed, zero_offset);
            }
        }
    }
}
