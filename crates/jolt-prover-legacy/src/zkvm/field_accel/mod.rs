//! PROTOTYPE (branch aleo/field-accel-prototype): foreign-field acceleration
//! witness — the invocation log and its 86-bit-limb decomposition.
//!
//! Every advice-backed field op contributes one record satisfying
//! `x * y = w * q + z` over the integers (Mul: (a,b,c); Square: (a,a,c);
//! Div normalizes to (c,b,a)). The B1 batched sumcheck (sumcheck.rs) proves
//! all records at once via the per-column limb equation; see CARRY_BOUNDS.md
//! for the soundness bounds that B2 range checks must enforce.
//!
//! PROTOTYPE: records are collected by the host example (thread-local log in
//! the inline crate) rather than plumbed through witness generation.

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

    /// Modulus as three 86-bit limbs (public inputs of the gadget).
    pub fn modulus_limbs_86(&self) -> [u128; 3] {
        limbs_86(&self.modulus_limbs)
    }
}

/// One field-op invocation, normalized so the verified identity is always
/// `x * y = w * q + z` with x, y, z, w < 2^253.
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
    /// is honest; the sumcheck is what catches dishonest logs).
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

/// Decompose a 256-bit little-endian limb value into three 86-bit limbs
/// (86 + 86 + 84 bits of capacity; inputs are < 2^253).
pub fn limbs_86(x: &[u64; 4]) -> [u128; 3] {
    const MASK_86: u128 = (1u128 << 86) - 1;
    let lo = x[0] as u128 | ((x[1] as u128) << 64); // bits 0..128
    let hi = x[2] as u128 | ((x[3] as u128) << 64); // bits 128..256
    let l0 = lo & MASK_86;
    let l1 = ((lo >> 86) | (hi << 42)) & MASK_86; // bits 86..172
    let l2 = hi >> 44; // bits 172..256
    [l0, l1, l2]
}

/// Recompose (test helper / documentation of the layout).
pub fn recompose_86(l: &[u128; 3]) -> BigUint {
    BigUint::from(l[0]) + (BigUint::from(l[1]) << 86) + (BigUint::from(l[2]) << 172)
}

/// Per-record signed carries balancing the five product columns:
///   S_k = Σ_{i+j=k} xL_i·yL_j − Σ_{i+j=k} wL_i·qL_j − zL_k·[k<3]
///   S_0 = carry_0·2^86;  S_k + carry_{k−1} = carry_k·2^86 (k=1..4, carry_4 = 0)
/// Carries are signed (w·q is subtracted); see CARRY_BOUNDS.md.
pub fn column_carries(record: &FieldOpRecord, params: &FieldAccelParams) -> [i128; 4] {
    use num_bigint::BigInt;
    let x = limbs_86(&record.x).map(BigInt::from);
    let y = limbs_86(&record.y).map(BigInt::from);
    let z = limbs_86(&record.z).map(BigInt::from);
    let w = limbs_86(&record.w).map(BigInt::from);
    let q = params.modulus_limbs_86().map(BigInt::from);

    let mut carries = [0i128; 4];
    let mut carry_in = BigInt::ZERO;
    for k in 0..5usize {
        let mut s = BigInt::ZERO;
        for i in 0..3usize {
            let Some(j) = k.checked_sub(i) else { continue };
            if j >= 3 {
                continue;
            }
            s += &x[i] * &y[j];
            s -= &w[i] * &q[j];
        }
        if k < 3 {
            s -= &z[k];
        }
        s += &carry_in;
        if k == 4 {
            assert_eq!(s, BigInt::ZERO, "column 4 must balance exactly");
        } else {
            let two_86 = BigInt::from(1u128 << 86) * BigInt::from(1u128); // 2^86
            let carry = &s / &two_86;
            assert_eq!(&carry * &two_86, s, "column {k} not divisible by 2^86");
            carries[k] = i128::try_from(&carry).expect("carry exceeds i128");
            carry_in = carry;
        }
    }
    carries
}

/// The 16 committed columns of the gadget witness, one entry per record,
/// padded with all-zero records (which satisfy the identity trivially) to a
/// power of two. Values are held as integers here; Task 5 maps them into the
/// proof field (signed carries via offset).
#[derive(Clone, Debug)]
pub struct FieldAccelWitness {
    pub x_limbs: [Vec<u128>; 3],
    pub y_limbs: [Vec<u128>; 3],
    pub z_limbs: [Vec<u128>; 3],
    pub w_limbs: [Vec<u128>; 3],
    pub carries: [Vec<i128>; 4],
    pub num_records: usize,
}

impl FieldAccelWitness {
    pub fn from_records(records: &[FieldOpRecord], params: &FieldAccelParams) -> Self {
        let n = records.len().max(1).next_power_of_two();
        let mut w = FieldAccelWitness {
            x_limbs: Default::default(),
            y_limbs: Default::default(),
            z_limbs: Default::default(),
            w_limbs: Default::default(),
            carries: Default::default(),
            num_records: records.len(),
        };
        for cols in [&mut w.x_limbs, &mut w.y_limbs, &mut w.z_limbs, &mut w.w_limbs] {
            for col in cols.iter_mut() {
                col.reserve(n);
            }
        }
        for record in records {
            let (x, y, z, wq) = (
                limbs_86(&record.x),
                limbs_86(&record.y),
                limbs_86(&record.z),
                limbs_86(&record.w),
            );
            for i in 0..3 {
                w.x_limbs[i].push(x[i]);
                w.y_limbs[i].push(y[i]);
                w.z_limbs[i].push(z[i]);
                w.w_limbs[i].push(wq[i]);
            }
            let carries = column_carries(record, params);
            for i in 0..4 {
                w.carries[i].push(carries[i]);
            }
        }
        // zero-pad: the all-zero record satisfies 0*0 = 0*q + 0 with zero carries
        for i in 0..3 {
            w.x_limbs[i].resize(n, 0);
            w.y_limbs[i].resize(n, 0);
            w.z_limbs[i].resize(n, 0);
            w.w_limbs[i].resize(n, 0);
        }
        for i in 0..4 {
            w.carries[i].resize(n, 0);
        }
        w
    }

    pub fn padded_len(&self) -> usize {
        self.x_limbs[0].len()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
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
    fn limbs_86_roundtrip() {
        let mut s = 42u64;
        for _ in 0..200 {
            let x = random_element(&mut s);
            let l = limbs_86(&x);
            assert!(l.iter().all(|&v| v < (1u128 << 86)));
            assert_eq!(recompose_86(&l), limbs_to_biguint(&x));
        }
        // edge: max 256-bit value decomposes and recomposes
        let max = [u64::MAX; 4];
        assert_eq!(recompose_86(&limbs_86(&max)), limbs_to_biguint(&max));
    }

    #[test]
    fn record_identity_and_carries_balance() {
        let mut s = 7u64;
        for _ in 0..100 {
            let (a, b) = (random_element(&mut s), random_element(&mut s));
            let record = mulmod_record(a, b);
            // w < 2^253 fits limbs
            assert!(limbs_86(&record.w).iter().all(|&v| v < (1u128 << 86)));
            // column_carries panics internally if any column fails to balance
            let carries = column_carries(&record, &params());
            // carry magnitudes stay well below 2^92 (see CARRY_BOUNDS.md)
            assert!(carries.iter().all(|c| c.unsigned_abs() < (1u128 << 92)));
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
        // padding rows are all zero across every column
        for i in 0..3 {
            assert_eq!(&w.x_limbs[i][5..], &[0, 0, 0]);
            assert_eq!(&w.z_limbs[i][5..], &[0, 0, 0]);
        }
        for i in 0..4 {
            assert_eq!(&w.carries[i][5..], &[0, 0, 0]);
        }
    }
}
