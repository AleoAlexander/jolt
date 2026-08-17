#![expect(clippy::unwrap_used)]

use crate::sdk::{Fq, MODULUS};
use ark_ed_on_bls12_377::Fq as ArkFq;
use ark_ff::{Field, PrimeField, UniformRand, Zero};

#[test]
fn modulus_matches_arkworks() {
    assert_eq!(MODULUS, ArkFq::MODULUS.0, "vendored modulus limb mismatch");
}

#[test]
fn mul_matches_arkworks_1000_random() {
    let mut rng = ark_std::test_rng();
    for _ in 0..1000 {
        let (a, b) = (ArkFq::rand(&mut rng), ArkFq::rand(&mut rng));
        let ours = Fq::from_canonical(a.into_bigint().0).mul(&Fq::from_canonical(b.into_bigint().0));
        assert_eq!(ours.to_canonical(), (a * b).into_bigint().0);
    }
}

#[test]
fn square_matches_arkworks_1000_random() {
    let mut rng = ark_std::test_rng();
    for _ in 0..1000 {
        let a = ArkFq::rand(&mut rng);
        let ours = Fq::from_canonical(a.into_bigint().0).square();
        assert_eq!(ours.to_canonical(), a.square().into_bigint().0);
    }
}

#[test]
fn add_sub_match_arkworks_1000_random() {
    let mut rng = ark_std::test_rng();
    for _ in 0..1000 {
        let (a, b) = (ArkFq::rand(&mut rng), ArkFq::rand(&mut rng));
        let (fa, fb) = (
            Fq::from_canonical(a.into_bigint().0),
            Fq::from_canonical(b.into_bigint().0),
        );
        assert_eq!(fa.add(&fb).to_canonical(), (a + b).into_bigint().0);
        assert_eq!(fa.sub(&fb).to_canonical(), (a - b).into_bigint().0);
    }
}

#[test]
fn edge_cases() {
    let q_minus_1 = {
        let mut m = MODULUS;
        m[0] -= 1;
        Fq::from_canonical(m)
    };
    // (q-1)^2 == 1  (since q-1 == -1 mod q)
    assert_eq!(q_minus_1.square().to_canonical(), [1, 0, 0, 0]);
    // x * 0 == 0; x * 1 == x
    assert_eq!(q_minus_1.mul(&Fq::ZERO), Fq::ZERO);
    assert_eq!(q_minus_1.mul(&Fq::ONE), q_minus_1);
    // 0 - 1 == q - 1
    assert_eq!(Fq::ZERO.sub(&Fq::ONE), q_minus_1);
    // (q-1) + 1 == 0
    assert_eq!(q_minus_1.add(&Fq::ONE), Fq::ZERO);
    // arkworks zero really is our zero
    assert!(Fq::from_canonical(ArkFq::zero().into_bigint().0).is_zero());
}

// --- M4: division / inverse / point ops --------------------------------------

use crate::sdk::{EdwardsPoint, COEFF_D};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::{AdditiveGroup, CurveGroup, PrimeGroup};
type ArkP = ark_ed_on_bls12_377::EdwardsProjective;

fn assert_point_eq(ours: &EdwardsPoint, theirs: &ArkP, ctx: &str) {
    let ta = theirs.into_affine();
    assert_eq!(
        ours.to_affine(),
        (ta.x.into_bigint().0, ta.y.into_bigint().0),
        "{ctx}"
    );
}

#[test]
fn div_inverse_match_arkworks() {
    let mut rng = ark_std::test_rng();
    for _ in 0..500 {
        let (a, b) = (ArkFq::rand(&mut rng), ArkFq::rand(&mut rng));
        let (fa, fb) = (
            Fq::from_canonical(a.into_bigint().0),
            Fq::from_canonical(b.into_bigint().0),
        );
        assert_eq!(
            fa.div(&fb).to_canonical(),
            (a * b.inverse().unwrap()).into_bigint().0
        );
        assert_eq!(
            fb.inverse().unwrap().to_canonical(),
            b.inverse().unwrap().into_bigint().0
        );
    }
    assert!(Fq::ZERO.inverse().is_none());
}

#[test]
fn curve_constants_match_arkworks() {
    type Cfg = ark_ed_on_bls12_377::EdwardsConfig;
    // a = -1
    let minus_one = ArkFq::zero() - ArkFq::from(1u64);
    assert_eq!(<Cfg as TECurveConfig>::COEFF_A, minus_one);
    // d matches our vendored constant
    assert_eq!(
        <Cfg as TECurveConfig>::COEFF_D.into_bigint().0,
        COEFF_D.to_canonical()
    );
    // generator matches
    assert_point_eq(&EdwardsPoint::generator(), &ArkP::generator(), "generator");
}

#[test]
fn point_add_double_match_arkworks() {
    let g_ours = EdwardsPoint::generator();
    let g_ark = ArkP::generator();

    // doubling chain: 2G, 4G, 8G, ... 2^20 G
    let (mut p_ours, mut p_ark) = (g_ours, g_ark);
    for i in 0..20 {
        p_ours = p_ours.double();
        p_ark.double_in_place();
        assert_point_eq(&p_ours, &p_ark, &format!("double chain step {i}"));
    }

    // mixed add/double chain: p = 2p + G interleaved
    let (mut p_ours, mut p_ark) = (g_ours, g_ark);
    for i in 0..20 {
        p_ours = p_ours.double().add(&g_ours);
        p_ark = p_ark + p_ark + g_ark;
        assert_point_eq(&p_ours, &p_ark, &format!("add chain step {i}"));
    }
}

#[test]
fn point_edge_cases() {
    let g = EdwardsPoint::generator();
    // P + identity == P
    assert_point_eq(&g.add(&EdwardsPoint::IDENTITY), &ArkP::generator(), "P + O");
    // P + (-P) == identity == (0, 1)
    let sum = g.add(&g.neg());
    assert_eq!(sum.to_affine(), ([0u64; 4], [1u64, 0, 0, 0]), "P + (-P)");
    // double(identity) == identity
    assert_eq!(
        EdwardsPoint::IDENTITY.double().to_affine(),
        ([0u64; 4], [1u64, 0, 0, 0]),
        "2O"
    );
}

#[test]
fn scalar_mul_matches_arkworks() {
    let mut rng = ark_std::test_rng();
    let g = EdwardsPoint::generator();
    for _ in 0..50 {
        let s = ark_ed_on_bls12_377::Fr::rand(&mut rng);
        let ours = g.scalar_mul(&s.into_bigint().0);
        let theirs = (ArkP::generator() * s).into_affine();
        assert_eq!(
            ours.to_affine(),
            (theirs.x.into_bigint().0, theirs.y.into_bigint().0)
        );
    }
    // edge cases: 0*G == identity, 1*G == G
    assert_eq!(
        g.scalar_mul(&[0, 0, 0, 0]).to_affine(),
        ([0u64; 4], [1u64, 0, 0, 0])
    );
    assert_point_eq(&g.scalar_mul(&[1, 0, 0, 0]), &ArkP::generator(), "1*G");
}

// --- B2 record blob (plan Task 2) -------------------------------------------

#[test]
fn record_blob_layout_and_identity() {
    use crate::sequence_builder::{build_record_blob, record_from_xyz};
    use jolt_inlines_sdk::host::{limbs_to_nbiguint, NBigUint};

    let q = limbs_to_nbiguint(&crate::sdk::MODULUS);
    let a = Fq { e: [3, 1, 4, 0x100] };
    let b = Fq { e: [2, 7, 1, 0x80] };
    let c = a.mul(&b);

    let rec = record_from_xyz(a.e, b.e, c.e);
    // rec = (x, y, z, w) with x*y == w*q + z exactly over the integers
    let (x, y, z, w) = rec;
    assert_eq!(x, a.e);
    assert_eq!(y, b.e);
    assert_eq!(z, c.e);
    let lhs = limbs_to_nbiguint(&x) * limbs_to_nbiguint(&y);
    let rhs = limbs_to_nbiguint(&w) * &q + limbs_to_nbiguint(&z);
    assert_eq!(lhs, rhs, "x*y == w*q + z");

    // Div normalization: block is (c, b, a) with c*b == w*q + a
    let quotient = a.div(&b);
    let (dx, dy, dz, dw) = record_from_xyz(quotient.e, b.e, a.e);
    let dlhs = limbs_to_nbiguint(&dx) * limbs_to_nbiguint(&dy);
    let drhs = limbs_to_nbiguint(&dw) * &q + limbs_to_nbiguint(&dz);
    assert_eq!(dlhs, drhs, "c*b == w*q + a");

    // blob: 16-word blocks in record order
    let blob = build_record_blob(&[rec, (dx, dy, dz, dw)]);
    assert_eq!(blob.len(), 32);
    assert_eq!(&blob[0..4], &x);
    assert_eq!(&blob[4..8], &y);
    assert_eq!(&blob[8..12], &z);
    assert_eq!(&blob[12..16], &w);
    assert_eq!(&blob[16..20], &dx);
    assert_eq!(&blob[28..32], &dw);
    let _ = NBigUint::ZERO; // silence unused-import lint if asserts compile out
}

#[test]
fn field_op_log_returns_xyzw_tuples() {
    use crate::sequence_builder::{log_record_for_test, take_field_op_log};
    let a = Fq { e: [5, 0, 0, 0] };
    let b = Fq { e: [7, 0, 0, 0] };
    let c = a.mul(&b);
    let _ = take_field_op_log(); // drain
    log_record_for_test(a.e, b.e, c.e);
    let log = take_field_op_log();
    assert_eq!(log.len(), 1);
    let (x, y, z, w) = log[0];
    assert_eq!((x, y, z), (a.e, b.e, c.e));
    assert_eq!(w, [0, 0, 0, 0], "5*7=35 < q so quotient is 0");
}

#[test]
fn padded_blob_satisfies_guest_pad_rule() {
    use crate::bind::{head_pad, RECORD_BYTES};
    use crate::sequence_builder::{build_record_blob_padded, record_from_xyz};

    let a = Fq { e: [3, 1, 4, 0x100] };
    let b = Fq { e: [2, 7, 1, 0x80] };
    let c = a.mul(&b);
    let rec = record_from_xyz(a.e, b.e, c.e);

    for n in [1usize, 2, 5, 1000] {
        let records = vec![rec; n];
        let blob = build_record_blob_padded(&records);
        let pad = head_pad(blob.len());
        assert!(blob.len() >= pad);
        assert_eq!((blob.len() - pad) % RECORD_BYTES, 0, "n={n}");
        assert_eq!((blob.len() - pad) / RECORD_BYTES, n, "n={n}");
        // pad bytes are zero; first block starts with x0
        assert!(blob[..pad].iter().all(|&v| v == 0));
        assert_eq!(&blob[pad..pad + 8], &rec.0[0].to_le_bytes());
    }
}
