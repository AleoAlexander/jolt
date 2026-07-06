#![expect(clippy::unwrap_used)]

use crate::sdk::{Fq, MODULUS};
use ark_ed_on_bls12_377::Fq as ArkFq;
use ark_ff::{BigInt, Field, PrimeField, UniformRand, Zero};

fn ark(e: [u64; 4]) -> ArkFq {
    ArkFq::new(BigInt(e))
}

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
