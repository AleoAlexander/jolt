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
