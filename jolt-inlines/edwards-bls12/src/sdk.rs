//! Edwards-BLS12 base-field type routed through Jolt inlines.
//!
//! `Fq` holds the canonical (non-Montgomery) little-endian limb representation
//! of an element of the BLS12-377 scalar field (the Aleo curve's base field).
//! mul/square/div execute as single inline instructions in the guest; add/sub
//! are plain limb arithmetic (cheap in RV64 — deliberately no inline).

use serde::{Deserialize, Serialize};

#[cfg(feature = "host")]
use ark_ed_on_bls12_377::Fq as ArkFq;
#[cfg(feature = "host")]
use ark_ff::{BigInt, Field, PrimeField};

/// BLS12-377 Fr modulus limbs (little-endian): the Aleo curve's base field.
pub const MODULUS: [u64; 4] = [
    0x0a11800000000001,
    0x59aa76fed0000001,
    0x60b44d1e5c37b001,
    0x12ab655e9a2ca556,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fq {
    pub(crate) e: [u64; 4],
}

/// `true` iff `x >= q` (non-canonical).
#[inline(always)]
fn is_fq_non_canonical(x: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if x[i] < MODULUS[i] {
            return false;
        }
        if x[i] > MODULUS[i] {
            return true;
        }
    }
    true // x == q
}

/// Limb add with carry chain; returns (sum, carry).
#[inline(always)]
fn adc(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut carry = false;
    for i in 0..4 {
        let (v1, c1) = a[i].overflowing_add(b[i]);
        let (v2, c2) = v1.overflowing_add(u64::from(carry));
        out[i] = v2;
        carry = c1 | c2;
    }
    (out, carry)
}

/// Limb sub with borrow chain; returns (diff, borrow).
#[inline(always)]
fn sbb(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (v1, b1) = a[i].overflowing_sub(b[i]);
        let (v2, b2) = v1.overflowing_sub(u64::from(borrow));
        out[i] = v2;
        borrow = b1 | b2;
    }
    (out, borrow)
}

impl Fq {
    pub const ZERO: Fq = Fq { e: [0; 4] };
    pub const ONE: Fq = Fq { e: [1, 0, 0, 0] };

    /// Canonical little-endian limbs. Panics on non-canonical input in debug.
    pub fn from_canonical(e: [u64; 4]) -> Self {
        debug_assert!(!is_fq_non_canonical(&e), "non-canonical Fq input");
        Fq { e }
    }

    pub fn to_canonical(&self) -> [u64; 4] {
        self.e
    }

    pub fn from_u64(v: u64) -> Self {
        Fq { e: [v, 0, 0, 0] }
    }

    /// q is 253-bit so the 256-bit add never overflows; reduce once if >= q.
    pub fn add(&self, other: &Fq) -> Fq {
        let (sum, carry) = adc(&self.e, &other.e);
        debug_assert!(!carry, "253-bit canonical adds cannot carry out");
        if is_fq_non_canonical(&sum) {
            let (reduced, _) = sbb(&sum, &MODULUS);
            Fq { e: reduced }
        } else {
            Fq { e: sum }
        }
    }

    pub fn sub(&self, other: &Fq) -> Fq {
        let (diff, borrow) = sbb(&self.e, &other.e);
        if borrow {
            let (wrapped, _) = adc(&diff, &MODULUS);
            Fq { e: wrapped }
        } else {
            Fq { e: diff }
        }
    }

    pub fn is_zero(&self) -> bool {
        self.e == [0; 4]
    }
}

#[cfg(all(target_arch = "riscv64", not(feature = "host")))]
impl Fq {
    pub fn mul(&self, other: &Fq) -> Fq {
        let mut e = [0u64; 4];
        unsafe {
            use crate::{EDBLS_FUNCT7, EDBLS_MULQ_FUNCT3, INLINE_OPCODE};
            core::arch::asm!(
                ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
                opcode = const INLINE_OPCODE,
                funct3 = const EDBLS_MULQ_FUNCT3,
                funct7 = const EDBLS_FUNCT7,
                rd = in(reg) e.as_mut_ptr(),
                rs1 = in(reg) self.e.as_ptr(),
                rs2 = in(reg) other.e.as_ptr(),
                options(nostack)
            );
        }
        if is_fq_non_canonical(&e) {
            jolt_inlines_sdk::spoil_proof();
        }
        crate::bind::weld(&self.e, &other.e, &e);
        Fq { e }
    }

    pub fn square(&self) -> Fq {
        let mut e = [0u64; 4];
        unsafe {
            use crate::{EDBLS_FUNCT7, EDBLS_SQUAREQ_FUNCT3, INLINE_OPCODE};
            core::arch::asm!(
                ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, x0",
                opcode = const INLINE_OPCODE,
                funct3 = const EDBLS_SQUAREQ_FUNCT3,
                funct7 = const EDBLS_FUNCT7,
                rd = in(reg) e.as_mut_ptr(),
                rs1 = in(reg) self.e.as_ptr(),
                options(nostack)
            );
        }
        if is_fq_non_canonical(&e) {
            jolt_inlines_sdk::spoil_proof();
        }
        crate::bind::weld(&self.e, &self.e, &e);
        Fq { e }
    }
}

#[cfg(all(not(target_arch = "riscv64"), not(feature = "host")))]
impl Fq {
    pub fn mul(&self, _other: &Fq) -> Fq {
        panic!("Fq::mul called on non-RISC-V target without host feature");
    }
    pub fn square(&self) -> Fq {
        panic!("Fq::square called on non-RISC-V target without host feature");
    }
}

#[cfg(feature = "host")]
impl Fq {
    pub fn mul(&self, other: &Fq) -> Fq {
        Fq {
            e: (ArkFq::new(BigInt(self.e)) * ArkFq::new(BigInt(other.e)))
                .into_bigint()
                .0,
        }
    }
    pub fn square(&self) -> Fq {
        Fq {
            e: ArkFq::new(BigInt(self.e)).square().into_bigint().0,
        }
    }
}

// --- Division / inverse -----------------------------------------------------

#[cfg(all(target_arch = "riscv64", not(feature = "host")))]
impl Fq {
    /// self / divisor via the DIVQ inline (advice inverse, verified by
    /// multiplication in the sequence). Division by zero spoils the proof
    /// in-guest, BEFORE the inline runs or the result is welded — this
    /// guard is what the B2 soundness inventory relies on for the
    /// zero-divisor case (a divisor of 0 admits no valid record).
    pub fn div(&self, divisor: &Fq) -> Fq {
        if divisor.is_zero() {
            jolt_inlines_sdk::spoil_proof();
        }
        let mut e = [0u64; 4];
        unsafe {
            use crate::{EDBLS_DIVQ_FUNCT3, EDBLS_FUNCT7, INLINE_OPCODE};
            core::arch::asm!(
                ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
                opcode = const INLINE_OPCODE,
                funct3 = const EDBLS_DIVQ_FUNCT3,
                funct7 = const EDBLS_FUNCT7,
                rd = in(reg) e.as_mut_ptr(),
                rs1 = in(reg) self.e.as_ptr(),
                rs2 = in(reg) divisor.e.as_ptr(),
                options(nostack)
            );
        }
        if is_fq_non_canonical(&e) {
            jolt_inlines_sdk::spoil_proof();
        }
        // Div normalizes to the verified identity (c, b, a): c*b == a.
        crate::bind::weld(&e, &divisor.e, &self.e);
        Fq { e }
    }
}

#[cfg(all(not(target_arch = "riscv64"), not(feature = "host")))]
impl Fq {
    pub fn div(&self, _divisor: &Fq) -> Fq {
        panic!("Fq::div called on non-RISC-V target without host feature");
    }
}

#[cfg(feature = "host")]
impl Fq {
    pub fn div(&self, divisor: &Fq) -> Fq {
        let inv = ArkFq::new(BigInt(divisor.e))
            .inverse()
            .expect("division by zero in edwards-bls12 base field");
        Fq {
            e: (ArkFq::new(BigInt(self.e)) * inv).into_bigint().0,
        }
    }
}

impl Fq {
    pub fn inverse(&self) -> Option<Fq> {
        if self.is_zero() {
            None
        } else {
            Some(Fq::ONE.div(self))
        }
    }

    pub fn neg(&self) -> Fq {
        Fq::ZERO.sub(self)
    }
}

// --- Twisted Edwards point ops (extended coordinates, a = -1) ---------------
//
// Curve: -x^2 + y^2 = 1 + d*x^2*y^2 over Fq, d = 3021 (Aleo Edwards-BLS12).
// Constants are locked to arkworks by tests (curve_constants_match_arkworks).

/// d = 3021
pub const COEFF_D: Fq = Fq { e: [0x0000000000000bcd, 0, 0, 0] };
/// 2d = 6042
const TWO_D: Fq = Fq { e: [0x000000000000179a, 0, 0, 0] };

const GENERATOR_X: Fq = Fq {
    e: [
        0x894e2328f3ebca05,
        0x6068dd2835790980,
        0x6fed91c9ae9ebfa0,
        0x09f1b5a5baf6acf0,
    ],
};
const GENERATOR_Y: Fq = Fq {
    e: [
        0xb50a67bf1a806781,
        0x4453c177aaf3131b,
        0xd906b256080ba845,
        0x09a20df36571ac3c,
    ],
};

/// Extended twisted-Edwards coordinates (X, Y, T, Z), T = XY/Z.
#[derive(Clone, Copy, Debug)]
pub struct EdwardsPoint {
    pub x: Fq,
    pub y: Fq,
    pub t: Fq,
    pub z: Fq,
}

impl EdwardsPoint {
    pub const IDENTITY: EdwardsPoint = EdwardsPoint {
        x: Fq::ZERO,
        y: Fq::ONE,
        t: Fq::ZERO,
        z: Fq::ONE,
    };

    pub fn generator() -> EdwardsPoint {
        EdwardsPoint {
            x: GENERATOR_X,
            y: GENERATOR_Y,
            t: GENERATOR_X.mul(&GENERATOR_Y),
            z: Fq::ONE,
        }
    }

    /// Unified addition (add-2008-hwcd-3 for a = -1): 8M + 1 small-constant M.
    pub fn add(&self, other: &EdwardsPoint) -> EdwardsPoint {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&other.t).mul(&TWO_D);
        let zz = self.z.mul(&other.z);
        let d = zz.add(&zz);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        EdwardsPoint {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Doubling (dbl-2008-hwcd for a = -1): 4S + 4M.
    pub fn double(&self) -> EdwardsPoint {
        let a = self.x.square();
        let b = self.y.square();
        let zz = self.z.square();
        let c = zz.add(&zz);
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = b.sub(&a); // D + B with D = -A
        let f = g.sub(&c);
        let h = a.add(&b).neg(); // D - B
        EdwardsPoint {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    pub fn neg(&self) -> EdwardsPoint {
        EdwardsPoint {
            x: self.x.neg(),
            y: self.y,
            t: self.t.neg(),
            z: self.z,
        }
    }

    /// Canonical affine coordinates (two DIVQ inlines).
    pub fn to_affine(&self) -> ([u64; 4], [u64; 4]) {
        (
            self.x.div(&self.z).to_canonical(),
            self.y.div(&self.z).to_canonical(),
        )
    }
}

impl EdwardsPoint {
    /// Plain MSB-first double-and-add over the unified `add`. Windowing is
    /// deliberately omitted: at ~40-cycle field ops the prototype doesn't need
    /// it, and branches cost cycles, not privacy, here.
    pub fn scalar_mul(&self, scalar: &[u64; 4]) -> EdwardsPoint {
        let mut acc = EdwardsPoint::IDENTITY;
        let mut started = false;
        for limb_idx in (0..4).rev() {
            for bit_idx in (0..64).rev() {
                if started {
                    acc = acc.double();
                }
                if (scalar[limb_idx] >> bit_idx) & 1 == 1 {
                    if started {
                        acc = acc.add(self);
                    } else {
                        acc = *self;
                        started = true;
                    }
                }
            }
        }
        acc
    }
}
