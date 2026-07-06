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
