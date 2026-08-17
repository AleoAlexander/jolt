//! Edwards-BLS12 inline implementation module.
//!
//! Base-field (Fq = BLS12-377 scalar field, 253-bit) operations for the Aleo
//! embedded curve, as advice-quotient inlines in the secp256k1 pattern:
//! 0x00: base field multiplication
//! 0x01: base field squaring
//! 0x02: base field division
//!
//! Unlike secp256k1, the negated modulus p = 2^256 - q has four significant
//! limbs (q is 253-bit), so the w*p accumulation in the sequence builder is a
//! full 4x4 schoolbook product rather than the 1-2 limb special case.
//!
//! The curve's scalar field (251-bit) is deliberately not covered in v1: the
//! Aleo transfer workload does no hot scalar-field arithmetic.

#![cfg_attr(not(feature = "host"), no_std)]

pub const INLINE_OPCODE: u32 = 0x0B;
pub const EDBLS_FUNCT7: u32 = 0x08;

// base field (q) multiplication: given a, b in Fq, compute c = a*b mod q,
// verified via a*b + w*(2^256 - q) = 2^256*w + c with quotient advice w
pub const EDBLS_MULQ_FUNCT3: u32 = 0x00;
pub const EDBLS_MULQ_NAME: &str = "EDBLS_MULQ";

// base field (q) squaring
pub const EDBLS_SQUAREQ_FUNCT3: u32 = 0x01;
pub const EDBLS_SQUAREQ_NAME: &str = "EDBLS_SQUAREQ";

// base field (q) division: given a, b in Fq, compute c = a/b,
// verified as c*b = a via the multiplication identity
pub const EDBLS_DIVQ_FUNCT3: u32 = 0x02;
pub const EDBLS_DIVQ_NAME: &str = "EDBLS_DIVQ";

pub mod bind;
pub mod sdk;
pub use sdk::*;

#[cfg(feature = "host")]
pub mod sequence_builder;

#[cfg(feature = "host")]
mod host;

#[cfg(all(test, feature = "host"))]
mod tests;
