// PROTOTYPE (B0, branch aleo/field-accel-prototype): advice-only field ops.
//
// The Phase 0 verified sequences (tag `phase0-complete`) proved that in-sequence
// verification of a 253-bit modmul is instruction-count parity with software
// (310 vs 252 cycles/op — see examples/aleo-transfer/FINDINGS.md). This branch
// replaces them with pure advice (~8 cycles/op) to measure the trace-level
// ceiling of prover-side field acceleration.
//
// PROTOTYPE: UNSOUND until the batched verification sumcheck (B1) lands —
// the tracer supplies correct results, but nothing in the proof binds them.
// The quotient w = floor(a*b / q) needed by B1's verification identity is
// re-derived deterministically from (a, b, c) at witness-log-building time.

use ark_ed_on_bls12_377::Fq;
use ark_ff::{BigInt, Field, PrimeField};
use jolt_inlines_sdk::host::{
    load_field_element_limbs, ExpandedInstructionSequence, ExpansionError, FieldElementAdvice,
    FormatInline, InlineAdviceContext, InlineAdviceError, InlineBuilderExt,
    InlineExpansionBuilder, InlineOp, InlineOperands,
};

/// p = 2^256 - q, computed from the arkworks modulus (never hand-transcribed).
/// Retained for the B1 verification gadget.
pub fn neg_modulus_limbs() -> [u64; 4] {
    let m = Fq::MODULUS.0;
    let mut p = [0u64; 4];
    let mut carry = 1u64;
    for i in 0..4 {
        let (v, c) = (!m[i]).overflowing_add(carry);
        p[i] = v;
        carry = u64::from(c);
    }
    p
}

fn load_fq(ctx: &mut dyn InlineAdviceContext, addr: u64) -> Result<Fq, InlineAdviceError> {
    Ok(Fq::new(BigInt(load_field_element_limbs(ctx, addr)?)))
}

/// One logged invocation in verified-identity order: (x, y, z, w) with
/// x*y = w*q + z exactly over the integers.
pub type LoggedRecord = ([u64; 4], [u64; 4], [u64; 4], [u64; 4]);

// PROTOTYPE: host-side invocation log. Records are normalized to the
// verified identity shape x*y = w*q + z (Mul: (a,b,c); Square: (a,a,c);
// Div: (c,b,a)); the quotient w is derived at log time. Drained by the
// prover host via `take_field_op_log()`.
std::thread_local! {
    static FIELD_OP_LOG: std::cell::RefCell<Vec<LoggedRecord>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Drain the (x, y, z, w) invocation log accumulated since the last call.
pub fn take_field_op_log() -> Vec<LoggedRecord> {
    FIELD_OP_LOG.with(|log| std::mem::take(&mut *log.borrow_mut()))
}

/// Derive the quotient w for (x, y, z): x*y = w*q + z. Panics if the
/// identity does not divide exactly (the host tracer is honest; the B2
/// gadget is what catches dishonest logs).
pub fn record_from_xyz(x: [u64; 4], y: [u64; 4], z: [u64; 4]) -> LoggedRecord {
    use jolt_inlines_sdk::host::limbs_to_nbiguint;
    let q = limbs_to_nbiguint(&crate::sdk::MODULUS);
    let product = limbs_to_nbiguint(&x) * limbs_to_nbiguint(&y);
    let z_big = limbs_to_nbiguint(&z);
    assert!(product >= z_big, "record does not satisfy x*y >= z");
    let diff = product - z_big;
    assert!(
        (&diff % &q) == jolt_inlines_sdk::host::NBigUint::ZERO,
        "record does not satisfy x*y ≡ z (mod q)"
    );
    let w_big = diff / q;
    let bytes = w_big.to_bytes_le();
    assert!(bytes.len() <= 32, "quotient exceeds 256 bits");
    let mut w = [0u64; 4];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut b = [0u8; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        w[i] = u64::from_le_bytes(b);
    }
    (x, y, z, w)
}

/// Padded byte blob for the guest's untrusted-advice input: a head pad of
/// `128 − varint_size(total_len)` zero bytes, then the 128-byte record
/// blocks, so postcard's length prefix plus the pad total exactly 128 bytes
/// and every block lands on a 16-word boundary starting at region word 16
/// (`bind::head_pad` is the shared rule). The guest re-verifies the rule
/// from `len` alone and spoils on violation (`bind::init`) — no trusted
/// offsets.
pub fn build_record_blob_padded(records: &[LoggedRecord]) -> Vec<u8> {
    let blocks = records.len() * crate::bind::RECORD_BYTES;
    let mut pad = crate::bind::head_pad(blocks + 8);
    loop {
        let candidate = crate::bind::head_pad(blocks + pad);
        if candidate == pad {
            break;
        }
        pad = candidate;
    }
    let mut bytes = vec![0u8; pad];
    for (x, y, z, w) in records {
        for value in [x, y, z, w] {
            for limb in value {
                bytes.extend_from_slice(&limb.to_le_bytes());
            }
        }
    }
    bytes
}

fn log_record(x: Fq, y: Fq, z: Fq) {
    let record = record_from_xyz(x.into_bigint().0, y.into_bigint().0, z.into_bigint().0);
    FIELD_OP_LOG.with(|log| log.borrow_mut().push(record));
}

/// Test-only entry to the log path (same derivation as `log_record`).
#[cfg(test)]
pub(crate) fn log_record_for_test(x: [u64; 4], y: [u64; 4], z: [u64; 4]) {
    let record = record_from_xyz(x, y, z);
    FIELD_OP_LOG.with(|log| log.borrow_mut().push(record));
}

/// Advice-store-only sequence: 4 doublewords of result written to rs3.
fn advice_only_sequence(
    mut asm: InlineExpansionBuilder,
    operands: InlineOperands,
) -> Result<ExpandedInstructionSequence, ExpansionError> {
    let vr = asm.allocate_for_inline()?;
    asm.emit_advice_stores(*vr, operands.rs3, 4);
    asm.release(vr);
    asm.finalize()
}

fn result_advice(c: Fq) -> FieldElementAdvice {
    FieldElementAdvice {
        limbs: c.into_bigint().0,
    }
}

macro_rules! edbls_advice_op {
    ($name:ident, funct3: $funct3:expr, name: $op_name:expr, compute: $compute:expr, normalize: $normalize:expr) => {
        pub struct $name;
        impl InlineOp for $name {
            type Advice = FieldElementAdvice;

            const OPCODE: u32 = crate::INLINE_OPCODE;
            const FUNCT3: u32 = $funct3;
            const FUNCT7: u32 = crate::EDBLS_FUNCT7;
            const NAME: &'static str = $op_name;
            fn build_sequence(
                asm: InlineExpansionBuilder,
                operands: InlineOperands,
            ) -> Result<ExpandedInstructionSequence, ExpansionError> {
                advice_only_sequence(asm, operands)
            }
            fn build_advice(
                operands: FormatInline,
                ctx: &mut dyn InlineAdviceContext,
            ) -> Result<Self::Advice, InlineAdviceError> {
                let compute: fn(Fq, Fq) -> Fq = $compute;
                let normalize: fn(Fq, Fq, Fq) -> (Fq, Fq, Fq) = $normalize;
                let a_addr = ctx.register(operands.rs1 as usize);
                let a = load_fq(ctx, a_addr)?;
                let b_addr = ctx.register(operands.rs2 as usize);
                let b = load_fq(ctx, b_addr)?;
                let c = compute(a, b);
                let (x, y, z) = normalize(a, b, c);
                log_record(x, y, z);
                Ok(result_advice(c))
            }
        }
    };
}

edbls_advice_op!(EdBlsMulQ, funct3: crate::EDBLS_MULQ_FUNCT3, name: crate::EDBLS_MULQ_NAME,
    compute: |a, b| a * b,
    normalize: |a, b, c| (a, b, c));
edbls_advice_op!(EdBlsSquareQ, funct3: crate::EDBLS_SQUAREQ_FUNCT3, name: crate::EDBLS_SQUAREQ_NAME,
    compute: |a, _b| a.square(),
    normalize: |a, _b, c| (a, a, c));
edbls_advice_op!(EdBlsDivQ, funct3: crate::EDBLS_DIVQ_FUNCT3, name: crate::EDBLS_DIVQ_NAME,
    compute: |a, b| {
        a * b
            .inverse()
            .expect("Attempted to divide by zero in edwards-bls12 base field")
    },
    normalize: |a, b, c| (c, b, a));
