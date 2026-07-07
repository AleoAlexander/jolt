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
    Cpu, ExpandedInstructionSequence, ExpansionError, FieldElementAdvice, FormatInline,
    InlineBuilderExt, InlineExpansionBuilder, InlineOp, InlineOperands,
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

fn load_fq(cpu: &mut Cpu, addr: u64) -> Fq {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = cpu.mmu.load_doubleword(addr + 8 * i as u64).map(|v| v.0).unwrap_or(0);
    }
    Fq::new(BigInt(limbs))
}

// PROTOTYPE: host-side invocation log. Records are normalized to the
// verified identity shape x*y = w*q + z (Mul: (a,b,c); Square: (a,a,c);
// Div: (c,b,a)); the quotient w is re-derived by the consumer. Drained by
// the prover host via `take_field_op_log()`.
std::thread_local! {
    static FIELD_OP_LOG: std::cell::RefCell<Vec<([u64; 4], [u64; 4], [u64; 4])>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Drain the (x, y, z) invocation log accumulated since the last call.
pub fn take_field_op_log() -> Vec<([u64; 4], [u64; 4], [u64; 4])> {
    FIELD_OP_LOG.with(|log| std::mem::take(&mut *log.borrow_mut()))
}

fn log_record(x: Fq, y: Fq, z: Fq) {
    FIELD_OP_LOG.with(|log| {
        log.borrow_mut()
            .push((x.into_bigint().0, y.into_bigint().0, z.into_bigint().0));
    });
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
            fn build_advice(operands: FormatInline, cpu: &mut Cpu) -> Self::Advice {
                let compute: fn(Fq, Fq) -> Fq = $compute;
                let normalize: fn(Fq, Fq, Fq) -> (Fq, Fq, Fq) = $normalize;
                let a = load_fq(cpu, cpu.x[operands.rs1 as usize] as u64);
                let b = load_fq(cpu, cpu.x[operands.rs2 as usize] as u64);
                let c = compute(a, b);
                let (x, y, z) = normalize(a, b, c);
                log_record(x, y, z);
                result_advice(c)
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
