use ark_ed_on_bls12_377::Fq;
use ark_ff::{BigInt, Field, PrimeField};
use jolt_inlines_sdk::host::{
    instruction::{
        add::ADD, ld::LD, lui::LUI, mul::MUL, mulhu::MULHU, sd::SD, sltu::SLTU,
        virtual_advice::VirtualAdvice, virtual_assert_eq::VirtualAssertEQ,
        virtual_assert_lte::VirtualAssertLTE,
    },
    limbs_to_nbiguint, mulq_division_advice, mulq_quotient_advice, Cpu,
    ExpandedInstructionSequence, ExpansionError, FormatInline, InlineExpansionBuilder, InlineOp,
    InlineOperands, InlineRegister, ModularDivisionAdvice, MulqType, QuotientAdvice,
};

// Same verification identity as the secp256k1 MulqBuilder:
//   ab = wq + c  for advice quotient w, rearranged with p = 2^256 - q to
//   ab + wp = 2^256*w + c
// so all arithmetic is unsigned 512-bit accumulation checked limb-by-limb.
//
// Since q is 253-bit, w = floor(ab/q) < q < 2^253 fits four limbs, and
// p = 2^256 - q has FOUR significant limbs (unlike secp256k1's 1-2). The w*p
// contribution is therefore a full 4x4 schoolbook product: limb k of the LHS
// accumulates lo(a_i*b_j) and lo(w_i*p_j) for i+j == k, plus hi(a_i*b_j) and
// hi(w_i*p_j) for i+j == k-1.
//
// Carry-overflow safety: each 64-bit limb accumulator takes at most 16
// product-limb additions plus carries per position; the carry counter in the
// ping-pong companion limb stays far below 2^64.
//
// As in the secp256k1 inline, the result c is checked to fit 256 bits (final
// VirtualAssertLTE), not to be canonical (< q). The SDK layer enforces
// canonicity after each op and spoils the proof otherwise.

/// p = 2^256 - q, computed from the arkworks modulus (never hand-transcribed).
fn neg_modulus_limbs() -> [u64; 4] {
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

fn edwards_bls12_modulus(_is_scalar_field: bool) -> jolt_inlines_sdk::host::NBigUint {
    Fq::MODULUS.into()
}

struct MulqBuilder {
    asm: InlineExpansionBuilder,
    a: [InlineRegister; 4],
    b: Option<[InlineRegister; 4]>,
    w: [InlineRegister; 4],
    p: [InlineRegister; 4],
    aux: InlineRegister,
    aux2: Option<InlineRegister>,
    r: [InlineRegister; 2],
    operands: InlineOperands,
    op_type: MulqType,
}

impl MulqBuilder {
    fn new(
        mut asm: InlineExpansionBuilder,
        operands: InlineOperands,
        op_type: MulqType,
    ) -> Result<Self, ExpansionError> {
        let a = asm.allocate_inline_array::<4>()?;
        let b = match op_type {
            MulqType::Square => None,
            _ => Some(asm.allocate_inline_array::<4>()?),
        };
        let w = asm.allocate_inline_array::<4>()?;
        let p = asm.allocate_inline_array::<4>()?;
        let aux = asm.allocate_for_inline()?;
        let aux2 = match op_type {
            MulqType::Square => Some(asm.allocate_for_inline()?),
            _ => None,
        };
        let r = asm.allocate_inline_array::<2>()?;
        Ok(MulqBuilder {
            asm,
            a,
            b,
            w,
            p,
            aux,
            aux2,
            r,
            operands,
            op_type,
        })
    }

    fn quotient_advice(
        operands: FormatInline,
        cpu: &mut Cpu,
        op_type: &MulqType,
    ) -> QuotientAdvice {
        mulq_quotient_advice(&operands, cpu, false, op_type, edwards_bls12_modulus)
    }

    fn division_advice(operands: FormatInline, cpu: &mut Cpu) -> ModularDivisionAdvice {
        mulq_division_advice(&operands, cpu, false, edwards_bls12_modulus, |b, a| {
            limbs_to_nbiguint(
                &(Fq::new(BigInt(*b))
                    .inverse()
                    .expect("Attempted to invert zero in edwards-bls12 base field")
                    * Fq::new(BigInt(*a)))
                .into_bigint()
                .0,
            )
        })
    }

    /// The second operand of the schoolbook product: `b` for Mul/Div, `a` for Square.
    fn b_or_a(&self, j: usize) -> u8 {
        match self.op_type {
            MulqType::Square => *self.a[j],
            _ => *self.b.as_ref().unwrap()[j],
        }
    }

    fn inline_sequence(mut self) -> Result<ExpandedInstructionSequence, ExpansionError> {
        for i in 0..4 {
            match self.op_type {
                MulqType::Mul => {
                    self.asm
                        .emit_ld::<LD>(*self.a[i], self.operands.rs1, i as i64 * 8);
                    self.asm.emit_ld::<LD>(
                        *self.b.as_ref().unwrap()[i],
                        self.operands.rs2,
                        i as i64 * 8,
                    );
                }
                MulqType::Square => {
                    self.asm
                        .emit_ld::<LD>(*self.a[i], self.operands.rs1, i as i64 * 8);
                }
                MulqType::Div => {
                    self.asm.emit_ld::<LD>(
                        *self.b.as_ref().unwrap()[i],
                        self.operands.rs2,
                        i as i64 * 8,
                    );
                    self.asm.emit_j::<VirtualAdvice>(*self.a[i], 0);
                    self.asm
                        .emit_s::<SD>(self.operands.rs3, *self.a[i], i as i64 * 8);
                }
            }
            self.asm.emit_j::<VirtualAdvice>(*self.w[i], 0);
        }
        let p_limbs = neg_modulus_limbs();
        for i in 0..4 {
            self.asm.emit_u::<LUI>(*self.p[i], p_limbs[i]);
        }

        // Limb 0: lo(a0*b0) + lo(w0*p0); the mac_low initializes the carry limb.
        match self.op_type {
            MulqType::Square => {
                self.asm.emit_r::<MUL>(*self.r[0], *self.a[0], *self.a[0]);
            }
            _ => {
                self.asm
                    .emit_r::<MUL>(*self.r[0], *self.a[0], self.b_or_a(0));
            }
        }
        self.mac_low(*self.r[1], *self.r[0], *self.w[0], *self.p[0], *self.aux);
        match self.op_type {
            MulqType::Div => {
                self.asm.emit_ld::<LD>(*self.aux, self.operands.rs1, 0);
                self.asm.emit_b::<VirtualAssertEQ>(*self.r[0], *self.aux, 0);
            }
            _ => {
                self.asm.emit_s::<SD>(self.operands.rs3, *self.r[0], 0);
            }
        }

        for k in 1..7 {
            let mut first = true;
            let rk = *self.r[k % 2];
            let rk_next = *self.r[(k + 1) % 2];

            // w*p low terms: i + j == k
            for i in 0..4usize {
                let Some(j) = k.checked_sub(i) else { continue };
                if j >= 4 {
                    continue;
                }
                self.mac_low_conditional(!first, rk_next, rk, *self.w[i], *self.p[j], *self.aux);
                first = false;
            }
            // w*p high terms: i + j == k - 1
            for i in 0..4usize {
                let Some(j) = (k - 1).checked_sub(i) else { continue };
                if j >= 4 {
                    continue;
                }
                self.mac_high_conditional(!first, rk_next, rk, *self.w[i], *self.p[j], *self.aux);
                first = false;
            }

            // a*b low terms: i + j == k
            for i in 0..=k {
                let j = k - i;
                if i < 4 && j < 4 {
                    match self.op_type {
                        MulqType::Square => {
                            if i > j {
                                break;
                            } else if i == j {
                                self.mac_low_conditional(
                                    !first, rk_next, rk, *self.a[i], *self.a[j], *self.aux,
                                );
                                first = false;
                            } else {
                                if !first {
                                    self.m2ac_low_w_carry(
                                        rk_next,
                                        rk,
                                        *self.a[i],
                                        *self.a[j],
                                        *self.aux,
                                        **self.aux2.as_ref().unwrap(),
                                    );
                                } else {
                                    self.m2ac_low(rk_next, rk, *self.a[i], *self.a[j], *self.aux);
                                }
                                first = false;
                            }
                        }
                        _ => {
                            self.mac_low_conditional(
                                !first,
                                rk_next,
                                rk,
                                *self.a[i],
                                self.b_or_a(j),
                                *self.aux,
                            );
                            first = false;
                        }
                    }
                }
            }
            // a*b high terms: i + j == k - 1
            for i in 0..=k - 1 {
                let j = k - 1 - i;
                if i < 4 && j < 4 {
                    match self.op_type {
                        MulqType::Square => {
                            if i > j {
                                break;
                            } else if i == j {
                                self.mac_high_conditional(
                                    !first, rk_next, rk, *self.a[i], *self.a[j], *self.aux,
                                );
                                first = false;
                            } else {
                                if !first {
                                    self.m2ac_high_w_carry(
                                        rk_next,
                                        rk,
                                        *self.a[i],
                                        *self.a[j],
                                        *self.aux,
                                        **self.aux2.as_ref().unwrap(),
                                    );
                                } else {
                                    self.m2ac_high(rk_next, rk, *self.a[i], *self.a[j], *self.aux);
                                }
                                first = false;
                            }
                        }
                        _ => {
                            self.mac_high_conditional(
                                !first,
                                rk_next,
                                rk,
                                *self.a[i],
                                self.b_or_a(j),
                                *self.aux,
                            );
                            first = false;
                        }
                    }
                }
            }

            if k < 4 {
                match self.op_type {
                    MulqType::Div => {
                        self.asm
                            .emit_ld::<LD>(*self.aux, self.operands.rs1, k as i64 * 8);
                        self.asm.emit_b::<VirtualAssertEQ>(rk, *self.aux, 0);
                    }
                    _ => {
                        self.asm.emit_s::<SD>(self.operands.rs3, rk, k as i64 * 8);
                    }
                }
            } else {
                self.asm.emit_b::<VirtualAssertEQ>(rk, *self.w[k - 4], 0);
            }
        }

        // Limb 7 tail: hi(a3*b3) + hi(w3*p3), each add wrap-checked, then the
        // final RHS binding (limb 7 of 2^256*w is w[3]).
        match self.op_type {
            MulqType::Square => {
                self.asm.emit_r::<MULHU>(*self.aux, *self.a[3], *self.a[3]);
            }
            _ => {
                self.asm
                    .emit_r::<MULHU>(*self.aux, *self.a[3], self.b_or_a(3));
            }
        }
        self.asm.emit_r::<ADD>(*self.r[1], *self.r[1], *self.aux);
        self.asm
            .emit_b::<VirtualAssertLTE>(*self.aux, *self.r[1], 0);
        self.asm.emit_r::<MULHU>(*self.aux, *self.w[3], *self.p[3]);
        self.asm.emit_r::<ADD>(*self.r[1], *self.r[1], *self.aux);
        self.asm
            .emit_b::<VirtualAssertLTE>(*self.aux, *self.r[1], 0);
        self.asm
            .emit_b::<VirtualAssertEQ>(*self.r[1], *self.w[3], 0);

        self.asm.release_many(self.a);
        match self.op_type {
            MulqType::Square => {}
            _ => {
                self.asm.release_many(self.b.unwrap());
            }
        }
        self.asm.release_many(self.w);
        self.asm.release_many(self.p);
        self.asm.release(self.aux);
        if let MulqType::Square = self.op_type {
            self.asm.release(self.aux2.unwrap())
        }
        self.asm.release_many(self.r);
        self.asm.finalize()
    }

    fn mac_low(&mut self, c2: u8, c1: u8, a: u8, b: u8, aux: u8) {
        self.asm.emit_r::<MUL>(aux, a, b);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(c2, c1, aux);
    }
    fn mac_high(&mut self, c2: u8, c1: u8, a: u8, b: u8, aux: u8) {
        self.asm.emit_r::<MULHU>(aux, a, b);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(c2, c1, aux);
    }
    fn mac_low_w_carry(&mut self, c2: u8, c1: u8, a: u8, b: u8, aux: u8) {
        self.asm.emit_r::<MUL>(aux, a, b);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(aux, c1, aux);
        self.asm.emit_r::<ADD>(c2, c2, aux);
    }
    fn mac_high_w_carry(&mut self, c2: u8, c1: u8, a: u8, b: u8, aux: u8) {
        self.asm.emit_r::<MULHU>(aux, a, b);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(aux, c1, aux);
        self.asm.emit_r::<ADD>(c2, c2, aux);
    }
    fn mac_low_conditional(&mut self, carry_exists: bool, c2: u8, c1: u8, a: u8, b: u8, aux: u8) {
        if carry_exists {
            self.mac_low_w_carry(c2, c1, a, b, aux);
        } else {
            self.mac_low(c2, c1, a, b, aux);
        }
    }
    fn mac_high_conditional(&mut self, carry_exists: bool, c2: u8, c1: u8, a: u8, b: u8, aux: u8) {
        if carry_exists {
            self.mac_high_w_carry(c2, c1, a, b, aux);
        } else {
            self.mac_high(c2, c1, a, b, aux);
        }
    }
    fn m2ac_low(&mut self, c2: u8, c1: u8, a: u8, b: u8, aux: u8) {
        self.asm.emit_r::<MUL>(aux, a, b);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(c2, c1, aux);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(aux, c1, aux);
        self.asm.emit_r::<ADD>(c2, c2, aux);
    }
    fn m2ac_high(&mut self, c2: u8, c1: u8, a: u8, b: u8, aux: u8) {
        self.asm.emit_r::<MULHU>(aux, a, b);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(c2, c1, aux);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(aux, c1, aux);
        self.asm.emit_r::<ADD>(c2, c2, aux);
    }
    fn m2ac_low_w_carry(&mut self, c2: u8, c1: u8, a: u8, b: u8, aux: u8, aux2: u8) {
        self.asm.emit_r::<MUL>(aux, a, b);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(aux2, c1, aux);
        self.asm.emit_r::<ADD>(c2, c2, aux2);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(aux2, c1, aux);
        self.asm.emit_r::<ADD>(c2, c2, aux2);
    }
    fn m2ac_high_w_carry(&mut self, c2: u8, c1: u8, a: u8, b: u8, aux: u8, aux2: u8) {
        self.asm.emit_r::<MULHU>(aux, a, b);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(aux2, c1, aux);
        self.asm.emit_r::<ADD>(c2, c2, aux2);
        self.asm.emit_r::<ADD>(c1, c1, aux);
        self.asm.emit_r::<SLTU>(aux2, c1, aux);
        self.asm.emit_r::<ADD>(c2, c2, aux2);
    }
}

macro_rules! edbls_mulq_op {
    ($name:ident, funct3: $funct3:expr, name: $op_name:expr, mul_type: MulqType::Div) => {
        pub struct $name;
        impl InlineOp for $name {
            type Advice = ModularDivisionAdvice;

            const OPCODE: u32 = crate::INLINE_OPCODE;
            const FUNCT3: u32 = $funct3;
            const FUNCT7: u32 = crate::EDBLS_FUNCT7;
            const NAME: &'static str = $op_name;
            fn build_sequence(
                asm: InlineExpansionBuilder,
                operands: InlineOperands,
            ) -> Result<ExpandedInstructionSequence, ExpansionError> {
                MulqBuilder::new(asm, operands, MulqType::Div)?.inline_sequence()
            }
            fn build_advice(operands: FormatInline, cpu: &mut Cpu) -> Self::Advice {
                MulqBuilder::division_advice(operands, cpu)
            }
        }
    };
    ($name:ident, funct3: $funct3:expr, name: $op_name:expr, mul_type: $mul_type:expr) => {
        pub struct $name;
        impl InlineOp for $name {
            type Advice = QuotientAdvice;

            const OPCODE: u32 = crate::INLINE_OPCODE;
            const FUNCT3: u32 = $funct3;
            const FUNCT7: u32 = crate::EDBLS_FUNCT7;
            const NAME: &'static str = $op_name;
            fn build_sequence(
                asm: InlineExpansionBuilder,
                operands: InlineOperands,
            ) -> Result<ExpandedInstructionSequence, ExpansionError> {
                MulqBuilder::new(asm, operands, $mul_type)?.inline_sequence()
            }
            fn build_advice(operands: FormatInline, cpu: &mut Cpu) -> Self::Advice {
                MulqBuilder::quotient_advice(operands, cpu, &$mul_type)
            }
        }
    };
}

edbls_mulq_op!(EdBlsMulQ,    funct3: crate::EDBLS_MULQ_FUNCT3,    name: crate::EDBLS_MULQ_NAME,    mul_type: MulqType::Mul);
edbls_mulq_op!(EdBlsSquareQ, funct3: crate::EDBLS_SQUAREQ_FUNCT3, name: crate::EDBLS_SQUAREQ_NAME, mul_type: MulqType::Square);
edbls_mulq_op!(EdBlsDivQ,    funct3: crate::EDBLS_DIVQ_FUNCT3,    name: crate::EDBLS_DIVQ_NAME,    mul_type: MulqType::Div);
