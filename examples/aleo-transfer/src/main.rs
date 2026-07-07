pub fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // drain any log noise from prior compiles, then trace the transfer
    let _ = jolt_inlines_edwards_bls12::sequence_builder::take_field_op_log();
    let summary = guest::analyze_transfer_private(0xA1E0_0001_u64 as u64);

    let transfer_log = jolt_inlines_edwards_bls12::sequence_builder::take_field_op_log();
    let usdcx_summary = guest::analyze_usdcx_transfer_private(0xA1E0_0003_u64 as u64);
    println!("usdcx_transfer_private trace: {} cycles", usdcx_summary.trace_len());
    {
        use jolt_inlines_edwards_bls12::sdk::MODULUS;
        use jolt_prover_legacy::transcripts::{Blake2bTranscript, Transcript};
        use jolt_prover_legacy::zkvm::field_accel::{
            sumcheck::{prove_field_accel, verify_field_accel},
            FieldAccelParams, FieldAccelWitness, FieldOpRecord,
        };
        let params = FieldAccelParams { modulus_limbs: MODULUS };
        let records: Vec<FieldOpRecord> = jolt_inlines_edwards_bls12::sequence_builder::take_field_op_log()
            .iter()
            .map(|(x, y, z)| FieldOpRecord::new(*x, *y, *z, &params))
            .collect();
        let witness = FieldAccelWitness::from_records(&records, &params);
        let log_n = witness.padded_len().trailing_zeros() as usize;
        let t = std::time::Instant::now();
        let proof = prove_field_accel::<jolt_sdk::F, _>(
            &witness, &params, &mut Blake2bTranscript::new(b"field_accel"));
        let prove_s = t.elapsed().as_secs_f64();
        verify_field_accel(&proof, &params, log_n, &mut Blake2bTranscript::new(b"field_accel"))
            .expect("usdcx gadget proof failed");
        println!(
            "usdcx field-accel gadget: {} records, prove {:.3}s",
            records.len(), prove_s
        );
    }

    // B1 gadget cost at transfer scale: prove the invocation log of the trace
    {
        use jolt_inlines_edwards_bls12::sdk::MODULUS;
        use jolt_prover_legacy::transcripts::{Blake2bTranscript, Transcript};
        use jolt_prover_legacy::zkvm::field_accel::{
            sumcheck::{prove_field_accel, verify_field_accel},
            FieldAccelParams, FieldAccelWitness, FieldOpRecord,
        };
        let params = FieldAccelParams { modulus_limbs: MODULUS };
        let records: Vec<FieldOpRecord> = transfer_log
            .iter()
            .map(|(x, y, z)| FieldOpRecord::new(*x, *y, *z, &params))
            .collect();
        let witness = FieldAccelWitness::from_records(&records, &params);
        let log_n = witness.padded_len().trailing_zeros() as usize;
        let t = std::time::Instant::now();
        let gadget_proof = prove_field_accel::<jolt_sdk::F, _>(
            &witness, &params, &mut Blake2bTranscript::new(b"field_accel"));
        let prove_s = t.elapsed().as_secs_f64();
        let t = std::time::Instant::now();
        verify_field_accel(&gadget_proof, &params, log_n, &mut Blake2bTranscript::new(b"field_accel"))
            .expect("transfer-scale gadget proof failed");
        println!(
            "field-accel gadget (transfer scale): {} records, prove {:.3}s, verify {:.4}s",
            records.len(), prove_s, t.elapsed().as_secs_f64()
        );
    }

    let soft = guest::analyze_usdcx_transfer_private_soft(0xA1E0_0003_u64 as u64);
    println!("usdcx_transfer_private_soft trace: {} cycles", soft.trace_len());

    println!("\n=== aleo-transfer trace summary ===");
    println!("total trace length (cycles): {}", summary.trace_len());
    println!("\ntop instructions:");
    for (name, count) in summary.analyze::<jolt_sdk::F>().iter().take(12) {
        println!("  {name:>12}: {count}");
    }

    // End-to-end proof of the small workload to measure real prover throughput.
    let seed = 0xA1E0_0002_u64;
    let bench_summary = guest::analyze_mult_bench(seed);
    let bench_cycles = bench_summary.trace_len();
    println!("\n=== mult_bench (1 scalar mult + 1 poseidon perm) ===");
    println!("trace length (cycles): {bench_cycles}");

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_mult_bench(target_dir);
    let t = std::time::Instant::now();
    let shared = guest::preprocess_shared_mult_bench(&mut program).unwrap();
    let prover_pp = guest::preprocess_prover_mult_bench(shared.clone());
    let verifier_pp = guest::preprocess_verifier_mult_bench(
        shared,
        prover_pp.generators.to_verifier_setup(),
        None,
    );
    println!("preprocessing: {:.1}s", t.elapsed().as_secs_f64());

    let prove_fn = guest::build_prover_mult_bench(program, prover_pp);
    let verify_fn = guest::build_verifier_mult_bench(verifier_pp);

    let t = std::time::Instant::now();
    let (output, proof, program_io) = prove_fn(seed);
    let prove_secs = t.elapsed().as_secs_f64();
    println!(
        "prover time: {prove_secs:.2}s  ({:.0} cycles/s)",
        bench_cycles as f64 / prove_secs
    );

    let proof_bytes = jolt_sdk::postcard::to_stdvec(&proof).unwrap();
    println!("proof size: {} bytes", proof_bytes.len());

    let t = std::time::Instant::now();
    let is_valid = verify_fn(seed, output, program_io.panic, proof);
    println!("verify time: {:.3}s, valid: {is_valid}", t.elapsed().as_secs_f64());
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use jolt_inlines_edwards_bls12::sdk::Fq;

    fn fq_from_dec(s: &str) -> Fq {
        let ten = Fq::from_u64(10);
        let mut acc = Fq::ZERO;
        for b in s.bytes() {
            assert!(b.is_ascii_digit(), "non-digit in field literal");
            acc = acc.mul(&ten).add(&Fq::from_u64(u64::from(b - b'0')));
        }
        acc
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../vectors.json")).unwrap()
    }

    #[test]
    fn poseidon_matches_snarkvm_vectors_host() {
        let v = vectors();
        for case in v["poseidon2_hash"].as_array().unwrap() {
            let inputs: Vec<Fq> = case["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| fq_from_dec(i.as_str().unwrap()))
                .collect();
            let expected = fq_from_dec(case["output"].as_str().unwrap());
            assert_eq!(guest::poseidon2_hash(&inputs), expected, "inputs {:?}", case["inputs"]);
        }
    }

    #[test]
    fn poseidon4_matches_snarkvm_vectors_host() {
        let v = vectors();
        for case in v["poseidon4_hash"].as_array().unwrap() {
            let inputs: Vec<Fq> = case["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| fq_from_dec(i.as_str().unwrap()))
                .collect();
            let expected = fq_from_dec(case["output"].as_str().unwrap());
            assert_eq!(guest::poseidon4_hash(&inputs), expected, "psd4 inputs {:?}", case["inputs"]);
        }
    }

    #[test]
    fn poseidon_matches_snarkvm_vector_in_guest() {
        // The "12345" single-input case, executed inside the RISC-V guest.
        let summary = guest::analyze_poseidon_hash_bench(12345);
        let out: [u64; 4] = jolt_sdk::postcard::from_bytes(&summary.io_device.outputs).unwrap();
        let v = vectors();
        let case = v["poseidon2_hash"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| {
                let ins = c["inputs"].as_array().unwrap();
                ins.len() == 1 && ins[0].as_str().unwrap() == "12345"
            })
            .unwrap();
        let expected = fq_from_dec(case["output"].as_str().unwrap()).to_canonical();
        assert_eq!(out, expected);
    }
}
