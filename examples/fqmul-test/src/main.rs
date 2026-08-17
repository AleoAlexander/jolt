use jolt_inlines_edwards_bls12::sdk::Fq;

fn expected_chain(seed: u64) -> [u64; 4] {
    let three = Fq::from_u64(3);
    let mut x = Fq::from_u64(seed);
    for _ in 0..500 {
        x = x.square().mul(&three);
    }
    x.to_canonical()
}

pub fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let seed = 7u64;

    // Trace-level check: the guest (inline path) must agree with the host
    // (arkworks fallback path), and the cycle count tells us whether the
    // inlines actually engaged.
    let summary = guest::analyze_fqmul_chain(seed);
    let cycles = summary.trace_len();
    let out: [u64; 4] =
        jolt_sdk::postcard::from_bytes(&summary.io_device.outputs).expect("guest output");
    assert_eq!(out, expected_chain(seed), "guest/host mismatch");
    println!("fqmul_chain: {cycles} cycles for 1000 field ops ({} cycles/op)", cycles / 1000);

    let ark_summary = guest::analyze_ark_chain(seed);
    let ark_cycles = ark_summary.trace_len();
    println!(
        "ark_chain (software control): {ark_cycles} cycles ({} cycles/op) — inline speedup {:.2}x",
        ark_cycles / 1000,
        ark_cycles as f64 / cycles as f64
    );

    // B2: build the record blob from the pass-1 log (op order = execution
    // order); the bound chain below re-executes the same 1000 ops.
    let pass1_records = jolt_inlines_edwards_bls12::sequence_builder::take_field_op_log();
    assert_eq!(pass1_records.len(), 1000, "pass-1 log should hold the chain's ops");
    let blob =
        jolt_inlines_edwards_bls12::sequence_builder::build_record_blob_padded(&pass1_records);

    // PROTOTYPE: unsound until B1 — the advice results are not yet bound by
    // any verification; this prove/verify only exercises the pipeline shape.
    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_fqmul_chain(target_dir);
    let shared = guest::preprocess_shared_fqmul_chain(&mut program).expect("preprocessing");
    let prover_pp = guest::preprocess_prover_fqmul_chain(shared.clone());
    let verifier_pp = guest::preprocess_verifier_fqmul_chain(
        shared,
        prover_pp.generators.to_verifier_setup(),
        None,
    );
    let prove = guest::build_prover_fqmul_chain(program, prover_pp);
    let verify = guest::build_verifier_fqmul_chain(verifier_pp);

    let now = std::time::Instant::now();
    let (output, proof, program_io) = prove(seed);
    println!("prover time: {:.2}s", now.elapsed().as_secs_f64());
    assert_eq!(output, expected_chain(seed), "proved output mismatch");

    let is_valid = verify(seed, output, program_io.panic, proof);
    println!("valid: {is_valid}");
    assert!(is_valid, "M3 GATE FAILED: proof did not verify");
    println!("M3 gate PASSED: inlines prove and verify end-to-end");

    // B1 GATE: the field-accel side proof over the invocation log captured
    // during the trace passes above. PROTOTYPE: final evals unbound (no PCS);
    // this demonstrates the gadget's prover/verifier flow and cost.
    use jolt_inlines_edwards_bls12::sdk::MODULUS;
    use jolt_inlines_edwards_bls12::sequence_builder::take_field_op_log;
    use jolt_prover_legacy::transcripts::{Blake2bTranscript, Transcript};
    use jolt_prover_legacy::zkvm::field_accel::{
        sumcheck::{prove_field_accel, verify_field_accel},
        FieldAccelParams, FieldAccelWitness, FieldOpRecord,
    };

    let params = FieldAccelParams { modulus_limbs: MODULUS };
    let log = take_field_op_log();
    let records: Vec<FieldOpRecord> = log
        .iter()
        .map(|(x, y, z, _w)| FieldOpRecord::new(*x, *y, *z, &params))
        .collect();
    println!("field-accel log: {} records", records.len());

    let witness = FieldAccelWitness::from_records(&records, &params);
    let log_n = witness.padded_len().trailing_zeros() as usize;

    let now = std::time::Instant::now();
    let gadget_proof =
        prove_field_accel::<jolt_sdk::F, _>(&witness, &params, &mut Blake2bTranscript::new(b"field_accel"));
    let gadget_prove_time = now.elapsed().as_secs_f64();

    let now = std::time::Instant::now();
    verify_field_accel(
        &gadget_proof,
        &params,
        log_n,
        &mut Blake2bTranscript::new(b"field_accel"),
    )
    .expect("B1 GATE FAILED: gadget proof did not verify");
    println!(
        "B1 gate PASSED: gadget sumcheck over {} records proved in {:.3}s, verified in {:.3}s",
        records.len(),
        gadget_prove_time,
        now.elapsed().as_secs_f64()
    );

    // B2 WELD GATE: the bound chain welds every op to its record block in the
    // committed untrusted-advice region; an honest blob proves and verifies,
    // a tampered blob spoils the proof.
    println!("\n=== B2 weld gate ===");
    let mut program_b = guest::compile_fqmul_chain_bound(target_dir);
    let shared_b = guest::preprocess_shared_fqmul_chain_bound(&mut program_b).expect("preprocessing");
    let prover_pp_b = guest::preprocess_prover_fqmul_chain_bound(shared_b.clone());
    let verifier_pp_b = guest::preprocess_verifier_fqmul_chain_bound(
        shared_b,
        prover_pp_b.generators.to_verifier_setup(),
        None,
    );
    let verify_b = guest::build_verifier_fqmul_chain_bound(verifier_pp_b);

    let prove_b = guest::build_prover_fqmul_chain_bound(program_b, prover_pp_b.clone());
    let now = std::time::Instant::now();
    let (output_b, proof_b, io_b) = prove_b(seed, jolt_sdk::UntrustedAdvice::new(blob.as_slice()));
    println!("bound prover time: {:.2}s", now.elapsed().as_secs_f64());
    assert_eq!(output_b, expected_chain(seed), "bound output mismatch");
    let bound_valid = verify_b(seed, output_b, io_b.panic, proof_b);
    assert!(bound_valid, "B2 WELD GATE FAILED: honest bound proof did not verify");
    println!("B2 weld gate PASSED: bound chain proves and verifies with honest blob");

    // Negative: flip one byte of record 0's x value — the weld must spoil.
    let mut tampered = blob.clone();
    let pad = jolt_inlines_edwards_bls12::bind::head_pad(tampered.len());
    tampered[pad] ^= 1;
    let mut program_neg = guest::compile_fqmul_chain_bound(target_dir);
    let _ = guest::preprocess_shared_fqmul_chain_bound(&mut program_neg);
    let prove_neg = guest::build_prover_fqmul_chain_bound(program_neg, prover_pp_b);
    let neg = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (o, p, io) = prove_neg(seed, jolt_sdk::UntrustedAdvice::new(tampered.as_slice()));
        verify_b(seed, o, io.panic, p)
    }));
    match neg {
        Ok(true) => panic!("B2 WELD NEGATIVE FAILED: tampered blob verified"),
        Ok(false) => println!("B2 weld negative PASSED: tampered blob rejected by verifier"),
        Err(_) => println!("B2 weld negative PASSED: tampered blob spoiled the trace (prover abort)"),
    }
}
