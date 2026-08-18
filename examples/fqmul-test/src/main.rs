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
    let bound_summary =
        guest::analyze_fqmul_chain_bound(seed, jolt_sdk::UntrustedAdvice::new(blob.as_slice()));
    let bound_cycles = bound_summary.trace_len();
    println!(
        "fqmul_chain_bound: {bound_cycles} cycles ({} cycles/op incl. weld, +{} vs unbound)",
        bound_cycles / 1000,
        (bound_cycles - cycles) / 1000
    );
    let _ = jolt_inlines_edwards_bls12::sequence_builder::take_field_op_log();

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
    let bound_valid = verify_b(seed, output_b, io_b.panic, proof_b.clone());
    assert!(bound_valid, "B2 WELD GATE FAILED: honest bound proof did not verify");
    println!("B2 weld gate PASSED: bound chain proves and verifies with honest blob");

    // Negative: flip one byte of record 0's x value — the weld must spoil.
    let mut tampered = blob.clone();
    let pad = jolt_inlines_edwards_bls12::bind::head_pad(tampered.len());
    tampered[pad] ^= 1;
    let mut program_neg = guest::compile_fqmul_chain_bound(target_dir);
    let _ = guest::preprocess_shared_fqmul_chain_bound(&mut program_neg);
    let prove_neg = guest::build_prover_fqmul_chain_bound(program_neg, prover_pp_b.clone());
    let neg = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (o, p, io) = prove_neg(seed, jolt_sdk::UntrustedAdvice::new(tampered.as_slice()));
        verify_b(seed, o, io.panic, p)
    }));
    match neg {
        Ok(true) => panic!("B2 WELD NEGATIVE FAILED: tampered blob verified"),
        Ok(false) => println!("B2 weld negative PASSED: tampered blob rejected by verifier"),
        Err(_) => println!("B2 weld negative PASSED: tampered blob spoiled the trace (prover abort)"),
    }

    // B2 BOUND GATE: the sidecar gadget proof — modular identity over the
    // SAME committed advice region the welds bind to, with Dory-bound
    // evaluations, digit range checks, and the header-derived record count.
    println!("\n=== B2 bound gate ===");
    use jolt_prover_legacy::zkvm::field_accel::bound::{
        prove_field_accel_bound, verify_field_accel_bound,
    };
    use jolt_prover_legacy::poly::commitment::commitment_scheme::CommitmentScheme as _;

    const MAX_ADVICE: usize = 262144; // fqmul_chain_bound's max_untrusted_advice_size

    // the exact bytes the prover pipeline serialized into the advice region
    let advice_bytes =
        jolt_sdk::postcard::to_stdvec(&jolt_sdk::UntrustedAdvice::new(blob.as_slice()))
            .expect("advice serialization");

    let setup = &prover_pp_b.generators;
    let verifier_setup = jolt_sdk::PCS::setup_verifier(setup);

    let now = std::time::Instant::now();
    let mut pt = jolt_prover_legacy::transcripts::Blake2bTranscript::new(b"field_accel_bound");
    let bound_proof = prove_field_accel_bound::<jolt_sdk::F, jolt_sdk::PCS, _>(
        &advice_bytes,
        MAX_ADVICE,
        &params,
        setup,
        &mut pt,
    )
    .expect("bound gadget proving failed");
    println!("bound gadget prover time: {:.3}s", now.elapsed().as_secs_f64());

    // Recompute the advice commitment and require it to EQUAL the one the
    // main proof carries — the bridge that welds sidecar to main proof.
    let (advice_commitment, _) = jolt_prover_legacy::zkvm::field_accel::bound::commit_advice_region::<
        jolt_sdk::F,
        jolt_sdk::PCS,
    >(&advice_bytes, MAX_ADVICE, setup);
    let recomputed_vc =
        <jolt_sdk::PCS as jolt_sdk::ProofCommitmentScheme<jolt_sdk::F>>::commitment_into_verifier(
            advice_commitment.clone(),
        );
    assert_eq!(
        Some(recomputed_vc),
        proof_b.untrusted_advice_commitment,
        "B2 BOUND GATE FAILED: sidecar advice commitment differs from the main proof's"
    );
    println!("advice commitment matches the main proof's untrusted_advice_commitment");

    let now = std::time::Instant::now();
    let mut vt = jolt_prover_legacy::transcripts::Blake2bTranscript::new(b"field_accel_bound");
    verify_field_accel_bound::<jolt_sdk::F, jolt_sdk::PCS, _>(
        &bound_proof,
        &advice_commitment,
        MAX_ADVICE,
        &params,
        &verifier_setup,
        &mut vt,
    )
    .expect("B2 BOUND GATE FAILED: bound gadget proof did not verify");
    println!(
        "B2 bound gate PASSED: gadget verifies against the committed region in {:.4}s",
        now.elapsed().as_secs_f64()
    );

    // negative: a tampered corner evaluation must fail
    let mut bad = bound_proof.clone();
    bad.aux_corner_evals[7] += <jolt_sdk::F as jolt_prover_legacy::field::JoltField>::from_u64(1);
    let mut vt = jolt_prover_legacy::transcripts::Blake2bTranscript::new(b"field_accel_bound");
    assert!(
        verify_field_accel_bound::<jolt_sdk::F, jolt_sdk::PCS, _>(
            &bad,
            &advice_commitment,
            MAX_ADVICE,
            &params,
            &verifier_setup,
            &mut vt,
        )
        .is_err(),
        "B2 BOUND NEGATIVE FAILED: tampered corner eval verified"
    );
    println!("B2 bound negative PASSED: tampered corner evaluation rejected");
}
