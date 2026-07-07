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
}
