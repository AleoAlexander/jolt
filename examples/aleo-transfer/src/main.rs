pub fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let summary = guest::analyze_transfer_private(0xA1E0_0001_u64 as u64);

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
    use ark_ed_on_bls12_377::Fq;
    use ark_ff::{PrimeField, Zero};

    fn fq_from_dec(s: &str) -> Fq {
        let mut acc = Fq::zero();
        let ten = Fq::from(10u64);
        for b in s.bytes() {
            assert!(b.is_ascii_digit(), "non-digit in field literal");
            acc = acc * ten + Fq::from(u64::from(b - b'0'));
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
        let expected = fq_from_dec(case["output"].as_str().unwrap()).into_bigint().0;
        assert_eq!(out, expected);
    }
}
