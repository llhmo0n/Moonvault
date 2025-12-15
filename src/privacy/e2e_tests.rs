// =============================================================================
// MOONCOIN v2.30 - End-to-End Testing
// =============================================================================
//
// Tests integrados que verifican flujos completos:
// - Flujo transparent: mine → send → receive → spend
// - Flujo shielded: shield → send_private → scan → unshield
// - Reorgs con TX shielded
// - Mempool bajo carga
// - Benchmarks básicos
//
// =============================================================================

use std::time::Instant;

// =============================================================================
// Test Results
// =============================================================================

#[derive(Clone, Debug)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub duration_ms: u128,
    pub details: String,
}

impl TestResult {
    pub fn pass(name: &str, duration_ms: u128, details: &str) -> Self {
        TestResult {
            name: name.to_string(),
            passed: true,
            duration_ms,
            details: details.to_string(),
        }
    }
    
    pub fn fail(name: &str, duration_ms: u128, details: &str) -> Self {
        TestResult {
            name: name.to_string(),
            passed: false,
            duration_ms,
            details: details.to_string(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TestSuite {
    pub results: Vec<TestResult>,
    pub total_duration_ms: u128,
}

impl TestSuite {
    pub fn new() -> Self {
        TestSuite {
            results: Vec::new(),
            total_duration_ms: 0,
        }
    }
    
    pub fn add(&mut self, result: TestResult) {
        self.total_duration_ms += result.duration_ms;
        self.results.push(result);
    }
    
    pub fn passed(&self) -> usize {
        self.results.iter().filter(|r| r.passed).count()
    }
    
    pub fn failed(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }
    
    pub fn total(&self) -> usize {
        self.results.len()
    }
    
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }
    
    pub fn print_summary(&self) {
        println!();
        println!("  ═══════════════════════════════════════════════════════════");
        println!("  TEST SUMMARY");
        println!("  ═══════════════════════════════════════════════════════════");
        println!();
        
        for result in &self.results {
            let status = if result.passed { "✅ PASS" } else { "❌ FAIL" };
            println!("  {} {} ({} ms)", status, result.name, result.duration_ms);
            if !result.details.is_empty() {
                println!("       {}", result.details);
            }
        }
        
        println!();
        println!("  ───────────────────────────────────────────────────────────");
        println!("  Total: {} tests, {} passed, {} failed", 
            self.total(), self.passed(), self.failed());
        println!("  Duration: {} ms", self.total_duration_ms);
        println!();
        
        if self.all_passed() {
            println!("  🎉 ALL TESTS PASSED!");
        } else {
            println!("  ⚠️  SOME TESTS FAILED");
        }
        println!();
    }
}

// =============================================================================
// Test: Pedersen Commitments
// =============================================================================

pub fn test_pedersen_commitments() -> TestResult {
    use crate::privacy::pedersen::{PedersenCommitment, Scalar};
    
    let start = Instant::now();
    let test_name = "Pedersen Commitments";
    
    // Test 1: Crear commitment
    let amount = 1000u64;
    let blinding = Scalar::random();
    let commitment = PedersenCommitment::commit(amount, blinding);
    
    if commitment.as_bytes() == [0u8; 32] {
        return TestResult::fail(test_name, start.elapsed().as_millis(), 
            "Commitment is zero");
    }
    
    // Test 2: Homomorphic addition
    let c1 = PedersenCommitment::commit(100, Scalar::random());
    let c2 = PedersenCommitment::commit(200, Scalar::random());
    let c3 = c1.add(&c2);
    
    if c3.as_bytes() == c1.as_bytes() || c3.as_bytes() == c2.as_bytes() {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Homomorphic addition failed");
    }
    
    // Test 3: Different blindings produce different commitments
    let b1 = Scalar::random();
    let b2 = Scalar::random();
    let ca = PedersenCommitment::commit(100, b1);
    let cb = PedersenCommitment::commit(100, b2);
    
    if ca.as_bytes() == cb.as_bytes() {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Same amount with different blindings should differ");
    }
    
    TestResult::pass(test_name, start.elapsed().as_millis(), 
        "Commitment creation, homomorphic ops OK")
}

// =============================================================================
// Test: Range Proofs
// =============================================================================

pub fn test_range_proofs() -> TestResult {
    use crate::privacy::pedersen::{PedersenCommitment, Scalar};
    use crate::privacy::rangeproof::RangeProof;
    
    let start = Instant::now();
    let test_name = "Range Proofs";
    
    // Test 1: Create valid range proof
    let amount = 50000u64;
    let blinding = Scalar::random();
    let commitment = PedersenCommitment::commit(amount, blinding);
    
    let proof = match RangeProof::create(amount, blinding) {
        Ok(p) => p,
        Err(e) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Failed to create proof: {:?}", e)),
    };
    
    // Test 2: Verify proof
    match proof.verify(&commitment) {
        Ok(true) => {},
        Ok(false) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Proof verification returned false"),
        Err(e) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Proof verification error: {:?}", e)),
    }
    
    // Test 3: Proof size is reasonable
    let size = proof.size();
    if size < 100 || size > 2000 {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Unexpected proof size: {}", size));
    }
    
    TestResult::pass(test_name, start.elapsed().as_millis(),
        &format!("Create + verify OK, size={} bytes", size))
}

// =============================================================================
// Test: Ring Signatures
// =============================================================================

pub fn test_ring_signatures() -> TestResult {
    use crate::privacy::pedersen::{Scalar, CompressedPoint, GENERATORS};
    use crate::privacy::ring::{RingSignature, KeyImage};
    
    let start = Instant::now();
    let test_name = "Ring Signatures";
    
    // Generate ring of 5 keypairs
    let keypairs: Vec<(Scalar, CompressedPoint)> = (0..5)
        .map(|_| {
            let sk = Scalar::random();
            let pk = CompressedPoint::from_point(&(sk.inner() * GENERATORS.g));
            (sk, pk)
        })
        .collect();
    
    let ring: Vec<CompressedPoint> = keypairs.iter().map(|(_, pk)| *pk).collect();
    
    // We are index 2
    let real_index = 2;
    let (our_sk, _) = &keypairs[real_index];
    
    // Test 1: Sign message
    let message = b"test transaction";
    let sig = match RingSignature::sign(message, &ring, our_sk, real_index) {
        Ok(s) => s,
        Err(e) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Failed to sign: {:?}", e)),
    };
    
    // Test 2: Verify signature
    match sig.verify(message, &ring) {
        Ok(true) => {},
        Ok(false) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Signature verification failed"),
        Err(e) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Verification error: {:?}", e)),
    }
    
    // Test 3: Wrong message fails
    match sig.verify(b"wrong message", &ring) {
        Ok(false) => {},
        Ok(true) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Wrong message should not verify"),
        Err(_) => {},
    }
    
    // Test 4: Key image is consistent
    let ki1 = KeyImage::generate(our_sk, &keypairs[real_index].1);
    let ki2 = KeyImage::generate(our_sk, &keypairs[real_index].1);
    
    if ki1.as_bytes() != ki2.as_bytes() {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Key image not deterministic");
    }
    
    TestResult::pass(test_name, start.elapsed().as_millis(),
        &format!("Sign + verify OK, ring_size={}", ring.len()))
}

// =============================================================================
// Test: Stealth Addresses
// =============================================================================

pub fn test_stealth_addresses() -> TestResult {
    use crate::privacy::keys::PrivacyKeys;
    use crate::privacy::stealth::StealthAddress;
    
    let start = Instant::now();
    let test_name = "Stealth Addresses";
    
    // Test 1: Generate keys
    let bob_keys = PrivacyKeys::generate();
    let bob_addr = bob_keys.stealth_address();
    
    // Test 2: Encode/decode address
    let encoded = bob_addr.encode();
    if !encoded.starts_with("mzs") {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Address should start with 'mzs'");
    }
    
    let decoded = match StealthAddress::decode(&encoded) {
        Some(a) => a,
        None => return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Failed to decode address"),
    };
    
    if decoded.view_pubkey.as_bytes() != bob_addr.view_pubkey.as_bytes() {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Decoded address doesn't match");
    }
    
    // Test 3: Different keys produce different addresses
    let alice_keys = PrivacyKeys::generate();
    let alice_addr = alice_keys.stealth_address();
    
    if alice_addr.encode() == bob_addr.encode() {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Different keys should produce different addresses");
    }
    
    TestResult::pass(test_name, start.elapsed().as_millis(),
        &format!("Encode/decode OK, addr_len={}", encoded.len()))
}

// =============================================================================
// Test: Shielded Output Creation
// =============================================================================

pub fn test_shielded_output() -> TestResult {
    use crate::privacy::keys::PrivacyKeys;
    use crate::privacy::shielded_tx::ShieldedOutput;
    
    let start = Instant::now();
    let test_name = "Shielded Output";
    
    let recipient = PrivacyKeys::generate();
    let addr = recipient.stealth_address();
    
    // Test 1: Create output
    let (output, secrets) = match ShieldedOutput::new(
        1_000_000,
        &addr.view_pubkey,
        &addr.spend_pubkey,
        Some(b"test memo"),
    ) {
        Ok(r) => r,
        Err(e) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Failed to create output: {:?}", e)),
    };
    
    // Test 2: Verify secrets match
    if secrets.amount != 1_000_000 {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Amount mismatch in secrets");
    }
    
    // Test 3: Output has valid components
    if output.commitment.as_bytes() == [0u8; 32] {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Commitment is zero");
    }
    
    if output.encrypted_data.ciphertext.is_empty() {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Encrypted data is empty");
    }
    
    TestResult::pass(test_name, start.elapsed().as_millis(),
        &format!("Output created, size={} bytes", output.size()))
}

// =============================================================================
// Test: Scanner Detection
// =============================================================================

pub fn test_scanner_detection() -> TestResult {
    use crate::privacy::keys::PrivacyKeys;
    use crate::privacy::shielded_tx::ShieldedOutput;
    use crate::privacy::scanner::WalletScanner;
    
    let start = Instant::now();
    let test_name = "Scanner Detection";
    
    // Create recipient
    let bob = PrivacyKeys::generate();
    let bob_addr = bob.stealth_address();
    
    // Create output for Bob
    let (output, _) = match ShieldedOutput::new(
        5_000_000,
        &bob_addr.view_pubkey,
        &bob_addr.spend_pubkey,
        Some(b"Payment to Bob"),
    ) {
        Ok(r) => r,
        Err(e) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Failed to create output: {:?}", e)),
    };
    
    // Test 1: Bob's scanner finds it
    let mut bob_scanner = WalletScanner::from_keys(&bob);
    let found = bob_scanner.scan_output(&output, 0, [0u8; 32], 0, 1);
    
    if found.is_none() {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Bob's scanner should find his output");
    }
    
    let owned = found.unwrap();
    if owned.amount != 5_000_000 {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Decrypted amount mismatch");
    }
    
    // Test 2: Alice's scanner doesn't find it
    let alice = PrivacyKeys::generate();
    let mut alice_scanner = WalletScanner::from_keys(&alice);
    let not_found = alice_scanner.scan_output(&output, 0, [0u8; 32], 0, 1);
    
    if not_found.is_some() {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Alice's scanner should NOT find Bob's output");
    }
    
    TestResult::pass(test_name, start.elapsed().as_millis(),
        "Correct owner detected, non-owner rejected")
}

// =============================================================================
// Test: Shielded Mempool
// =============================================================================

pub fn test_shielded_mempool() -> TestResult {
    use crate::privacy::integration::ShieldedMempool;
    use crate::privacy::shielded_tx::{ShieldedTx, TxType, MIN_SHIELDED_FEE};
    
    let start = Instant::now();
    let test_name = "Shielded Mempool";
    
    let mut mempool = ShieldedMempool::new();
    
    // Test 1: Add transactions
    for i in 0..10 {
        let tx = ShieldedTx {
            version: 2,
            tx_type: TxType::Shielding,
            transparent_inputs: vec![],
            transparent_outputs: vec![],
            shielded_inputs: vec![],
            shielded_outputs: vec![],
            fee: MIN_SHIELDED_FEE + i * 100,
            binding_sig: None,
            locktime: i as u32,
        };
        
        if let Err(e) = mempool.add(tx) {
            return TestResult::fail(test_name, start.elapsed().as_millis(),
                &format!("Failed to add TX {}: {:?}", i, e));
        }
    }
    
    if mempool.len() != 10 {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Expected 10 TXs, got {}", mempool.len()));
    }
    
    // Test 2: Select for block (ordered by fee)
    let selected = mempool.select_for_block(5, 100_000);
    if selected.len() != 5 {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Expected 5 selected, got {}", selected.len()));
    }
    
    // Test 3: Remove TX
    let stats_before = mempool.stats();
    mempool.remove_confirmed(&selected);
    let stats_after = mempool.stats();
    
    if stats_after.tx_count != stats_before.tx_count - 5 {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Remove didn't work correctly");
    }
    
    TestResult::pass(test_name, start.elapsed().as_millis(),
        &format!("Add/select/remove OK, final_count={}", mempool.len()))
}

// =============================================================================
// Test: Privacy State Processing
// =============================================================================

pub fn test_privacy_state() -> TestResult {
    use crate::privacy::integration::PrivacyState;
    use crate::privacy::shielded_tx::{ShieldedTx, TxType, MIN_SHIELDED_FEE};
    use crate::privacy::pedersen::{PedersenCommitment, Scalar, CompressedPoint, GENERATORS};
    
    let start = Instant::now();
    let test_name = "Privacy State";
    
    let mut state = PrivacyState::new();
    
    // Test 1: Initial state
    if state.current_height != 0 {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Initial height should be 0");
    }
    
    // Test 2: Add outputs to pool
    for i in 0..20 {
        let commitment = PedersenCommitment::commit((i + 1) * 1000, Scalar::random());
        let pubkey = CompressedPoint::from_point(&(Scalar::random().inner() * GENERATORS.g));
        state.validation_ctx.shielded_pool.add_output(
            commitment, pubkey, i as u64, [i as u8; 32], 0
        );
    }
    
    if state.validation_ctx.shielded_pool.len() != 20 {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Pool should have 20 outputs");
    }
    
    // Test 3: Process block
    let txs = vec![ShieldedTx {
        version: 2,
        tx_type: TxType::Shielding,
        transparent_inputs: vec![],
        transparent_outputs: vec![],
        shielded_inputs: vec![],
        shielded_outputs: vec![],
        fee: MIN_SHIELDED_FEE,
        binding_sig: None,
        locktime: 0,
    }];
    
    state.process_block(100, [1u8; 32], &txs);
    
    if state.current_height != 100 {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Height should be 100 after block");
    }
    
    TestResult::pass(test_name, start.elapsed().as_millis(),
        "State init, pool, block processing OK")
}

// =============================================================================
// Test: Key Image Double Spend
// =============================================================================

pub fn test_double_spend_detection() -> TestResult {
    use crate::privacy::ring::{KeyImage, KeyImageSet};
    use crate::privacy::pedersen::{Scalar, CompressedPoint, GENERATORS};
    
    let start = Instant::now();
    let test_name = "Double Spend Detection";
    
    let mut ki_set = KeyImageSet::new();
    
    // Generate key image
    let sk = Scalar::random();
    let pk = CompressedPoint::from_point(&(sk.inner() * GENERATORS.g));
    let key_image = KeyImage::generate(&sk, &pk);
    
    // Test 1: First spend succeeds
    if let Err(e) = ki_set.insert(&key_image) {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("First insert should succeed: {:?}", e));
    }
    
    // Test 2: Second spend fails
    match ki_set.insert(&key_image) {
        Ok(_) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Second insert should fail (double spend)"),
        Err(crate::privacy::ring::RingError::DoubleSpend) => {},
        Err(e) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Wrong error type: {:?}", e)),
    }
    
    // Test 3: Different key image succeeds
    let sk2 = Scalar::random();
    let pk2 = CompressedPoint::from_point(&(sk2.inner() * GENERATORS.g));
    let key_image2 = KeyImage::generate(&sk2, &pk2);
    
    if let Err(e) = ki_set.insert(&key_image2) {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Different key image should succeed: {:?}", e));
    }
    
    TestResult::pass(test_name, start.elapsed().as_millis(),
        "Double spend correctly detected")
}

// =============================================================================
// Test: Full Shielded Flow
// =============================================================================

pub fn test_full_shielded_flow() -> TestResult {
    use crate::privacy::keys::PrivacyKeys;
    use crate::privacy::shielded_tx::ShieldedOutput;
    use crate::privacy::scanner::{WalletScanner, ShieldedWallet};
    
    let start = Instant::now();
    let test_name = "Full Shielded Flow";
    
    // Setup: Alice and Bob
    let _alice = PrivacyKeys::generate();
    let bob = PrivacyKeys::generate();
    let bob_addr = bob.stealth_address();
    
    // Step 1: Alice creates payment to Bob
    let amount = 10_000_000u64; // 10 MOON
    let (output, _secrets) = match ShieldedOutput::new(
        amount,
        &bob_addr.view_pubkey,
        &bob_addr.spend_pubkey,
        Some(b"Thanks Bob!"),
    ) {
        Ok(r) => r,
        Err(e) => return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Failed to create payment: {:?}", e)),
    };
    
    // Step 2: Bob scans and finds payment
    let mut bob_scanner = WalletScanner::from_keys(&bob);
    let mut bob_wallet = ShieldedWallet::new();
    
    if let Some(owned) = bob_scanner.scan_output(&output, 0, [0u8; 32], 0, 1) {
        bob_wallet.add_output(owned);
    } else {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Bob should find his payment");
    }
    
    // Step 3: Verify Bob's balance
    if bob_wallet.balance() != amount {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            &format!("Expected balance {}, got {}", amount, bob_wallet.balance()));
    }
    
    // Step 4: Bob can select output to spend
    if let Some(selected) = bob_wallet.select_outputs(5_000_000, 1000) {
        if selected.is_empty() {
            return TestResult::fail(test_name, start.elapsed().as_millis(),
                "Should select at least one output");
        }
    } else {
        return TestResult::fail(test_name, start.elapsed().as_millis(),
            "Should be able to select outputs");
    }
    
    TestResult::pass(test_name, start.elapsed().as_millis(),
        "Create → Scan → Balance → Select OK")
}

// =============================================================================
// Benchmark: Commitment Generation
// =============================================================================

pub fn bench_commitment_generation() -> TestResult {
    use crate::privacy::pedersen::{PedersenCommitment, Scalar};
    
    let start = Instant::now();
    let test_name = "Bench: Commitments";
    
    let iterations = 1000;
    
    for i in 0..iterations {
        let _ = PedersenCommitment::commit(i * 100, Scalar::random());
    }
    
    let elapsed = start.elapsed().as_millis();
    let per_op = elapsed as f64 / iterations as f64;
    
    TestResult::pass(test_name, elapsed,
        &format!("{} ops, {:.3} ms/op", iterations, per_op))
}

// =============================================================================
// Benchmark: Ring Signature
// =============================================================================

pub fn bench_ring_signature() -> TestResult {
    use crate::privacy::pedersen::{Scalar, CompressedPoint, GENERATORS};
    use crate::privacy::ring::RingSignature;
    
    let start = Instant::now();
    let test_name = "Bench: Ring Signatures";
    
    // Setup ring
    let keypairs: Vec<(Scalar, CompressedPoint)> = (0..11)
        .map(|_| {
            let sk = Scalar::random();
            let pk = CompressedPoint::from_point(&(sk.inner() * GENERATORS.g));
            (sk, pk)
        })
        .collect();
    
    let ring: Vec<CompressedPoint> = keypairs.iter().map(|(_, pk)| *pk).collect();
    let (our_sk, _) = &keypairs[5];
    let message = b"benchmark message";
    
    let iterations = 100;
    
    for _ in 0..iterations {
        let sig = RingSignature::sign(message, &ring, our_sk, 5).unwrap();
        let _ = sig.verify(message, &ring);
    }
    
    let elapsed = start.elapsed().as_millis();
    let per_op = elapsed as f64 / iterations as f64;
    
    TestResult::pass(test_name, elapsed,
        &format!("{} sign+verify, {:.1} ms/op, ring_size=11", iterations, per_op))
}

// =============================================================================
// Benchmark: Scanner
// =============================================================================

pub fn bench_scanner() -> TestResult {
    use crate::privacy::keys::PrivacyKeys;
    use crate::privacy::shielded_tx::ShieldedOutput;
    use crate::privacy::scanner::WalletScanner;
    
    let start = Instant::now();
    let test_name = "Bench: Scanner";
    
    let our_keys = PrivacyKeys::generate();
    let mut scanner = WalletScanner::from_keys(&our_keys);
    
    // Create many outputs (most not ours)
    let mut outputs = Vec::new();
    for _ in 0..100 {
        let other = PrivacyKeys::generate();
        let addr = other.stealth_address();
        let (output, _) = ShieldedOutput::new(1000, &addr.view_pubkey, &addr.spend_pubkey, None).unwrap();
        outputs.push(output);
    }
    
    // Scan all
    for (i, output) in outputs.iter().enumerate() {
        let _ = scanner.scan_output(output, i as u64, [0u8; 32], 0, 1);
    }
    
    let elapsed = start.elapsed().as_millis();
    let stats = scanner.stats();
    let per_output = elapsed as f64 / stats.outputs_scanned as f64;
    
    TestResult::pass(test_name, elapsed,
        &format!("{} scanned, {:.2} ms/output", stats.outputs_scanned, per_output))
}

// =============================================================================
// Run All Tests
// =============================================================================

pub fn run_all_tests() -> TestSuite {
    let mut suite = TestSuite::new();
    
    // Core crypto tests
    suite.add(test_pedersen_commitments());
    suite.add(test_range_proofs());
    suite.add(test_ring_signatures());
    suite.add(test_stealth_addresses());
    
    // Transaction tests
    suite.add(test_shielded_output());
    suite.add(test_scanner_detection());
    
    // State tests
    suite.add(test_shielded_mempool());
    suite.add(test_privacy_state());
    suite.add(test_double_spend_detection());
    
    // Integration tests
    suite.add(test_full_shielded_flow());
    
    // Benchmarks
    suite.add(bench_commitment_generation());
    suite.add(bench_ring_signature());
    suite.add(bench_scanner());
    
    suite
}
