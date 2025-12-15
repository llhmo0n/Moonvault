// =============================================================================
// MOONCOIN v2.34 - Atomic Swaps
// =============================================================================
//
// Trustless cross-chain exchanges using Hash Time Lock Contracts (HTLCs).
//
// How it works:
// 1. Alice wants Bob's BTC, Bob wants Alice's MOON
// 2. Alice generates secret R, shares hash H(R) with Bob
// 3. Alice locks MOON in HTLC (claimable by Bob with R, refundable after 24h)
// 4. Bob locks BTC in HTLC (claimable by Alice with R, refundable after 12h)
// 5. Alice claims BTC (reveals R on Bitcoin chain)
// 6. Bob sees R, claims MOON
// 7. Swap complete! Trustless, no intermediary needed.
//
// Security:
// - Alice's timeout (24h) > Bob's timeout (12h)
// - This ensures Alice must reveal R before Bob's refund window
// - If Alice doesn't claim, both parties get refunds
//
// =============================================================================

pub mod swap;
pub mod htlc_script;
pub mod protocol;

pub use swap::{
    AtomicSwap, SwapState, SwapRole, SwapParams,
    
};
pub use htlc_script::{
    create_htlc_script,
    HtlcScriptParams, disassemble_htlc,
};
pub use protocol::{
    SwapProtocol, SwapMessage,
};

// =============================================================================
// Constants
// =============================================================================

/// Default initiator timeout (24 hours in blocks, ~288 blocks at 5 min/block)
pub const INITIATOR_TIMEOUT_BLOCKS: u32 = 288;

/// Default participant timeout (12 hours in blocks)
pub const PARTICIPANT_TIMEOUT_BLOCKS: u32 = 144;

/// Minimum timeout difference (safety margin)
pub const MIN_TIMEOUT_DIFFERENCE: u32 = 72; // 6 hours

/// Secret/preimage size in bytes
pub const SECRET_SIZE: usize = 32;

/// Hash size in bytes
pub const HASH_SIZE: usize = 32;

// =============================================================================
// Helper Functions
// =============================================================================

/// Generate a random secret for the swap
pub fn generate_secret() -> [u8; SECRET_SIZE] {
    rand::random()
}

/// Hash a secret using SHA256
pub fn hash_secret(secret: &[u8; SECRET_SIZE]) -> [u8; HASH_SIZE] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(secret);
    let result = hasher.finalize();
    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&result);
    hash
}

/// Verify a secret matches a hash
pub fn verify_secret(secret: &[u8; SECRET_SIZE], hash: &[u8; HASH_SIZE]) -> bool {
    &hash_secret(secret) == hash
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_generation() {
        let secret1 = generate_secret();
        let secret2 = generate_secret();
        
        // Different secrets each time
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_hash_secret() {
        let secret = generate_secret();
        let hash = hash_secret(&secret);
        
        // Same secret = same hash
        assert_eq!(hash, hash_secret(&secret));
        
        // Different secret = different hash
        let secret2 = generate_secret();
        assert_ne!(hash, hash_secret(&secret2));
    }

    #[test]
    fn test_verify_secret() {
        let secret = generate_secret();
        let hash = hash_secret(&secret);
        
        assert!(verify_secret(&secret, &hash));
        
        let wrong_secret = generate_secret();
        assert!(!verify_secret(&wrong_secret, &hash));
    }
}
