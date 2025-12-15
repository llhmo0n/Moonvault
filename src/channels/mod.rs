// =============================================================================
// MOONCOIN v2.33 - Payment Channels
// =============================================================================
//
// Lightning-style payment channels for instant off-chain payments.
//
// Architecture:
// ┌─────────────────────────────────────────────────────────────────────────┐
// │                         PAYMENT CHANNELS                                │
// ├─────────────────────────────────────────────────────────────────────────┤
// │                                                                         │
// │  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────────────┐  │
// │  │ Channel  │    │ Commit   │    │  HTLC    │    │    Channel       │  │
// │  │  State   │───▶│   TX     │───▶│ Manager  │───▶│    Manager       │  │
// │  └──────────┘    └──────────┘    └──────────┘    └──────────────────┘  │
// │       │                                                   │            │
// │       ▼                                                   ▼            │
// │  ┌──────────┐                                      ┌──────────────┐    │
// │  │Revocation│                                      │   Routing    │    │
// │  │  Keys    │                                      │   (Multi-hop)│    │
// │  └──────────┘                                      └──────────────┘    │
// │                                                                         │
// └─────────────────────────────────────────────────────────────────────────┘
//
// Features:
// - Bidirectional payment channels
// - 2-of-2 multisig funding
// - Commitment transactions with revocation
// - HTLC support for routing
// - Cooperative and forced close
// - Penalty transactions for cheaters
// - CSV timelocks for safety
//
// =============================================================================

pub mod state;
pub mod commitment;
pub mod htlc;
pub mod manager;

pub use state::{
    ChannelId,
};
pub use htlc::{
    PaymentPreimage, Invoice,
};
pub use manager::ChannelManager;

// =============================================================================
// Constants
// =============================================================================

/// Default channel capacity (10 MOON)
pub const DEFAULT_CHANNEL_CAPACITY: u64 = 10 * 100_000_000;

/// Minimum channel capacity (0.001 MOON)
pub const MIN_CHANNEL_CAPACITY: u64 = 100_000;

/// Maximum channel capacity (1000 MOON)
pub const MAX_CHANNEL_CAPACITY: u64 = 1000 * 100_000_000;

/// Default HTLC minimum (1000 satoshis)
pub const DEFAULT_HTLC_MINIMUM: u64 = 1000;

/// Maximum HTLCs per channel
pub const MAX_HTLCS_PER_CHANNEL: usize = 483;

/// Default CSV delay (144 blocks = ~12 hours with 5 min blocks)
pub const DEFAULT_CSV_DELAY: u32 = 144;

/// Dust limit (546 satoshis)
pub const DUST_LIMIT: u64 = 546;

/// Channel reserve (1% of capacity, minimum 1000 sat)
pub const CHANNEL_RESERVE_PERCENT: u64 = 1;
pub const MIN_CHANNEL_RESERVE: u64 = 1000;

/// Maximum CLTV expiry for HTLCs (2 weeks)
pub const MAX_CLTV_EXPIRY: u32 = 2016 * 2;

/// HTLC timeout delta (6 blocks)
pub const CLTV_EXPIRY_DELTA: u32 = 6;

// =============================================================================
// Helper Functions
// =============================================================================

/// Calculate channel reserve from capacity
pub fn calculate_reserve(capacity: u64) -> u64 {
    let reserve = capacity * CHANNEL_RESERVE_PERCENT / 100;
    std::cmp::max(reserve, MIN_CHANNEL_RESERVE)
}

/// Generate channel ID from funding outpoint
pub fn generate_channel_id(funding_txid: &[u8; 32], funding_index: u32) -> ChannelId {
    let mut id = *funding_txid;
    // XOR with output index (like Lightning)
    let idx_bytes = funding_index.to_le_bytes();
    id[0] ^= idx_bytes[0];
    id[1] ^= idx_bytes[1];
    id[2] ^= idx_bytes[2];
    id[3] ^= idx_bytes[3];
    ChannelId(id)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_reserve() {
        // 10 MOON = 1B satoshis, 1% = 10M satoshis
        let capacity = 10 * 100_000_000;
        let reserve = calculate_reserve(capacity);
        assert_eq!(reserve, 10_000_000);

        // Small capacity uses minimum
        let small = 50_000;
        assert_eq!(calculate_reserve(small), MIN_CHANNEL_RESERVE);
    }

    #[test]
    fn test_generate_channel_id() {
        let txid = [0xAB; 32];
        let id1 = generate_channel_id(&txid, 0);
        let id2 = generate_channel_id(&txid, 1);
        
        // Different output indices = different channel IDs
        assert_ne!(id1, id2);
    }
}
