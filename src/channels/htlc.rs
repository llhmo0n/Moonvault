// =============================================================================
// MOONCOIN v2.33 - HTLC (Hash Time Lock Contracts)
// =============================================================================
//
// HTLCs enable trustless multi-hop payments through the network.
//
// How it works:
// 1. Alice wants to pay Carol through Bob
// 2. Carol generates secret R, gives hash H(R) to Alice
// 3. Alice → Bob: "I'll pay you X if you give me R before block N"
// 4. Bob → Carol: "I'll pay you X-fee if you give me R before block N-delta"
// 5. Carol reveals R to Bob (claims payment)
// 6. Bob reveals R to Alice (claims payment)
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │                           HTLC FLOW                                     │
// ├─────────────────────────────────────────────────────────────────────────┤
// │                                                                         │
// │   Alice ──────── HTLC(H) ────────▶ Bob ──────── HTLC(H) ────────▶ Carol │
// │                                                                         │
// │   Alice ◀──────── R ─────────────── Bob ◀─────── R ─────────────── Carol│
// │                                                                         │
// │   Timeout: N                    Timeout: N-6                           │
// │                                                                         │
// └─────────────────────────────────────────────────────────────────────────┘
//
// =============================================================================

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

use super::state::ChannelError;
use super::{CLTV_EXPIRY_DELTA, MAX_CLTV_EXPIRY};

// =============================================================================
// Payment Hash & Preimage
// =============================================================================

/// Payment hash (SHA256 of preimage)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PaymentHash(pub [u8; 32]);

impl PaymentHash {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PaymentHash(bytes)
    }

    /// Create from preimage
    pub fn from_preimage(preimage: &PaymentPreimage) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&preimage.0);
        let result = hasher.finalize();
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        PaymentHash(hash)
    }

    /// To hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Short display
    pub fn short(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

impl std::fmt::Display for PaymentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short())
    }
}

/// Payment preimage (secret that unlocks HTLC)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentPreimage(pub [u8; 32]);

impl PaymentPreimage {
    /// Generate random preimage
    pub fn generate() -> Self {
        let bytes: [u8; 32] = rand::random();
        PaymentPreimage(bytes)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PaymentPreimage(bytes)
    }

    /// Get the payment hash for this preimage
    pub fn payment_hash(&self) -> PaymentHash {
        PaymentHash::from_preimage(self)
    }

    /// Verify this preimage matches a payment hash
    pub fn verify(&self, hash: &PaymentHash) -> bool {
        self.payment_hash() == *hash
    }

    /// To hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

// =============================================================================
// HTLC Identifier
// =============================================================================

/// Unique HTLC identifier within a channel
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HtlcId(pub u64);

impl HtlcId {
    pub fn new(id: u64) -> Self {
        HtlcId(id)
    }
}

impl std::fmt::Display for HtlcId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTLC#{}", self.0)
    }
}

// =============================================================================
// HTLC Direction
// =============================================================================

/// Direction of HTLC from our perspective
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtlcDirection {
    /// We are offering (sending) this HTLC
    Offered,
    /// We are receiving this HTLC
    Received,
}

impl HtlcDirection {
    pub fn is_offered(&self) -> bool {
        matches!(self, HtlcDirection::Offered)
    }

    pub fn is_received(&self) -> bool {
        matches!(self, HtlcDirection::Received)
    }
}

// =============================================================================
// HTLC State
// =============================================================================

/// State of an HTLC
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtlcState {
    /// HTLC proposed, waiting for commitment
    LocalPending,
    
    /// HTLC proposed by remote, waiting for our response
    RemotePending,
    
    /// HTLC committed in channel
    Committed,
    
    /// We know the preimage, waiting to claim
    KnownPreimage {
        preimage: [u8; 32],
    },
    
    /// HTLC fulfilled (preimage revealed)
    Fulfilled {
        preimage: [u8; 32],
    },
    
    /// HTLC failed (timeout or explicit fail)
    Failed {
        reason: HtlcFailReason,
    },
    
    /// HTLC removed from channel
    Removed,
}

impl HtlcState {
    pub fn is_pending(&self) -> bool {
        matches!(self, HtlcState::LocalPending | HtlcState::RemotePending)
    }

    pub fn is_committed(&self) -> bool {
        matches!(self, HtlcState::Committed)
    }

    pub fn is_resolved(&self) -> bool {
        matches!(
            self,
            HtlcState::Fulfilled { .. } | HtlcState::Failed { .. } | HtlcState::Removed
        )
    }
}

/// Reason for HTLC failure
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtlcFailReason {
    /// Timeout expired
    Timeout,
    /// Insufficient capacity
    InsufficientCapacity,
    /// Unknown payment hash
    UnknownPaymentHash,
    /// Incorrect payment amount
    IncorrectAmount,
    /// Final expiry too soon
    ExpiryTooSoon,
    /// Channel disabled
    ChannelDisabled,
    /// Temporary failure
    TemporaryFailure,
    /// Permanent failure
    PermanentFailure,
    /// Custom error
    Custom(String),
}

// =============================================================================
// HTLC
// =============================================================================

/// Hash Time Lock Contract
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Htlc {
    /// Unique ID within channel
    pub id: HtlcId,
    
    /// Payment hash
    pub payment_hash: PaymentHash,
    
    /// Amount in satoshis
    pub amount: u64,
    
    /// Direction (offered or received)
    pub direction: HtlcDirection,
    
    /// CLTV expiry (block height)
    pub cltv_expiry: u32,
    
    /// Current state
    pub state: HtlcState,
    
    /// Onion routing packet (encrypted next-hop info)
    pub onion_packet: Option<Vec<u8>>,
    
    /// Timestamps
    pub created_at: u64,
    pub resolved_at: Option<u64>,
}

impl Htlc {
    /// Create a new offered HTLC (we're sending)
    pub fn new_offered(
        id: HtlcId,
        payment_hash: PaymentHash,
        amount: u64,
        cltv_expiry: u32,
    ) -> Result<Self, ChannelError> {
        Self::validate_expiry(cltv_expiry)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Htlc {
            id,
            payment_hash,
            amount,
            direction: HtlcDirection::Offered,
            cltv_expiry,
            state: HtlcState::LocalPending,
            onion_packet: None,
            created_at: now,
            resolved_at: None,
        })
    }

    /// Create a new received HTLC (we're receiving)
    pub fn new_received(
        id: HtlcId,
        payment_hash: PaymentHash,
        amount: u64,
        cltv_expiry: u32,
        onion_packet: Option<Vec<u8>>,
    ) -> Result<Self, ChannelError> {
        Self::validate_expiry(cltv_expiry)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Htlc {
            id,
            payment_hash,
            amount,
            direction: HtlcDirection::Received,
            cltv_expiry,
            state: HtlcState::RemotePending,
            onion_packet,
            created_at: now,
            resolved_at: None,
        })
    }

    /// Validate CLTV expiry
    fn validate_expiry(cltv_expiry: u32) -> Result<(), ChannelError> {
        if cltv_expiry > MAX_CLTV_EXPIRY {
            return Err(ChannelError::HtlcExpired);
        }
        Ok(())
    }

    /// Mark as committed
    pub fn commit(&mut self) {
        if self.state.is_pending() {
            self.state = HtlcState::Committed;
        }
    }

    /// Fulfill with preimage
    pub fn fulfill(&mut self, preimage: &PaymentPreimage) -> Result<(), ChannelError> {
        // Verify preimage matches
        if !preimage.verify(&self.payment_hash) {
            return Err(ChannelError::InvalidPreimage);
        }

        self.state = HtlcState::Fulfilled {
            preimage: preimage.0,
        };
        self.resolved_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        Ok(())
    }

    /// Fail HTLC
    pub fn fail(&mut self, reason: HtlcFailReason) {
        self.state = HtlcState::Failed { reason };
        self.resolved_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
    }

    /// Check if HTLC has timed out
    pub fn is_expired(&self, current_height: u32) -> bool {
        current_height >= self.cltv_expiry
    }

    /// Get minimum forwarding expiry (for routing)
    pub fn min_forwarding_expiry(&self) -> u32 {
        self.cltv_expiry.saturating_sub(CLTV_EXPIRY_DELTA)
    }

    /// Mark as removed
    pub fn remove(&mut self) {
        self.state = HtlcState::Removed;
    }

    /// Get preimage if fulfilled
    pub fn preimage(&self) -> Option<PaymentPreimage> {
        match &self.state {
            HtlcState::Fulfilled { preimage } => Some(PaymentPreimage(*preimage)),
            HtlcState::KnownPreimage { preimage } => Some(PaymentPreimage(*preimage)),
            _ => None,
        }
    }
}

// =============================================================================
// HTLC Manager
// =============================================================================

/// Manages HTLCs for a channel
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HtlcManager {
    /// Next HTLC ID to assign
    next_id: u64,
    
    /// Active HTLCs (offered by us)
    pub offered: Vec<Htlc>,
    
    /// Active HTLCs (received from remote)
    pub received: Vec<Htlc>,
    
    /// Total value offered (in flight)
    pub total_offered: u64,
    
    /// Total value received (in flight)
    pub total_received: u64,
}

impl HtlcManager {
    pub fn new() -> Self {
        HtlcManager {
            next_id: 0,
            offered: Vec::new(),
            received: Vec::new(),
            total_offered: 0,
            total_received: 0,
        }
    }

    /// Add offered HTLC
    pub fn add_offered(
        &mut self,
        payment_hash: PaymentHash,
        amount: u64,
        cltv_expiry: u32,
        max_htlcs: usize,
        max_value: u64,
    ) -> Result<HtlcId, ChannelError> {
        // Check limits
        if self.offered.len() >= max_htlcs {
            return Err(ChannelError::TooManyHtlcs);
        }
        if self.total_offered + amount > max_value {
            return Err(ChannelError::HtlcValueExceeded);
        }

        let id = HtlcId::new(self.next_id);
        self.next_id += 1;

        let htlc = Htlc::new_offered(id, payment_hash, amount, cltv_expiry)?;
        self.offered.push(htlc);
        self.total_offered += amount;

        Ok(id)
    }

    /// Add received HTLC
    pub fn add_received(
        &mut self,
        payment_hash: PaymentHash,
        amount: u64,
        cltv_expiry: u32,
        onion_packet: Option<Vec<u8>>,
        max_htlcs: usize,
        max_value: u64,
    ) -> Result<HtlcId, ChannelError> {
        // Check limits
        if self.received.len() >= max_htlcs {
            return Err(ChannelError::TooManyHtlcs);
        }
        if self.total_received + amount > max_value {
            return Err(ChannelError::HtlcValueExceeded);
        }

        let id = HtlcId::new(self.next_id);
        self.next_id += 1;

        let htlc = Htlc::new_received(id, payment_hash, amount, cltv_expiry, onion_packet)?;
        self.received.push(htlc);
        self.total_received += amount;

        Ok(id)
    }

    /// Find HTLC by ID
    pub fn find(&self, id: HtlcId) -> Option<&Htlc> {
        self.offered.iter()
            .chain(self.received.iter())
            .find(|h| h.id == id)
    }

    /// Find HTLC by ID (mutable)
    pub fn find_mut(&mut self, id: HtlcId) -> Option<&mut Htlc> {
        for htlc in self.offered.iter_mut().chain(self.received.iter_mut()) {
            if htlc.id == id {
                return Some(htlc);
            }
        }
        None
    }

    /// Find HTLC by payment hash
    pub fn find_by_hash(&self, hash: &PaymentHash) -> Option<&Htlc> {
        self.offered.iter()
            .chain(self.received.iter())
            .find(|h| h.payment_hash == *hash)
    }

    /// Fulfill HTLC
    pub fn fulfill(&mut self, id: HtlcId, preimage: &PaymentPreimage) -> Result<u64, ChannelError> {
        let htlc = self.find_mut(id).ok_or(ChannelError::UnknownHtlc)?;
        let amount = htlc.amount;
        let direction = htlc.direction;

        htlc.fulfill(preimage)?;

        // Update totals
        match direction {
            HtlcDirection::Offered => self.total_offered -= amount,
            HtlcDirection::Received => self.total_received -= amount,
        }

        Ok(amount)
    }

    /// Fail HTLC
    pub fn fail(&mut self, id: HtlcId, reason: HtlcFailReason) -> Result<u64, ChannelError> {
        let htlc = self.find_mut(id).ok_or(ChannelError::UnknownHtlc)?;
        let amount = htlc.amount;
        let direction = htlc.direction;

        htlc.fail(reason);

        // Update totals
        match direction {
            HtlcDirection::Offered => self.total_offered -= amount,
            HtlcDirection::Received => self.total_received -= amount,
        }

        Ok(amount)
    }

    /// Get all pending HTLCs
    pub fn pending(&self) -> impl Iterator<Item = &Htlc> {
        self.offered.iter()
            .chain(self.received.iter())
            .filter(|h| h.state.is_pending() || h.state.is_committed())
    }

    /// Get expired HTLCs
    pub fn expired(&self, current_height: u32) -> Vec<&Htlc> {
        self.pending()
            .filter(|h| h.is_expired(current_height))
            .collect()
    }

    /// Remove resolved HTLCs
    pub fn cleanup(&mut self) {
        self.offered.retain(|h| !matches!(h.state, HtlcState::Removed));
        self.received.retain(|h| !matches!(h.state, HtlcState::Removed));
    }

    /// Count active HTLCs
    pub fn count(&self) -> usize {
        self.offered.len() + self.received.len()
    }

    /// Total value in flight
    pub fn total_in_flight(&self) -> u64 {
        self.total_offered + self.total_received
    }
}

// =============================================================================
// Invoice (Payment Request)
// =============================================================================

/// A payment invoice (payment request)
#[derive(Clone, Debug)]
pub struct Invoice {
    /// Payment hash
    pub payment_hash: PaymentHash,
    
    /// Amount in satoshis (optional for zero-amount invoices)
    pub amount: Option<u64>,
    
    /// Description
    pub description: String,
    
    /// Expiry time (seconds from creation)
    pub expiry: u32,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Final CLTV delta
    pub min_final_cltv_expiry: u32,
    
    /// Payee public key
    pub payee_pubkey: Option<[u8; 33]>,
}

impl Invoice {
    /// Create a new invoice
    pub fn new(
        preimage: &PaymentPreimage,
        amount: Option<u64>,
        description: &str,
        expiry: u32,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Invoice {
            payment_hash: preimage.payment_hash(),
            amount,
            description: description.to_string(),
            expiry,
            created_at: now,
            min_final_cltv_expiry: CLTV_EXPIRY_DELTA,
            payee_pubkey: None,
        }
    }

    /// Is the invoice expired?
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now > self.created_at + self.expiry as u64
    }

    /// Encode as string (simplified)
    pub fn encode(&self) -> String {
        // In production, use BOLT11 encoding
        format!(
            "moon1{}{}",
            self.payment_hash.to_hex(),
            self.amount.map(|a| format!("{}", a)).unwrap_or_default()
        )
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_preimage() {
        let preimage = PaymentPreimage::generate();
        let hash = preimage.payment_hash();
        
        assert!(preimage.verify(&hash));
        
        let wrong_preimage = PaymentPreimage::generate();
        assert!(!wrong_preimage.verify(&hash));
    }

    #[test]
    fn test_htlc_offered() {
        let preimage = PaymentPreimage::generate();
        let hash = preimage.payment_hash();

        let mut htlc = Htlc::new_offered(
            HtlcId::new(0),
            hash,
            100_000,
            1000,
        ).unwrap();

        assert!(htlc.state.is_pending());
        assert_eq!(htlc.direction, HtlcDirection::Offered);

        // Commit
        htlc.commit();
        assert!(htlc.state.is_committed());

        // Fulfill
        htlc.fulfill(&preimage).unwrap();
        assert!(htlc.state.is_resolved());
    }

    #[test]
    fn test_htlc_wrong_preimage() {
        let preimage = PaymentPreimage::generate();
        let hash = preimage.payment_hash();

        let mut htlc = Htlc::new_offered(
            HtlcId::new(0),
            hash,
            100_000,
            1000,
        ).unwrap();

        htlc.commit();

        let wrong_preimage = PaymentPreimage::generate();
        let result = htlc.fulfill(&wrong_preimage);
        assert!(matches!(result, Err(ChannelError::InvalidPreimage)));
    }

    #[test]
    fn test_htlc_manager() {
        let mut manager = HtlcManager::new();

        let preimage1 = PaymentPreimage::generate();
        let hash1 = preimage1.payment_hash();

        let id1 = manager.add_offered(hash1, 50_000, 1000, 10, u64::MAX).unwrap();
        assert_eq!(manager.count(), 1);
        assert_eq!(manager.total_offered, 50_000);

        let preimage2 = PaymentPreimage::generate();
        let hash2 = preimage2.payment_hash();

        let _id2 = manager.add_received(hash2, 30_000, 1000, None, 10, u64::MAX).unwrap();
        assert_eq!(manager.count(), 2);
        assert_eq!(manager.total_received, 30_000);

        // Fulfill first
        let amount = manager.fulfill(id1, &preimage1).unwrap();
        assert_eq!(amount, 50_000);
        assert_eq!(manager.total_offered, 0);
    }

    #[test]
    fn test_htlc_expiry() {
        let preimage = PaymentPreimage::generate();
        let hash = preimage.payment_hash();

        let htlc = Htlc::new_offered(
            HtlcId::new(0),
            hash,
            100_000,
            1000,
        ).unwrap();

        assert!(!htlc.is_expired(999));
        assert!(htlc.is_expired(1000));
        assert!(htlc.is_expired(1001));
    }

    #[test]
    fn test_invoice() {
        let preimage = PaymentPreimage::generate();
        let invoice = Invoice::new(
            &preimage,
            Some(100_000),
            "Test payment",
            3600,
        );

        assert!(!invoice.is_expired());
        assert!(preimage.verify(&invoice.payment_hash));
    }
}
