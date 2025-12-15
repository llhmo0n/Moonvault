// =============================================================================
// MOONCOIN v2.34 - Atomic Swap Core
// =============================================================================
//
// Core types and state machine for atomic swaps.
//
// =============================================================================

use serde::{Serialize, Deserialize};

use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    SECRET_SIZE, HASH_SIZE,
    INITIATOR_TIMEOUT_BLOCKS, PARTICIPANT_TIMEOUT_BLOCKS,
    MIN_TIMEOUT_DIFFERENCE,
    generate_secret, hash_secret, verify_secret,
};

// =============================================================================
// Swap Identifier
// =============================================================================

/// Unique swap identifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SwapId(pub [u8; 32]);

impl SwapId {
    /// Generate new random swap ID
    pub fn generate() -> Self {
        SwapId(rand::random())
    }

    /// Create from hash
    pub fn from_hash(hash: &[u8; HASH_SIZE]) -> Self {
        SwapId(*hash)
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

impl std::fmt::Display for SwapId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short())
    }
}

// =============================================================================
// Swap Role
// =============================================================================

/// Role in the atomic swap
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwapRole {
    /// Initiator creates the secret and hash
    /// Locks funds first, but has longer timeout
    Initiator,
    
    /// Participant receives hash from initiator
    /// Locks funds second, but has shorter timeout
    Participant,
}

impl SwapRole {
    /// Get the counterparty role
    pub fn counterparty(&self) -> Self {
        match self {
            SwapRole::Initiator => SwapRole::Participant,
            SwapRole::Participant => SwapRole::Initiator,
        }
    }

    /// Get default timeout for this role
    pub fn default_timeout(&self) -> u32 {
        match self {
            SwapRole::Initiator => INITIATOR_TIMEOUT_BLOCKS,
            SwapRole::Participant => PARTICIPANT_TIMEOUT_BLOCKS,
        }
    }
}

// =============================================================================
// Swap Parameters
// =============================================================================

/// Parameters for an atomic swap
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapParams {
    /// Amount we're offering (in satoshis)
    pub offer_amount: u64,
    
    /// Asset we're offering (chain identifier)
    pub offer_asset: String,
    
    /// Amount we want (in satoshis)
    pub want_amount: u64,
    
    /// Asset we want (chain identifier)
    pub want_asset: String,
    
    /// Our refund address
    pub refund_address: String,
    
    /// Their claim address (on our chain)
    pub counterparty_address: String,
    
    /// Timeout in blocks
    pub timeout_blocks: u32,
    
    /// Minimum confirmations required
    pub min_confirmations: u32,
}

impl SwapParams {
    /// Create swap params for initiator
    pub fn new_initiator(
        offer_amount: u64,
        offer_asset: &str,
        want_amount: u64,
        want_asset: &str,
        refund_address: &str,
        counterparty_address: &str,
    ) -> Self {
        SwapParams {
            offer_amount,
            offer_asset: offer_asset.to_string(),
            want_amount,
            want_asset: want_asset.to_string(),
            refund_address: refund_address.to_string(),
            counterparty_address: counterparty_address.to_string(),
            timeout_blocks: INITIATOR_TIMEOUT_BLOCKS,
            min_confirmations: 3,
        }
    }

    /// Create swap params for participant
    pub fn new_participant(
        offer_amount: u64,
        offer_asset: &str,
        want_amount: u64,
        want_asset: &str,
        refund_address: &str,
        counterparty_address: &str,
        initiator_timeout: u32,
    ) -> Result<Self, SwapError> {
        // Participant timeout must be less than initiator timeout
        let timeout = if initiator_timeout > MIN_TIMEOUT_DIFFERENCE {
            initiator_timeout - MIN_TIMEOUT_DIFFERENCE
        } else {
            return Err(SwapError::InvalidTimeout(
                "Initiator timeout too short".to_string()
            ));
        };

        Ok(SwapParams {
            offer_amount,
            offer_asset: offer_asset.to_string(),
            want_amount,
            want_asset: want_asset.to_string(),
            refund_address: refund_address.to_string(),
            counterparty_address: counterparty_address.to_string(),
            timeout_blocks: timeout,
            min_confirmations: 3,
        })
    }

    /// Calculate exchange rate (offer/want)
    pub fn exchange_rate(&self) -> f64 {
        self.offer_amount as f64 / self.want_amount as f64
    }
}

// =============================================================================
// Swap State
// =============================================================================

/// State of an atomic swap
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwapState {
    /// Initial state - negotiating terms
    Negotiating,
    
    /// Terms agreed, waiting for initiator to lock funds
    WaitingForInitiatorLock,
    
    /// Initiator has locked funds, waiting for participant
    InitiatorLocked {
        lock_tx: String,
        lock_height: u64,
    },
    
    /// Participant has locked funds
    ParticipantLocked {
        initiator_lock_tx: String,
        participant_lock_tx: String,
        lock_height: u64,
    },
    
    /// Initiator has claimed (revealed secret)
    InitiatorClaimed {
        claim_tx: String,
        secret: [u8; SECRET_SIZE],
    },
    
    /// Participant has claimed
    ParticipantClaimed {
        claim_tx: String,
    },
    
    /// Swap completed successfully
    Completed {
        initiator_claim_tx: String,
        participant_claim_tx: String,
    },
    
    /// Swap refunded (timeout)
    Refunded {
        refund_tx: String,
        reason: String,
    },
    
    /// Swap failed
    Failed {
        reason: String,
    },
}

impl SwapState {
    /// Is the swap in progress?
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            SwapState::Negotiating |
            SwapState::WaitingForInitiatorLock |
            SwapState::InitiatorLocked { .. } |
            SwapState::ParticipantLocked { .. } |
            SwapState::InitiatorClaimed { .. } |
            SwapState::ParticipantClaimed { .. }
        )
    }

    /// Is the swap complete?
    pub fn is_completed(&self) -> bool {
        matches!(self, SwapState::Completed { .. })
    }

    /// Is the swap failed or refunded?
    pub fn is_failed(&self) -> bool {
        matches!(
            self,
            SwapState::Refunded { .. } | SwapState::Failed { .. }
        )
    }

    /// Can we claim?
    pub fn can_claim(&self) -> bool {
        matches!(
            self,
            SwapState::ParticipantLocked { .. } |
            SwapState::InitiatorClaimed { .. }
        )
    }

    /// Can we refund?
    pub fn can_refund(&self, current_height: u64, lock_height: u64, timeout: u32) -> bool {
        let refund_height = lock_height + timeout as u64;
        current_height >= refund_height && self.is_active()
    }
}

// =============================================================================
// Swap Error
// =============================================================================

/// Atomic swap errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwapError {
    /// Invalid state for operation
    InvalidState(String),
    /// Invalid secret
    InvalidSecret,
    /// Invalid hash
    InvalidHash,
    /// Invalid timeout
    InvalidTimeout(String),
    /// Timeout expired
    TimeoutExpired,
    /// Insufficient funds
    InsufficientFunds,
    /// Transaction failed
    TransactionFailed(String),
    /// Network error
    NetworkError(String),
    /// Protocol error
    ProtocolError(String),
}

impl std::fmt::Display for SwapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwapError::InvalidState(s) => write!(f, "Invalid state: {}", s),
            SwapError::InvalidSecret => write!(f, "Invalid secret"),
            SwapError::InvalidHash => write!(f, "Invalid hash"),
            SwapError::InvalidTimeout(s) => write!(f, "Invalid timeout: {}", s),
            SwapError::TimeoutExpired => write!(f, "Timeout expired"),
            SwapError::InsufficientFunds => write!(f, "Insufficient funds"),
            SwapError::TransactionFailed(s) => write!(f, "Transaction failed: {}", s),
            SwapError::NetworkError(s) => write!(f, "Network error: {}", s),
            SwapError::ProtocolError(s) => write!(f, "Protocol error: {}", s),
        }
    }
}

impl std::error::Error for SwapError {}

// =============================================================================
// Atomic Swap
// =============================================================================

/// An atomic swap between two chains
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicSwap {
    /// Unique swap identifier
    pub id: SwapId,
    
    /// Our role in the swap
    pub role: SwapRole,
    
    /// Current state
    pub state: SwapState,
    
    /// Swap parameters
    pub params: SwapParams,
    
    /// Secret (only known by initiator until claim)
    pub secret: Option<[u8; SECRET_SIZE]>,
    
    /// Secret hash (known by both parties)
    pub secret_hash: [u8; HASH_SIZE],
    
    /// Our HTLC lock transaction
    pub our_lock_tx: Option<String>,
    
    /// Their HTLC lock transaction
    pub their_lock_tx: Option<String>,
    
    /// Our claim/refund transaction
    pub our_final_tx: Option<String>,
    
    /// Block height when we locked
    pub lock_height: Option<u64>,
    
    /// Created timestamp
    pub created_at: u64,
    
    /// Last updated timestamp
    pub updated_at: u64,
}

impl AtomicSwap {
    /// Create a new swap as initiator
    pub fn new_initiator(params: SwapParams) -> Self {
        let secret = generate_secret();
        let secret_hash = hash_secret(&secret);
        let id = SwapId::from_hash(&secret_hash);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        AtomicSwap {
            id,
            role: SwapRole::Initiator,
            state: SwapState::Negotiating,
            params,
            secret: Some(secret),
            secret_hash,
            our_lock_tx: None,
            their_lock_tx: None,
            our_final_tx: None,
            lock_height: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new swap as participant
    pub fn new_participant(
        params: SwapParams,
        secret_hash: [u8; HASH_SIZE],
    ) -> Self {
        let id = SwapId::from_hash(&secret_hash);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        AtomicSwap {
            id,
            role: SwapRole::Participant,
            state: SwapState::WaitingForInitiatorLock,
            params,
            secret: None, // Participant doesn't know secret yet
            secret_hash,
            our_lock_tx: None,
            their_lock_tx: None,
            our_final_tx: None,
            lock_height: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Get swap ID
    pub fn id(&self) -> SwapId {
        self.id
    }

    /// Get secret hash (for HTLC creation)
    pub fn secret_hash(&self) -> &[u8; HASH_SIZE] {
        &self.secret_hash
    }

    /// Get secret (only for initiator, or after learning from claim)
    pub fn secret(&self) -> Option<&[u8; SECRET_SIZE]> {
        self.secret.as_ref()
    }

    // =========================================================================
    // State Transitions
    // =========================================================================

    /// Initiator: Lock funds in HTLC
    pub fn initiator_lock(
        &mut self,
        lock_tx: String,
        lock_height: u64,
    ) -> Result<(), SwapError> {
        if self.role != SwapRole::Initiator {
            return Err(SwapError::InvalidState("Not initiator".to_string()));
        }

        match &self.state {
            SwapState::Negotiating | SwapState::WaitingForInitiatorLock => {
                self.our_lock_tx = Some(lock_tx.clone());
                self.lock_height = Some(lock_height);
                self.state = SwapState::InitiatorLocked {
                    lock_tx,
                    lock_height,
                };
                self.update_timestamp();
                Ok(())
            }
            _ => Err(SwapError::InvalidState(format!(
                "Cannot lock in state {:?}",
                self.state
            ))),
        }
    }

    /// Participant: Confirm initiator lock and lock own funds
    pub fn participant_lock(
        &mut self,
        initiator_lock_tx: String,
        participant_lock_tx: String,
        lock_height: u64,
    ) -> Result<(), SwapError> {
        if self.role != SwapRole::Participant {
            return Err(SwapError::InvalidState("Not participant".to_string()));
        }

        match &self.state {
            SwapState::WaitingForInitiatorLock => {
                self.their_lock_tx = Some(initiator_lock_tx.clone());
                self.our_lock_tx = Some(participant_lock_tx.clone());
                self.lock_height = Some(lock_height);
                self.state = SwapState::ParticipantLocked {
                    initiator_lock_tx,
                    participant_lock_tx,
                    lock_height,
                };
                self.update_timestamp();
                Ok(())
            }
            _ => Err(SwapError::InvalidState(format!(
                "Cannot lock in state {:?}",
                self.state
            ))),
        }
    }

    /// Initiator: Record participant's lock
    pub fn record_participant_lock(
        &mut self,
        participant_lock_tx: String,
        lock_height: u64,
    ) -> Result<(), SwapError> {
        if self.role != SwapRole::Initiator {
            return Err(SwapError::InvalidState("Not initiator".to_string()));
        }

        match &self.state {
            SwapState::InitiatorLocked { lock_tx, .. } => {
                self.their_lock_tx = Some(participant_lock_tx.clone());
                self.state = SwapState::ParticipantLocked {
                    initiator_lock_tx: lock_tx.clone(),
                    participant_lock_tx,
                    lock_height,
                };
                self.update_timestamp();
                Ok(())
            }
            _ => Err(SwapError::InvalidState(format!(
                "Cannot record participant lock in state {:?}",
                self.state
            ))),
        }
    }

    /// Initiator: Claim participant's funds (reveals secret)
    pub fn initiator_claim(&mut self, claim_tx: String) -> Result<[u8; SECRET_SIZE], SwapError> {
        if self.role != SwapRole::Initiator {
            return Err(SwapError::InvalidState("Not initiator".to_string()));
        }

        let secret = self.secret.ok_or(SwapError::InvalidSecret)?;

        match &self.state {
            SwapState::ParticipantLocked { .. } => {
                self.our_final_tx = Some(claim_tx.clone());
                self.state = SwapState::InitiatorClaimed {
                    claim_tx,
                    secret,
                };
                self.update_timestamp();
                Ok(secret)
            }
            _ => Err(SwapError::InvalidState(format!(
                "Cannot claim in state {:?}",
                self.state
            ))),
        }
    }

    /// Participant: Learn secret and claim
    pub fn participant_claim(
        &mut self,
        secret: [u8; SECRET_SIZE],
        claim_tx: String,
    ) -> Result<(), SwapError> {
        if self.role != SwapRole::Participant {
            return Err(SwapError::InvalidState("Not participant".to_string()));
        }

        // Verify secret
        if !verify_secret(&secret, &self.secret_hash) {
            return Err(SwapError::InvalidSecret);
        }

        match &self.state {
            SwapState::ParticipantLocked { .. } | SwapState::InitiatorClaimed { .. } => {
                self.secret = Some(secret);
                self.our_final_tx = Some(claim_tx.clone());
                self.state = SwapState::ParticipantClaimed { claim_tx };
                self.update_timestamp();
                Ok(())
            }
            _ => Err(SwapError::InvalidState(format!(
                "Cannot claim in state {:?}",
                self.state
            ))),
        }
    }

    /// Mark swap as completed
    pub fn complete(
        &mut self,
        initiator_claim_tx: String,
        participant_claim_tx: String,
    ) -> Result<(), SwapError> {
        match &self.state {
            SwapState::InitiatorClaimed { .. } | SwapState::ParticipantClaimed { .. } => {
                self.state = SwapState::Completed {
                    initiator_claim_tx,
                    participant_claim_tx,
                };
                self.update_timestamp();
                Ok(())
            }
            _ => Err(SwapError::InvalidState(format!(
                "Cannot complete in state {:?}",
                self.state
            ))),
        }
    }

    /// Refund (timeout expired)
    pub fn refund(
        &mut self,
        refund_tx: String,
        current_height: u64,
    ) -> Result<(), SwapError> {
        let lock_height = self.lock_height.ok_or(SwapError::InvalidState(
            "No lock height".to_string()
        ))?;

        if !self.state.can_refund(current_height, lock_height, self.params.timeout_blocks) {
            return Err(SwapError::InvalidState(
                "Cannot refund yet".to_string()
            ));
        }

        self.our_final_tx = Some(refund_tx.clone());
        self.state = SwapState::Refunded {
            refund_tx,
            reason: "Timeout expired".to_string(),
        };
        self.update_timestamp();
        Ok(())
    }

    /// Mark as failed
    pub fn fail(&mut self, reason: &str) {
        self.state = SwapState::Failed {
            reason: reason.to_string(),
        };
        self.update_timestamp();
    }

    // =========================================================================
    // Queries
    // =========================================================================

    /// Check if we can claim
    pub fn can_claim(&self) -> bool {
        self.state.can_claim() && 
        (self.role == SwapRole::Initiator || self.secret.is_some())
    }

    /// Check if we can refund
    pub fn can_refund(&self, current_height: u64) -> bool {
        if let Some(lock_height) = self.lock_height {
            self.state.can_refund(current_height, lock_height, self.params.timeout_blocks)
        } else {
            false
        }
    }

    /// Get remaining blocks until refund is possible
    pub fn blocks_until_refund(&self, current_height: u64) -> Option<u64> {
        self.lock_height.map(|lock_height| {
            let refund_height = lock_height + self.params.timeout_blocks as u64;
            if current_height >= refund_height {
                0
            } else {
                refund_height - current_height
            }
        })
    }

    /// Get swap summary
    pub fn summary(&self) -> SwapSummary {
        SwapSummary {
            id: self.id,
            role: self.role,
            state: format!("{:?}", self.state),
            offer: format!("{} {}", self.params.offer_amount, self.params.offer_asset),
            want: format!("{} {}", self.params.want_amount, self.params.want_asset),
            secret_hash: hex::encode(&self.secret_hash[..8]),
            has_secret: self.secret.is_some(),
        }
    }

    fn update_timestamp(&mut self) {
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

// =============================================================================
// Swap Summary
// =============================================================================

/// Summary information about a swap
#[derive(Clone, Debug)]
pub struct SwapSummary {
    pub id: SwapId,
    pub role: SwapRole,
    pub state: String,
    pub offer: String,
    pub want: String,
    pub secret_hash: String,
    pub has_secret: bool,
}

impl std::fmt::Display for SwapSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Swap: {}", self.id)?;
        writeln!(f, "  Role: {:?}", self.role)?;
        writeln!(f, "  State: {}", self.state)?;
        writeln!(f, "  Offering: {}", self.offer)?;
        writeln!(f, "  Wanting: {}", self.want)?;
        writeln!(f, "  Hash: {}...", self.secret_hash)?;
        writeln!(f, "  Has Secret: {}", self.has_secret)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_initiator_params() -> SwapParams {
        SwapParams::new_initiator(
            10 * 100_000_000, // 10 MOON
            "MOON",
            100_000,          // 0.001 BTC
            "BTC",
            "moon1refund...",
            "moon1counter...",
        )
    }

    fn create_participant_params(initiator_timeout: u32) -> SwapParams {
        SwapParams::new_participant(
            100_000,          // 0.001 BTC
            "BTC",
            10 * 100_000_000, // 10 MOON
            "MOON",
            "bc1refund...",
            "bc1counter...",
            initiator_timeout,
        ).unwrap()
    }

    #[test]
    fn test_create_initiator_swap() {
        let params = create_initiator_params();
        let swap = AtomicSwap::new_initiator(params);

        assert_eq!(swap.role, SwapRole::Initiator);
        assert!(swap.secret.is_some());
        assert!(matches!(swap.state, SwapState::Negotiating));
    }

    #[test]
    fn test_create_participant_swap() {
        let init_params = create_initiator_params();
        let initiator = AtomicSwap::new_initiator(init_params);

        let part_params = create_participant_params(INITIATOR_TIMEOUT_BLOCKS);
        let participant = AtomicSwap::new_participant(
            part_params,
            initiator.secret_hash,
        );

        assert_eq!(participant.role, SwapRole::Participant);
        assert!(participant.secret.is_none());
        assert_eq!(participant.secret_hash, initiator.secret_hash);
    }

    #[test]
    fn test_swap_flow() {
        // Create initiator
        let init_params = create_initiator_params();
        let mut initiator = AtomicSwap::new_initiator(init_params);

        // Create participant
        let part_params = create_participant_params(INITIATOR_TIMEOUT_BLOCKS);
        let mut participant = AtomicSwap::new_participant(
            part_params,
            initiator.secret_hash,
        );

        // Initiator locks
        initiator.initiator_lock("init_lock_tx".to_string(), 100).unwrap();
        assert!(matches!(initiator.state, SwapState::InitiatorLocked { .. }));

        // Participant sees and locks
        participant.participant_lock(
            "init_lock_tx".to_string(),
            "part_lock_tx".to_string(),
            101,
        ).unwrap();
        assert!(matches!(participant.state, SwapState::ParticipantLocked { .. }));

        // Initiator records participant lock
        initiator.record_participant_lock("part_lock_tx".to_string(), 101).unwrap();

        // Initiator claims (reveals secret)
        let secret = initiator.initiator_claim("init_claim_tx".to_string()).unwrap();
        assert!(matches!(initiator.state, SwapState::InitiatorClaimed { .. }));

        // Participant learns secret and claims
        participant.participant_claim(secret, "part_claim_tx".to_string()).unwrap();
        assert!(matches!(participant.state, SwapState::ParticipantClaimed { .. }));

        // Both complete
        initiator.complete("init_claim_tx".to_string(), "part_claim_tx".to_string()).unwrap();
        participant.complete("init_claim_tx".to_string(), "part_claim_tx".to_string()).unwrap();

        assert!(initiator.state.is_completed());
        assert!(participant.state.is_completed());
    }

    #[test]
    fn test_refund() {
        let params = create_initiator_params();
        let mut swap = AtomicSwap::new_initiator(params);

        swap.initiator_lock("lock_tx".to_string(), 100).unwrap();

        // Can't refund before timeout
        assert!(!swap.can_refund(200));

        // Can refund after timeout
        let refund_height = 100 + INITIATOR_TIMEOUT_BLOCKS as u64;
        assert!(swap.can_refund(refund_height));

        swap.refund("refund_tx".to_string(), refund_height).unwrap();
        assert!(matches!(swap.state, SwapState::Refunded { .. }));
    }
}
