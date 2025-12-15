// =============================================================================
// MOONCOIN v2.33 - Channel State
// =============================================================================
//
// Channel state machine and core types.
//
// Channel Lifecycle:
// ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
// │   Created   │────▶│  Funding    │────▶│   Active    │
// └─────────────┘     └─────────────┘     └─────────────┘
//                                               │
//                     ┌─────────────────────────┼─────────────────────────┐
//                     ▼                         ▼                         ▼
//              ┌─────────────┐          ┌─────────────┐          ┌─────────────┐
//              │  Closing    │          │  Force      │          │  Shutdown   │
//              │(cooperative)│          │  Closing    │          │ (initiated) │
//              └─────────────┘          └─────────────┘          └─────────────┘
//                     │                         │                         │
//                     ▼                         ▼                         ▼
//              ┌─────────────────────────────────────────────────────────────┐
//              │                         CLOSED                              │
//              └─────────────────────────────────────────────────────────────┘
//
// =============================================================================

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    DEFAULT_CSV_DELAY, DUST_LIMIT, calculate_reserve,
    MAX_HTLCS_PER_CHANNEL,
};

// =============================================================================
// Channel Identifier
// =============================================================================

/// Unique channel identifier (32 bytes)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(pub [u8; 32]);

impl ChannelId {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        ChannelId(bytes)
    }

    /// Create temporary ID (before funding)
    pub fn temporary() -> Self {
        let mut bytes = [0u8; 32];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        bytes[..16].copy_from_slice(&timestamp.to_le_bytes());
        
        // Add randomness
        let random: [u8; 16] = rand::random();
        bytes[16..].copy_from_slice(&random);
        
        ChannelId(bytes)
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Short display (first 8 chars)
    pub fn short(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short())
    }
}

// =============================================================================
// Channel Party (Local vs Remote)
// =============================================================================

/// Which side of the channel
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelParty {
    Local,
    Remote,
}

impl ChannelParty {
    pub fn other(&self) -> Self {
        match self {
            ChannelParty::Local => ChannelParty::Remote,
            ChannelParty::Remote => ChannelParty::Local,
        }
    }
}

// =============================================================================
// Balance
// =============================================================================

/// Channel balance for both parties
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// Our balance in satoshis
    pub local: u64,
    /// Their balance in satoshis
    pub remote: u64,
    /// Pending HTLCs (inbound)
    pub pending_inbound: u64,
    /// Pending HTLCs (outbound)
    pub pending_outbound: u64,
}

impl Balance {
    pub fn new(local: u64, remote: u64) -> Self {
        Balance {
            local,
            remote,
            pending_inbound: 0,
            pending_outbound: 0,
        }
    }

    /// Total channel capacity
    pub fn total(&self) -> u64 {
        self.local + self.remote + self.pending_inbound + self.pending_outbound
    }

    /// Available to send (considering reserve)
    pub fn available_to_send(&self, reserve: u64) -> u64 {
        if self.local > reserve {
            self.local - reserve
        } else {
            0
        }
    }

    /// Available to receive
    pub fn available_to_receive(&self, reserve: u64) -> u64 {
        if self.remote > reserve {
            self.remote - reserve
        } else {
            0
        }
    }

    /// Transfer from local to remote
    pub fn transfer_to_remote(&mut self, amount: u64) -> Result<(), ChannelError> {
        if amount > self.local {
            return Err(ChannelError::InsufficientBalance);
        }
        self.local -= amount;
        self.remote += amount;
        Ok(())
    }

    /// Transfer from remote to local
    pub fn transfer_to_local(&mut self, amount: u64) -> Result<(), ChannelError> {
        if amount > self.remote {
            return Err(ChannelError::InsufficientBalance);
        }
        self.remote -= amount;
        self.local += amount;
        Ok(())
    }
}

// =============================================================================
// Channel State
// =============================================================================

/// Current state of the channel
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelState {
    /// Channel created, waiting for funding TX
    Created,
    
    /// Funding TX broadcast, waiting for confirmations
    FundingBroadcast {
        funding_txid: [u8; 32],
        confirmations: u32,
        required_confirmations: u32,
    },
    
    /// Channel is open and operational
    Active,
    
    /// Shutdown initiated, resolving HTLCs
    ShutdownInitiated {
        initiator: ChannelParty,
    },
    
    /// All HTLCs resolved, negotiating close
    ShutdownComplete,
    
    /// Cooperative close TX broadcast
    ClosingBroadcast {
        closing_txid: [u8; 32],
    },
    
    /// Force close initiated (unilateral)
    ForceClosing {
        commitment_txid: [u8; 32],
        broadcast_height: u64,
    },
    
    /// Waiting for CSV timeout after force close
    AwaitingCsvTimeout {
        commitment_txid: [u8; 32],
        timeout_height: u64,
    },
    
    /// Channel fully closed
    Closed {
        close_type: CloseType,
        final_balance_local: u64,
        final_balance_remote: u64,
    },
}

impl ChannelState {
    /// Is the channel operational?
    pub fn is_active(&self) -> bool {
        matches!(self, ChannelState::Active)
    }

    /// Is the channel closed or closing?
    pub fn is_closing(&self) -> bool {
        matches!(
            self,
            ChannelState::ShutdownInitiated { .. } |
            ChannelState::ShutdownComplete |
            ChannelState::ClosingBroadcast { .. } |
            ChannelState::ForceClosing { .. } |
            ChannelState::AwaitingCsvTimeout { .. } |
            ChannelState::Closed { .. }
        )
    }

    /// Can send/receive payments?
    pub fn can_transact(&self) -> bool {
        matches!(self, ChannelState::Active)
    }
}

/// How the channel was closed
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseType {
    /// Both parties agreed
    Cooperative,
    /// We force closed
    LocalForceClose,
    /// They force closed
    RemoteForceClose,
    /// Penalty transaction (they cheated)
    Breach,
}

// =============================================================================
// Channel Configuration
// =============================================================================

/// Channel configuration parameters
#[derive(Clone, Debug)]
pub struct ChannelConfig {
    /// CSV delay for our outputs (blocks)
    pub to_self_delay: u32,
    /// CSV delay for their outputs (blocks)  
    pub to_remote_delay: u32,
    /// Minimum HTLC value we accept
    pub htlc_minimum: u64,
    /// Maximum HTLCs in flight
    pub max_htlcs: usize,
    /// Maximum HTLC value in flight
    pub max_htlc_value_in_flight: u64,
    /// Dust limit
    pub dust_limit: u64,
    /// Required confirmations for funding
    pub funding_confirmations: u32,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        ChannelConfig {
            to_self_delay: DEFAULT_CSV_DELAY,
            to_remote_delay: DEFAULT_CSV_DELAY,
            htlc_minimum: 1000,
            max_htlcs: MAX_HTLCS_PER_CHANNEL,
            max_htlc_value_in_flight: u64::MAX,
            dust_limit: DUST_LIMIT,
            funding_confirmations: 3,
        }
    }
}

// =============================================================================
// Channel Keys
// =============================================================================

/// Keys used in the channel
#[derive(Clone, Debug)]
pub struct ChannelKeys {
    /// Funding pubkey (for 2-of-2 multisig)
    pub funding_pubkey: [u8; 33],
    
    /// Revocation base point
    pub revocation_basepoint: [u8; 33],
    
    /// Payment base point
    pub payment_basepoint: [u8; 33],
    
    /// Delayed payment base point
    pub delayed_payment_basepoint: [u8; 33],
    
    /// HTLC base point
    pub htlc_basepoint: [u8; 33],
    
    /// First per-commitment point
    pub first_per_commitment_point: [u8; 33],
}

impl ChannelKeys {
    /// Generate new random keys
    pub fn generate() -> Self {
        // In production, derive from HD wallet
        ChannelKeys {
            funding_pubkey: Self::random_pubkey(),
            revocation_basepoint: Self::random_pubkey(),
            payment_basepoint: Self::random_pubkey(),
            delayed_payment_basepoint: Self::random_pubkey(),
            htlc_basepoint: Self::random_pubkey(),
            first_per_commitment_point: Self::random_pubkey(),
        }
    }

    fn random_pubkey() -> [u8; 33] {
        use secp256k1::{Secp256k1, SecretKey, PublicKey};
        let secp = Secp256k1::new();
        let secret = SecretKey::new(&mut rand::thread_rng());
        let public = PublicKey::from_secret_key(&secp, &secret);
        public.serialize()
    }
}

// =============================================================================
// Channel Error
// =============================================================================

/// Channel-related errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// Invalid channel state for operation
    InvalidState(String),
    /// Insufficient balance
    InsufficientBalance,
    /// Amount below dust limit
    BelowDustLimit,
    /// Amount below HTLC minimum
    BelowHtlcMinimum,
    /// Too many HTLCs
    TooManyHtlcs,
    /// HTLC value exceeds limit
    HtlcValueExceeded,
    /// Invalid signature
    InvalidSignature,
    /// Invalid commitment number
    InvalidCommitmentNumber,
    /// Unknown HTLC
    UnknownHtlc,
    /// HTLC already exists
    DuplicateHtlc,
    /// Invalid preimage
    InvalidPreimage,
    /// HTLC expired
    HtlcExpired,
    /// Channel reserve violated
    ReserveViolation,
    /// Funding error
    FundingError(String),
    /// Close error
    CloseError(String),
    /// Protocol error
    ProtocolError(String),
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::InvalidState(s) => write!(f, "Invalid state: {}", s),
            ChannelError::InsufficientBalance => write!(f, "Insufficient balance"),
            ChannelError::BelowDustLimit => write!(f, "Amount below dust limit"),
            ChannelError::BelowHtlcMinimum => write!(f, "Amount below HTLC minimum"),
            ChannelError::TooManyHtlcs => write!(f, "Too many HTLCs"),
            ChannelError::HtlcValueExceeded => write!(f, "HTLC value exceeded"),
            ChannelError::InvalidSignature => write!(f, "Invalid signature"),
            ChannelError::InvalidCommitmentNumber => write!(f, "Invalid commitment number"),
            ChannelError::UnknownHtlc => write!(f, "Unknown HTLC"),
            ChannelError::DuplicateHtlc => write!(f, "Duplicate HTLC"),
            ChannelError::InvalidPreimage => write!(f, "Invalid preimage"),
            ChannelError::HtlcExpired => write!(f, "HTLC expired"),
            ChannelError::ReserveViolation => write!(f, "Channel reserve violated"),
            ChannelError::FundingError(s) => write!(f, "Funding error: {}", s),
            ChannelError::CloseError(s) => write!(f, "Close error: {}", s),
            ChannelError::ProtocolError(s) => write!(f, "Protocol error: {}", s),
        }
    }
}

impl std::error::Error for ChannelError {}

// =============================================================================
// Channel
// =============================================================================

/// A payment channel between two parties
#[derive(Clone, Debug)]
pub struct Channel {
    /// Unique channel identifier
    pub channel_id: ChannelId,
    
    /// Temporary ID (before funding confirmed)
    pub temporary_id: Option<ChannelId>,
    
    /// Current state
    pub state: ChannelState,
    
    /// Who initiated the channel
    pub initiator: ChannelParty,
    
    /// Total channel capacity
    pub capacity: u64,
    
    /// Current balance
    pub balance: Balance,
    
    /// Channel reserve (each side must maintain)
    pub reserve: u64,
    
    /// Our channel keys
    pub local_keys: ChannelKeys,
    
    /// Their channel keys
    pub remote_keys: Option<ChannelKeys>,
    
    /// Channel configuration
    pub config: ChannelConfig,
    
    /// Funding transaction details
    pub funding_txid: Option<[u8; 32]>,
    pub funding_output_index: Option<u32>,
    
    /// Current commitment number (increases with each update)
    pub commitment_number: u64,
    
    /// Pending HTLCs
    pub htlcs: Vec<super::htlc::Htlc>,
    
    /// Timestamps
    pub created_at: u64,
    pub last_updated: u64,
}

impl Channel {
    /// Create a new outbound channel (we are initiating)
    pub fn new_outbound(capacity: u64, push_amount: u64) -> Result<Self, ChannelError> {
        Self::validate_capacity(capacity)?;

        let reserve = calculate_reserve(capacity);
        let local_balance = capacity - push_amount;
        let remote_balance = push_amount;

        // Verify we have enough after reserve
        if local_balance < reserve {
            return Err(ChannelError::ReserveViolation);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Channel {
            channel_id: ChannelId::temporary(),
            temporary_id: Some(ChannelId::temporary()),
            state: ChannelState::Created,
            initiator: ChannelParty::Local,
            capacity,
            balance: Balance::new(local_balance, remote_balance),
            reserve,
            local_keys: ChannelKeys::generate(),
            remote_keys: None,
            config: ChannelConfig::default(),
            funding_txid: None,
            funding_output_index: None,
            commitment_number: 0,
            htlcs: Vec::new(),
            created_at: now,
            last_updated: now,
        })
    }

    /// Create a new inbound channel (they are initiating)
    pub fn new_inbound(
        capacity: u64,
        push_amount: u64,
        remote_keys: ChannelKeys,
    ) -> Result<Self, ChannelError> {
        Self::validate_capacity(capacity)?;

        let reserve = calculate_reserve(capacity);
        let remote_balance = capacity - push_amount;
        let local_balance = push_amount;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Channel {
            channel_id: ChannelId::temporary(),
            temporary_id: Some(ChannelId::temporary()),
            state: ChannelState::Created,
            initiator: ChannelParty::Remote,
            capacity,
            balance: Balance::new(local_balance, remote_balance),
            reserve,
            local_keys: ChannelKeys::generate(),
            remote_keys: Some(remote_keys),
            config: ChannelConfig::default(),
            funding_txid: None,
            funding_output_index: None,
            commitment_number: 0,
            htlcs: Vec::new(),
            created_at: now,
            last_updated: now,
        })
    }

    /// Validate channel capacity
    fn validate_capacity(capacity: u64) -> Result<(), ChannelError> {
        if capacity < super::MIN_CHANNEL_CAPACITY {
            return Err(ChannelError::FundingError(
                format!("Capacity {} below minimum {}", capacity, super::MIN_CHANNEL_CAPACITY)
            ));
        }
        if capacity > super::MAX_CHANNEL_CAPACITY {
            return Err(ChannelError::FundingError(
                format!("Capacity {} above maximum {}", capacity, super::MAX_CHANNEL_CAPACITY)
            ));
        }
        Ok(())
    }

    /// Set funding transaction
    pub fn set_funding(&mut self, txid: [u8; 32], output_index: u32) {
        self.funding_txid = Some(txid);
        self.funding_output_index = Some(output_index);
        
        // Update channel ID from funding outpoint
        self.channel_id = super::generate_channel_id(&txid, output_index);
        
        self.state = ChannelState::FundingBroadcast {
            funding_txid: txid,
            confirmations: 0,
            required_confirmations: self.config.funding_confirmations,
        };
        
        self.update_timestamp();
    }

    /// Confirm funding (add confirmation)
    pub fn add_funding_confirmation(&mut self) -> Result<bool, ChannelError> {
        match &mut self.state {
            ChannelState::FundingBroadcast { 
                confirmations, 
                required_confirmations, 
                .. 
            } => {
                *confirmations += 1;
                
                if *confirmations >= *required_confirmations {
                    self.state = ChannelState::Active;
                    self.update_timestamp();
                    return Ok(true); // Channel is now active
                }
                
                self.update_timestamp();
                Ok(false)
            }
            _ => Err(ChannelError::InvalidState(
                "Channel not in funding state".to_string()
            )),
        }
    }

    /// Send payment through channel
    pub fn send_payment(&mut self, amount: u64) -> Result<(), ChannelError> {
        if !self.state.can_transact() {
            return Err(ChannelError::InvalidState(
                "Channel not active".to_string()
            ));
        }

        if amount < self.config.htlc_minimum {
            return Err(ChannelError::BelowHtlcMinimum);
        }

        let available = self.balance.available_to_send(self.reserve);
        if amount > available {
            return Err(ChannelError::InsufficientBalance);
        }

        self.balance.transfer_to_remote(amount)?;
        self.commitment_number += 1;
        self.update_timestamp();

        Ok(())
    }

    /// Receive payment through channel
    pub fn receive_payment(&mut self, amount: u64) -> Result<(), ChannelError> {
        if !self.state.can_transact() {
            return Err(ChannelError::InvalidState(
                "Channel not active".to_string()
            ));
        }

        if amount < self.config.htlc_minimum {
            return Err(ChannelError::BelowHtlcMinimum);
        }

        let available = self.balance.available_to_receive(self.reserve);
        if amount > available {
            return Err(ChannelError::InsufficientBalance);
        }

        self.balance.transfer_to_local(amount)?;
        self.commitment_number += 1;
        self.update_timestamp();

        Ok(())
    }

    /// Initiate cooperative close
    pub fn initiate_shutdown(&mut self) -> Result<(), ChannelError> {
        match self.state {
            ChannelState::Active => {
                self.state = ChannelState::ShutdownInitiated {
                    initiator: ChannelParty::Local,
                };
                self.update_timestamp();
                Ok(())
            }
            _ => Err(ChannelError::InvalidState(
                "Can only shutdown active channel".to_string()
            )),
        }
    }

    /// Accept shutdown from remote
    pub fn accept_shutdown(&mut self) -> Result<(), ChannelError> {
        match self.state {
            ChannelState::Active => {
                self.state = ChannelState::ShutdownInitiated {
                    initiator: ChannelParty::Remote,
                };
                self.update_timestamp();
                Ok(())
            }
            ChannelState::ShutdownInitiated { .. } => {
                // Already shutting down, mark complete
                self.state = ChannelState::ShutdownComplete;
                self.update_timestamp();
                Ok(())
            }
            _ => Err(ChannelError::InvalidState(
                "Cannot accept shutdown in this state".to_string()
            )),
        }
    }

    /// Complete cooperative close
    pub fn complete_close(&mut self, closing_txid: [u8; 32]) -> Result<(), ChannelError> {
        match self.state {
            ChannelState::ShutdownComplete => {
                self.state = ChannelState::ClosingBroadcast { closing_txid };
                self.update_timestamp();
                Ok(())
            }
            _ => Err(ChannelError::InvalidState(
                "Channel not ready for close".to_string()
            )),
        }
    }

    /// Force close (unilateral)
    pub fn force_close(&mut self, current_height: u64) -> Result<[u8; 32], ChannelError> {
        if matches!(self.state, ChannelState::Closed { .. }) {
            return Err(ChannelError::InvalidState(
                "Channel already closed".to_string()
            ));
        }

        // Generate commitment transaction ID (simplified)
        let commitment_txid = self.generate_commitment_txid();

        self.state = ChannelState::ForceClosing {
            commitment_txid,
            broadcast_height: current_height,
        };

        self.update_timestamp();
        Ok(commitment_txid)
    }

    /// Mark channel as closed
    pub fn mark_closed(&mut self, close_type: CloseType) {
        self.state = ChannelState::Closed {
            close_type,
            final_balance_local: self.balance.local,
            final_balance_remote: self.balance.remote,
        };
        self.update_timestamp();
    }

    /// Get channel info
    pub fn info(&self) -> ChannelInfo {
        ChannelInfo {
            channel_id: self.channel_id,
            state: format!("{:?}", self.state),
            capacity: self.capacity,
            local_balance: self.balance.local,
            remote_balance: self.balance.remote,
            reserve: self.reserve,
            commitment_number: self.commitment_number,
            htlc_count: self.htlcs.len(),
            can_send: self.balance.available_to_send(self.reserve),
            can_receive: self.balance.available_to_receive(self.reserve),
        }
    }

    // Helper functions
    
    fn update_timestamp(&mut self) {
        self.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    fn generate_commitment_txid(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.channel_id.0);
        hasher.update(&self.commitment_number.to_le_bytes());
        hasher.update(&self.balance.local.to_le_bytes());
        hasher.update(&self.balance.remote.to_le_bytes());
        
        let result = hasher.finalize();
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&result);
        txid
    }
}

// =============================================================================
// Channel Info (for display)
// =============================================================================

/// Summary information about a channel
#[derive(Clone, Debug)]
pub struct ChannelInfo {
    pub channel_id: ChannelId,
    pub state: String,
    pub capacity: u64,
    pub local_balance: u64,
    pub remote_balance: u64,
    pub reserve: u64,
    pub commitment_number: u64,
    pub htlc_count: usize,
    pub can_send: u64,
    pub can_receive: u64,
}

impl std::fmt::Display for ChannelInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Channel: {}", self.channel_id)?;
        writeln!(f, "  State: {}", self.state)?;
        writeln!(f, "  Capacity: {} sat", self.capacity)?;
        writeln!(f, "  Local: {} sat", self.local_balance)?;
        writeln!(f, "  Remote: {} sat", self.remote_balance)?;
        writeln!(f, "  Can Send: {} sat", self.can_send)?;
        writeln!(f, "  Can Receive: {} sat", self.can_receive)?;
        writeln!(f, "  Commitments: {}", self.commitment_number)?;
        writeln!(f, "  HTLCs: {}", self.htlc_count)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_outbound_channel() {
        let channel = Channel::new_outbound(
            10 * 100_000_000, // 10 MOON
            0,                // no push
        ).unwrap();

        assert_eq!(channel.capacity, 10 * 100_000_000);
        assert_eq!(channel.balance.local, 10 * 100_000_000);
        assert_eq!(channel.balance.remote, 0);
        assert_eq!(channel.initiator, ChannelParty::Local);
        assert!(matches!(channel.state, ChannelState::Created));
    }

    #[test]
    fn test_channel_funding() {
        let mut channel = Channel::new_outbound(
            10 * 100_000_000,
            0,
        ).unwrap();

        let txid = [0xAB; 32];
        channel.set_funding(txid, 0);

        assert!(matches!(channel.state, ChannelState::FundingBroadcast { .. }));

        // Add confirmations
        for _ in 0..2 {
            let active = channel.add_funding_confirmation().unwrap();
            assert!(!active);
        }

        // Third confirmation activates
        let active = channel.add_funding_confirmation().unwrap();
        assert!(active);
        assert!(matches!(channel.state, ChannelState::Active));
    }

    #[test]
    fn test_send_payment() {
        let mut channel = Channel::new_outbound(
            10 * 100_000_000,
            0,
        ).unwrap();

        // Activate channel
        channel.set_funding([0xAB; 32], 0);
        for _ in 0..3 {
            channel.add_funding_confirmation().unwrap();
        }

        // Send payment
        let amount = 1 * 100_000_000; // 1 MOON
        channel.send_payment(amount).unwrap();

        assert_eq!(channel.balance.local, 9 * 100_000_000);
        assert_eq!(channel.balance.remote, 1 * 100_000_000);
        assert_eq!(channel.commitment_number, 1);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut channel = Channel::new_outbound(
            10 * 100_000_000,
            0,
        ).unwrap();

        channel.set_funding([0xAB; 32], 0);
        for _ in 0..3 {
            channel.add_funding_confirmation().unwrap();
        }

        // Try to send more than available (must maintain reserve)
        let result = channel.send_payment(10 * 100_000_000);
        assert!(matches!(result, Err(ChannelError::InsufficientBalance)));
    }

    #[test]
    fn test_cooperative_close() {
        let mut channel = Channel::new_outbound(
            10 * 100_000_000,
            0,
        ).unwrap();

        channel.set_funding([0xAB; 32], 0);
        for _ in 0..3 {
            channel.add_funding_confirmation().unwrap();
        }

        // Initiate shutdown
        channel.initiate_shutdown().unwrap();
        assert!(matches!(channel.state, ChannelState::ShutdownInitiated { .. }));

        // Accept shutdown
        channel.accept_shutdown().unwrap();
        assert!(matches!(channel.state, ChannelState::ShutdownComplete));

        // Complete close
        channel.complete_close([0xCD; 32]).unwrap();
        assert!(matches!(channel.state, ChannelState::ClosingBroadcast { .. }));
    }
}
