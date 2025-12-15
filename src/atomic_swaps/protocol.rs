// =============================================================================
// MOONCOIN v2.34 - Atomic Swap Protocol
// =============================================================================
//
// P2P protocol messages for negotiating and executing atomic swaps.
//
// =============================================================================

use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

use super::swap::{SwapId, SwapParams, SwapRole};
use super::{HASH_SIZE, SECRET_SIZE};

// =============================================================================
// Protocol Messages
// =============================================================================

/// Messages exchanged during atomic swap
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SwapMessage {
    /// Propose a new swap
    Propose {
        swap_id: SwapId,
        params: SwapParams,
        secret_hash: [u8; HASH_SIZE],
    },

    /// Accept a swap proposal
    Accept {
        swap_id: SwapId,
        params: SwapParams,
    },

    /// Reject a swap proposal
    Reject {
        swap_id: SwapId,
        reason: String,
    },

    /// Notify that initiator has locked funds
    InitiatorLocked {
        swap_id: SwapId,
        lock_tx: String,
        lock_script: Vec<u8>,
        lock_address: String,
    },

    /// Notify that participant has locked funds
    ParticipantLocked {
        swap_id: SwapId,
        lock_tx: String,
        lock_script: Vec<u8>,
        lock_address: String,
    },

    /// Notify that initiator has claimed (includes secret)
    InitiatorClaimed {
        swap_id: SwapId,
        claim_tx: String,
        secret: [u8; SECRET_SIZE],
    },

    /// Notify that participant has claimed
    ParticipantClaimed {
        swap_id: SwapId,
        claim_tx: String,
    },

    /// Notify of refund
    Refunded {
        swap_id: SwapId,
        refund_tx: String,
    },

    /// Request swap status
    GetStatus {
        swap_id: SwapId,
    },

    /// Swap status response
    Status {
        swap_id: SwapId,
        state: String,
        our_lock_tx: Option<String>,
        their_lock_tx: Option<String>,
    },
}

impl SwapMessage {
    /// Get the swap ID from any message
    pub fn swap_id(&self) -> SwapId {
        match self {
            SwapMessage::Propose { swap_id, .. } => *swap_id,
            SwapMessage::Accept { swap_id, .. } => *swap_id,
            SwapMessage::Reject { swap_id, .. } => *swap_id,
            SwapMessage::InitiatorLocked { swap_id, .. } => *swap_id,
            SwapMessage::ParticipantLocked { swap_id, .. } => *swap_id,
            SwapMessage::InitiatorClaimed { swap_id, .. } => *swap_id,
            SwapMessage::ParticipantClaimed { swap_id, .. } => *swap_id,
            SwapMessage::Refunded { swap_id, .. } => *swap_id,
            SwapMessage::GetStatus { swap_id } => *swap_id,
            SwapMessage::Status { swap_id, .. } => *swap_id,
        }
    }

    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

// =============================================================================
// Swap Negotiation
// =============================================================================

/// State of swap negotiation
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NegotiationState {
    /// Waiting for response to our proposal
    ProposalSent,
    /// Received proposal, deciding
    ProposalReceived,
    /// Both parties agreed
    Agreed,
    /// Negotiation rejected
    Rejected(String),
}

/// Swap negotiation handler
#[derive(Clone, Debug)]
pub struct SwapNegotiation {
    pub swap_id: SwapId,
    pub role: SwapRole,
    pub state: NegotiationState,
    pub our_params: SwapParams,
    pub their_params: Option<SwapParams>,
    pub secret_hash: [u8; HASH_SIZE],
    pub created_at: u64,
}

impl SwapNegotiation {
    /// Create new negotiation as initiator
    pub fn new_initiator(
        params: SwapParams,
        secret_hash: [u8; HASH_SIZE],
    ) -> Self {
        let swap_id = SwapId::from_hash(&secret_hash);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        SwapNegotiation {
            swap_id,
            role: SwapRole::Initiator,
            state: NegotiationState::ProposalSent,
            our_params: params,
            their_params: None,
            secret_hash,
            created_at: now,
        }
    }

    /// Create new negotiation as participant (receiving proposal)
    pub fn new_participant(
        swap_id: SwapId,
        their_params: SwapParams,
        secret_hash: [u8; HASH_SIZE],
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        SwapNegotiation {
            swap_id,
            role: SwapRole::Participant,
            state: NegotiationState::ProposalReceived,
            our_params: SwapParams {
                offer_amount: their_params.want_amount,
                offer_asset: their_params.want_asset.clone(),
                want_amount: their_params.offer_amount,
                want_asset: their_params.offer_asset.clone(),
                refund_address: String::new(),
                counterparty_address: String::new(),
                timeout_blocks: their_params.timeout_blocks / 2,
                min_confirmations: their_params.min_confirmations,
            },
            their_params: Some(their_params),
            secret_hash,
            created_at: now,
        }
    }

    /// Create proposal message
    pub fn create_proposal(&self) -> SwapMessage {
        SwapMessage::Propose {
            swap_id: self.swap_id,
            params: self.our_params.clone(),
            secret_hash: self.secret_hash,
        }
    }

    /// Accept the proposal
    pub fn accept(&mut self, our_params: SwapParams) -> SwapMessage {
        self.our_params = our_params.clone();
        self.state = NegotiationState::Agreed;

        SwapMessage::Accept {
            swap_id: self.swap_id,
            params: our_params,
        }
    }

    /// Reject the proposal
    pub fn reject(&mut self, reason: &str) -> SwapMessage {
        self.state = NegotiationState::Rejected(reason.to_string());

        SwapMessage::Reject {
            swap_id: self.swap_id,
            reason: reason.to_string(),
        }
    }

    /// Handle accept message
    pub fn handle_accept(&mut self, their_params: SwapParams) {
        self.their_params = Some(their_params);
        self.state = NegotiationState::Agreed;
    }

    /// Handle reject message
    pub fn handle_reject(&mut self, reason: String) {
        self.state = NegotiationState::Rejected(reason);
    }

    /// Is negotiation complete?
    pub fn is_complete(&self) -> bool {
        matches!(
            self.state,
            NegotiationState::Agreed | NegotiationState::Rejected(_)
        )
    }

    /// Did negotiation succeed?
    pub fn is_agreed(&self) -> bool {
        matches!(self.state, NegotiationState::Agreed)
    }
}

// =============================================================================
// Swap Protocol
// =============================================================================

/// High-level swap protocol handler
#[derive(Clone, Debug)]
pub struct SwapProtocol {
    /// Active negotiations
    pub negotiations: Vec<SwapNegotiation>,
    
    /// Message history
    pub message_history: Vec<(u64, SwapMessage)>,
}

impl SwapProtocol {
    pub fn new() -> Self {
        SwapProtocol {
            negotiations: Vec::new(),
            message_history: Vec::new(),
        }
    }

    /// Start a new swap as initiator
    pub fn initiate_swap(
        &mut self,
        params: SwapParams,
        secret_hash: [u8; HASH_SIZE],
    ) -> SwapMessage {
        let negotiation = SwapNegotiation::new_initiator(params, secret_hash);
        let message = negotiation.create_proposal();
        
        self.record_message(&message);
        self.negotiations.push(negotiation);
        
        message
    }

    /// Handle incoming proposal
    pub fn handle_proposal(
        &mut self,
        swap_id: SwapId,
        params: SwapParams,
        secret_hash: [u8; HASH_SIZE],
    ) -> &SwapNegotiation {
        let negotiation = SwapNegotiation::new_participant(swap_id, params, secret_hash);
        self.negotiations.push(negotiation);
        self.negotiations.last().unwrap()
    }

    /// Accept a proposal
    pub fn accept_proposal(
        &mut self,
        swap_id: SwapId,
        our_params: SwapParams,
    ) -> Option<SwapMessage> {
        let negotiation = self.get_negotiation_mut(&swap_id)?;
        let message = negotiation.accept(our_params);
        self.record_message(&message);
        Some(message)
    }

    /// Reject a proposal
    pub fn reject_proposal(
        &mut self,
        swap_id: SwapId,
        reason: &str,
    ) -> Option<SwapMessage> {
        let negotiation = self.get_negotiation_mut(&swap_id)?;
        let message = negotiation.reject(reason);
        self.record_message(&message);
        Some(message)
    }

    /// Get negotiation by swap ID
    pub fn get_negotiation(&self, swap_id: &SwapId) -> Option<&SwapNegotiation> {
        self.negotiations.iter().find(|n| n.swap_id == *swap_id)
    }

    /// Get negotiation by swap ID (mutable)
    pub fn get_negotiation_mut(&mut self, swap_id: &SwapId) -> Option<&mut SwapNegotiation> {
        self.negotiations.iter_mut().find(|n| n.swap_id == *swap_id)
    }

    /// Record a message in history
    fn record_message(&mut self, message: &SwapMessage) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.message_history.push((now, message.clone()));
    }

    /// Get pending negotiations (not yet agreed/rejected)
    pub fn pending_negotiations(&self) -> Vec<&SwapNegotiation> {
        self.negotiations
            .iter()
            .filter(|n| !n.is_complete())
            .collect()
    }
}

impl Default for SwapProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::generate_secret;

    fn sample_params() -> SwapParams {
        SwapParams::new_initiator(
            10 * 100_000_000,
            "MOON",
            100_000,
            "BTC",
            "moon1refund...",
            "moon1counter...",
        )
    }

    #[test]
    fn test_swap_message_serialization() {
        let secret_hash = [0xAB; 32];
        let params = sample_params();
        
        let msg = SwapMessage::Propose {
            swap_id: SwapId::from_hash(&secret_hash),
            params,
            secret_hash,
        };
        
        let bytes = msg.to_bytes();
        let decoded = SwapMessage::from_bytes(&bytes).unwrap();
        
        assert_eq!(msg.swap_id(), decoded.swap_id());
    }

    #[test]
    fn test_negotiation_flow() {
        let secret = generate_secret();
        let secret_hash = super::super::hash_secret(&secret);
        
        // Initiator creates proposal
        let init_params = sample_params();
        let mut init_neg = SwapNegotiation::new_initiator(init_params, secret_hash);
        let proposal = init_neg.create_proposal();
        
        assert_eq!(init_neg.state, NegotiationState::ProposalSent);
        
        // Participant receives and accepts
        if let SwapMessage::Propose { swap_id, params, secret_hash } = proposal {
            let mut part_neg = SwapNegotiation::new_participant(swap_id, params, secret_hash);
            
            assert_eq!(part_neg.state, NegotiationState::ProposalReceived);
            
            let accept_params = SwapParams::new_participant(
                100_000, "BTC",
                10 * 100_000_000, "MOON",
                "bc1refund...", "bc1counter...",
                288,
            ).unwrap();
            
            let accept_msg = part_neg.accept(accept_params);
            
            assert_eq!(part_neg.state, NegotiationState::Agreed);
            
            // Initiator receives accept
            if let SwapMessage::Accept { params, .. } = accept_msg {
                init_neg.handle_accept(params);
                assert_eq!(init_neg.state, NegotiationState::Agreed);
            }
        }
    }

    #[test]
    fn test_protocol() {
        let mut protocol = SwapProtocol::new();
        
        let secret = generate_secret();
        let secret_hash = super::super::hash_secret(&secret);
        let params = sample_params();
        
        // Initiate swap
        let proposal = protocol.initiate_swap(params, secret_hash);
        
        assert_eq!(protocol.negotiations.len(), 1);
        assert_eq!(protocol.message_history.len(), 1);
        
        // Verify proposal message
        assert!(matches!(proposal, SwapMessage::Propose { .. }));
    }
}
