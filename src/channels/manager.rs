// =============================================================================
// MOONCOIN v2.33 - Channel Manager
// =============================================================================
//
// High-level interface for managing payment channels.
//
// Responsibilities:
// - Create and accept channels
// - Process channel state updates
// - Route payments through channels
// - Handle channel events
// - Persist channel state
//
// =============================================================================

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::state::{
    Channel, ChannelId, ChannelState, ChannelKeys,
    ChannelError, ChannelInfo, CloseType,
};
use super::commitment::CommitmentSecret;
use super::htlc::{
    HtlcManager, HtlcId, PaymentHash, PaymentPreimage,
    HtlcFailReason, Invoice,
};

// =============================================================================
// Channel Events
// =============================================================================

/// Events emitted by channel manager
#[derive(Clone, Debug)]
pub enum ChannelEvent {
    /// Channel created, waiting for funding
    ChannelCreated {
        channel_id: ChannelId,
        capacity: u64,
    },
    
    /// Funding transaction broadcast
    FundingBroadcast {
        channel_id: ChannelId,
        funding_txid: [u8; 32],
    },
    
    /// Channel is now active
    ChannelActive {
        channel_id: ChannelId,
    },
    
    /// Payment sent successfully
    PaymentSent {
        channel_id: ChannelId,
        payment_hash: PaymentHash,
        amount: u64,
    },
    
    /// Payment received
    PaymentReceived {
        channel_id: ChannelId,
        payment_hash: PaymentHash,
        amount: u64,
    },
    
    /// HTLC forwarded
    HtlcForwarded {
        from_channel: ChannelId,
        to_channel: ChannelId,
        htlc_id: HtlcId,
    },
    
    /// Channel closing initiated
    ChannelClosing {
        channel_id: ChannelId,
        cooperative: bool,
    },
    
    /// Channel closed
    ChannelClosed {
        channel_id: ChannelId,
        close_type: CloseType,
        local_balance: u64,
        remote_balance: u64,
    },
    
    /// Possible breach detected
    PossibleBreach {
        channel_id: ChannelId,
        commitment_number: u64,
    },
}

// =============================================================================
// Pending Payment
// =============================================================================

/// A payment being routed through channels
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingPayment {
    /// Payment hash
    pub payment_hash: PaymentHash,
    
    /// Total amount
    pub amount: u64,
    
    /// HTLCs used for this payment
    pub htlcs: Vec<(ChannelId, HtlcId)>,
    
    /// Preimage (if known)
    pub preimage: Option<PaymentPreimage>,
    
    /// Status
    pub status: PaymentStatus,
    
    /// Created timestamp
    pub created_at: u64,
}

/// Payment status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// Payment in progress
    Pending,
    /// Payment succeeded
    Succeeded,
    /// Payment failed
    Failed(String),
}

// =============================================================================
// Channel Manager
// =============================================================================

/// Manages all payment channels
#[derive(Clone, Debug)]
pub struct ChannelManager {
    /// Our node public key
    pub node_pubkey: [u8; 33],
    
    /// All channels indexed by ID
    pub channels: HashMap<ChannelId, Channel>,
    
    /// HTLC managers per channel
    pub htlc_managers: HashMap<ChannelId, HtlcManager>,
    
    /// Pending outbound payments
    pub pending_payments: HashMap<PaymentHash, PendingPayment>,
    
    /// Known preimages (for received payments)
    pub known_preimages: HashMap<PaymentHash, PaymentPreimage>,
    
    /// Generated invoices
    pub invoices: HashMap<PaymentHash, (PaymentPreimage, Invoice)>,
    
    /// Revocation secrets we've received (for penalty)
    pub revocation_secrets: HashMap<(ChannelId, u64), CommitmentSecret>,
    
    /// Current block height
    pub current_height: u64,
    
    /// Event queue
    pub events: Vec<ChannelEvent>,
    
    /// Statistics
    pub stats: ChannelStats,
}

/// Channel statistics
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChannelStats {
    pub total_channels_opened: u64,
    pub total_channels_closed: u64,
    pub total_payments_sent: u64,
    pub total_payments_received: u64,
    pub total_amount_sent: u64,
    pub total_amount_received: u64,
    pub total_routing_fees: u64,
}

impl ChannelManager {
    /// Create a new channel manager
    pub fn new(node_pubkey: [u8; 33]) -> Self {
        ChannelManager {
            node_pubkey,
            channels: HashMap::new(),
            htlc_managers: HashMap::new(),
            pending_payments: HashMap::new(),
            known_preimages: HashMap::new(),
            invoices: HashMap::new(),
            revocation_secrets: HashMap::new(),
            current_height: 0,
            events: Vec::new(),
            stats: ChannelStats::default(),
        }
    }

    /// Set current block height
    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    // =========================================================================
    // Channel Creation
    // =========================================================================

    /// Open a new outbound channel
    pub fn open_channel(
        &mut self,
        capacity: u64,
        push_amount: u64,
    ) -> Result<ChannelId, ChannelError> {
        let channel = Channel::new_outbound(capacity, push_amount)?;
        let channel_id = channel.channel_id;

        self.channels.insert(channel_id, channel);
        self.htlc_managers.insert(channel_id, HtlcManager::new());
        
        self.stats.total_channels_opened += 1;
        
        self.events.push(ChannelEvent::ChannelCreated {
            channel_id,
            capacity,
        });

        Ok(channel_id)
    }

    /// Accept an inbound channel
    pub fn accept_channel(
        &mut self,
        capacity: u64,
        push_amount: u64,
        remote_keys: ChannelKeys,
    ) -> Result<ChannelId, ChannelError> {
        let channel = Channel::new_inbound(capacity, push_amount, remote_keys)?;
        let channel_id = channel.channel_id;

        self.channels.insert(channel_id, channel);
        self.htlc_managers.insert(channel_id, HtlcManager::new());
        
        self.stats.total_channels_opened += 1;

        self.events.push(ChannelEvent::ChannelCreated {
            channel_id,
            capacity,
        });

        Ok(channel_id)
    }

    // =========================================================================
    // Funding
    // =========================================================================

    /// Set funding transaction for channel
    pub fn channel_funded(
        &mut self,
        channel_id: ChannelId,
        funding_txid: [u8; 32],
        output_index: u32,
    ) -> Result<(), ChannelError> {
        let channel = self.channels.get_mut(&channel_id)
            .ok_or(ChannelError::InvalidState("Channel not found".to_string()))?;

        channel.set_funding(funding_txid, output_index);

        self.events.push(ChannelEvent::FundingBroadcast {
            channel_id,
            funding_txid,
        });

        Ok(())
    }

    /// Process new block (for funding confirmations)
    pub fn process_block(&mut self, height: u64) -> Vec<ChannelEvent> {
        self.current_height = height;
        let mut new_events = Vec::new();

        for channel in self.channels.values_mut() {
            if let ChannelState::FundingBroadcast { .. } = &channel.state {
                if let Ok(active) = channel.add_funding_confirmation() {
                    if active {
                        new_events.push(ChannelEvent::ChannelActive {
                            channel_id: channel.channel_id,
                        });
                    }
                }
            }
        }

        self.events.extend(new_events.clone());
        new_events
    }

    // =========================================================================
    // Payments
    // =========================================================================

    /// Send a payment through a channel
    pub fn send_payment(
        &mut self,
        channel_id: ChannelId,
        payment_hash: PaymentHash,
        amount: u64,
        cltv_expiry: u32,
    ) -> Result<HtlcId, ChannelError> {
        // Get channel
        let channel = self.channels.get_mut(&channel_id)
            .ok_or(ChannelError::InvalidState("Channel not found".to_string()))?;

        // Check channel can transact
        if !channel.state.can_transact() {
            return Err(ChannelError::InvalidState("Channel not active".to_string()));
        }

        // Check balance
        let available = channel.balance.available_to_send(channel.reserve);
        if amount > available {
            return Err(ChannelError::InsufficientBalance);
        }

        // Add HTLC
        let htlc_manager = self.htlc_managers.entry(channel_id).or_insert_with(HtlcManager::new);
        let htlc_id = htlc_manager.add_offered(
            payment_hash,
            amount,
            cltv_expiry,
            channel.config.max_htlcs,
            channel.config.max_htlc_value_in_flight,
        )?;

        // Update channel balance (tentatively)
        channel.balance.pending_outbound += amount;
        channel.commitment_number += 1;

        // Track payment
        let pending = PendingPayment {
            payment_hash,
            amount,
            htlcs: vec![(channel_id, htlc_id)],
            preimage: None,
            status: PaymentStatus::Pending,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        self.pending_payments.insert(payment_hash, pending);

        Ok(htlc_id)
    }

    /// Fulfill a received HTLC with preimage
    pub fn fulfill_htlc(
        &mut self,
        channel_id: ChannelId,
        htlc_id: HtlcId,
        preimage: PaymentPreimage,
    ) -> Result<u64, ChannelError> {
        let htlc_manager = self.htlc_managers.get_mut(&channel_id)
            .ok_or(ChannelError::InvalidState("Channel not found".to_string()))?;

        let amount = htlc_manager.fulfill(htlc_id, &preimage)?;

        // Update channel balance
        let channel = self.channels.get_mut(&channel_id).unwrap();
        channel.balance.pending_inbound -= amount;
        channel.balance.local += amount;
        channel.commitment_number += 1;

        self.stats.total_payments_received += 1;
        self.stats.total_amount_received += amount;

        let payment_hash = preimage.payment_hash();
        self.events.push(ChannelEvent::PaymentReceived {
            channel_id,
            payment_hash,
            amount,
        });

        Ok(amount)
    }

    /// Fail a received HTLC
    pub fn fail_htlc(
        &mut self,
        channel_id: ChannelId,
        htlc_id: HtlcId,
        reason: HtlcFailReason,
    ) -> Result<u64, ChannelError> {
        let htlc_manager = self.htlc_managers.get_mut(&channel_id)
            .ok_or(ChannelError::InvalidState("Channel not found".to_string()))?;

        let amount = htlc_manager.fail(htlc_id, reason)?;

        // Update channel balance
        let channel = self.channels.get_mut(&channel_id).unwrap();
        channel.balance.pending_inbound -= amount;
        channel.balance.remote += amount;
        channel.commitment_number += 1;

        Ok(amount)
    }

    /// Process incoming HTLC fulfillment (for outbound payment)
    pub fn htlc_fulfilled(
        &mut self,
        channel_id: ChannelId,
        htlc_id: HtlcId,
        preimage: PaymentPreimage,
    ) -> Result<(), ChannelError> {
        let htlc_manager = self.htlc_managers.get_mut(&channel_id)
            .ok_or(ChannelError::InvalidState("Channel not found".to_string()))?;

        let htlc = htlc_manager.find_mut(htlc_id)
            .ok_or(ChannelError::UnknownHtlc)?;

        let amount = htlc.amount;
        let payment_hash = htlc.payment_hash;

        htlc.fulfill(&preimage)?;

        // Update channel balance
        let channel = self.channels.get_mut(&channel_id).unwrap();
        channel.balance.pending_outbound -= amount;
        channel.balance.remote += amount;

        // Update pending payment
        if let Some(pending) = self.pending_payments.get_mut(&payment_hash) {
            pending.preimage = Some(preimage.clone());
            pending.status = PaymentStatus::Succeeded;
        }

        // Store preimage
        self.known_preimages.insert(payment_hash, preimage);

        self.stats.total_payments_sent += 1;
        self.stats.total_amount_sent += amount;

        self.events.push(ChannelEvent::PaymentSent {
            channel_id,
            payment_hash,
            amount,
        });

        Ok(())
    }

    // =========================================================================
    // Invoices
    // =========================================================================

    /// Create a new invoice
    pub fn create_invoice(
        &mut self,
        amount: Option<u64>,
        description: &str,
        expiry: u32,
    ) -> Invoice {
        let preimage = PaymentPreimage::generate();
        let invoice = Invoice::new(&preimage, amount, description, expiry);
        
        let payment_hash = invoice.payment_hash;
        self.invoices.insert(payment_hash, (preimage, invoice.clone()));
        
        invoice
    }

    /// Look up preimage for an invoice
    pub fn get_invoice_preimage(&self, payment_hash: &PaymentHash) -> Option<&PaymentPreimage> {
        self.invoices.get(payment_hash).map(|(p, _)| p)
    }

    // =========================================================================
    // Channel Closing
    // =========================================================================

    /// Initiate cooperative close
    pub fn close_channel(&mut self, channel_id: ChannelId) -> Result<(), ChannelError> {
        let channel = self.channels.get_mut(&channel_id)
            .ok_or(ChannelError::InvalidState("Channel not found".to_string()))?;

        channel.initiate_shutdown()?;

        self.events.push(ChannelEvent::ChannelClosing {
            channel_id,
            cooperative: true,
        });

        Ok(())
    }

    /// Force close a channel
    pub fn force_close_channel(&mut self, channel_id: ChannelId) -> Result<[u8; 32], ChannelError> {
        let channel = self.channels.get_mut(&channel_id)
            .ok_or(ChannelError::InvalidState("Channel not found".to_string()))?;

        let commitment_txid = channel.force_close(self.current_height)?;

        self.events.push(ChannelEvent::ChannelClosing {
            channel_id,
            cooperative: false,
        });

        Ok(commitment_txid)
    }

    /// Complete channel close
    pub fn complete_close(
        &mut self,
        channel_id: ChannelId,
        close_type: CloseType,
    ) -> Result<(), ChannelError> {
        let channel = self.channels.get_mut(&channel_id)
            .ok_or(ChannelError::InvalidState("Channel not found".to_string()))?;

        let local_balance = channel.balance.local;
        let remote_balance = channel.balance.remote;

        channel.mark_closed(close_type.clone());
        
        self.stats.total_channels_closed += 1;

        self.events.push(ChannelEvent::ChannelClosed {
            channel_id,
            close_type,
            local_balance,
            remote_balance,
        });

        Ok(())
    }

    // =========================================================================
    // Revocation
    // =========================================================================

    /// Store revocation secret (received from counterparty)
    pub fn store_revocation_secret(
        &mut self,
        channel_id: ChannelId,
        commitment_number: u64,
        secret: CommitmentSecret,
    ) {
        self.revocation_secrets.insert((channel_id, commitment_number), secret);
    }

    /// Check for breach (old commitment broadcast)
    pub fn check_breach(
        &self,
        channel_id: ChannelId,
        commitment_number: u64,
    ) -> Option<&CommitmentSecret> {
        // If we have a revocation secret for this commitment,
        // and it's older than the current commitment, it's a breach
        let channel = self.channels.get(&channel_id)?;
        
        if commitment_number < channel.commitment_number {
            return self.revocation_secrets.get(&(channel_id, commitment_number));
        }
        
        None
    }

    // =========================================================================
    // Queries
    // =========================================================================

    /// Get channel info
    pub fn get_channel(&self, channel_id: &ChannelId) -> Option<&Channel> {
        self.channels.get(channel_id)
    }

    /// List all channels
    pub fn list_channels(&self) -> Vec<ChannelInfo> {
        self.channels.values().map(|c| c.info()).collect()
    }

    /// List active channels
    pub fn active_channels(&self) -> Vec<&Channel> {
        self.channels.values()
            .filter(|c| c.state.is_active())
            .collect()
    }

    /// Get total local balance across all channels
    pub fn total_local_balance(&self) -> u64 {
        self.channels.values()
            .filter(|c| c.state.is_active())
            .map(|c| c.balance.local)
            .sum()
    }

    /// Get total remote balance across all channels
    pub fn total_remote_balance(&self) -> u64 {
        self.channels.values()
            .filter(|c| c.state.is_active())
            .map(|c| c.balance.remote)
            .sum()
    }

    /// Get total capacity across all channels
    pub fn total_capacity(&self) -> u64 {
        self.channels.values()
            .filter(|c| c.state.is_active())
            .map(|c| c.capacity)
            .sum()
    }

    /// Take events (clears the queue)
    pub fn take_events(&mut self) -> Vec<ChannelEvent> {
        std::mem::take(&mut self.events)
    }

    /// Get pending payment status
    pub fn payment_status(&self, payment_hash: &PaymentHash) -> Option<&PaymentStatus> {
        self.pending_payments.get(payment_hash).map(|p| &p.status)
    }

    /// Summary of all channels
    pub fn summary(&self) -> ChannelSummary {
        let active: Vec<_> = self.channels.values()
            .filter(|c| c.state.is_active())
            .collect();

        ChannelSummary {
            total_channels: self.channels.len(),
            active_channels: active.len(),
            total_capacity: active.iter().map(|c| c.capacity).sum(),
            local_balance: active.iter().map(|c| c.balance.local).sum(),
            remote_balance: active.iter().map(|c| c.balance.remote).sum(),
            pending_htlcs: self.htlc_managers.values().map(|m| m.count()).sum(),
        }
    }
}

/// Channel summary
#[derive(Clone, Debug)]
pub struct ChannelSummary {
    pub total_channels: usize,
    pub active_channels: usize,
    pub total_capacity: u64,
    pub local_balance: u64,
    pub remote_balance: u64,
    pub pending_htlcs: usize,
}

impl std::fmt::Display for ChannelSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Channel Summary:")?;
        writeln!(f, "  Total: {} ({} active)", self.total_channels, self.active_channels)?;
        writeln!(f, "  Capacity: {} sat", self.total_capacity)?;
        writeln!(f, "  Local: {} sat", self.local_balance)?;
        writeln!(f, "  Remote: {} sat", self.remote_balance)?;
        writeln!(f, "  Pending HTLCs: {}", self.pending_htlcs)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_manager() -> ChannelManager {
        ChannelManager::new([0x02; 33])
    }

    #[test]
    fn test_open_channel() {
        let mut manager = create_manager();
        
        let channel_id = manager.open_channel(
            10 * 100_000_000, // 10 MOON
            0,
        ).unwrap();

        assert!(manager.channels.contains_key(&channel_id));
        assert_eq!(manager.stats.total_channels_opened, 1);
    }

    #[test]
    fn test_channel_funding() {
        let mut manager = create_manager();
        
        let channel_id = manager.open_channel(10 * 100_000_000, 0).unwrap();
        
        // Fund the channel
        manager.channel_funded(channel_id, [0xAB; 32], 0).unwrap();

        // Process blocks for confirmations
        for i in 1..=3 {
            let events = manager.process_block(i);
            if i == 3 {
                assert!(events.iter().any(|e| matches!(e, ChannelEvent::ChannelActive { .. })));
            }
        }

        let channel = manager.get_channel(&channel_id).unwrap();
        assert!(channel.state.is_active());
    }

    #[test]
    fn test_send_payment() {
        let mut manager = create_manager();
        
        // Create and activate channel
        let channel_id = manager.open_channel(10 * 100_000_000, 0).unwrap();
        manager.channel_funded(channel_id, [0xAB; 32], 0).unwrap();
        for i in 1..=3 {
            manager.process_block(i);
        }

        // Create payment
        let preimage = PaymentPreimage::generate();
        let payment_hash = preimage.payment_hash();

        // Send payment
        let htlc_id = manager.send_payment(
            channel_id,
            payment_hash,
            1_000_000, // 0.01 MOON
            1000,
        ).unwrap();

        assert!(manager.pending_payments.contains_key(&payment_hash));

        // Simulate fulfillment
        manager.htlc_fulfilled(channel_id, htlc_id, preimage).unwrap();

        // Check payment succeeded
        let status = manager.payment_status(&payment_hash).unwrap();
        assert_eq!(*status, PaymentStatus::Succeeded);
    }

    #[test]
    fn test_create_invoice() {
        let mut manager = create_manager();
        
        let invoice = manager.create_invoice(
            Some(100_000),
            "Test payment",
            3600,
        );

        assert!(manager.invoices.contains_key(&invoice.payment_hash));
        assert!(manager.get_invoice_preimage(&invoice.payment_hash).is_some());
    }

    #[test]
    fn test_close_channel() {
        let mut manager = create_manager();
        
        // Create and activate channel
        let channel_id = manager.open_channel(10 * 100_000_000, 0).unwrap();
        manager.channel_funded(channel_id, [0xAB; 32], 0).unwrap();
        for i in 1..=3 {
            manager.process_block(i);
        }

        // Initiate close
        manager.close_channel(channel_id).unwrap();

        let channel = manager.get_channel(&channel_id).unwrap();
        assert!(channel.state.is_closing());
    }

    #[test]
    fn test_channel_summary() {
        let mut manager = create_manager();
        
        // Create channels
        for _ in 0..3 {
            let id = manager.open_channel(10 * 100_000_000, 0).unwrap();
            manager.channel_funded(id, rand::random(), 0).unwrap();
        }

        // Activate all
        for i in 1..=3 {
            manager.process_block(i);
        }

        let summary = manager.summary();
        assert_eq!(summary.total_channels, 3);
        assert_eq!(summary.active_channels, 3);
        assert_eq!(summary.total_capacity, 30 * 100_000_000);
    }
}
