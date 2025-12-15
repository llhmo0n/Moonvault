// =============================================================================
// MOONCOIN v2.33 - Commitment Transactions
// =============================================================================
//
// Commitment transactions are the heart of payment channels. Each party holds
// a different version that they can broadcast to close the channel.
//
// Structure:
// ┌─────────────────────────────────────────────────────────────────────────┐
// │                     COMMITMENT TRANSACTION                              │
// ├─────────────────────────────────────────────────────────────────────────┤
// │  Input:                                                                 │
// │    - Funding TX output (2-of-2 multisig)                               │
// │                                                                         │
// │  Outputs (Alice's version):                                             │
// │    1. To Alice (delayed): CSV + revocation                             │
// │       - IF: <revocation_key> CHECKSIG (Bob can claim if Alice cheats) │
// │       - ELSE: <CSV_delay> CSV DROP <alice_delayed_key> CHECKSIG       │
// │    2. To Bob (immediate): <bob_key> CHECKSIG                           │
// │    3+ HTLC outputs (if any)                                            │
// │                                                                         │
// │  Bob's version is symmetric (Bob delayed, Alice immediate)              │
// └─────────────────────────────────────────────────────────────────────────┘
//
// =============================================================================

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

use super::state::{ChannelId, Balance, ChannelError};
use super::htlc::Htlc;

// =============================================================================
// Commitment Number
// =============================================================================

/// Commitment transaction number (starts at 0, increments with each update)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CommitmentNumber(pub u64);

impl CommitmentNumber {
    pub fn new(n: u64) -> Self {
        CommitmentNumber(n)
    }

    pub fn increment(&self) -> Self {
        CommitmentNumber(self.0 + 1)
    }

    pub fn to_obscured(&self, obscuring_factor: &[u8; 32]) -> u64 {
        // XOR with obscuring factor for privacy
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&obscuring_factor[..8]);
        self.0 ^ u64::from_le_bytes(bytes)
    }
}

// =============================================================================
// Commitment Secret
// =============================================================================

/// Per-commitment secret (32 bytes)
/// Each commitment has a secret that, when revealed, allows revocation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentSecret(pub [u8; 32]);

impl CommitmentSecret {
    /// Generate from seed and commitment number
    pub fn derive(seed: &[u8; 32], commitment_number: u64) -> Self {
        // Use commitment number to derive unique secret
        // In production, use shachain for efficient storage
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(&commitment_number.to_le_bytes());
        hasher.update(b"commitment_secret");
        
        let result = hasher.finalize();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&result);
        CommitmentSecret(secret)
    }

    /// Derive revocation pubkey from this secret
    pub fn derive_revocation_pubkey(&self, basepoint: &[u8; 33]) -> [u8; 33] {
        // Simplified: hash(basepoint || secret) as pubkey
        // In production, use proper EC point derivation
        let mut hasher = Sha256::new();
        hasher.update(basepoint);
        hasher.update(&self.0);
        
        let result = hasher.finalize();
        let mut pubkey = [0u8; 33];
        pubkey[0] = 0x02; // compressed pubkey prefix
        pubkey[1..].copy_from_slice(&result);
        pubkey
    }

    /// Verify this is the correct secret for a commitment point
    pub fn verify(&self, commitment_point: &[u8; 33]) -> bool {
        // Simplified verification
        let derived = self.to_commitment_point();
        derived == *commitment_point
    }

    /// Convert secret to commitment point
    pub fn to_commitment_point(&self) -> [u8; 33] {
        // Simplified: just hash the secret
        let mut hasher = Sha256::new();
        hasher.update(&self.0);
        hasher.update(b"commitment_point");
        
        let result = hasher.finalize();
        let mut point = [0u8; 33];
        point[0] = 0x02;
        point[1..].copy_from_slice(&result);
        point
    }
}

// =============================================================================
// Revocation Key
// =============================================================================

/// Revocation key derived from per-commitment secret
#[derive(Clone, Debug)]
pub struct RevocationKey {
    /// The public key
    pub pubkey: [u8; 33],
    /// The commitment number this revokes
    pub commitment_number: u64,
}

impl RevocationKey {
    /// Create from commitment secret and basepoint
    pub fn from_secret(
        secret: &CommitmentSecret,
        basepoint: &[u8; 33],
        commitment_number: u64,
    ) -> Self {
        RevocationKey {
            pubkey: secret.derive_revocation_pubkey(basepoint),
            commitment_number,
        }
    }
}

// =============================================================================
// Commitment Output
// =============================================================================

/// Type of output in a commitment transaction
#[derive(Clone, Debug)]
pub enum CommitmentOutputType {
    /// To local party (delayed with CSV)
    ToLocal {
        amount: u64,
        csv_delay: u32,
        delayed_pubkey: [u8; 33],
        revocation_pubkey: [u8; 33],
    },
    /// To remote party (immediately spendable)
    ToRemote {
        amount: u64,
        pubkey: [u8; 33],
    },
    /// HTLC offered (we're offering)
    HtlcOffered {
        htlc_id: u64,
        amount: u64,
        payment_hash: [u8; 32],
        cltv_expiry: u32,
    },
    /// HTLC received (we're receiving)
    HtlcReceived {
        htlc_id: u64,
        amount: u64,
        payment_hash: [u8; 32],
        cltv_expiry: u32,
    },
    /// Anchor output (for fee bumping)
    Anchor {
        amount: u64,
        pubkey: [u8; 33],
    },
}

/// Output in a commitment transaction
#[derive(Clone, Debug)]
pub struct CommitmentOutput {
    pub output_type: CommitmentOutputType,
    pub script: Vec<u8>,
    pub output_index: u32,
}

impl CommitmentOutput {
    /// Create to_local output
    pub fn to_local(
        amount: u64,
        csv_delay: u32,
        delayed_pubkey: [u8; 33],
        revocation_pubkey: [u8; 33],
    ) -> Self {
        // Build script:
        // OP_IF
        //   <revocation_pubkey> OP_CHECKSIG
        // OP_ELSE
        //   <csv_delay> OP_CSV OP_DROP
        //   <delayed_pubkey> OP_CHECKSIG
        // OP_ENDIF
        
        let mut script = Vec::new();
        
        // OP_IF
        script.push(0x63);
        
        // <revocation_pubkey> OP_CHECKSIG
        script.push(33); // push 33 bytes
        script.extend_from_slice(&revocation_pubkey);
        script.push(0xAC); // OP_CHECKSIG
        
        // OP_ELSE
        script.push(0x67);
        
        // <csv_delay> OP_CSV OP_DROP
        let delay_bytes = encode_script_number(csv_delay as i64);
        script.push(delay_bytes.len() as u8);
        script.extend_from_slice(&delay_bytes);
        script.push(0xB2); // OP_CSV
        script.push(0x75); // OP_DROP
        
        // <delayed_pubkey> OP_CHECKSIG
        script.push(33);
        script.extend_from_slice(&delayed_pubkey);
        script.push(0xAC); // OP_CHECKSIG
        
        // OP_ENDIF
        script.push(0x68);

        CommitmentOutput {
            output_type: CommitmentOutputType::ToLocal {
                amount,
                csv_delay,
                delayed_pubkey,
                revocation_pubkey,
            },
            script,
            output_index: 0,
        }
    }

    /// Create to_remote output
    pub fn to_remote(amount: u64, pubkey: [u8; 33]) -> Self {
        // Simple P2PKH-style: <pubkey> OP_CHECKSIG
        let mut script = Vec::new();
        script.push(33);
        script.extend_from_slice(&pubkey);
        script.push(0xAC); // OP_CHECKSIG

        CommitmentOutput {
            output_type: CommitmentOutputType::ToRemote { amount, pubkey },
            script,
            output_index: 0,
        }
    }

    /// Create HTLC offered output
    pub fn htlc_offered(
        htlc_id: u64,
        amount: u64,
        payment_hash: [u8; 32],
        cltv_expiry: u32,
        local_htlc_pubkey: [u8; 33],
        remote_htlc_pubkey: [u8; 33],
        revocation_pubkey: [u8; 33],
    ) -> Self {
        // HTLC-offered script:
        // OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocation_pubkey))> OP_EQUAL
        // OP_IF
        //     OP_CHECKSIG
        // OP_ELSE
        //     <remote_htlc_pubkey> OP_SWAP OP_SIZE 32 OP_EQUAL
        //     OP_NOTIF
        //         OP_DROP 2 OP_SWAP <local_htlc_pubkey> 2 OP_CHECKMULTISIG
        //     OP_ELSE
        //         OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
        //         OP_CHECKSIG
        //     OP_ENDIF
        // OP_ENDIF
        
        // Simplified version for now
        let script = build_htlc_offered_script(
            &payment_hash,
            cltv_expiry,
            &local_htlc_pubkey,
            &remote_htlc_pubkey,
            &revocation_pubkey,
        );

        CommitmentOutput {
            output_type: CommitmentOutputType::HtlcOffered {
                htlc_id,
                amount,
                payment_hash,
                cltv_expiry,
            },
            script,
            output_index: 0,
        }
    }

    /// Create HTLC received output
    pub fn htlc_received(
        htlc_id: u64,
        amount: u64,
        payment_hash: [u8; 32],
        cltv_expiry: u32,
        local_htlc_pubkey: [u8; 33],
        remote_htlc_pubkey: [u8; 33],
        revocation_pubkey: [u8; 33],
    ) -> Self {
        let script = build_htlc_received_script(
            &payment_hash,
            cltv_expiry,
            &local_htlc_pubkey,
            &remote_htlc_pubkey,
            &revocation_pubkey,
        );

        CommitmentOutput {
            output_type: CommitmentOutputType::HtlcReceived {
                htlc_id,
                amount,
                payment_hash,
                cltv_expiry,
            },
            script,
            output_index: 0,
        }
    }

    pub fn amount(&self) -> u64 {
        match &self.output_type {
            CommitmentOutputType::ToLocal { amount, .. } => *amount,
            CommitmentOutputType::ToRemote { amount, .. } => *amount,
            CommitmentOutputType::HtlcOffered { amount, .. } => *amount,
            CommitmentOutputType::HtlcReceived { amount, .. } => *amount,
            CommitmentOutputType::Anchor { amount, .. } => *amount,
        }
    }
}

// =============================================================================
// Commitment Transaction
// =============================================================================

/// A commitment transaction
#[derive(Clone, Debug)]
pub struct CommitmentTx {
    /// Channel ID
    pub channel_id: ChannelId,
    
    /// Commitment number
    pub commitment_number: CommitmentNumber,
    
    /// Whose commitment is this (local or remote)
    pub is_local: bool,
    
    /// Fee for this commitment
    pub fee: u64,
    
    /// Funding outpoint
    pub funding_txid: [u8; 32],
    pub funding_output_index: u32,
    
    /// Outputs
    pub outputs: Vec<CommitmentOutput>,
    
    /// Our signature (if signed)
    pub local_signature: Option<[u8; 64]>,
    
    /// Their signature (if received)
    pub remote_signature: Option<[u8; 64]>,
    
    /// Obscured commitment number (for locktime)
    pub obscured_commitment_number: u64,
}

impl CommitmentTx {
    /// Build a new commitment transaction
    pub fn build(
        channel_id: ChannelId,
        commitment_number: CommitmentNumber,
        is_local: bool,
        balance: &Balance,
        htlcs: &[Htlc],
        funding_txid: [u8; 32],
        funding_output_index: u32,
        local_delayed_pubkey: [u8; 33],
        local_revocation_pubkey: [u8; 33],
        remote_pubkey: [u8; 33],
        csv_delay: u32,
        dust_limit: u64,
        fee_rate: u64,
    ) -> Result<Self, ChannelError> {
        let mut outputs = Vec::new();
        
        // Calculate fee
        let base_weight = 724; // Base commitment TX weight
        let htlc_weight: u64 = htlcs.len() as u64 * 172; // Weight per HTLC
        let total_weight = base_weight + htlc_weight;
        let fee = (total_weight * fee_rate) / 1000;

        // Determine who pays the fee
        let (local_amount, remote_amount) = if is_local {
            // Local pays fee
            let local = if balance.local > fee { balance.local - fee } else { 0 };
            (local, balance.remote)
        } else {
            // Remote pays fee
            let remote = if balance.remote > fee { balance.remote - fee } else { 0 };
            (balance.local, remote)
        };

        // Add to_local output (delayed)
        if local_amount >= dust_limit {
            outputs.push(CommitmentOutput::to_local(
                local_amount,
                csv_delay,
                local_delayed_pubkey,
                local_revocation_pubkey,
            ));
        }

        // Add to_remote output (immediate)
        if remote_amount >= dust_limit {
            outputs.push(CommitmentOutput::to_remote(remote_amount, remote_pubkey));
        }

        // Add HTLC outputs
        // TODO: Add HTLC outputs based on direction

        // Assign output indices
        for (i, output) in outputs.iter_mut().enumerate() {
            output.output_index = i as u32;
        }

        // Calculate obscured commitment number
        let obscuring_factor = Self::calculate_obscuring_factor(&funding_txid);
        let obscured = commitment_number.to_obscured(&obscuring_factor);

        Ok(CommitmentTx {
            channel_id,
            commitment_number,
            is_local,
            fee,
            funding_txid,
            funding_output_index,
            outputs,
            local_signature: None,
            remote_signature: None,
            obscured_commitment_number: obscured,
        })
    }

    /// Calculate obscuring factor from funding TX
    fn calculate_obscuring_factor(funding_txid: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(funding_txid);
        hasher.update(b"obscure");
        
        let result = hasher.finalize();
        let mut factor = [0u8; 32];
        factor.copy_from_slice(&result);
        factor
    }

    /// Get transaction ID (hash)
    pub fn txid(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.channel_id.0);
        hasher.update(&self.commitment_number.0.to_le_bytes());
        hasher.update(&[self.is_local as u8]);
        hasher.update(&self.fee.to_le_bytes());
        
        for output in &self.outputs {
            hasher.update(&output.amount().to_le_bytes());
            hasher.update(&output.script);
        }
        
        let result = hasher.finalize();
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&result);
        txid
    }

    /// Sign this commitment (local signature)
    pub fn sign_local(&mut self, _secret_key: &[u8; 32]) {
        // Simplified: just mark as signed
        // In production, create proper ECDSA signature
        self.local_signature = Some([0xAA; 64]);
    }

    /// Add remote signature
    pub fn add_remote_signature(&mut self, signature: [u8; 64]) {
        self.remote_signature = Some(signature);
    }

    /// Is fully signed?
    pub fn is_fully_signed(&self) -> bool {
        self.local_signature.is_some() && self.remote_signature.is_some()
    }

    /// Total output value
    pub fn total_output_value(&self) -> u64 {
        self.outputs.iter().map(|o| o.amount()).sum()
    }

    /// Serialize for broadcast
    pub fn serialize(&self) -> Vec<u8> {
        // Simplified serialization
        let mut data = Vec::new();
        
        // Version
        data.extend_from_slice(&2u32.to_le_bytes());
        
        // Input (funding outpoint)
        data.extend_from_slice(&self.funding_txid);
        data.extend_from_slice(&self.funding_output_index.to_le_bytes());
        
        // Outputs
        data.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for output in &self.outputs {
            data.extend_from_slice(&output.amount().to_le_bytes());
            data.extend_from_slice(&(output.script.len() as u32).to_le_bytes());
            data.extend_from_slice(&output.script);
        }
        
        // Locktime (obscured commitment number)
        data.extend_from_slice(&(self.obscured_commitment_number as u32).to_le_bytes());
        
        data
    }
}

// =============================================================================
// Commitment Pair
// =============================================================================

/// A pair of commitment transactions (local and remote versions)
#[derive(Clone, Debug)]
pub struct CommitmentPair {
    /// Our version (we broadcast this to force close)
    pub local: CommitmentTx,
    /// Their version (they broadcast this to force close)
    pub remote: CommitmentTx,
}

impl CommitmentPair {
    /// Create a new commitment pair
    pub fn new(local: CommitmentTx, remote: CommitmentTx) -> Self {
        CommitmentPair { local, remote }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Encode a number for Bitcoin Script
fn encode_script_number(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }

    let negative = n < 0;
    let mut abs_n = n.abs() as u64;
    let mut result = Vec::new();

    while abs_n > 0 {
        result.push((abs_n & 0xFF) as u8);
        abs_n >>= 8;
    }

    // If high bit is set, add extra byte for sign
    if result.last().unwrap() & 0x80 != 0 {
        if negative {
            result.push(0x80);
        } else {
            result.push(0x00);
        }
    } else if negative {
        *result.last_mut().unwrap() |= 0x80;
    }

    result
}

/// Build HTLC offered script (simplified)
fn build_htlc_offered_script(
    payment_hash: &[u8; 32],
    cltv_expiry: u32,
    _local_htlc_pubkey: &[u8; 33],
    remote_htlc_pubkey: &[u8; 33],
    revocation_pubkey: &[u8; 33],
) -> Vec<u8> {
    // Simplified HTLC-offered script:
    // OP_IF
    //   <revocation_pubkey> OP_CHECKSIG  (revocation path)
    // OP_ELSE
    //   OP_SHA256 <payment_hash> OP_EQUALVERIFY
    //   <remote_htlc_pubkey> OP_CHECKSIG  (success path)
    //   OR
    //   <cltv_expiry> OP_CLTV OP_DROP  (timeout path)
    // OP_ENDIF

    let mut script = Vec::new();
    
    // OP_IF (revocation)
    script.push(0x63);
    script.push(33);
    script.extend_from_slice(revocation_pubkey);
    script.push(0xAC); // OP_CHECKSIG
    
    // OP_ELSE
    script.push(0x67);
    
    // Payment hash check
    script.push(0xA8); // OP_SHA256
    script.push(32);
    script.extend_from_slice(payment_hash);
    script.push(0x88); // OP_EQUALVERIFY
    
    // Remote can claim with preimage
    script.push(33);
    script.extend_from_slice(remote_htlc_pubkey);
    script.push(0xAC); // OP_CHECKSIG
    
    // Timeout path (local can claim after expiry)
    let expiry_bytes = encode_script_number(cltv_expiry as i64);
    script.push(expiry_bytes.len() as u8);
    script.extend_from_slice(&expiry_bytes);
    script.push(0xB1); // OP_CLTV
    script.push(0x75); // OP_DROP
    
    // OP_ENDIF
    script.push(0x68);
    
    script
}

/// Build HTLC received script (simplified)
fn build_htlc_received_script(
    payment_hash: &[u8; 32],
    cltv_expiry: u32,
    local_htlc_pubkey: &[u8; 33],
    _remote_htlc_pubkey: &[u8; 33],
    revocation_pubkey: &[u8; 33],
) -> Vec<u8> {
    // HTLC-received is the mirror of HTLC-offered
    let mut script = Vec::new();
    
    // OP_IF (revocation)
    script.push(0x63);
    script.push(33);
    script.extend_from_slice(revocation_pubkey);
    script.push(0xAC);
    
    // OP_ELSE
    script.push(0x67);
    
    // Payment hash check
    script.push(0xA8); // OP_SHA256
    script.push(32);
    script.extend_from_slice(payment_hash);
    script.push(0x88); // OP_EQUALVERIFY
    
    // Local can claim with preimage
    script.push(33);
    script.extend_from_slice(local_htlc_pubkey);
    script.push(0xAC);
    
    // Timeout
    let expiry_bytes = encode_script_number(cltv_expiry as i64);
    script.push(expiry_bytes.len() as u8);
    script.extend_from_slice(&expiry_bytes);
    script.push(0xB1); // OP_CLTV
    script.push(0x75); // OP_DROP
    
    // OP_ENDIF
    script.push(0x68);
    
    script
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_number() {
        let cn = CommitmentNumber::new(0);
        assert_eq!(cn.increment().0, 1);

        let obscure = [0xAB; 32];
        let obscured = cn.to_obscured(&obscure);
        assert_ne!(obscured, 0);
    }

    #[test]
    fn test_commitment_secret() {
        let seed = [0x42; 32];
        let secret1 = CommitmentSecret::derive(&seed, 0);
        let secret2 = CommitmentSecret::derive(&seed, 1);
        
        // Different commitment numbers = different secrets
        assert_ne!(secret1.0, secret2.0);

        // Same inputs = same secret
        let secret1_again = CommitmentSecret::derive(&seed, 0);
        assert_eq!(secret1.0, secret1_again.0);
    }

    #[test]
    fn test_commitment_output() {
        let delayed_key = [0x02; 33];
        let revocation_key = [0x03; 33];
        
        let output = CommitmentOutput::to_local(
            1_000_000,
            144,
            delayed_key,
            revocation_key,
        );

        assert_eq!(output.amount(), 1_000_000);
        assert!(!output.script.is_empty());
    }

    #[test]
    fn test_encode_script_number() {
        assert_eq!(encode_script_number(0), Vec::<u8>::new());
        assert_eq!(encode_script_number(1), vec![0x01]);
        assert_eq!(encode_script_number(127), vec![0x7F]);
        assert_eq!(encode_script_number(128), vec![0x80, 0x00]);
        assert_eq!(encode_script_number(144), vec![0x90, 0x00]);
        assert_eq!(encode_script_number(-1), vec![0x81]);
    }

    #[test]
    fn test_commitment_tx() {
        let channel_id = ChannelId([0xAB; 32]);
        let balance = Balance::new(5_000_000, 5_000_000);
        
        let tx = CommitmentTx::build(
            channel_id,
            CommitmentNumber::new(0),
            true,
            &balance,
            &[],
            [0xCD; 32],
            0,
            [0x02; 33],
            [0x03; 33],
            [0x04; 33],
            144,
            546,
            1000, // 1 sat/byte
        ).unwrap();

        assert_eq!(tx.outputs.len(), 2); // to_local and to_remote
        assert!(tx.fee > 0);
    }
}
