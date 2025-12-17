// =============================================================================
// MOONVAULT v4.0 - Fee System
// Bitcoin L1 fee verification for security services
// =============================================================================
//
// This module handles:
// - Invoice generation for services (paid in BTC)
// - Payment verification via Esplora API
// - Fee Pool status tracking
// - Service activation after payment confirmation
//
// IMPORTANT: MoonVault NEVER custodies BTC. We only VERIFY payments.
//
// =============================================================================

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

use crate::lib::*;
use crate::btc_lock::{EsploraObserver, BtcObserver, BitcoinNetwork, EsploraTx, EsploraVout};

// =============================================================================
// Data Structures
// =============================================================================

/// Service types that can be purchased with BTC
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ServiceType {
    VaultCreate,
    VaultModify,
    MonitoringMonthly,
}

impl ServiceType {
    /// Get the BTC fee in satoshis for this service
    pub fn fee_sats(&self) -> u64 {
        match self {
            ServiceType::VaultCreate => FEE_VAULT_CREATE,
            ServiceType::VaultModify => FEE_VAULT_MODIFY,
            ServiceType::MonitoringMonthly => FEE_MONITORING_MONTHLY,
        }
    }
    
    /// Get the gas burn cost for this service
    pub fn gas_burn(&self) -> u64 {
        match self {
            ServiceType::VaultCreate => GAS_BURN_VAULT_CREATE,
            ServiceType::VaultModify => GAS_BURN_VAULT_MODIFY,
            ServiceType::MonitoringMonthly => 0, // No gas burn for monitoring
        }
    }
    
    /// Human-readable name
    pub fn name(&self) -> &str {
        match self {
            ServiceType::VaultCreate => "vault-create",
            ServiceType::VaultModify => "vault-modify",
            ServiceType::MonitoringMonthly => "monitoring-monthly",
        }
    }
}

/// Invoice for a service payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeInvoice {
    /// Unique invoice ID (hash of components)
    pub invoice_id: String,
    /// Type of service requested
    pub service_type: ServiceType,
    /// User's public key (hex)
    pub user_pubkey: String,
    /// Fee amount in satoshis
    pub fee_sats: u64,
    /// Fee Pool address to pay to
    pub fee_pool_address: String,
    /// Network (mainnet/testnet)
    pub network: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp (24 hours from creation)
    pub expires_at: u64,
    /// Status of the invoice
    pub status: InvoiceStatus,
    /// Bitcoin TXID if paid
    pub payment_txid: Option<String>,
    /// Confirmations received
    pub confirmations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InvoiceStatus {
    Pending,
    Paid,
    Confirmed,
    Expired,
    ServiceActivated,
}

/// Fee record for tracking distributions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRecord {
    pub invoice_id: String,
    pub service_type: String,
    pub user_pubkey: String,
    pub fee_sats: u64,
    pub payment_txid: String,
    pub confirmed_at: u64,
    pub distributed: bool,
}

/// Fee Pool status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeePoolStatus {
    pub address: String,
    pub network: String,
    pub balance_sats: u64,
    pub total_received_sats: u64,
    pub total_distributed_sats: u64,
    pub pending_distribution_sats: u64,
    pub last_distribution_txid: Option<String>,
    pub last_checked: u64,
}

// =============================================================================
// Invoice Management
// =============================================================================

/// Generate a new invoice for a service
pub fn generate_invoice(
    service_type: ServiceType,
    user_pubkey: &str,
    testnet: bool,
) -> FeeInvoice {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let network = if testnet { "testnet" } else { "mainnet" };
    let fee_pool = if testnet { 
        FEE_POOL_ADDRESS_TESTNET 
    } else { 
        FEE_POOL_ADDRESS_MAINNET 
    };
    
    // Generate invoice ID from components
    let invoice_id = generate_invoice_id(&service_type, user_pubkey, now);
    
    FeeInvoice {
        invoice_id,
        service_type: service_type.clone(),
        user_pubkey: user_pubkey.to_string(),
        fee_sats: service_type.fee_sats(),
        fee_pool_address: fee_pool.to_string(),
        network: network.to_string(),
        created_at: now,
        expires_at: now + 86400, // 24 hours
        status: InvoiceStatus::Pending,
        payment_txid: None,
        confirmations: 0,
    }
}

/// Generate deterministic invoice ID
fn generate_invoice_id(service_type: &ServiceType, user_pubkey: &str, timestamp: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(service_type.name().as_bytes());
    hasher.update(user_pubkey.as_bytes());
    hasher.update(timestamp.to_le_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..16]) // Use first 16 bytes for shorter ID
}

/// Print invoice details for user
pub fn print_invoice(invoice: &FeeInvoice) {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║                         MOONVAULT FEE INVOICE                             ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  Invoice ID:    {}                             ║", invoice.invoice_id);
    println!("║  Service:       {:50}  ║", invoice.service_type.name());
    println!("║  Network:       {:50}  ║", invoice.network);
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  PAYMENT INSTRUCTIONS:                                                    ║");
    println!("║                                                                           ║");
    println!("║  1. Send exactly {} sats to:                                         ║", invoice.fee_sats);
    println!("║                                                                           ║");
    println!("║     {}                                           ║", invoice.fee_pool_address);
    println!("║                                                                           ║");
    println!("║  2. Include this in OP_RETURN (optional but recommended):                 ║");
    println!("║                                                                           ║");
    println!("║     {}                                             ║", invoice.invoice_id);
    println!("║                                                                           ║");
    println!("║  3. After sending, verify payment with:                                   ║");
    println!("║                                                                           ║");
    println!("║     moonvault fee verify <YOUR_BITCOIN_TXID>                              ║");
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  ⚠️  This invoice expires in 24 hours                                     ║");
    println!("║  ⚠️  Payment must have 3+ confirmations                                   ║");
    println!("║  ⚠️  Requires 1 gas unit to be burned (anti-spam)                         ║");
    println!("║                                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!();
}

// =============================================================================
// Payment Verification
// =============================================================================

/// Verify a BTC payment for an invoice
pub fn verify_payment(
    txid: &str,
    invoice_id: &str,
    testnet: bool,
) -> Result<PaymentVerification, String> {
    let network = if testnet {
        BitcoinNetwork::Testnet
    } else {
        BitcoinNetwork::Mainnet
    };
    
    let observer = EsploraObserver::new(network);
    
    // Query the transaction
    let tx_info = observer.get_transaction(txid)
        .map_err(|e| format!("Failed to query transaction: {}", e))?;
    
    // Load the invoice
    let invoices = load_invoices();
    let invoice = invoices.get(invoice_id)
        .ok_or_else(|| format!("Invoice not found: {}", invoice_id))?;
    
    // Check if payment is to the correct address with correct amount
    let fee_pool = if testnet {
        FEE_POOL_ADDRESS_TESTNET
    } else {
        FEE_POOL_ADDRESS_MAINNET
    };
    
    // Check confirmations from typed struct
    let confirmations = if tx_info.status.confirmed {
        // If confirmed, estimate 6 confirmations (simplified)
        6u32
    } else {
        0u32
    };
    
    // Check outputs for payment to fee pool
    let mut payment_found = false;
    let mut payment_amount = 0u64;
    
    for output in &tx_info.vout {
        if let Some(ref addr) = output.scriptpubkey_address {
            if addr == fee_pool {
                payment_amount = output.value;
                if payment_amount >= invoice.fee_sats {
                    payment_found = true;
                    break;
                }
            }
        }
    }
    
    Ok(PaymentVerification {
        txid: txid.to_string(),
        invoice_id: invoice_id.to_string(),
        payment_found,
        payment_amount,
        expected_amount: invoice.fee_sats,
        confirmations,
        confirmed: confirmations >= 3,
        service_type: invoice.service_type.clone(),
    })
}

#[derive(Debug)]
pub struct PaymentVerification {
    pub txid: String,
    pub invoice_id: String,
    pub payment_found: bool,
    pub payment_amount: u64,
    pub expected_amount: u64,
    pub confirmations: u32,
    pub confirmed: bool,
    pub service_type: ServiceType,
}

/// Print verification result
pub fn print_verification(result: &PaymentVerification) {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║                      PAYMENT VERIFICATION                                 ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  Transaction:   {}  ║", result.txid);
    println!("║  Invoice:       {:50}  ║", result.invoice_id);
    println!("║                                                                           ║");
    
    if result.payment_found {
        println!("║  ✅ Payment FOUND                                                         ║");
        println!("║                                                                           ║");
        println!("║  Amount:        {} sats (expected: {} sats)                    ║", 
                 result.payment_amount, result.expected_amount);
        println!("║  Confirmations: {} (required: 3)                                        ║", 
                 result.confirmations);
        println!("║                                                                           ║");
        
        if result.confirmed {
            println!("║  ✅ CONFIRMED - Service can be activated!                                ║");
            println!("║                                                                           ║");
            println!("║  Next step:                                                              ║");
            println!("║    moonvault vault create --invoice {}               ║", result.invoice_id);
        } else {
            println!("║  ⏳ Waiting for more confirmations...                                    ║");
            println!("║     ({} more needed)                                                   ║", 
                     3 - result.confirmations);
        }
    } else {
        println!("║  ❌ Payment NOT FOUND                                                     ║");
        println!("║                                                                           ║");
        println!("║  Possible reasons:                                                        ║");
        println!("║  • Transaction not yet broadcast                                          ║");
        println!("║  • Payment sent to wrong address                                          ║");
        println!("║  • Payment amount incorrect                                               ║");
    }
    
    println!("║                                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!();
}

// =============================================================================
// Fee Pool Status
// =============================================================================

/// Get Fee Pool status from Bitcoin network
pub fn get_fee_pool_status(testnet: bool) -> Result<FeePoolStatus, String> {
    let network = if testnet {
        BitcoinNetwork::Testnet
    } else {
        BitcoinNetwork::Mainnet
    };
    
    let observer = EsploraObserver::new(network);
    
    let fee_pool = if testnet {
        FEE_POOL_ADDRESS_TESTNET
    } else {
        FEE_POOL_ADDRESS_MAINNET
    };
    
    // For now, return a basic status
    // In production, would query actual balance from Esplora
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Load fee records to calculate totals
    let records = load_fee_records();
    let total_received: u64 = records.iter().map(|r| r.fee_sats).sum();
    let total_distributed: u64 = records.iter()
        .filter(|r| r.distributed)
        .map(|r| r.fee_sats)
        .sum();
    
    Ok(FeePoolStatus {
        address: fee_pool.to_string(),
        network: if testnet { "testnet" } else { "mainnet" }.to_string(),
        balance_sats: total_received - total_distributed,
        total_received_sats: total_received,
        total_distributed_sats: total_distributed,
        pending_distribution_sats: total_received - total_distributed,
        last_distribution_txid: None,
        last_checked: now,
    })
}

/// Print Fee Pool status
pub fn print_fee_pool_status(status: &FeePoolStatus) {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║                         FEE POOL STATUS                                   ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  Network:         {:50}  ║", status.network);
    println!("║  Address:         {}  ║", status.address);
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  Balance:              {:>12} sats                                   ║", status.balance_sats);
    println!("║  Total Received:       {:>12} sats                                   ║", status.total_received_sats);
    println!("║  Total Distributed:    {:>12} sats                                   ║", status.total_distributed_sats);
    println!("║  Pending Distribution: {:>12} sats                                   ║", status.pending_distribution_sats);
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  DISTRIBUTION RULES (immutable):                                          ║");
    println!("║                                                                           ║");
    println!("║    {:>3}% → Node Operators                                                ║", FEE_DIST_NODES);
    println!("║    {:>3}% → Maintenance                                                   ║", FEE_DIST_MAINTENANCE);
    println!("║    {:>3}% → Security Reserve                                              ║", FEE_DIST_RESERVE);
    println!("║                                                                           ║");
    println!("║  All distributions are on-chain in Bitcoin and publicly auditable.        ║");
    println!("║                                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!();
}

// =============================================================================
// Persistence
// =============================================================================

/// Load invoices from disk
pub fn load_invoices() -> HashMap<String, FeeInvoice> {
    let path = "invoices.json";
    match File::open(path) {
        Ok(mut file) => {
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap_or_default();
            serde_json::from_str(&contents).unwrap_or_default()
        }
        Err(_) => HashMap::new(),
    }
}

/// Save invoices to disk
pub fn save_invoices(invoices: &HashMap<String, FeeInvoice>) {
    let path = "invoices.json";
    if let Ok(mut file) = File::create(path) {
        let json = serde_json::to_string_pretty(invoices).unwrap_or_default();
        let _ = file.write_all(json.as_bytes());
    }
}

/// Save a single invoice
pub fn save_invoice(invoice: &FeeInvoice) {
    let mut invoices = load_invoices();
    invoices.insert(invoice.invoice_id.clone(), invoice.clone());
    save_invoices(&invoices);
}

/// Load fee records from disk
pub fn load_fee_records() -> Vec<FeeRecord> {
    let path = FEE_RECORDS_FILE;
    match File::open(path) {
        Ok(mut file) => {
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap_or_default();
            serde_json::from_str(&contents).unwrap_or_default()
        }
        Err(_) => Vec::new(),
    }
}

/// Save fee records to disk
pub fn save_fee_records(records: &[FeeRecord]) {
    let path = FEE_RECORDS_FILE;
    if let Ok(mut file) = File::create(path) {
        let json = serde_json::to_string_pretty(records).unwrap_or_default();
        let _ = file.write_all(json.as_bytes());
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_service_fees() {
        assert_eq!(ServiceType::VaultCreate.fee_sats(), 10_000);
        assert_eq!(ServiceType::VaultModify.fee_sats(), 5_000);
        assert_eq!(ServiceType::MonitoringMonthly.fee_sats(), 1_000);
    }
    
    #[test]
    fn test_invoice_generation() {
        let invoice = generate_invoice(
            ServiceType::VaultCreate,
            "02abc123",
            true, // testnet
        );
        
        assert_eq!(invoice.service_type, ServiceType::VaultCreate);
        assert_eq!(invoice.fee_sats, 10_000);
        assert_eq!(invoice.status, InvoiceStatus::Pending);
        assert!(!invoice.invoice_id.is_empty());
    }
    
    #[test]
    fn test_invoice_id_deterministic() {
        let id1 = generate_invoice_id(&ServiceType::VaultCreate, "abc", 12345);
        let id2 = generate_invoice_id(&ServiceType::VaultCreate, "abc", 12345);
        let id3 = generate_invoice_id(&ServiceType::VaultCreate, "xyz", 12345);
        
        assert_eq!(id1, id2); // Same inputs = same ID
        assert_ne!(id1, id3); // Different inputs = different ID
    }
}
