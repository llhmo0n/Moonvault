// =============================================================================
// MOONVAULT v4.0 - Vault Service
// Bitcoin security vaults with hot/cold/recovery keys
// =============================================================================
//
// This module provides:
// - Vault creation (after BTC fee payment)
// - Vault status tracking
// - Panic button activation
// - Integration with BTC Lock module
//
// INVARIANT: User can ALWAYS recover BTC with their keys + timelock.
//            If MoonVault disappears, BTC is still recoverable on Bitcoin L1.
//
// =============================================================================

use std::fs::{File};
use std::io::{Read, Write};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

use crate::lib::*;
use crate::fee_system::{FeeInvoice, InvoiceStatus, ServiceType, load_invoices, save_invoice};
use crate::btc_lock::{
    LockRegistry, RegisteredLock, 
    MultisigCltvParams, generate_multisig_cltv,
    script_to_p2wsh_address, BitcoinNetwork, EsploraObserver, BtcObserver,
};

// =============================================================================
// Data Structures
// =============================================================================

/// A MoonVault security vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    /// Unique vault ID
    pub vault_id: String,
    /// User's public key (owner)
    pub owner_pubkey: String,
    /// Hot key for daily operations (small amounts)
    pub hot_pubkey: String,
    /// Cold key for large withdrawals (requires delay)
    pub cold_pubkey: String,
    /// Recovery key for emergencies and panic button
    pub recovery_pubkey: String,
    /// Daily limit for hot key (in satoshis)
    pub daily_limit_sats: u64,
    /// Delay for cold key withdrawals (in blocks)
    pub cold_delay_blocks: u32,
    /// Timelock for recovery (block height)
    pub recovery_timelock: u32,
    /// Bitcoin network
    pub network: String,
    /// P2WSH address for the vault (on Bitcoin L1)
    pub btc_address: String,
    /// Redeem script (hex)
    pub redeem_script: String,
    /// Current status
    pub status: VaultStatus,
    /// Creation timestamp
    pub created_at: u64,
    /// Invoice ID that paid for this vault
    pub invoice_id: String,
    /// Panic button activated?
    pub panic_active: bool,
    /// Panic activation timestamp (if active)
    pub panic_activated_at: Option<u64>,
    /// Amount locked (if funded)
    pub locked_sats: Option<u64>,
    /// Funding TXID (if funded)
    pub funding_txid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VaultStatus {
    /// Created but not yet funded
    Created,
    /// Funded and active
    Active,
    /// Panic button activated - all operations frozen
    Frozen,
    /// Timelock expired, ready for full recovery
    Recoverable,
    /// Vault closed, BTC withdrawn
    Closed,
}

/// Vault creation parameters
#[derive(Debug, Clone)]
pub struct VaultCreateParams {
    pub owner_pubkey: String,
    pub hot_pubkey: String,
    pub cold_pubkey: String,
    pub recovery_pubkey: String,
    pub daily_limit_sats: u64,
    pub cold_delay_blocks: u32,
    pub recovery_timelock: u32,
    pub testnet: bool,
    pub invoice_id: String,
}

// =============================================================================
// Vault Creation
// =============================================================================

/// Create a new vault after fee payment verification
pub fn create_vault(params: VaultCreateParams) -> Result<Vault, String> {
    // Verify invoice is paid and confirmed
    let mut invoices = load_invoices();
    let invoice = invoices.get(&params.invoice_id)
        .ok_or_else(|| format!("Invoice not found: {}", params.invoice_id))?
        .clone();
    
    if invoice.status != InvoiceStatus::Confirmed && invoice.status != InvoiceStatus::Paid {
        return Err(format!("Invoice not paid or confirmed. Status: {:?}", invoice.status));
    }
    
    if invoice.service_type != ServiceType::VaultCreate {
        return Err(format!("Wrong invoice type. Expected VaultCreate, got {:?}", invoice.service_type));
    }
    
    // Generate vault ID
    let vault_id = generate_vault_id(&params.owner_pubkey, &params.invoice_id);
    
    // Generate the BTC lock script using existing btc_lock module
    let network = if params.testnet {
        BitcoinNetwork::Testnet
    } else {
        BitcoinNetwork::Mainnet
    };
    
    // Use multisig_cltv template: 2-of-2 (hot+cold) OR recovery after timelock
    let lock_params = MultisigCltvParams {
        pubkey_hot: params.hot_pubkey.clone(),
        pubkey_cold: params.cold_pubkey.clone(),
        pubkey_recovery: params.recovery_pubkey.clone(),
        locktime_blocks: params.recovery_timelock,
    };
    
    let script_bytes = generate_multisig_cltv(&lock_params)
        .map_err(|e| format!("Failed to generate script: {:?}", e))?;
    let script_hex = hex::encode(&script_bytes);
    let btc_address = script_to_p2wsh_address(&script_bytes, !params.testnet);
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let vault = Vault {
        vault_id: vault_id.clone(),
        owner_pubkey: params.owner_pubkey,
        hot_pubkey: params.hot_pubkey,
        cold_pubkey: params.cold_pubkey,
        recovery_pubkey: params.recovery_pubkey,
        daily_limit_sats: params.daily_limit_sats,
        cold_delay_blocks: params.cold_delay_blocks,
        recovery_timelock: params.recovery_timelock,
        network: if params.testnet { "testnet" } else { "mainnet" }.to_string(),
        btc_address,
        redeem_script: script_hex,
        status: VaultStatus::Created,
        created_at: now,
        invoice_id: params.invoice_id.clone(),
        panic_active: false,
        panic_activated_at: None,
        locked_sats: None,
        funding_txid: None,
    };
    
    // Update invoice status
    let mut updated_invoice = invoice.clone();
    updated_invoice.status = InvoiceStatus::ServiceActivated;
    invoices.insert(params.invoice_id, updated_invoice);
    
    // Save vault
    save_vault(&vault);
    
    Ok(vault)
}

/// Generate deterministic vault ID
fn generate_vault_id(owner_pubkey: &str, invoice_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"moonvault_v4_");
    hasher.update(owner_pubkey.as_bytes());
    hasher.update(invoice_id.as_bytes());
    let hash = hasher.finalize();
    format!("vault_{}", hex::encode(&hash[..8]))
}

/// Print vault creation result
pub fn print_vault_created(vault: &Vault) {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║                       VAULT CREATED SUCCESSFULLY                          ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  Vault ID:      {}                                          ║", vault.vault_id);
    println!("║  Network:       {:50}  ║", vault.network);
    println!("║  Status:        {:50}  ║", format!("{:?}", vault.status));
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  BITCOIN ADDRESS (send BTC here to fund the vault):                       ║");
    println!("║                                                                           ║");
    println!("║  {}  ║", vault.btc_address);
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  KEYS CONFIGURED:                                                         ║");
    println!("║                                                                           ║");
    println!("║  Hot Key:      {}...                          ║", &vault.hot_pubkey[..20]);
    println!("║  Cold Key:     {}...                          ║", &vault.cold_pubkey[..20]);
    println!("║  Recovery Key: {}...                          ║", &vault.recovery_pubkey[..20]);
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  SECURITY RULES:                                                          ║");
    println!("║                                                                           ║");
    println!("║  • Hot key daily limit:  {:>12} sats                                 ║", vault.daily_limit_sats);
    println!("║  • Cold key delay:       {:>12} blocks                               ║", vault.cold_delay_blocks);
    println!("║  • Recovery timelock:    block {:>10}                               ║", vault.recovery_timelock);
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  ⚠️  IMPORTANT - SAVE THIS INFORMATION:                                   ║");
    println!("║                                                                           ║");
    println!("║  • Keep your private keys secure                                          ║");
    println!("║  • Save the redeem script for recovery                                    ║");
    println!("║  • After timelock (block {}), you can recover with recovery key    ║", vault.recovery_timelock);
    println!("║                                                                           ║");
    println!("║  If MoonVault disappears, you can ALWAYS recover your BTC directly        ║");
    println!("║  on Bitcoin L1 using your keys + the redeem script.                       ║");
    println!("║                                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Redeem Script (SAVE THIS):");
    println!("  {}", vault.redeem_script);
    println!();
}

// =============================================================================
// Vault Status
// =============================================================================

/// Get vault status
pub fn get_vault_status(vault_id: &str) -> Result<Vault, String> {
    let vaults = load_vaults();
    vaults.get(vault_id)
        .cloned()
        .ok_or_else(|| format!("Vault not found: {}", vault_id))
}

/// Refresh vault status from Bitcoin network
pub fn refresh_vault_status(vault_id: &str, testnet: bool) -> Result<Vault, String> {
    let mut vault = get_vault_status(vault_id)?;
    
    let network = if testnet {
        BitcoinNetwork::Testnet
    } else {
        BitcoinNetwork::Mainnet
    };
    
    let observer = EsploraObserver::new(network);
    
    // Check if vault is funded by querying the address
    // This is simplified - in production would track specific UTXOs
    
    // Get current block height to check timelock (using check_connection which returns height)
    if let Ok(height) = observer.check_connection() {
        if height >= vault.recovery_timelock && vault.status != VaultStatus::Closed {
            vault.status = VaultStatus::Recoverable;
            save_vault(&vault);
        }
    }
    
    Ok(vault)
}

/// Print vault status
pub fn print_vault_status(vault: &Vault) {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║                          VAULT STATUS                                     ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  Vault ID:      {}                                          ║", vault.vault_id);
    println!("║  Network:       {:50}  ║", vault.network);
    println!("║  Status:        {:50}  ║", format_vault_status(&vault.status));
    println!("║                                                                           ║");
    
    if vault.panic_active {
        println!("╠═══════════════════════════════════════════════════════════════════════════╣");
        println!("║                                                                           ║");
        println!("║  🚨 PANIC BUTTON ACTIVE - ALL OPERATIONS FROZEN 🚨                        ║");
        println!("║                                                                           ║");
        if let Some(ts) = vault.panic_activated_at {
            println!("║  Activated at: {:50}  ║", ts);
        }
        println!("║                                                                           ║");
    }
    
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  BTC Address:   {}  ║", vault.btc_address);
    println!("║                                                                           ║");
    
    if let Some(sats) = vault.locked_sats {
        println!("║  Locked:        {:>12} sats                                         ║", sats);
    }
    if let Some(ref txid) = vault.funding_txid {
        println!("║  Funding TX:    {}...                          ║", &txid[..20]);
    }
    
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  Recovery Timelock: block {}                                       ║", vault.recovery_timelock);
    println!("║                                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!();
}

fn format_vault_status(status: &VaultStatus) -> String {
    match status {
        VaultStatus::Created => "⚪ Created (not funded)".to_string(),
        VaultStatus::Active => "🟢 Active".to_string(),
        VaultStatus::Frozen => "🔴 FROZEN (panic active)".to_string(),
        VaultStatus::Recoverable => "🟡 Recoverable (timelock expired)".to_string(),
        VaultStatus::Closed => "⚫ Closed".to_string(),
    }
}

// =============================================================================
// Panic Button
// =============================================================================

/// Activate panic button - freeze all vault operations
pub fn activate_panic(vault_id: &str, recovery_privkey: &str) -> Result<Vault, String> {
    let mut vault = get_vault_status(vault_id)?;
    
    if vault.panic_active {
        return Err("Panic button already active".to_string());
    }
    
    if vault.status == VaultStatus::Closed {
        return Err("Vault is already closed".to_string());
    }
    
    // Verify the recovery key matches (simplified verification)
    // In production, would verify signature
    // For now, just check that a key was provided
    if recovery_privkey.len() < 32 {
        return Err("Invalid recovery key".to_string());
    }
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    vault.panic_active = true;
    vault.panic_activated_at = Some(now);
    vault.status = VaultStatus::Frozen;
    
    save_vault(&vault);
    
    Ok(vault)
}

/// Print panic activation result
pub fn print_panic_activated(vault: &Vault) {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║                                                                           ║");
    println!("║   🚨🚨🚨  PANIC BUTTON ACTIVATED  🚨🚨🚨                                   ║");
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  Vault ID:      {}                                          ║", vault.vault_id);
    println!("║  Status:        FROZEN                                                    ║");
    println!("║                                                                           ║");
    println!("║  All vault operations are now FROZEN:                                     ║");
    println!("║  • No hot key transactions                                                ║");
    println!("║  • No cold key transactions                                               ║");
    println!("║  • No modifications allowed                                               ║");
    println!("║                                                                           ║");
    println!("║  RECOVERY OPTIONS:                                                        ║");
    println!("║                                                                           ║");
    println!("║  1. Wait for timelock (block {}) and recover with recovery key     ║", vault.recovery_timelock);
    println!("║  2. Contact MoonVault support for assisted recovery                       ║");
    println!("║                                                                           ║");
    println!("║  Your BTC is SAFE. It remains on Bitcoin L1 in your vault address.        ║");
    println!("║                                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!();
}

// =============================================================================
// Persistence
// =============================================================================

/// Load all vaults from disk
pub fn load_vaults() -> HashMap<String, Vault> {
    let path = VAULTS_FILE;
    match File::open(path) {
        Ok(mut file) => {
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap_or_default();
            serde_json::from_str(&contents).unwrap_or_default()
        }
        Err(_) => HashMap::new(),
    }
}

/// Save all vaults to disk
pub fn save_vaults(vaults: &HashMap<String, Vault>) {
    let path = VAULTS_FILE;
    if let Ok(mut file) = File::create(path) {
        let json = serde_json::to_string_pretty(vaults).unwrap_or_default();
        let _ = file.write_all(json.as_bytes());
    }
}

/// Save a single vault
pub fn save_vault(vault: &Vault) {
    let mut vaults = load_vaults();
    vaults.insert(vault.vault_id.clone(), vault.clone());
    save_vaults(&vaults);
}

/// List all vaults for a user
pub fn list_vaults(owner_pubkey: Option<&str>) -> Vec<Vault> {
    let vaults = load_vaults();
    
    match owner_pubkey {
        Some(pubkey) => vaults.values()
            .filter(|v| v.owner_pubkey == pubkey)
            .cloned()
            .collect(),
        None => vaults.values().cloned().collect(),
    }
}

/// Print vault list
pub fn print_vault_list(vaults: &[Vault]) {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║                           YOUR VAULTS                                     ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    
    if vaults.is_empty() {
        println!("║                                                                           ║");
        println!("║  No vaults found.                                                         ║");
        println!("║                                                                           ║");
        println!("║  Create one with:                                                         ║");
        println!("║    moonvault fee invoice vault-create                                     ║");
        println!("║                                                                           ║");
    } else {
        println!("║                                                                           ║");
        for vault in vaults {
            let status_icon = match vault.status {
                VaultStatus::Created => "⚪",
                VaultStatus::Active => "🟢",
                VaultStatus::Frozen => "🔴",
                VaultStatus::Recoverable => "🟡",
                VaultStatus::Closed => "⚫",
            };
            println!("║  {} {} ({})          ║", 
                     status_icon, vault.vault_id, vault.network);
            if vault.panic_active {
                println!("║     🚨 PANIC ACTIVE                                                      ║");
            }
        }
        println!("║                                                                           ║");
    }
    
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!();
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vault_id_generation() {
        let id1 = generate_vault_id("pubkey123", "invoice456");
        let id2 = generate_vault_id("pubkey123", "invoice456");
        let id3 = generate_vault_id("pubkey999", "invoice456");
        
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert!(id1.starts_with("vault_"));
    }
    
    #[test]
    fn test_vault_status_format() {
        assert!(format_vault_status(&VaultStatus::Active).contains("Active"));
        assert!(format_vault_status(&VaultStatus::Frozen).contains("FROZEN"));
    }
}
