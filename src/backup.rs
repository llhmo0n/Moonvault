// =============================================================================
// MOONCOIN v2.0 - Backup & Restore
// =============================================================================
//
// Sistema completo de backup:
// - Exportar wallet (seed, claves, direcciones)
// - Exportar etiquetas y configuración
// - Formato encriptado opcional
// - Restaurar desde backup
// - Verificar integridad de backups
//
// =============================================================================

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;
use chrono::{DateTime, Utc};

// =============================================================================
// Backup Data Structures
// =============================================================================

/// Backup completo del wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletBackup {
    /// Versión del formato de backup
    pub version: u32,
    /// Timestamp de creación
    pub created_at: String,
    /// Tipo de wallet
    pub wallet_type: WalletType,
    /// Datos del HD Wallet (si aplica)
    pub hd_wallet: Option<HdWalletBackup>,
    /// Datos del wallet legacy (si aplica)
    pub legacy_wallet: Option<LegacyWalletBackup>,
    /// Etiquetas de direcciones
    pub labels: Option<LabelsBackup>,
    /// Configuración
    pub config: Option<ConfigBackup>,
    /// Watch-only addresses
    pub watch_addresses: Option<Vec<WatchAddressBackup>>,
    /// Checksum para verificación
    pub checksum: String,
}

/// Tipo de wallet
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum WalletType {
    HdWallet,
    Legacy,
    WatchOnly,
    Mixed,
}

/// Backup de HD Wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HdWalletBackup {
    /// Mnemonic (24 palabras)
    pub mnemonic: String,
    /// Passphrase (puede estar vacío)
    pub passphrase: String,
    /// Índice de derivación actual
    pub derivation_index: u32,
    /// Direcciones generadas
    pub addresses: Vec<AddressBackup>,
}

/// Backup de wallet legacy
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyWalletBackup {
    /// Clave privada en WIF o hex
    pub private_key: String,
    /// Formato de la clave
    pub key_format: String,
    /// Dirección
    pub address: String,
}

/// Backup de una dirección
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressBackup {
    pub address: String,
    pub path: String,
    pub index: u32,
    pub address_type: String,
}

/// Backup de etiquetas
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LabelsBackup {
    pub labels: Vec<LabelEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LabelEntry {
    pub address: String,
    pub label: String,
    pub category: Option<String>,
    pub is_mine: bool,
}

/// Backup de configuración
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigBackup {
    pub network: String,
    pub pruning_enabled: bool,
    pub pruning_keep_blocks: u64,
}

/// Backup de dirección watch-only
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchAddressBackup {
    pub address: String,
    pub label: String,
}

// =============================================================================
// Backup Manager
// =============================================================================

/// Gestor de backups
pub struct BackupManager;

impl BackupManager {
    /// Crea un backup completo
    pub fn create_backup(include_labels: bool, include_config: bool) -> Result<WalletBackup, String> {
        let now: DateTime<Utc> = Utc::now();
        
        let mut backup = WalletBackup {
            version: 1,
            created_at: now.to_rfc3339(),
            wallet_type: WalletType::Legacy,
            hd_wallet: None,
            legacy_wallet: None,
            labels: None,
            config: None,
            watch_addresses: None,
            checksum: String::new(),
        };
        
        // Intentar cargar HD Wallet
        if let Ok(hd_backup) = Self::backup_hd_wallet() {
            backup.hd_wallet = Some(hd_backup);
            backup.wallet_type = WalletType::HdWallet;
        }
        
        // Intentar cargar wallet legacy
        if let Ok(legacy_backup) = Self::backup_legacy_wallet() {
            backup.legacy_wallet = Some(legacy_backup);
            if backup.hd_wallet.is_some() {
                backup.wallet_type = WalletType::Mixed;
            }
        }
        
        // Cargar etiquetas
        if include_labels {
            if let Ok(labels) = Self::backup_labels() {
                backup.labels = Some(labels);
            }
        }
        
        // Cargar configuración
        if include_config {
            backup.config = Some(Self::backup_config());
        }
        
        // Cargar watch addresses
        if let Ok(watch) = Self::backup_watch_addresses() {
            if !watch.is_empty() {
                backup.watch_addresses = Some(watch);
            }
        }
        
        // Calcular checksum
        backup.checksum = Self::calculate_checksum(&backup);
        
        Ok(backup)
    }
    
    /// Backup del HD Wallet
    fn backup_hd_wallet() -> Result<HdWalletBackup, String> {
        let hd_file = "hd_wallet.json";
        
        if !Path::new(hd_file).exists() {
            return Err("HD Wallet not found".to_string());
        }
        
        let data = fs::read_to_string(hd_file)
            .map_err(|e| format!("Read error: {}", e))?;
        
        // Parsear el archivo existente
        let hd: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| format!("Parse error: {}", e))?;
        
        Ok(HdWalletBackup {
            mnemonic: hd["mnemonic"].as_str().unwrap_or("").to_string(),
            passphrase: hd["passphrase"].as_str().unwrap_or("").to_string(),
            derivation_index: hd["next_index"].as_u64().unwrap_or(0) as u32,
            addresses: Vec::new(), // Se pueden agregar después
        })
    }
    
    /// Backup del wallet legacy
    fn backup_legacy_wallet() -> Result<LegacyWalletBackup, String> {
        let wallet_file = "wallet.key";
        
        if !Path::new(wallet_file).exists() {
            return Err("Legacy wallet not found".to_string());
        }
        
        let key_hex = fs::read_to_string(wallet_file)
            .map_err(|e| format!("Read error: {}", e))?
            .trim()
            .to_string();
        
        // Obtener dirección (simplificado)
        let address = "Unknown".to_string();
        
        Ok(LegacyWalletBackup {
            private_key: key_hex,
            key_format: "hex".to_string(),
            address,
        })
    }
    
    /// Backup de etiquetas
    fn backup_labels() -> Result<LabelsBackup, String> {
        let labels_file = "address_labels.json";
        
        if !Path::new(labels_file).exists() {
            return Ok(LabelsBackup { labels: Vec::new() });
        }
        
        let data = fs::read_to_string(labels_file)
            .map_err(|e| format!("Read error: {}", e))?;
        
        let manager: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| format!("Parse error: {}", e))?;
        
        let mut labels = Vec::new();
        
        if let Some(label_map) = manager["labels"].as_object() {
            for (addr, val) in label_map {
                labels.push(LabelEntry {
                    address: addr.clone(),
                    label: val["label"].as_str().unwrap_or("").to_string(),
                    category: val["category"].as_str().map(|s| s.to_string()),
                    is_mine: val["is_mine"].as_bool().unwrap_or(false),
                });
            }
        }
        
        Ok(LabelsBackup { labels })
    }
    
    /// Backup de configuración
    fn backup_config() -> ConfigBackup {
        // Valores por defecto si no existe configuración
        ConfigBackup {
            network: "mainnet".to_string(),
            pruning_enabled: false,
            pruning_keep_blocks: 1000,
        }
    }
    
    /// Backup de watch addresses
    fn backup_watch_addresses() -> Result<Vec<WatchAddressBackup>, String> {
        let watch_file = "watch_wallet.json";
        
        if !Path::new(watch_file).exists() {
            return Ok(Vec::new());
        }
        
        let data = fs::read_to_string(watch_file)
            .map_err(|e| format!("Read error: {}", e))?;
        
        let wallet: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| format!("Parse error: {}", e))?;
        
        let mut addresses = Vec::new();
        
        if let Some(entries) = wallet["entries"].as_object() {
            for (addr, val) in entries {
                addresses.push(WatchAddressBackup {
                    address: addr.clone(),
                    label: val["label"].as_str().unwrap_or("").to_string(),
                });
            }
        }
        
        Ok(addresses)
    }
    
    /// Calcula checksum del backup
    fn calculate_checksum(backup: &WalletBackup) -> String {
        let mut hasher = Sha256::new();
        
        hasher.update(backup.version.to_le_bytes());
        hasher.update(backup.created_at.as_bytes());
        
        if let Some(ref hd) = backup.hd_wallet {
            hasher.update(hd.mnemonic.as_bytes());
        }
        
        if let Some(ref legacy) = backup.legacy_wallet {
            hasher.update(legacy.private_key.as_bytes());
        }
        
        let result = hasher.finalize();
        hex::encode(&result[..8]) // Solo primeros 8 bytes
    }
    
    /// Verifica checksum de un backup
    pub fn verify_checksum(backup: &WalletBackup) -> bool {
        let mut backup_copy = backup.clone();
        backup_copy.checksum = String::new();
        let calculated = Self::calculate_checksum(&backup_copy);
        calculated == backup.checksum
    }
    
    /// Guarda backup a archivo
    pub fn save_backup(backup: &WalletBackup, filename: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(backup)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        fs::write(filename, json)
            .map_err(|e| format!("Write error: {}", e))
    }
    
    /// Carga backup desde archivo
    pub fn load_backup(filename: &str) -> Result<WalletBackup, String> {
        let data = fs::read_to_string(filename)
            .map_err(|e| format!("Read error: {}", e))?;
        
        let backup: WalletBackup = serde_json::from_str(&data)
            .map_err(|e| format!("Parse error: {}", e))?;
        
        // Verificar checksum
        if !Self::verify_checksum(&backup) {
            return Err("Checksum verification failed - backup may be corrupted".to_string());
        }
        
        Ok(backup)
    }
    
    /// Restaura HD Wallet desde backup
    pub fn restore_hd_wallet(backup: &HdWalletBackup) -> Result<(), String> {
        use crate::hdwallet::HdWallet;
        
        let wallet = HdWallet::from_phrase(&backup.mnemonic)?;
        wallet.save()?;
        
        Ok(())
    }
    
    /// Restaura wallet legacy desde backup
    pub fn restore_legacy_wallet(backup: &LegacyWalletBackup) -> Result<(), String> {
        fs::write("wallet.key", &backup.private_key)
            .map_err(|e| format!("Write error: {}", e))
    }
    
    /// Restaura etiquetas desde backup
    pub fn restore_labels(backup: &LabelsBackup) -> Result<(), String> {
        use crate::labels::LabelManager;
        
        let mut manager = LabelManager::new();
        
        for entry in &backup.labels {
            manager.set_label(&entry.address, &entry.label, entry.is_mine);
            if let Some(ref cat) = entry.category {
                let _ = manager.set_category(&entry.address, cat);
            }
        }
        
        manager.save()
    }
    
    /// Restaura watch addresses desde backup
    pub fn restore_watch_addresses(addresses: &[WatchAddressBackup]) -> Result<(), String> {
        use crate::watch_wallet::WatchWallet;
        
        let mut wallet = WatchWallet::new();
        
        for addr in addresses {
            let _ = wallet.add_address(&addr.address, &addr.label);
        }
        
        wallet.save()
    }
    
    /// Restauración completa desde backup
    pub fn restore_full(backup: &WalletBackup) -> Result<RestoreResult, String> {
        let mut result = RestoreResult::default();
        
        // Restaurar HD Wallet
        if let Some(ref hd) = backup.hd_wallet {
            match Self::restore_hd_wallet(hd) {
                Ok(()) => result.hd_wallet = true,
                Err(e) => result.errors.push(format!("HD Wallet: {}", e)),
            }
        }
        
        // Restaurar Legacy Wallet
        if let Some(ref legacy) = backup.legacy_wallet {
            match Self::restore_legacy_wallet(legacy) {
                Ok(()) => result.legacy_wallet = true,
                Err(e) => result.errors.push(format!("Legacy Wallet: {}", e)),
            }
        }
        
        // Restaurar Labels
        if let Some(ref labels) = backup.labels {
            match Self::restore_labels(labels) {
                Ok(()) => result.labels = labels.labels.len(),
                Err(e) => result.errors.push(format!("Labels: {}", e)),
            }
        }
        
        // Restaurar Watch Addresses
        if let Some(ref watch) = backup.watch_addresses {
            match Self::restore_watch_addresses(watch) {
                Ok(()) => result.watch_addresses = watch.len(),
                Err(e) => result.errors.push(format!("Watch Addresses: {}", e)),
            }
        }
        
        Ok(result)
    }
    
    /// Genera nombre de archivo para backup
    pub fn generate_filename() -> String {
        let now: DateTime<Utc> = Utc::now();
        format!("mooncoin_backup_{}.json", now.format("%Y%m%d_%H%M%S"))
    }
}

/// Resultado de restauración
#[derive(Clone, Debug, Default)]
pub struct RestoreResult {
    pub hd_wallet: bool,
    pub legacy_wallet: bool,
    pub labels: usize,
    pub watch_addresses: usize,
    pub errors: Vec<String>,
}

impl RestoreResult {
    pub fn success(&self) -> bool {
        self.errors.is_empty() && (self.hd_wallet || self.legacy_wallet)
    }
}

// =============================================================================
// Backup Info Display
// =============================================================================

/// Muestra información de un backup
pub fn display_backup_info(backup: &WalletBackup) {
    println!("  Backup Information:");
    println!("  ────────────────────");
    println!("  Version:     {}", backup.version);
    println!("  Created:     {}", backup.created_at);
    println!("  Type:        {:?}", backup.wallet_type);
    println!("  Checksum:    {}", backup.checksum);
    println!();
    
    if backup.hd_wallet.is_some() {
        println!("  ✅ HD Wallet (seed phrase)");
    }
    
    if backup.legacy_wallet.is_some() {
        println!("  ✅ Legacy Wallet (private key)");
    }
    
    if let Some(ref labels) = backup.labels {
        println!("  ✅ Labels ({} addresses)", labels.labels.len());
    }
    
    if let Some(ref watch) = backup.watch_addresses {
        println!("  ✅ Watch Addresses ({})", watch.len());
    }
    
    if backup.config.is_some() {
        println!("  ✅ Configuration");
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_checksum() {
        let backup = WalletBackup {
            version: 1,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            wallet_type: WalletType::Legacy,
            hd_wallet: None,
            legacy_wallet: Some(LegacyWalletBackup {
                private_key: "test123".to_string(),
                key_format: "hex".to_string(),
                address: "MCtest".to_string(),
            }),
            labels: None,
            config: None,
            watch_addresses: None,
            checksum: String::new(),
        };
        
        let checksum = BackupManager::calculate_checksum(&backup);
        assert!(!checksum.is_empty());
        assert_eq!(checksum.len(), 16); // 8 bytes = 16 hex chars
    }
    
    #[test]
    fn test_wallet_type() {
        assert_eq!(WalletType::HdWallet, WalletType::HdWallet);
        assert_ne!(WalletType::HdWallet, WalletType::Legacy);
    }
}
