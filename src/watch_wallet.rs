// =============================================================================
// MOONCOIN v2.0 - Watch-Only Wallet
// =============================================================================
//
// Wallet de solo lectura para:
// - Monitorear direcciones sin clave privada
// - Cold storage (firmar offline)
// - Auditoría de fondos
// - Notificaciones de transacciones
//
// =============================================================================

use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::block::Block;
use crate::transaction::{Tx, tx_hash};

// =============================================================================
// Constants
// =============================================================================

const WATCH_WALLET_FILE: &str = "watch_wallet.json";

// =============================================================================
// Watch Entry
// =============================================================================

/// Entrada de una dirección monitoreada
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchEntry {
    /// Dirección
    pub address: String,
    /// Etiqueta/nombre
    pub label: String,
    /// Balance actual (satoshis)
    pub balance: u64,
    /// Total recibido
    pub total_received: u64,
    /// Total enviado
    pub total_sent: u64,
    /// Número de transacciones
    pub tx_count: usize,
    /// Fecha de adición
    pub added_at: u64,
    /// Última actividad
    pub last_activity: Option<u64>,
    /// Notificaciones habilitadas
    pub notifications: bool,
}

impl WatchEntry {
    pub fn new(address: String, label: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        WatchEntry {
            address,
            label,
            balance: 0,
            total_received: 0,
            total_sent: 0,
            tx_count: 0,
            added_at: now,
            last_activity: None,
            notifications: true,
        }
    }
}

// =============================================================================
// Transaction Record
// =============================================================================

/// Registro de transacción
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxRecord {
    pub txid: String,
    pub block_height: Option<u64>,
    pub timestamp: u64,
    pub amount: i64, // Positivo = recibido, negativo = enviado
    pub fee: Option<u64>,
    pub confirmations: u64,
    pub addresses_involved: Vec<String>,
}

// =============================================================================
// Watch Wallet
// =============================================================================

/// Wallet de solo lectura
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchWallet {
    /// Direcciones monitoreadas
    pub entries: HashMap<String, WatchEntry>,
    /// Historial de transacciones
    pub transactions: Vec<TxRecord>,
    /// Altura del último escaneo
    pub last_scan_height: u64,
    /// Alertas pendientes
    pub pending_alerts: Vec<WatchAlert>,
}

/// Alerta de actividad
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchAlert {
    pub address: String,
    pub txid: String,
    pub amount: i64,
    pub timestamp: u64,
    pub seen: bool,
}

impl Default for WatchWallet {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchWallet {
    /// Crea un nuevo watch wallet
    pub fn new() -> Self {
        WatchWallet {
            entries: HashMap::new(),
            transactions: Vec::new(),
            last_scan_height: 0,
            pending_alerts: Vec::new(),
        }
    }
    
    /// Añade una dirección para monitorear
    pub fn add_address(&mut self, address: &str, label: &str) -> Result<(), String> {
        if self.entries.contains_key(address) {
            return Err("Address already being watched".to_string());
        }
        
        // Validar formato de dirección
        if !is_valid_address(address) {
            return Err("Invalid address format".to_string());
        }
        
        let entry = WatchEntry::new(address.to_string(), label.to_string());
        self.entries.insert(address.to_string(), entry);
        
        Ok(())
    }
    
    /// Elimina una dirección del monitoreo
    pub fn remove_address(&mut self, address: &str) -> Result<(), String> {
        if self.entries.remove(address).is_none() {
            return Err("Address not found".to_string());
        }
        Ok(())
    }
    
    /// Actualiza la etiqueta de una dirección
    pub fn update_label(&mut self, address: &str, label: &str) -> Result<(), String> {
        if let Some(entry) = self.entries.get_mut(address) {
            entry.label = label.to_string();
            Ok(())
        } else {
            Err("Address not found".to_string())
        }
    }
    
    /// Habilita/deshabilita notificaciones para una dirección
    pub fn set_notifications(&mut self, address: &str, enabled: bool) -> Result<(), String> {
        if let Some(entry) = self.entries.get_mut(address) {
            entry.notifications = enabled;
            Ok(())
        } else {
            Err("Address not found".to_string())
        }
    }
    
    /// Escanea la blockchain para actualizar balances
    pub fn scan_blockchain(&mut self, chain: &[Block]) {
        if chain.is_empty() {
            return;
        }
        
        // Obtener direcciones monitoreadas
        let watched: HashSet<String> = self.entries.keys().cloned().collect();
        
        if watched.is_empty() {
            return;
        }
        
        // Escanear desde el último bloque conocido
        let start_height = self.last_scan_height;
        
        for block in chain.iter().skip(start_height as usize) {
            self.process_block(block, &watched);
        }
        
        self.last_scan_height = chain.len() as u64;
    }
    
    /// Procesa un bloque
    fn process_block(&mut self, block: &Block, watched: &HashSet<String>) {
        for tx in &block.txs {
            self.process_transaction(tx, block.height, block.timestamp, watched);
        }
    }
    
    /// Procesa una transacción
    fn process_transaction(
        &mut self,
        tx: &Tx,
        block_height: u64,
        timestamp: u64,
        watched: &HashSet<String>,
    ) {
        let txid = tx_hash(tx);
        let mut involved_addresses = Vec::new();
        let mut our_amount: i64 = 0;
        
        // Verificar outputs (recibidos)
        for output in &tx.outputs {
            if watched.contains(&output.to) {
                involved_addresses.push(output.to.clone());
                our_amount += output.amount as i64;
                
                // Actualizar entrada
                if let Some(entry) = self.entries.get_mut(&output.to) {
                    entry.balance += output.amount;
                    entry.total_received += output.amount;
                    entry.tx_count += 1;
                    entry.last_activity = Some(timestamp);
                    
                    // Crear alerta si notificaciones habilitadas
                    if entry.notifications {
                        self.pending_alerts.push(WatchAlert {
                            address: output.to.clone(),
                            txid: txid.clone(),
                            amount: output.amount as i64,
                            timestamp,
                            seen: false,
                        });
                    }
                }
            }
        }
        
        // Guardar transacción si involucra direcciones monitoreadas
        if !involved_addresses.is_empty() {
            self.transactions.push(TxRecord {
                txid,
                block_height: Some(block_height),
                timestamp,
                amount: our_amount,
                fee: None,
                confirmations: 0,
                addresses_involved: involved_addresses,
            });
        }
    }
    
    /// Actualiza confirmaciones
    pub fn update_confirmations(&mut self, current_height: u64) {
        for tx in &mut self.transactions {
            if let Some(block_height) = tx.block_height {
                tx.confirmations = current_height.saturating_sub(block_height) + 1;
            }
        }
    }
    
    /// Obtiene balance total
    pub fn total_balance(&self) -> u64 {
        self.entries.values().map(|e| e.balance).sum()
    }
    
    /// Obtiene transacciones de una dirección
    pub fn get_address_transactions(&self, address: &str) -> Vec<&TxRecord> {
        self.transactions.iter()
            .filter(|tx| tx.addresses_involved.contains(&address.to_string()))
            .collect()
    }
    
    /// Obtiene alertas no vistas
    pub fn get_unseen_alerts(&self) -> Vec<&WatchAlert> {
        self.pending_alerts.iter()
            .filter(|a| !a.seen)
            .collect()
    }
    
    /// Marca alertas como vistas
    pub fn mark_alerts_seen(&mut self) {
        for alert in &mut self.pending_alerts {
            alert.seen = true;
        }
    }
    
    /// Limpia alertas antiguas
    pub fn clear_old_alerts(&mut self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.pending_alerts.retain(|a| now - a.timestamp < max_age_secs);
    }
    
    /// Guarda el wallet a disco
    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        fs::write(WATCH_WALLET_FILE, json)
            .map_err(|e| format!("Failed to write file: {}", e))?;
        
        Ok(())
    }
    
    /// Carga el wallet desde disco
    pub fn load() -> Result<Self, String> {
        if !Path::new(WATCH_WALLET_FILE).exists() {
            return Ok(WatchWallet::new());
        }
        
        let json = fs::read_to_string(WATCH_WALLET_FILE)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        serde_json::from_str(&json)
            .map_err(|e| format!("Parse error: {}", e))
    }
    
    /// Exporta a CSV
    pub fn export_csv(&self) -> String {
        let mut csv = String::from("Address,Label,Balance,Received,Sent,TxCount\n");
        
        for entry in self.entries.values() {
            csv.push_str(&format!(
                "{},{},{},{},{},{}\n",
                entry.address,
                entry.label,
                entry.balance,
                entry.total_received,
                entry.total_sent,
                entry.tx_count
            ));
        }
        
        csv
    }
    
    /// Estadísticas del wallet
    pub fn stats(&self) -> WatchWalletStats {
        WatchWalletStats {
            addresses_count: self.entries.len(),
            total_balance: self.total_balance(),
            total_transactions: self.transactions.len(),
            unseen_alerts: self.pending_alerts.iter().filter(|a| !a.seen).count(),
            last_scan_height: self.last_scan_height,
        }
    }
}

/// Estadísticas del watch wallet
#[derive(Clone, Debug)]
pub struct WatchWalletStats {
    pub addresses_count: usize,
    pub total_balance: u64,
    pub total_transactions: usize,
    pub unseen_alerts: usize,
    pub last_scan_height: u64,
}

// =============================================================================
// Helpers
// =============================================================================

/// Valida el formato de una dirección
fn is_valid_address(address: &str) -> bool {
    // Direcciones legacy (M...)
    if address.starts_with('M') && address.len() >= 26 && address.len() <= 35 {
        return true;
    }
    
    // Direcciones SegWit (mc1...)
    if address.starts_with("mc1") && address.len() >= 42 && address.len() <= 62 {
        return true;
    }
    
    // P2SH (3...)
    if address.starts_with('3') && address.len() >= 26 && address.len() <= 35 {
        return true;
    }
    
    false
}

// =============================================================================
// PSBT - Partially Signed Bitcoin Transaction (para cold storage)
// =============================================================================

/// Transacción parcialmente firmada (para firmar offline)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnsignedTx {
    /// Transacción sin firmar
    pub tx: Tx,
    /// Información de inputs para firmar
    pub input_info: Vec<InputInfo>,
    /// Estado
    pub status: UnsignedTxStatus,
    /// Creado en
    pub created_at: u64,
}

/// Información de un input
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputInfo {
    pub prev_txid: String,
    pub prev_index: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub address: String,
}

/// Estado de la TX
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum UnsignedTxStatus {
    Created,
    ReadyToSign,
    PartiallySigned,
    FullySigned,
    Broadcast,
}

impl UnsignedTx {
    /// Crea una nueva TX sin firmar
    pub fn new(tx: Tx, input_info: Vec<InputInfo>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        UnsignedTx {
            tx,
            input_info,
            status: UnsignedTxStatus::Created,
            created_at: now,
        }
    }
    
    /// Exporta a formato hexadecimal para firmar offline
    pub fn export_hex(&self) -> String {
        let bytes = bincode::serialize(self).unwrap_or_default();
        hex::encode(bytes)
    }
    
    /// Importa desde formato hexadecimal
    pub fn import_hex(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| format!("Invalid hex: {}", e))?;
        
        bincode::deserialize(&bytes)
            .map_err(|e| format!("Invalid format: {}", e))
    }
    
    /// Calcula el total de inputs
    pub fn total_input(&self) -> u64 {
        self.input_info.iter().map(|i| i.amount).sum()
    }
    
    /// Calcula el total de outputs
    pub fn total_output(&self) -> u64 {
        self.tx.outputs.iter().map(|o| o.amount).sum()
    }
    
    /// Calcula el fee
    pub fn fee(&self) -> u64 {
        self.total_input().saturating_sub(self.total_output())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_watch_wallet() {
        let mut wallet = WatchWallet::new();
        
        // Añadir dirección
        wallet.add_address("MCtest123456789012345678901234", "Test").unwrap();
        assert_eq!(wallet.entries.len(), 1);
        
        // Intentar añadir duplicado
        assert!(wallet.add_address("MCtest123456789012345678901234", "Test2").is_err());
        
        // Eliminar
        wallet.remove_address("MCtest123456789012345678901234").unwrap();
        assert_eq!(wallet.entries.len(), 0);
    }
    
    #[test]
    fn test_address_validation() {
        assert!(is_valid_address("MCtest12345678901234567890123456"));
        assert!(is_valid_address("mc1qtest12345678901234567890123456789012345"));
        assert!(!is_valid_address("invalid"));
        assert!(!is_valid_address(""));
    }
    
    #[test]
    fn test_stats() {
        let wallet = WatchWallet::new();
        let stats = wallet.stats();
        
        assert_eq!(stats.addresses_count, 0);
        assert_eq!(stats.total_balance, 0);
    }
}
