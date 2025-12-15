// =============================================================================
// MOONCOIN v2.0 - Blockchain Pruning
// =============================================================================
//
// Reducción del tamaño de la blockchain:
// - Eliminar datos de bloques antiguos
// - Mantener solo headers + UTXO set
// - Preservar capacidad de validar nuevos bloques
// - Configuración de profundidad de pruning
//
// =============================================================================

use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

use crate::block::Block;
use crate::transaction::Tx;

// =============================================================================
// Constants
// =============================================================================

/// Archivo de configuración de pruning
const PRUNING_CONFIG_FILE: &str = "pruning.json";

/// Mínimo de bloques a mantener (seguridad contra reorgs)
const MIN_BLOCKS_TO_KEEP: u64 = 288; // ~1 día de bloques

/// Profundidad por defecto de pruning
const DEFAULT_PRUNE_DEPTH: u64 = 1000;

// =============================================================================
// Pruning Mode
// =============================================================================

/// Modo de pruning
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PruneMode {
    /// Sin pruning - mantener todo
    None,
    /// Mantener últimos N bloques completos
    KeepRecent(u64),
    /// Mantener solo headers (más agresivo)
    HeadersOnly,
    /// Modo personalizado
    Custom {
        keep_blocks: u64,
        keep_witnesses: bool,
    },
}

impl Default for PruneMode {
    fn default() -> Self {
        PruneMode::None
    }
}

impl PruneMode {
    /// Descripción del modo
    pub fn description(&self) -> String {
        match self {
            PruneMode::None => "Full node (no pruning)".to_string(),
            PruneMode::KeepRecent(n) => format!("Keep last {} blocks", n),
            PruneMode::HeadersOnly => "Headers only (minimal)".to_string(),
            PruneMode::Custom { keep_blocks, keep_witnesses } => {
                format!("Custom: {} blocks, witnesses: {}", keep_blocks, keep_witnesses)
            }
        }
    }
    
    /// Bloques a mantener
    pub fn blocks_to_keep(&self) -> u64 {
        match self {
            PruneMode::None => u64::MAX,
            PruneMode::KeepRecent(n) => *n,
            PruneMode::HeadersOnly => 0,
            PruneMode::Custom { keep_blocks, .. } => *keep_blocks,
        }
    }
}

// =============================================================================
// Pruned Block
// =============================================================================

/// Bloque podado (solo header)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrunedBlock {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub merkle_root: String,
    pub timestamp: u64,
    pub difficulty_bits: u32,
    pub nonce: u64,
    /// Número de transacciones (para referencia)
    pub tx_count: usize,
    /// Indica si los datos completos fueron podados
    pub pruned: bool,
}

impl PrunedBlock {
    /// Convierte un bloque completo a podado
    pub fn from_block(block: &Block) -> Self {
        PrunedBlock {
            height: block.height,
            hash: block.hash.clone(),
            prev_hash: block.prev_hash.clone(),
            merkle_root: block.merkle_root.clone(),
            timestamp: block.timestamp,
            difficulty_bits: block.difficulty_bits,
            nonce: block.nonce,
            tx_count: block.txs.len(),
            pruned: true,
        }
    }
    
    /// Tamaño estimado en bytes
    pub fn size_bytes(&self) -> usize {
        // Header básico ~80 bytes + overhead
        100
    }
}

// =============================================================================
// Pruning Config
// =============================================================================

/// Configuración de pruning
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningConfig {
    /// Modo de pruning
    pub mode: PruneMode,
    /// Última altura podada
    pub last_pruned_height: u64,
    /// Espacio ahorrado (bytes)
    pub space_saved: u64,
    /// Bloques podados
    pub blocks_pruned: u64,
    /// Auto-prune habilitado
    pub auto_prune: bool,
    /// Umbral de espacio (MB) para auto-prune
    pub space_threshold_mb: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        PruningConfig {
            mode: PruneMode::None,
            last_pruned_height: 0,
            space_saved: 0,
            blocks_pruned: 0,
            auto_prune: false,
            space_threshold_mb: 1000, // 1GB por defecto
        }
    }
}

impl PruningConfig {
    /// Carga la configuración
    pub fn load() -> Self {
        if !Path::new(PRUNING_CONFIG_FILE).exists() {
            return PruningConfig::default();
        }
        
        match fs::read_to_string(PRUNING_CONFIG_FILE) {
            Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
            Err(_) => PruningConfig::default(),
        }
    }
    
    /// Guarda la configuración
    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        fs::write(PRUNING_CONFIG_FILE, json)
            .map_err(|e| format!("Write error: {}", e))
    }
}

// =============================================================================
// Pruning Engine
// =============================================================================

/// Motor de pruning
pub struct PruningEngine {
    pub config: PruningConfig,
}

impl PruningEngine {
    /// Crea un nuevo motor de pruning
    pub fn new() -> Self {
        PruningEngine {
            config: PruningConfig::load(),
        }
    }
    
    /// Crea con configuración específica
    pub fn with_config(config: PruningConfig) -> Self {
        PruningEngine { config }
    }
    
    /// Establece el modo de pruning
    pub fn set_mode(&mut self, mode: PruneMode) {
        self.config.mode = mode;
        let _ = self.config.save();
    }
    
    /// Habilita/deshabilita auto-prune
    pub fn set_auto_prune(&mut self, enabled: bool) {
        self.config.auto_prune = enabled;
        let _ = self.config.save();
    }
    
    /// Verifica si un bloque debería ser podado
    /// 
    /// Un bloque se poda si:
    /// 1. El modo de pruning está activo (no es None)
    /// 2. El bloque está más allá del umbral de retención
    /// 
    /// Ejemplo: con KeepRecent(100) y current_height=200:
    /// - Bloques 0-99 serán podados (están antes del umbral 100)
    /// - Bloques 100-200 se mantienen
    pub fn should_prune(&self, block_height: u64, current_height: u64) -> bool {
        match self.config.mode {
            PruneMode::None => false,
            PruneMode::KeepRecent(keep) => {
                // Asegurarse de mantener al menos MIN_BLOCKS_TO_KEEP bloques recientes
                let effective_keep = keep.max(MIN_BLOCKS_TO_KEEP);
                let threshold = current_height.saturating_sub(effective_keep);
                block_height < threshold
            }
            PruneMode::HeadersOnly => {
                let threshold = current_height.saturating_sub(MIN_BLOCKS_TO_KEEP);
                block_height < threshold
            }
            PruneMode::Custom { keep_blocks, .. } => {
                let effective_keep = keep_blocks.max(MIN_BLOCKS_TO_KEEP);
                let threshold = current_height.saturating_sub(effective_keep);
                block_height < threshold
            }
        }
    }
    
    /// Poda una cadena de bloques
    pub fn prune_chain(&mut self, chain: &mut Vec<Block>, current_height: u64) -> PruneResult {
        let mut result = PruneResult::default();
        
        if self.config.mode == PruneMode::None {
            return result;
        }
        
        for block in chain.iter_mut() {
            if self.should_prune(block.height, current_height) {
                let original_size = estimate_block_size(block);
                
                // Podar transacciones (mantener solo coinbase para referencia)
                if block.txs.len() > 1 {
                    let coinbase = block.txs[0].clone();
                    block.txs = vec![coinbase];
                    
                    result.blocks_pruned += 1;
                    result.space_saved += original_size - estimate_block_size(block);
                }
            }
        }
        
        // Actualizar config
        self.config.blocks_pruned += result.blocks_pruned;
        self.config.space_saved += result.space_saved;
        self.config.last_pruned_height = current_height;
        let _ = self.config.save();
        
        result
    }
    
    /// Poda un bloque individual
    pub fn prune_block(&self, block: &Block) -> PrunedBlock {
        PrunedBlock::from_block(block)
    }
    
    /// Verifica si necesita auto-prune
    pub fn needs_auto_prune(&self, chain_size_mb: u64) -> bool {
        self.config.auto_prune && chain_size_mb > self.config.space_threshold_mb
    }
    
    /// Estadísticas de pruning
    pub fn stats(&self) -> PruningStats {
        PruningStats {
            mode: self.config.mode.description(),
            blocks_pruned: self.config.blocks_pruned,
            space_saved_mb: self.config.space_saved / (1024 * 1024),
            last_pruned_height: self.config.last_pruned_height,
            auto_prune: self.config.auto_prune,
        }
    }
}

impl Default for PruningEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Resultado de pruning
#[derive(Clone, Debug, Default)]
pub struct PruneResult {
    pub blocks_pruned: u64,
    pub space_saved: u64,
    pub errors: Vec<String>,
}

/// Estadísticas de pruning
#[derive(Clone, Debug)]
pub struct PruningStats {
    pub mode: String,
    pub blocks_pruned: u64,
    pub space_saved_mb: u64,
    pub last_pruned_height: u64,
    pub auto_prune: bool,
}

// =============================================================================
// UTXO Snapshot
// =============================================================================

/// Snapshot del UTXO set (para nodos podados)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoSnapshot {
    /// Altura del snapshot
    pub height: u64,
    /// Hash del bloque
    pub block_hash: String,
    /// UTXOs
    pub utxos: Vec<UtxoEntry>,
    /// Timestamp de creación
    pub created_at: u64,
    /// Hash del snapshot (para verificación)
    pub snapshot_hash: String,
}

/// Entrada UTXO para snapshot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub address: String,
    pub height: u64,
    pub coinbase: bool,
}

impl UtxoSnapshot {
    /// Crea un nuevo snapshot
    pub fn new(height: u64, block_hash: String, utxos: Vec<UtxoEntry>) -> Self {
        use sha2::{Sha256, Digest};
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Calcular hash del snapshot
        let mut hasher = Sha256::new();
        hasher.update(height.to_le_bytes());
        hasher.update(block_hash.as_bytes());
        hasher.update(utxos.len().to_le_bytes());
        let hash = hex::encode(hasher.finalize());
        
        UtxoSnapshot {
            height,
            block_hash,
            utxos,
            created_at: now,
            snapshot_hash: hash,
        }
    }
    
    /// Guarda el snapshot
    pub fn save(&self, path: &str) -> Result<(), String> {
        let data = bincode::serialize(self)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        fs::write(path, data)
            .map_err(|e| format!("Write error: {}", e))
    }
    
    /// Carga un snapshot
    pub fn load(path: &str) -> Result<Self, String> {
        let data = fs::read(path)
            .map_err(|e| format!("Read error: {}", e))?;
        
        bincode::deserialize(&data)
            .map_err(|e| format!("Parse error: {}", e))
    }
    
    /// Verifica la integridad del snapshot
    pub fn verify(&self) -> bool {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.block_hash.as_bytes());
        hasher.update(self.utxos.len().to_le_bytes());
        let expected = hex::encode(hasher.finalize());
        
        self.snapshot_hash == expected
    }
    
    /// Tamaño en bytes
    pub fn size_bytes(&self) -> usize {
        bincode::serialize(self).map(|d| d.len()).unwrap_or(0)
    }
    
    /// Número de UTXOs
    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }
    
    /// Balance total
    pub fn total_balance(&self) -> u64 {
        self.utxos.iter().map(|u| u.amount).sum()
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Estima el tamaño de un bloque en bytes
pub fn estimate_block_size(block: &Block) -> u64 {
    let mut size: u64 = 80; // Header
    
    for tx in &block.txs {
        size += estimate_tx_size(tx);
    }
    
    size
}

/// Estima el tamaño de una transacción
fn estimate_tx_size(tx: &Tx) -> u64 {
    let mut size: u64 = 10; // Overhead
    
    // Inputs (~148 bytes cada uno)
    size += tx.inputs.len() as u64 * 148;
    
    // Outputs (~34 bytes cada uno)
    size += tx.outputs.len() as u64 * 34;
    
    size
}

/// Calcula el tamaño total de la cadena
pub fn calculate_chain_size(chain: &[Block]) -> u64 {
    chain.iter().map(estimate_block_size).sum()
}

/// Formatea bytes a formato legible
pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} bytes", bytes)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_prune_mode() {
        assert_eq!(PruneMode::None.blocks_to_keep(), u64::MAX);
        assert_eq!(PruneMode::KeepRecent(1000).blocks_to_keep(), 1000);
        assert_eq!(PruneMode::HeadersOnly.blocks_to_keep(), 0);
    }
    
    #[test]
    fn test_should_prune() {
        // Test con KeepRecent(100) pero MIN_BLOCKS_TO_KEEP es 288
        // Entonces effective_keep = max(100, 288) = 288
        let engine = PruningEngine::with_config(PruningConfig {
            mode: PruneMode::KeepRecent(100),
            ..Default::default()
        });
        
        // Con current_height=500, threshold = 500 - 288 = 212
        // Bloque 50 < 212, debería podarse
        assert!(engine.should_prune(50, 500));
        
        // Bloque 300 >= 212, no debería podarse
        assert!(!engine.should_prune(300, 500));
        
        // Bloque 212 = 212, no debería podarse (está en el límite, se mantiene)
        assert!(!engine.should_prune(212, 500));
        
        // Test con keep mayor que MIN_BLOCKS_TO_KEEP
        let engine2 = PruningEngine::with_config(PruningConfig {
            mode: PruneMode::KeepRecent(500),
            ..Default::default()
        });
        
        // Con current_height=1000, threshold = 1000 - 500 = 500
        // Bloque 100 < 500, debería podarse
        assert!(engine2.should_prune(100, 1000));
        
        // Bloque 600 >= 500, no debería podarse
        assert!(!engine2.should_prune(600, 1000));
    }
    
    #[test]
    fn test_pruned_block() {
        use crate::transaction::TxOut;
        
        let block = Block {
            height: 100,
            hash: "abc123".to_string(),
            prev_hash: "def456".to_string(),
            merkle_root: "merkle".to_string(),
            timestamp: 12345,
            difficulty_bits: 0x1d00ffff,
            nonce: 999,
            txs: vec![Tx {
                inputs: vec![],
                outputs: vec![TxOut { to: "addr".to_string(), amount: 5000 }],
            }],
        };
        
        let pruned = PrunedBlock::from_block(&block);
        
        assert_eq!(pruned.height, 100);
        assert_eq!(pruned.hash, "abc123");
        assert_eq!(pruned.tx_count, 1);
        assert!(pruned.pruned);
    }
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 bytes");
        assert_eq!(format_bytes(2048), "2.00 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.00 GB");
    }
}
