// =============================================================================
// MOONCOIN v2.29 - Privacy Integration
// =============================================================================
//
// Integra el sistema de privacidad con el nodo principal:
// - Mempool para TX shielded
// - Validación en bloques
// - Broadcast P2P
// - Estado global de privacidad
//
// =============================================================================

use crate::privacy::shielded_tx::ShieldedTx;
use crate::privacy::validation::{
    ValidationContext, ShieldedValidator, 
    ValidationResult, quick_validate,
};
use crate::privacy::ring::KeyImage;



use std::collections::{HashMap, HashSet};

use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

// =============================================================================
// Constants
// =============================================================================

/// Máximo de TX shielded en mempool
pub const MAX_SHIELDED_MEMPOOL_SIZE: usize = 5000;

/// Tiempo máximo en mempool (24 horas)
pub const MAX_MEMPOOL_AGE_SECS: u64 = 86400;

/// Máximo de TX shielded por bloque
pub const MAX_SHIELDED_TXS_PER_BLOCK: usize = 100;

/// Peso de TX shielded (más pesadas que transparentes)
pub const SHIELDED_TX_WEIGHT_MULTIPLIER: u64 = 4;

// =============================================================================
// Shielded Mempool Entry
// =============================================================================

/// Entrada en el mempool shielded
#[derive(Clone, Debug)]
pub struct ShieldedMempoolEntry {
    /// La transacción
    pub tx: ShieldedTx,
    /// Hash de la TX
    pub tx_hash: [u8; 32],
    /// Timestamp de cuando entró al mempool
    pub added_time: u64,
    /// Fee
    pub fee: u64,
    /// Tamaño en bytes
    pub size: usize,
    /// Fee rate (fee / size)
    pub fee_rate: f64,
    /// Key images de esta TX
    pub key_images: Vec<KeyImage>,
}

impl ShieldedMempoolEntry {
    pub fn new(tx: ShieldedTx) -> Self {
        let tx_hash = tx.hash();
        let fee = tx.fee;
        let size = tx.size();
        let fee_rate = fee as f64 / size as f64;
        let key_images = tx.key_images();
        let added_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        ShieldedMempoolEntry {
            tx,
            tx_hash,
            added_time,
            fee,
            size,
            fee_rate,
            key_images,
        }
    }
}

// =============================================================================
// Shielded Mempool
// =============================================================================

/// Mempool para transacciones shielded
#[derive(Clone, Debug, Default)]
pub struct ShieldedMempool {
    /// TXs por hash
    txs: HashMap<[u8; 32], ShieldedMempoolEntry>,
    /// Key images en el mempool (para detectar conflictos)
    pending_key_images: HashSet<[u8; 32]>,
    /// Orden por fee rate (para selección de minería)
    by_fee_rate: Vec<[u8; 32]>,
}

impl ShieldedMempool {
    pub fn new() -> Self {
        ShieldedMempool {
            txs: HashMap::new(),
            pending_key_images: HashSet::new(),
            by_fee_rate: Vec::new(),
        }
    }
    
    /// Agrega una TX al mempool (ya validada)
    pub fn add(&mut self, tx: ShieldedTx) -> Result<[u8; 32], MempoolError> {
        // Verificar límite de tamaño
        if self.txs.len() >= MAX_SHIELDED_MEMPOOL_SIZE {
            return Err(MempoolError::MempoolFull);
        }
        
        let entry = ShieldedMempoolEntry::new(tx);
        let tx_hash = entry.tx_hash;
        
        // Verificar que no existe
        if self.txs.contains_key(&tx_hash) {
            return Err(MempoolError::AlreadyExists);
        }
        
        // Verificar key images no conflictan con otras TX en mempool
        for ki in &entry.key_images {
            if self.pending_key_images.contains(&ki.as_bytes()) {
                return Err(MempoolError::ConflictingKeyImage);
            }
        }
        
        // Agregar key images al set pendiente
        for ki in &entry.key_images {
            self.pending_key_images.insert(ki.as_bytes());
        }
        
        // Agregar al índice de fee rate
        self.by_fee_rate.push(tx_hash);
        self.by_fee_rate.sort_by(|a, b| {
            let fee_a = self.txs.get(a).map(|e| e.fee_rate).unwrap_or(0.0);
            let fee_b = self.txs.get(b).map(|e| e.fee_rate).unwrap_or(0.0);
            fee_b.partial_cmp(&fee_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Agregar TX
        self.txs.insert(tx_hash, entry);
        
        Ok(tx_hash)
    }
    
    /// Remueve una TX del mempool
    pub fn remove(&mut self, tx_hash: &[u8; 32]) -> Option<ShieldedMempoolEntry> {
        if let Some(entry) = self.txs.remove(tx_hash) {
            // Remover key images
            for ki in &entry.key_images {
                self.pending_key_images.remove(&ki.as_bytes());
            }
            // Remover del índice
            self.by_fee_rate.retain(|h| h != tx_hash);
            Some(entry)
        } else {
            None
        }
    }
    
    /// Obtiene una TX por hash
    pub fn get(&self, tx_hash: &[u8; 32]) -> Option<&ShieldedMempoolEntry> {
        self.txs.get(tx_hash)
    }
    
    /// Verifica si un key image está en el mempool
    pub fn has_key_image(&self, key_image: &KeyImage) -> bool {
        self.pending_key_images.contains(&key_image.as_bytes())
    }
    
    /// Selecciona TXs para un bloque (por fee rate)
    pub fn select_for_block(&self, max_count: usize, max_size: usize) -> Vec<ShieldedTx> {
        let mut selected = Vec::new();
        let mut total_size = 0;
        
        for tx_hash in &self.by_fee_rate {
            if selected.len() >= max_count {
                break;
            }
            
            if let Some(entry) = self.txs.get(tx_hash) {
                if total_size + entry.size <= max_size {
                    selected.push(entry.tx.clone());
                    total_size += entry.size;
                }
            }
        }
        
        selected
    }
    
    /// Remueve TXs confirmadas en un bloque
    pub fn remove_confirmed(&mut self, txs: &[ShieldedTx]) {
        for tx in txs {
            self.remove(&tx.hash());
        }
    }
    
    /// Remueve TXs que conflictan con key images confirmados
    pub fn remove_conflicting(&mut self, confirmed_key_images: &[KeyImage]) {
        let confirmed_set: HashSet<[u8; 32]> = confirmed_key_images
            .iter()
            .map(|ki| ki.as_bytes())
            .collect();
        
        let to_remove: Vec<[u8; 32]> = self.txs.iter()
            .filter(|(_, entry)| {
                entry.key_images.iter().any(|ki| confirmed_set.contains(&ki.as_bytes()))
            })
            .map(|(hash, _)| *hash)
            .collect();
        
        for hash in to_remove {
            self.remove(&hash);
        }
    }
    
    /// Limpia TXs expiradas
    pub fn cleanup_expired(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let expired: Vec<[u8; 32]> = self.txs.iter()
            .filter(|(_, entry)| now - entry.added_time > MAX_MEMPOOL_AGE_SECS)
            .map(|(hash, _)| *hash)
            .collect();
        
        for hash in expired {
            self.remove(&hash);
        }
    }
    
    /// Número de TXs en mempool
    pub fn len(&self) -> usize {
        self.txs.len()
    }
    
    /// Mempool vacío
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }
    
    /// Fee total en mempool
    pub fn total_fees(&self) -> u64 {
        self.txs.values().map(|e| e.fee).sum()
    }
    
    /// Estadísticas
    pub fn stats(&self) -> MempoolStats {
        let total_size: usize = self.txs.values().map(|e| e.size).sum();
        let total_fees: u64 = self.txs.values().map(|e| e.fee).sum();
        let avg_fee_rate = if !self.txs.is_empty() {
            self.txs.values().map(|e| e.fee_rate).sum::<f64>() / self.txs.len() as f64
        } else {
            0.0
        };
        
        MempoolStats {
            tx_count: self.txs.len(),
            total_size,
            total_fees,
            avg_fee_rate,
            pending_key_images: self.pending_key_images.len(),
        }
    }
}

/// Estadísticas del mempool
#[derive(Clone, Debug)]
pub struct MempoolStats {
    pub tx_count: usize,
    pub total_size: usize,
    pub total_fees: u64,
    pub avg_fee_rate: f64,
    pub pending_key_images: usize,
}

/// Errores del mempool
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MempoolError {
    MempoolFull,
    AlreadyExists,
    ConflictingKeyImage,
    InvalidTx(String),
    DoubleSpend,
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::MempoolFull => write!(f, "Mempool full"),
            MempoolError::AlreadyExists => write!(f, "Transaction already in mempool"),
            MempoolError::ConflictingKeyImage => write!(f, "Conflicting key image in mempool"),
            MempoolError::InvalidTx(s) => write!(f, "Invalid transaction: {}", s),
            MempoolError::DoubleSpend => write!(f, "Double spend detected"),
        }
    }
}

// =============================================================================
// Privacy Node State
// =============================================================================

/// Estado de privacidad del nodo
pub struct PrivacyState {
    /// Contexto de validación (pool + key images)
    pub validation_ctx: ValidationContext,
    /// Mempool shielded
    pub mempool: ShieldedMempool,
    /// Altura actual
    pub current_height: u64,
    /// Hash del mejor bloque
    pub best_block_hash: [u8; 32],
}

impl PrivacyState {
    pub fn new() -> Self {
        PrivacyState {
            validation_ctx: ValidationContext::new(),
            mempool: ShieldedMempool::new(),
            current_height: 0,
            best_block_hash: [0u8; 32],
        }
    }
    
    /// Procesa una TX shielded recibida
    pub fn process_tx(&mut self, tx: ShieldedTx) -> Result<[u8; 32], MempoolError> {
        // 1. Validación rápida
        quick_validate(&tx).map_err(|e| MempoolError::InvalidTx(e.to_string()))?;
        
        // 2. Verificar key images no en blockchain
        for ki in tx.key_images() {
            if self.validation_ctx.key_image_set.contains(&ki) {
                return Err(MempoolError::DoubleSpend);
            }
        }
        
        // 3. Verificar key images no en mempool
        for ki in tx.key_images() {
            if self.mempool.has_key_image(&ki) {
                return Err(MempoolError::ConflictingKeyImage);
            }
        }
        
        // 4. Validación completa
        let validator = ShieldedValidator::new(
            &self.validation_ctx.shielded_pool,
            &self.validation_ctx.key_image_set,
        );
        
        match validator.validate(&tx) {
            ValidationResult::Valid => {},
            ValidationResult::Invalid(e) => {
                return Err(MempoolError::InvalidTx(e.to_string()));
            }
        }
        
        // 5. Agregar al mempool
        self.mempool.add(tx)
    }
    
    /// Procesa un bloque con TXs shielded
    pub fn process_block(&mut self, height: u64, block_hash: [u8; 32], txs: &[ShieldedTx]) {
        // Aplicar cada TX al estado
        for tx in txs {
            self.validation_ctx.validate_and_apply(tx, height);
        }
        
        // Remover TXs confirmadas del mempool
        self.mempool.remove_confirmed(txs);
        
        // Remover TXs conflictantes
        let confirmed_key_images: Vec<KeyImage> = txs.iter()
            .flat_map(|tx| tx.key_images())
            .collect();
        self.mempool.remove_conflicting(&confirmed_key_images);
        
        // Actualizar estado
        self.current_height = height;
        self.best_block_hash = block_hash;
    }
    
    /// Revierte un bloque (para reorgs)
    pub fn revert_block(&mut self, height: u64, txs: &[ShieldedTx]) {
        self.validation_ctx.revert_block(height, txs);
        self.current_height = height - 1;
    }
    
    /// Obtiene TXs para minar
    pub fn get_txs_for_mining(&self, max_weight: usize) -> Vec<ShieldedTx> {
        self.mempool.select_for_block(
            MAX_SHIELDED_TXS_PER_BLOCK,
            max_weight / SHIELDED_TX_WEIGHT_MULTIPLIER as usize,
        )
    }
    
    /// Estadísticas
    pub fn stats(&self) -> PrivacyStats {
        let validation_stats = self.validation_ctx.stats();
        let mempool_stats = self.mempool.stats();
        
        PrivacyStats {
            current_height: self.current_height,
            shielded_outputs: validation_stats.shielded_outputs,
            key_images_used: validation_stats.key_images_used,
            mempool_txs: mempool_stats.tx_count,
            mempool_size: mempool_stats.total_size,
            mempool_fees: mempool_stats.total_fees,
        }
    }
}

impl Default for PrivacyState {
    fn default() -> Self {
        Self::new()
    }
}

/// Estadísticas de privacidad
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyStats {
    pub current_height: u64,
    pub shielded_outputs: usize,
    pub key_images_used: usize,
    pub mempool_txs: usize,
    pub mempool_size: usize,
    pub mempool_fees: u64,
}

// =============================================================================
// Block Builder Helper
// =============================================================================

/// Construye la parte shielded de un bloque
pub struct ShieldedBlockBuilder<'a> {
    state: &'a PrivacyState,
    selected_txs: Vec<ShieldedTx>,
    total_fees: u64,
    total_weight: usize,
}

impl<'a> ShieldedBlockBuilder<'a> {
    pub fn new(state: &'a PrivacyState) -> Self {
        ShieldedBlockBuilder {
            state,
            selected_txs: Vec::new(),
            total_fees: 0,
            total_weight: 0,
        }
    }
    
    /// Selecciona TXs para el bloque
    pub fn select_txs(&mut self, max_weight: usize) {
        self.selected_txs = self.state.get_txs_for_mining(max_weight);
        self.total_fees = self.selected_txs.iter().map(|tx| tx.fee).sum();
        self.total_weight = self.selected_txs.iter().map(|tx| tx.size()).sum();
    }
    
    /// Obtiene las TXs seleccionadas
    pub fn get_txs(&self) -> &[ShieldedTx] {
        &self.selected_txs
    }
    
    /// Obtiene el total de fees
    pub fn total_fees(&self) -> u64 {
        self.total_fees
    }
    
    /// Obtiene el peso total
    pub fn total_weight(&self) -> usize {
        self.total_weight
    }
}

// =============================================================================
// P2P Message Types
// =============================================================================

/// Mensajes P2P para privacidad
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PrivacyP2PMessage {
    /// Nueva TX shielded
    NewShieldedTx(ShieldedTx),
    /// Solicitar TX por hash
    GetShieldedTx([u8; 32]),
    /// Respuesta con TX
    ShieldedTx(ShieldedTx),
    /// Inventario de TXs shielded
    ShieldedInv(Vec<[u8; 32]>),
    /// Solicitar múltiples TXs
    GetShieldedTxs(Vec<[u8; 32]>),
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::shielded_tx::{TxType, MIN_SHIELDED_FEE, ShieldedTx};
    use crate::privacy::shielded_tx::ShieldedOutput;
    
    
    #[test]
    fn test_shielded_mempool() {
        let mut mempool = ShieldedMempool::new();
        
        // Crear TX dummy
        let tx = ShieldedTx {
            version: 2,
            tx_type: TxType::Shielding,
            transparent_inputs: vec![],
            transparent_outputs: vec![],
            shielded_inputs: vec![],
            shielded_outputs: vec![],
            fee: MIN_SHIELDED_FEE,
            binding_sig: None,
            locktime: 0,
        };
        
        let result = mempool.add(tx);
        assert!(result.is_ok());
        assert_eq!(mempool.len(), 1);
    }
    
    #[test]
    fn test_privacy_state() {
        let state = PrivacyState::new();
        
        assert_eq!(state.current_height, 0);
        assert!(state.mempool.is_empty());
    }
    
    #[test]
    fn test_mempool_stats() {
        let mempool = ShieldedMempool::new();
        let stats = mempool.stats();
        
        assert_eq!(stats.tx_count, 0);
        assert_eq!(stats.total_fees, 0);
    }
}
