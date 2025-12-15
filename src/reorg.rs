// =============================================================================
// MOONCOIN v2.0 - Manejo de Forks y Reorganizaciones
// =============================================================================

use crate::block::Block;
use crate::utxo::{UtxoSet, UtxoKey, UtxoEntry};
use crate::validation::validate_block;
use crate::difficulty::calculate_next_difficulty;
use std::collections::HashMap;

/// Calcula el trabajo acumulado de una cadena
/// Trabajo = suma de 2^difficulty_bits para cada bloque
pub fn calculate_chain_work(chain: &[Block]) -> u128 {
    chain.iter()
        .map(|block| {
            // Trabajo = 2^difficulty_bits (aproximación)
            1u128 << block.difficulty_bits
        })
        .sum()
}

/// Encuentra el ancestro común entre dos cadenas
/// Retorna el índice del último bloque común
pub fn find_common_ancestor(chain_a: &[Block], chain_b: &[Block]) -> Option<usize> {
    if chain_a.is_empty() || chain_b.is_empty() {
        return None;
    }
    
    // Crear set de hashes de chain_a
    let hashes_a: HashMap<String, usize> = chain_a.iter()
        .enumerate()
        .map(|(i, b)| (b.hash.clone(), i))
        .collect();
    
    // Buscar el bloque más alto de chain_b que esté en chain_a
    for block in chain_b.iter().rev() {
        if let Some(&index) = hashes_a.get(&block.hash) {
            return Some(index);
        }
    }
    
    None
}

/// Resultado de una reorganización
#[derive(Debug)]
pub struct ReorgResult {
    pub success: bool,
    pub old_tip: String,
    pub new_tip: String,
    pub blocks_disconnected: usize,
    pub blocks_connected: usize,
    pub reverted_txs: Vec<String>,  // TxIDs que volvieron al mempool
}

/// Información para revertir un bloque
#[derive(Clone)]
pub struct BlockUndo {
    pub height: u64,
    pub hash: String,
    /// UTXOs que fueron gastados en este bloque (para restaurar)
    pub spent_utxos: HashMap<UtxoKey, UtxoEntry>,
    /// UTXOs que fueron creados en este bloque (para eliminar)
    pub created_utxos: Vec<UtxoKey>,
}

impl BlockUndo {
    /// Crea la información de undo para un bloque
    pub fn from_block(block: &Block, utxo_before: &UtxoSet) -> Self {
        let mut spent_utxos = HashMap::new();
        let mut created_utxos = Vec::new();
        
        for tx in &block.txs {
            let txid = crate::transaction::tx_hash(tx);
            
            // Registrar UTXOs creados
            for (idx, _) in tx.outputs.iter().enumerate() {
                created_utxos.push((txid.clone(), idx as u32));
            }
            
            // Registrar UTXOs gastados (no aplica para coinbase)
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let key = (input.prev_tx_hash.clone(), input.prev_index);
                    if let Some(entry) = utxo_before.get(&key) {
                        spent_utxos.insert(key, entry.clone());
                    }
                }
            }
        }
        
        BlockUndo {
            height: block.height,
            hash: block.hash.clone(),
            spent_utxos,
            created_utxos,
        }
    }
}

/// Manager de reorganizaciones
pub struct ReorgManager {
    /// Información de undo para los últimos N bloques
    undo_data: HashMap<String, BlockUndo>,
    /// Máximo de bloques de undo a mantener
    max_undo_depth: usize,
}

impl ReorgManager {
    pub fn new(max_depth: usize) -> Self {
        ReorgManager {
            undo_data: HashMap::new(),
            max_undo_depth: max_depth,
        }
    }
    
    /// Guarda información de undo para un bloque
    pub fn save_undo(&mut self, block: &Block, utxo_before: &UtxoSet) {
        let undo = BlockUndo::from_block(block, utxo_before);
        self.undo_data.insert(block.hash.clone(), undo);
        
        // Limpiar undos antiguos si excedemos el límite
        if self.undo_data.len() > self.max_undo_depth {
            // Encontrar y eliminar el más antiguo (menor height)
            if let Some(oldest_hash) = self.undo_data.iter()
                .min_by_key(|(_, u)| u.height)
                .map(|(h, _)| h.clone())
            {
                self.undo_data.remove(&oldest_hash);
            }
        }
    }
    
    /// Obtiene información de undo para un bloque
    pub fn get_undo(&self, hash: &str) -> Option<&BlockUndo> {
        self.undo_data.get(hash)
    }
    
    /// Revierte un bloque aplicando su undo
    pub fn revert_block(&self, block: &Block, utxo: &mut UtxoSet) -> Result<Vec<String>, String> {
        let undo = self.get_undo(&block.hash)
            .ok_or_else(|| format!("No undo data for block {}", &block.hash[..16]))?;
        
        let mut reverted_txids = Vec::new();
        
        // 1. Eliminar UTXOs creados por este bloque
        for key in &undo.created_utxos {
            utxo.utxos.remove(key);
        }
        
        // 2. Restaurar UTXOs gastados
        for (key, entry) in &undo.spent_utxos {
            utxo.utxos.insert(key.clone(), entry.clone());
        }
        
        // 3. Recopilar txids para devolver al mempool (excepto coinbase)
        for tx in &block.txs {
            if !tx.is_coinbase() {
                reverted_txids.push(crate::transaction::tx_hash(tx));
            }
        }
        
        Ok(reverted_txids)
    }
    
    /// Intenta reorganizar a una cadena alternativa
    pub fn try_reorg(
        &mut self,
        current_chain: &mut Vec<Block>,
        utxo: &mut UtxoSet,
        new_blocks: &[Block],
    ) -> Result<ReorgResult, String> {
        if new_blocks.is_empty() {
            return Err("No blocks to connect".to_string());
        }
        
        let old_tip = current_chain.last()
            .map(|b| b.hash.clone())
            .unwrap_or_default();
        
        // Calcular trabajo de ambas cadenas
        let current_work = calculate_chain_work(current_chain);
        
        // Construir cadena hipotética con los nuevos bloques
        let fork_point = find_common_ancestor(current_chain, new_blocks);
        
        let (disconnect_count, hypothetical_chain) = if let Some(fork_idx) = fork_point {
            // Hay un ancestro común
            let mut hypo = current_chain[..=fork_idx].to_vec();
            
            // Encontrar bloques de new_blocks después del fork point
            let fork_hash = &current_chain[fork_idx].hash;
            let new_start = new_blocks.iter()
                .position(|b| &b.prev_hash == fork_hash)
                .unwrap_or(0);
            
            hypo.extend(new_blocks[new_start..].iter().cloned());
            
            (current_chain.len() - fork_idx - 1, hypo)
        } else {
            // Los bloques nuevos extienden la cadena actual
            let mut hypo = current_chain.clone();
            hypo.extend(new_blocks.iter().cloned());
            (0, hypo)
        };
        
        let new_work = calculate_chain_work(&hypothetical_chain);
        
        // Solo reorganizar si la nueva cadena tiene más trabajo
        if new_work <= current_work {
            return Err(format!(
                "New chain has less work: {} vs {}",
                new_work, current_work
            ));
        }
        
        // Realizar la reorganización
        let mut all_reverted_txs = Vec::new();
        
        // 1. Desconectar bloques de la cadena actual
        for _ in 0..disconnect_count {
            if let Some(block) = current_chain.pop() {
                match self.revert_block(&block, utxo) {
                    Ok(txids) => all_reverted_txs.extend(txids),
                    Err(e) => return Err(format!("Failed to revert block: {}", e)),
                }
            }
        }
        
        // 2. Conectar nuevos bloques
        let connect_start = if let Some(fork_idx) = fork_point {
            new_blocks.iter()
                .position(|b| &b.prev_hash == &current_chain[fork_idx].hash)
                .unwrap_or(0)
        } else {
            0
        };
        
        let mut connected = 0;
        for block in &new_blocks[connect_start..] {
            // Validar bloque
            let expected_diff = calculate_next_difficulty(current_chain);
            
            if let Err(e) = validate_block(block, current_chain, utxo, expected_diff) {
                // Rollback los bloques que ya conectamos
                return Err(format!("Block validation failed during reorg: {}", e));
            }
            
            // Guardar undo antes de aplicar
            self.save_undo(block, utxo);
            
            // Aplicar bloque
            utxo.apply_block(block);
            current_chain.push(block.clone());
            connected += 1;
        }
        
        let new_tip = current_chain.last()
            .map(|b| b.hash.clone())
            .unwrap_or_default();
        
        Ok(ReorgResult {
            success: true,
            old_tip,
            new_tip,
            blocks_disconnected: disconnect_count,
            blocks_connected: connected,
            reverted_txs: all_reverted_txs,
        })
    }
}

/// Determina si un bloque es huérfano (no conocemos su padre)
pub fn is_orphan(block: &Block, chain: &[Block]) -> bool {
    if block.height == 0 {
        return false; // Genesis nunca es huérfano
    }
    
    !chain.iter().any(|b| b.hash == block.prev_hash)
}

/// Verifica si debemos reorganizar basado en un nuevo bloque recibido
pub fn should_reorg(
    current_chain: &[Block],
    new_block: &Block,
) -> bool {
    // Si el nuevo bloque extiende nuestra cadena, no es reorg
    if let Some(tip) = current_chain.last() {
        if new_block.prev_hash == tip.hash {
            return false;
        }
    }
    
    // Si el nuevo bloque es de una cadena alternativa con más trabajo potencial
    // Esto es una heurística simple: si tiene más altura, probablemente más trabajo
    let our_height = current_chain.len() as u64;
    
    new_block.height >= our_height
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Tx;

    fn make_test_block(height: u64, prev_hash: &str, diff: u32) -> Block {
        Block {
            height,
            timestamp: 1000 + height,
            prev_hash: prev_hash.to_string(),
            merkle_root: "merkle".to_string(),
            difficulty_bits: diff,
            nonce: 0,
            hash: format!("hash_{}", height),
            txs: vec![Tx::new_coinbase("test".to_string(), 50, height)],
        }
    }

    #[test]
    fn test_chain_work() {
        let chain = vec![
            make_test_block(0, "0", 20),
            make_test_block(1, "hash_0", 20),
        ];
        
        let work = calculate_chain_work(&chain);
        assert_eq!(work, 2 * (1u128 << 20));
    }

    #[test]
    fn test_find_common_ancestor() {
        let chain_a = vec![
            make_test_block(0, "0", 20),
            make_test_block(1, "hash_0", 20),
            make_test_block(2, "hash_1", 20),
        ];
        
        let chain_b = vec![
            make_test_block(0, "0", 20),
            make_test_block(1, "hash_0", 20),
        ];
        
        let ancestor = find_common_ancestor(&chain_a, &chain_b);
        assert_eq!(ancestor, Some(1));
    }
}
