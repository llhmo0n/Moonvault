// =============================================================================
// MOONCOIN v2.0 - Storage Engine (Sled Database)
// =============================================================================

use sled::{Db, Tree};
use std::path::Path;

use crate::block::Block;
use crate::transaction::{Tx, tx_hash};
use crate::utxo::UtxoEntry;

const DB_PATH: &str = "mooncoin_data";

/// Motor de almacenamiento persistente
pub struct Storage {
    db: Db,
    
    // Trees (tablas)
    blocks: Tree,       // hash -> Block
    height_index: Tree, // height -> hash
    tx_index: Tree,     // txid -> (blockhash, tx_index_in_block)
    utxo: Tree,         // (txid, vout) -> UtxoEntry
    meta: Tree,         // metadata (best_hash, height, etc.)
}

impl Storage {
    /// Abre o crea la base de datos
    pub fn open() -> Result<Self, String> {
        let db = sled::open(DB_PATH)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        let blocks = db.open_tree("blocks")
            .map_err(|e| format!("Failed to open blocks tree: {}", e))?;
        let height_index = db.open_tree("height_index")
            .map_err(|e| format!("Failed to open height_index tree: {}", e))?;
        let tx_index = db.open_tree("tx_index")
            .map_err(|e| format!("Failed to open tx_index tree: {}", e))?;
        let utxo = db.open_tree("utxo")
            .map_err(|e| format!("Failed to open utxo tree: {}", e))?;
        let meta = db.open_tree("meta")
            .map_err(|e| format!("Failed to open meta tree: {}", e))?;
        
        Ok(Storage {
            db,
            blocks,
            height_index,
            tx_index,
            utxo,
            meta,
        })
    }
    
    /// Abre base de datos en una ruta específica
    pub fn open_path<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let db = sled::open(path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        let blocks = db.open_tree("blocks")
            .map_err(|e| format!("Failed to open blocks tree: {}", e))?;
        let height_index = db.open_tree("height_index")
            .map_err(|e| format!("Failed to open height_index tree: {}", e))?;
        let tx_index = db.open_tree("tx_index")
            .map_err(|e| format!("Failed to open tx_index tree: {}", e))?;
        let utxo = db.open_tree("utxo")
            .map_err(|e| format!("Failed to open utxo tree: {}", e))?;
        let meta = db.open_tree("meta")
            .map_err(|e| format!("Failed to open meta tree: {}", e))?;
        
        Ok(Storage {
            db,
            blocks,
            height_index,
            tx_index,
            utxo,
            meta,
        })
    }
    
    // =========================================================================
    // Blocks
    // =========================================================================
    
    /// Guarda un bloque
    pub fn put_block(&self, block: &Block) -> Result<(), String> {
        let data = bincode::serialize(block)
            .map_err(|e| format!("Serialize error: {}", e))?;
        
        // Guardar bloque por hash
        self.blocks.insert(block.hash.as_bytes(), data)
            .map_err(|e| format!("Insert error: {}", e))?;
        
        // Índice por altura
        self.height_index.insert(
            &block.height.to_be_bytes(),
            block.hash.as_bytes()
        ).map_err(|e| format!("Height index error: {}", e))?;
        
        // Indexar transacciones
        for (tx_idx, tx) in block.txs.iter().enumerate() {
            let txid = tx_hash(tx);
            let tx_loc = TxLocation {
                block_hash: block.hash.clone(),
                tx_index: tx_idx as u32,
            };
            let loc_data = bincode::serialize(&tx_loc)
                .map_err(|e| format!("Serialize tx_loc error: {}", e))?;
            
            self.tx_index.insert(txid.as_bytes(), loc_data)
                .map_err(|e| format!("Tx index error: {}", e))?;
        }
        
        Ok(())
    }
    
    /// Obtiene un bloque por hash
    pub fn get_block(&self, hash: &str) -> Option<Block> {
        self.blocks.get(hash.as_bytes()).ok()?.map(|data| {
            bincode::deserialize(&data).ok()
        })?
    }
    
    /// Obtiene un bloque por altura
    pub fn get_block_by_height(&self, height: u64) -> Option<Block> {
        let hash_bytes = self.height_index.get(&height.to_be_bytes()).ok()??;
        let hash = String::from_utf8(hash_bytes.to_vec()).ok()?;
        self.get_block(&hash)
    }
    
    /// Obtiene el hash del bloque a cierta altura
    pub fn get_block_hash(&self, height: u64) -> Option<String> {
        let hash_bytes = self.height_index.get(&height.to_be_bytes()).ok()??;
        String::from_utf8(hash_bytes.to_vec()).ok()
    }
    
    /// Verifica si existe un bloque
    pub fn has_block(&self, hash: &str) -> bool {
        self.blocks.contains_key(hash.as_bytes()).unwrap_or(false)
    }
    
    /// Elimina un bloque (para reorgs)
    pub fn delete_block(&self, hash: &str) -> Result<Option<Block>, String> {
        // Primero obtener el bloque para limpiar índices
        if let Some(block) = self.get_block(hash) {
            // Eliminar índice de altura
            self.height_index.remove(&block.height.to_be_bytes())
                .map_err(|e| format!("Remove height index error: {}", e))?;
            
            // Eliminar índices de transacciones
            for tx in &block.txs {
                let txid = tx_hash(tx);
                self.tx_index.remove(txid.as_bytes())
                    .map_err(|e| format!("Remove tx index error: {}", e))?;
            }
            
            // Eliminar bloque
            self.blocks.remove(hash.as_bytes())
                .map_err(|e| format!("Remove block error: {}", e))?;
            
            return Ok(Some(block));
        }
        
        Ok(None)
    }
    
    // =========================================================================
    // Transactions
    // =========================================================================
    
    /// Busca una transacción por txid
    pub fn get_transaction(&self, txid: &str) -> Option<(Tx, String, u32)> {
        let loc_data = self.tx_index.get(txid.as_bytes()).ok()??;
        let loc: TxLocation = bincode::deserialize(&loc_data).ok()?;
        
        let block = self.get_block(&loc.block_hash)?;
        let tx = block.txs.get(loc.tx_index as usize)?.clone();
        
        Some((tx, loc.block_hash, loc.tx_index))
    }
    
    /// Verifica si existe una transacción
    pub fn has_transaction(&self, txid: &str) -> bool {
        self.tx_index.contains_key(txid.as_bytes()).unwrap_or(false)
    }
    
    // =========================================================================
    // UTXO Set
    // =========================================================================
    
    /// Guarda un UTXO
    pub fn put_utxo(&self, txid: &str, vout: u32, entry: &UtxoEntry) -> Result<(), String> {
        let key = format!("{}:{}", txid, vout);
        let data = bincode::serialize(entry)
            .map_err(|e| format!("Serialize UTXO error: {}", e))?;
        
        self.utxo.insert(key.as_bytes(), data)
            .map_err(|e| format!("Insert UTXO error: {}", e))?;
        
        Ok(())
    }
    
    /// Obtiene un UTXO
    pub fn get_utxo(&self, txid: &str, vout: u32) -> Option<UtxoEntry> {
        let key = format!("{}:{}", txid, vout);
        let data = self.utxo.get(key.as_bytes()).ok()??;
        bincode::deserialize(&data).ok()
    }
    
    /// Elimina un UTXO (cuando se gasta)
    pub fn delete_utxo(&self, txid: &str, vout: u32) -> Result<(), String> {
        let key = format!("{}:{}", txid, vout);
        self.utxo.remove(key.as_bytes())
            .map_err(|e| format!("Delete UTXO error: {}", e))?;
        Ok(())
    }
    
    /// Verifica si existe un UTXO
    pub fn has_utxo(&self, txid: &str, vout: u32) -> bool {
        let key = format!("{}:{}", txid, vout);
        self.utxo.contains_key(key.as_bytes()).unwrap_or(false)
    }
    
    /// Obtiene todos los UTXOs de una dirección
    pub fn get_utxos_for_address(&self, address: &str) -> Vec<(String, u32, UtxoEntry)> {
        let mut result = Vec::new();
        
        for item in self.utxo.iter() {
            if let Ok((key, value)) = item {
                if let Ok(entry) = bincode::deserialize::<UtxoEntry>(&value) {
                    if entry.output.to == address {
                        if let Ok(key_str) = String::from_utf8(key.to_vec()) {
                            let parts: Vec<&str> = key_str.split(':').collect();
                            if parts.len() == 2 {
                                if let Ok(vout) = parts[1].parse::<u32>() {
                                    result.push((parts[0].to_string(), vout, entry));
                                }
                            }
                        }
                    }
                }
            }
        }
        
        result
    }
    
    /// Cuenta total de UTXOs
    pub fn utxo_count(&self) -> usize {
        self.utxo.len()
    }
    
    /// Itera sobre todos los UTXOs
    pub fn iter_utxos(&self) -> impl Iterator<Item = (String, u32, UtxoEntry)> + '_ {
        self.utxo.iter().filter_map(|item| {
            let (key, value) = item.ok()?;
            let entry: UtxoEntry = bincode::deserialize(&value).ok()?;
            let key_str = String::from_utf8(key.to_vec()).ok()?;
            let parts: Vec<&str> = key_str.split(':').collect();
            if parts.len() == 2 {
                let vout = parts[1].parse::<u32>().ok()?;
                Some((parts[0].to_string(), vout, entry))
            } else {
                None
            }
        })
    }
    
    // =========================================================================
    // Metadata
    // =========================================================================
    
    /// Guarda el mejor bloque (tip)
    pub fn set_best_block(&self, hash: &str, height: u64) -> Result<(), String> {
        self.meta.insert("best_hash", hash.as_bytes())
            .map_err(|e| format!("Set best_hash error: {}", e))?;
        self.meta.insert("best_height", &height.to_be_bytes())
            .map_err(|e| format!("Set best_height error: {}", e))?;
        Ok(())
    }
    
    /// Obtiene el hash del mejor bloque
    pub fn get_best_hash(&self) -> Option<String> {
        let data = self.meta.get("best_hash").ok()??;
        String::from_utf8(data.to_vec()).ok()
    }
    
    /// Obtiene la altura del mejor bloque
    pub fn get_best_height(&self) -> Option<u64> {
        let data = self.meta.get("best_height").ok()??;
        if data.len() == 8 {
            Some(u64::from_be_bytes(data.as_ref().try_into().ok()?))
        } else {
            None
        }
    }
    
    /// Obtiene el mejor bloque
    pub fn get_best_block(&self) -> Option<Block> {
        let hash = self.get_best_hash()?;
        self.get_block(&hash)
    }
    
    // =========================================================================
    // Chain Operations
    // =========================================================================
    
    /// Carga la cadena completa (para compatibilidad)
    pub fn load_chain(&self) -> Vec<Block> {
        let height = self.get_best_height().unwrap_or(0);
        let mut chain = Vec::new();
        
        for h in 0..=height {
            if let Some(block) = self.get_block_by_height(h) {
                chain.push(block);
            } else {
                break;
            }
        }
        
        chain
    }
    
    /// Aplica un bloque al UTXO set
    pub fn apply_block_to_utxo(&self, block: &Block) -> Result<(), String> {
        for tx in &block.txs {
            let txid = tx_hash(tx);
            
            // Eliminar UTXOs gastados (excepto coinbase)
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    self.delete_utxo(&input.prev_tx_hash, input.prev_index)?;
                }
            }
            
            // Crear nuevos UTXOs
            for (vout, output) in tx.outputs.iter().enumerate() {
                let entry = UtxoEntry {
                    output: output.clone(),
                    height: block.height,
                    is_coinbase: tx.is_coinbase(),
                };
                self.put_utxo(&txid, vout as u32, &entry)?;
            }
        }
        
        Ok(())
    }
    
    /// Revierte un bloque del UTXO set
    pub fn revert_block_from_utxo(&self, block: &Block, spent_utxos: &[(String, u32, UtxoEntry)]) -> Result<(), String> {
        // Eliminar UTXOs creados por este bloque
        for tx in &block.txs {
            let txid = tx_hash(tx);
            for (vout, _) in tx.outputs.iter().enumerate() {
                self.delete_utxo(&txid, vout as u32)?;
            }
        }
        
        // Restaurar UTXOs gastados
        for (txid, vout, entry) in spent_utxos {
            self.put_utxo(txid, *vout, entry)?;
        }
        
        Ok(())
    }
    
    /// Flush a disco
    pub fn flush(&self) -> Result<(), String> {
        self.db.flush()
            .map_err(|e| format!("Flush error: {}", e))?;
        Ok(())
    }
    
    /// Calcula el supply total
    pub fn total_supply(&self) -> u64 {
        self.iter_utxos()
            .map(|(_, _, entry)| entry.output.amount)
            .sum()
    }
    
    /// Calcula balance de una dirección
    pub fn balance_of(&self, address: &str) -> u64 {
        self.get_utxos_for_address(address)
            .iter()
            .map(|(_, _, entry)| entry.output.amount)
            .sum()
    }
    
    /// Calcula balance gastable (excluyendo coinbase inmaduro)
    pub fn spendable_balance(&self, address: &str, current_height: u64) -> u64 {
        self.get_utxos_for_address(address)
            .iter()
            .filter(|(_, _, entry)| {
                if entry.is_coinbase {
                    current_height >= entry.height + crate::lib::COINBASE_MATURITY
                } else {
                    true
                }
            })
            .map(|(_, _, entry)| entry.output.amount)
            .sum()
    }
}

/// Ubicación de una transacción
#[derive(serde::Serialize, serde::Deserialize)]
struct TxLocation {
    block_hash: String,
    tx_index: u32,
}

// =============================================================================
// Migración desde formato antiguo
// =============================================================================

/// Migra datos del formato antiguo (mooncoin.chain) al nuevo
pub fn migrate_from_legacy(storage: &Storage) -> Result<bool, String> {
    use crate::block::load_chain;
    
    // Verificar si ya hay datos
    if storage.get_best_height().is_some() {
        return Ok(false); // Ya migrado
    }
    
    // Cargar cadena antigua
    let chain = load_chain();
    if chain.is_empty() {
        return Ok(false); // Nada que migrar
    }
    
    println!("Migrating {} blocks to new database...", chain.len());
    
    // Migrar cada bloque
    for block in &chain {
        storage.put_block(block)?;
        storage.apply_block_to_utxo(block)?;
    }
    
    // Establecer tip
    if let Some(tip) = chain.last() {
        storage.set_best_block(&tip.hash, tip.height)?;
    }
    
    storage.flush()?;
    
    println!("Migration complete!");
    Ok(true)
}
