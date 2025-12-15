// =============================================================================
// MOONCOIN v2.0 - UTXO Set
// =============================================================================

use std::collections::HashMap;

use crate::lib::COINBASE_MATURITY;
use crate::block::Block;
use crate::transaction::{TxOut, tx_hash};

/// Clave única para identificar un UTXO: (tx_hash, output_index)
pub type UtxoKey = (String, u32);

/// Información almacenada de un UTXO
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UtxoEntry {
    pub output: TxOut,
    pub height: u64,        // Altura del bloque donde se creó
    pub is_coinbase: bool,  // Si viene de una coinbase
}

/// Set de UTXOs no gastados
#[derive(Default, Clone)]
pub struct UtxoSet {
    pub utxos: HashMap<UtxoKey, UtxoEntry>,
}

impl UtxoSet {
    pub fn new() -> Self {
        UtxoSet {
            utxos: HashMap::new(),
        }
    }

    /// Reconstruye el UTXO set desde una cadena completa
    pub fn rebuild_from_chain(chain: &[Block]) -> Self {
        let mut utxo_set = UtxoSet::new();
        for block in chain {
            utxo_set.apply_block(block);
        }
        utxo_set
    }

    /// Aplica un bloque al UTXO set
    pub fn apply_block(&mut self, block: &Block) {
        for tx in &block.txs {
            let txid = tx_hash(tx);
            let is_coinbase = tx.is_coinbase();

            // Agregar nuevos outputs
            for (index, output) in tx.outputs.iter().enumerate() {
                let key = (txid.clone(), index as u32);
                self.utxos.insert(key, UtxoEntry {
                    output: output.clone(),
                    height: block.height,
                    is_coinbase,
                });
            }

            // Remover inputs gastados (no aplica para coinbase)
            if !is_coinbase {
                for input in &tx.inputs {
                    let key = (input.prev_tx_hash.clone(), input.prev_index);
                    self.utxos.remove(&key);
                }
            }
        }
    }

    /// Revierte un bloque (para manejar reorgs)
    pub fn revert_block(&mut self, block: &Block, prev_utxos: &HashMap<UtxoKey, UtxoEntry>) {
        for tx in &block.txs {
            let txid = tx_hash(tx);

            // Remover outputs agregados
            for (index, _) in tx.outputs.iter().enumerate() {
                let key = (txid.clone(), index as u32);
                self.utxos.remove(&key);
            }

            // Restaurar inputs gastados
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let key = (input.prev_tx_hash.clone(), input.prev_index);
                    if let Some(entry) = prev_utxos.get(&key) {
                        self.utxos.insert(key, entry.clone());
                    }
                }
            }
        }
    }

    /// Calcula el balance de una dirección
    pub fn balance_of(&self, address: &str) -> u64 {
        self.utxos
            .values()
            .filter(|entry| entry.output.to == address)
            .map(|entry| entry.output.amount)
            .sum()
    }

    /// Calcula el balance gastable (considerando coinbase maturity)
    pub fn spendable_balance(&self, address: &str, current_height: u64) -> u64 {
        self.utxos
            .values()
            .filter(|entry| {
                entry.output.to == address && self.is_spendable(entry, current_height)
            })
            .map(|entry| entry.output.amount)
            .sum()
    }

    /// Verifica si un UTXO es gastable (coinbase maturity)
    fn is_spendable(&self, entry: &UtxoEntry, current_height: u64) -> bool {
        if entry.is_coinbase {
            // Coinbase necesita COINBASE_MATURITY confirmaciones
            current_height >= entry.height + COINBASE_MATURITY
        } else {
            true
        }
    }

    /// Encuentra UTXOs gastables para cubrir una cantidad
    pub fn find_spendable(
        &self,
        address: &str,
        amount: u64,
        current_height: u64,
    ) -> Option<Vec<(UtxoKey, UtxoEntry)>> {
        let mut found = Vec::new();
        let mut accumulated = 0u64;

        // Ordenar por cantidad (menor primero) para optimizar
        let mut candidates: Vec<_> = self.utxos
            .iter()
            .filter(|(_, entry)| {
                entry.output.to == address && self.is_spendable(entry, current_height)
            })
            .collect();

        candidates.sort_by_key(|(_, entry)| entry.output.amount);

        for (key, entry) in candidates {
            found.push((key.clone(), entry.clone()));
            accumulated += entry.output.amount;
            if accumulated >= amount {
                return Some(found);
            }
        }

        // No hay suficientes fondos
        None
    }

    /// Obtiene un UTXO específico
    pub fn get(&self, key: &UtxoKey) -> Option<&UtxoEntry> {
        self.utxos.get(key)
    }

    /// Verifica si existe un UTXO
    pub fn contains(&self, key: &UtxoKey) -> bool {
        self.utxos.contains_key(key)
    }

    /// Número total de UTXOs
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Supply total en circulación
    pub fn total_supply(&self) -> u64 {
        self.utxos.values().map(|e| e.output.amount).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Tx;

    #[test]
    fn test_coinbase_maturity() {
        let mut utxo = UtxoSet::new();
        
        // Simular coinbase en bloque 0
        let entry = UtxoEntry {
            output: TxOut { to: "MCtest".to_string(), amount: 50_00000000 },
            height: 0,
            is_coinbase: true,
        };
        utxo.utxos.insert(("tx1".to_string(), 0), entry);

        // En altura 50, aún no es gastable
        assert_eq!(utxo.spendable_balance("MCtest", 50), 0);
        
        // En altura 100, ya es gastable
        assert_eq!(utxo.spendable_balance("MCtest", 100), 50_00000000);
    }

    #[test]
    fn test_find_spendable() {
        let mut utxo = UtxoSet::new();
        
        // Agregar UTXOs no-coinbase
        utxo.utxos.insert(
            ("tx1".to_string(), 0),
            UtxoEntry {
                output: TxOut { to: "MCtest".to_string(), amount: 10 },
                height: 0,
                is_coinbase: false,
            },
        );
        utxo.utxos.insert(
            ("tx2".to_string(), 0),
            UtxoEntry {
                output: TxOut { to: "MCtest".to_string(), amount: 20 },
                height: 0,
                is_coinbase: false,
            },
        );

        let found = utxo.find_spendable("MCtest", 25, 1);
        assert!(found.is_some());
        
        let entries = found.unwrap();
        let total: u64 = entries.iter().map(|(_, e)| e.output.amount).sum();
        assert!(total >= 25);
    }
}
