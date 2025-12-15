// =============================================================================
// MOONCOIN v2.0 - Mempool con Transaction Fees
// =============================================================================

use std::collections::HashMap;
use std::fs;

use crate::lib::{PENDING_TX_FILE, MIN_RELAY_FEE, MIN_FEE_PER_BYTE};
use crate::transaction::{Tx, tx_hash, tx_size, fee_per_byte};
use crate::utxo::UtxoSet;
use crate::validation::{validate_transaction, ValidationError};

/// Entrada del mempool con metadata
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    pub tx: Tx,
    pub fee: u64,
    pub size: usize,
    pub fee_per_byte: u64,
    pub added_time: u64,
}

/// Mempool de transacciones pendientes
#[derive(Default)]
pub struct Mempool {
    /// Transacciones por txid
    pub txs: HashMap<String, MempoolEntry>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            txs: HashMap::new(),
        }
    }

    /// Carga el mempool desde disco
    pub fn load() -> Self {
        if let Ok(data) = fs::read(PENDING_TX_FILE) {
            if let Ok(txs) = bincode::deserialize::<Vec<(String, Tx, u64)>>(&data) {
                let mut mempool = Mempool::new();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                for (txid, tx, fee) in txs {
                    let size = tx_size(&tx);
                    mempool.txs.insert(txid, MempoolEntry {
                        tx,
                        fee,
                        size,
                        fee_per_byte: fee_per_byte(fee, size),
                        added_time: now,
                    });
                }
                return mempool;
            }
        }
        Mempool::new()
    }

    /// Guarda el mempool a disco
    pub fn save(&self) {
        let txs: Vec<(String, Tx, u64)> = self.txs.iter()
            .map(|(txid, entry)| (txid.clone(), entry.tx.clone(), entry.fee))
            .collect();
        if let Ok(data) = bincode::serialize(&txs) {
            let _ = fs::write(PENDING_TX_FILE, &data);
        }
    }

    /// Calcula el fee de una transacción basado en los UTXOs
    pub fn calculate_tx_fee(tx: &Tx, utxo: &UtxoSet) -> u64 {
        if tx.is_coinbase() {
            return 0;
        }
        
        let input_sum: u64 = tx.inputs.iter()
            .filter_map(|inp| {
                utxo.get(&(inp.prev_tx_hash.clone(), inp.prev_index))
                    .map(|e| e.output.amount)
            })
            .sum();
        
        let output_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        
        input_sum.saturating_sub(output_sum)
    }

    /// Agrega una transacción al mempool si es válida
    pub fn add_tx(
        &mut self,
        tx: Tx,
        utxo: &UtxoSet,
        current_height: u64,
    ) -> Result<String, MempoolError> {
        let txid = tx_hash(&tx);

        // No agregar duplicados
        if self.txs.contains_key(&txid) {
            return Ok(txid);
        }

        // No aceptar coinbase
        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseNotAllowed);
        }

        // Calcular fee
        let fee = Self::calculate_tx_fee(&tx, utxo);
        let size = tx_size(&tx);
        let fpb = fee_per_byte(fee, size);
        
        // Verificar fee mínimo
        if fee < MIN_RELAY_FEE {
            return Err(MempoolError::FeeTooLow { 
                got: fee, 
                min: MIN_RELAY_FEE 
            });
        }
        
        // Verificar fee por byte
        if fpb < MIN_FEE_PER_BYTE {
            return Err(MempoolError::FeePerByteTooLow { 
                got: fpb, 
                min: MIN_FEE_PER_BYTE 
            });
        }

        // Validar la transacción
        validate_transaction(&tx, utxo, current_height, false)
            .map_err(MempoolError::ValidationFailed)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Agregar al mempool
        self.txs.insert(txid.clone(), MempoolEntry {
            tx,
            fee,
            size,
            fee_per_byte: fpb,
            added_time: now,
        });
        
        self.save();

        Ok(txid)
    }

    /// Remueve una transacción del mempool
    pub fn remove_tx(&mut self, txid: &str) {
        self.txs.remove(txid);
        self.save();
    }

    /// Obtiene transacciones para incluir en un bloque, ordenadas por fee/byte
    pub fn get_txs_for_block(
        &self,
        utxo: &UtxoSet,
        current_height: u64,
        max_txs: usize,
    ) -> (Vec<Tx>, u64) {
        let mut selected = Vec::new();
        let mut total_fees = 0u64;
        let mut temp_utxo = utxo.clone();

        // Ordenar por fee_per_byte (mayor primero)
        let mut entries: Vec<_> = self.txs.values().collect();
        entries.sort_by(|a, b| b.fee_per_byte.cmp(&a.fee_per_byte));

        for entry in entries {
            if selected.len() >= max_txs {
                break;
            }

            // Revalidar contra el UTXO temporal
            if validate_transaction(&entry.tx, &temp_utxo, current_height, false).is_ok() {
                // Actualizar UTXO temporal
                for input in &entry.tx.inputs {
                    temp_utxo.utxos.remove(&(input.prev_tx_hash.clone(), input.prev_index));
                }
                
                let txid = tx_hash(&entry.tx);
                for (idx, output) in entry.tx.outputs.iter().enumerate() {
                    temp_utxo.utxos.insert(
                        (txid.clone(), idx as u32),
                        crate::utxo::UtxoEntry {
                            output: output.clone(),
                            height: current_height,
                            is_coinbase: false,
                        },
                    );
                }

                total_fees += entry.fee;
                selected.push(entry.tx.clone());
            }
        }

        (selected, total_fees)
    }

    /// Limpia transacciones que ya fueron incluidas en un bloque
    pub fn remove_confirmed(&mut self, block_txids: &[String]) {
        for txid in block_txids {
            self.txs.remove(txid);
        }
        self.save();
    }

    /// Limpia transacciones que ya no son válidas
    pub fn prune_invalid(&mut self, utxo: &UtxoSet, current_height: u64) {
        let invalid: Vec<String> = self.txs
            .iter()
            .filter(|(_, entry)| validate_transaction(&entry.tx, utxo, current_height, false).is_err())
            .map(|(txid, _)| txid.clone())
            .collect();

        for txid in invalid {
            self.txs.remove(&txid);
        }
        
        self.save();
    }

    /// Número de transacciones en el mempool
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Verifica si el mempool está vacío
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Total de fees en el mempool
    pub fn total_fees(&self) -> u64 {
        self.txs.values().map(|e| e.fee).sum()
    }

    /// Limpia todo el mempool
    pub fn clear(&mut self) {
        self.txs.clear();
        let _ = fs::remove_file(PENDING_TX_FILE);
    }
    
    /// Obtiene info de una transacción
    pub fn get_tx_info(&self, txid: &str) -> Option<&MempoolEntry> {
        self.txs.get(txid)
    }
    
    /// Obtiene HashMap de solo transacciones (sin metadata)
    pub fn get_txs_map(&self) -> HashMap<String, Tx> {
        self.txs.iter()
            .map(|(k, v)| (k.clone(), v.tx.clone()))
            .collect()
    }
    
    /// Estima el fee recomendado basado en el mempool actual
    pub fn estimate_fee(&self, target_blocks: usize) -> u64 {
        if self.txs.is_empty() {
            return MIN_RELAY_FEE;
        }
        
        // Obtener fees por byte ordenados
        let mut fees: Vec<u64> = self.txs.values().map(|e| e.fee_per_byte).collect();
        fees.sort_by(|a, b| b.cmp(a));
        
        // Para el próximo bloque, usar el percentil 75
        // Para más bloques, usar percentiles menores
        let percentile = match target_blocks {
            1 => 75,
            2 => 50,
            3..=6 => 25,
            _ => 10,
        };
        
        let index = (fees.len() * percentile / 100).min(fees.len() - 1);
        
        // Multiplicar por un tamaño promedio de tx (250 bytes)
        fees[index] * 250
    }
}

/// Errores del mempool
#[derive(Debug, Clone)]
pub enum MempoolError {
    CoinbaseNotAllowed,
    FeeTooLow { got: u64, min: u64 },
    FeePerByteTooLow { got: u64, min: u64 },
    ValidationFailed(ValidationError),
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CoinbaseNotAllowed => write!(f, "Coinbase transactions not allowed in mempool"),
            Self::FeeTooLow { got, min } => write!(f, "Fee too low: {} < {} minimum", got, min),
            Self::FeePerByteTooLow { got, min } => write!(f, "Fee per byte too low: {} < {} minimum", got, min),
            Self::ValidationFailed(e) => write!(f, "Validation failed: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::TxOut;

    #[test]
    fn test_mempool_basic() {
        let mempool = Mempool::new();
        assert!(mempool.is_empty());
    }
    
    #[test]
    fn test_fee_estimation() {
        let mempool = Mempool::new();
        let fee = mempool.estimate_fee(1);
        assert!(fee >= MIN_RELAY_FEE);
    }
}
