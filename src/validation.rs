// =============================================================================
// MOONCOIN v2.0 - Validación de Transacciones y Bloques
// =============================================================================

use crate::lib::*;
use crate::block::Block;
use crate::transaction::{Tx, tx_hash};
use crate::utxo::{UtxoSet, UtxoKey};
use crate::wallet::{verify_signature, address_from_pubkey_bytes};

/// Errores de validación
#[derive(Debug, Clone)]
pub enum ValidationError {
    // Errores de transacción
    EmptyOutputs,
    InvalidSignature(usize),  // índice del input
    MissingUtxo(String, u32), // tx_hash, index
    InsufficientFunds { input_sum: u64, output_sum: u64 },
    CoinbaseInNonFirstPosition,
    MultipleCoinbases,
    InvalidCoinbaseAmount { expected: u64, got: u64 },
    SpendingImmatureCoinbase { height: u64, current: u64 },
    OwnershipMismatch { expected: String, got: String },
    
    // Errores de bloque
    InvalidBlockHash,
    InvalidMerkleRoot,
    DifficultyNotMet,
    InvalidPreviousHash,
    InvalidHeight { expected: u64, got: u64 },
    TimestampTooOld,
    TimestampTooNew,
    BlockTooLarge,
    TooManyTransactions,
    NoCoinbase,
    InvalidDifficulty { expected: u32, got: u32 },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyOutputs => write!(f, "Transaction has no outputs"),
            Self::InvalidSignature(i) => write!(f, "Invalid signature at input {}", i),
            Self::MissingUtxo(h, i) => write!(f, "UTXO not found: {}:{}", h, i),
            Self::InsufficientFunds { input_sum, output_sum } => {
                write!(f, "Insufficient funds: {} < {}", input_sum, output_sum)
            }
            Self::CoinbaseInNonFirstPosition => write!(f, "Coinbase must be first transaction"),
            Self::MultipleCoinbases => write!(f, "Block has multiple coinbase transactions"),
            Self::InvalidCoinbaseAmount { expected, got } => {
                write!(f, "Invalid coinbase amount: expected {}, got {}", expected, got)
            }
            Self::SpendingImmatureCoinbase { height, current } => {
                write!(f, "Spending immature coinbase from height {} at height {}", height, current)
            }
            Self::OwnershipMismatch { expected, got } => {
                write!(f, "UTXO ownership mismatch: expected {}, got {}", expected, got)
            }
            Self::InvalidBlockHash => write!(f, "Block hash is invalid"),
            Self::InvalidMerkleRoot => write!(f, "Merkle root mismatch"),
            Self::DifficultyNotMet => write!(f, "Block hash does not meet difficulty"),
            Self::InvalidPreviousHash => write!(f, "Previous hash mismatch"),
            Self::InvalidHeight { expected, got } => {
                write!(f, "Invalid height: expected {}, got {}", expected, got)
            }
            Self::TimestampTooOld => write!(f, "Block timestamp too old"),
            Self::TimestampTooNew => write!(f, "Block timestamp too far in future"),
            Self::BlockTooLarge => write!(f, "Block exceeds maximum size"),
            Self::TooManyTransactions => write!(f, "Block has too many transactions"),
            Self::NoCoinbase => write!(f, "Block has no coinbase transaction"),
            Self::InvalidDifficulty { expected, got } => {
                write!(f, "Invalid difficulty: expected {}, got {}", expected, got)
            }
        }
    }
}

/// Valida una transacción contra el UTXO set
pub fn validate_transaction(
    tx: &Tx,
    utxo: &UtxoSet,
    current_height: u64,
    allow_coinbase: bool,
) -> Result<(), ValidationError> {
    // Coinbase tiene reglas especiales
    if tx.is_coinbase() {
        if !allow_coinbase {
            return Err(ValidationError::CoinbaseInNonFirstPosition);
        }
        // Coinbase válida si tiene outputs
        if tx.outputs.is_empty() {
            return Err(ValidationError::EmptyOutputs);
        }
        return Ok(());
    }

    // Transacción regular
    if tx.outputs.is_empty() {
        return Err(ValidationError::EmptyOutputs);
    }

    let mut input_sum = 0u64;

    for (i, input) in tx.inputs.iter().enumerate() {
        let key: UtxoKey = (input.prev_tx_hash.clone(), input.prev_index);

        // Verificar que el UTXO existe
        let entry = utxo.get(&key).ok_or_else(|| {
            ValidationError::MissingUtxo(input.prev_tx_hash.clone(), input.prev_index)
        })?;

        // Verificar coinbase maturity
        if entry.is_coinbase && current_height < entry.height + COINBASE_MATURITY {
            return Err(ValidationError::SpendingImmatureCoinbase {
                height: entry.height,
                current: current_height,
            });
        }

        // Verificar ownership: la pubkey debe derivar la address del UTXO
        if !input.pubkey.is_empty() {
            let signer_address = address_from_pubkey_bytes(&input.pubkey)
                .ok_or_else(|| ValidationError::InvalidSignature(i))?;
            
            if signer_address != entry.output.to {
                return Err(ValidationError::OwnershipMismatch {
                    expected: entry.output.to.clone(),
                    got: signer_address,
                });
            }
        }

        // Verificar firma
        if !verify_signature(tx, i) {
            return Err(ValidationError::InvalidSignature(i));
        }

        input_sum += entry.output.amount;
    }

    let output_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();

    // Verificar que inputs >= outputs (la diferencia es fee)
    if input_sum < output_sum {
        return Err(ValidationError::InsufficientFunds { input_sum, output_sum });
    }

    Ok(())
}

/// Valida un bloque completo
pub fn validate_block(
    block: &Block,
    chain: &[Block],
    utxo: &UtxoSet,
    expected_difficulty: u32,
) -> Result<(), ValidationError> {
    // Verificar hash del bloque
    if block.hash != block.calculate_hash() {
        return Err(ValidationError::InvalidBlockHash);
    }

    // Verificar merkle root
    let expected_merkle = crate::block::merkle_root(&block.txs);
    if block.merkle_root != expected_merkle {
        return Err(ValidationError::InvalidMerkleRoot);
    }

    // Verificar dificultad
    if block.difficulty_bits != expected_difficulty {
        return Err(ValidationError::InvalidDifficulty {
            expected: expected_difficulty,
            got: block.difficulty_bits,
        });
    }

    // Verificar que el hash cumple la dificultad
    if !block.hash_meets_difficulty() {
        return Err(ValidationError::DifficultyNotMet);
    }

    // Verificar altura
    let expected_height = chain.len() as u64;
    if block.height != expected_height {
        return Err(ValidationError::InvalidHeight {
            expected: expected_height,
            got: block.height,
        });
    }

    // Verificar previous hash
    if !chain.is_empty() {
        let last = chain.last().unwrap();
        if block.prev_hash != last.hash {
            return Err(ValidationError::InvalidPreviousHash);
        }
    }

    // Verificar timestamp (no más de 2 horas en el futuro)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    if block.timestamp > now + 7200 {
        return Err(ValidationError::TimestampTooNew);
    }

    // Verificar tamaño del bloque
    let block_size = bincode::serialize(&block).map(|b| b.len()).unwrap_or(0);
    if block_size > MAX_BLOCK_SIZE {
        return Err(ValidationError::BlockTooLarge);
    }

    // Verificar número de transacciones
    if block.txs.len() > MAX_TXS_PER_BLOCK {
        return Err(ValidationError::TooManyTransactions);
    }

    // Verificar transacciones
    if block.txs.is_empty() {
        return Err(ValidationError::NoCoinbase);
    }

    // Primera transacción debe ser coinbase
    if !block.txs[0].is_coinbase() {
        return Err(ValidationError::NoCoinbase);
    }

    // Verificar que solo hay una coinbase
    let coinbase_count = block.txs.iter().filter(|tx| tx.is_coinbase()).count();
    if coinbase_count != 1 {
        return Err(ValidationError::MultipleCoinbases);
    }

    // Verificar monto de coinbase
    let expected_reward = get_reward(block.height);
    let fees: u64 = calculate_block_fees(block, utxo);
    let max_coinbase = expected_reward + fees;
    let coinbase_amount = block.txs[0].output_sum();
    
    if coinbase_amount > max_coinbase {
        return Err(ValidationError::InvalidCoinbaseAmount {
            expected: max_coinbase,
            got: coinbase_amount,
        });
    }

    // Validar cada transacción (excepto coinbase que ya validamos)
    let mut temp_utxo = utxo.clone();
    for (i, tx) in block.txs.iter().enumerate() {
        validate_transaction(tx, &temp_utxo, block.height, i == 0)?;
        
        // Aplicar tx al utxo temporal para validar las siguientes
        let txid = tx_hash(tx);
        for input in &tx.inputs {
            if !tx.is_coinbase() {
                temp_utxo.utxos.remove(&(input.prev_tx_hash.clone(), input.prev_index));
            }
        }
        for (idx, output) in tx.outputs.iter().enumerate() {
            temp_utxo.utxos.insert(
                (txid.clone(), idx as u32),
                crate::utxo::UtxoEntry {
                    output: output.clone(),
                    height: block.height,
                    is_coinbase: tx.is_coinbase(),
                },
            );
        }
    }

    Ok(())
}

/// Calcula los fees de un bloque
fn calculate_block_fees(block: &Block, utxo: &UtxoSet) -> u64 {
    let mut total_fees = 0u64;
    
    for tx in &block.txs {
        if tx.is_coinbase() {
            continue;
        }
        
        let input_sum: u64 = tx.inputs.iter()
            .filter_map(|inp| {
                utxo.get(&(inp.prev_tx_hash.clone(), inp.prev_index))
                    .map(|e| e.output.amount)
            })
            .sum();
        
        let output_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        
        if input_sum > output_sum {
            total_fees += input_sum - output_sum;
        }
    }
    
    total_fees
}

/// Valida una cadena completa desde génesis
pub fn validate_chain(chain: &[Block]) -> Result<(), (usize, ValidationError)> {
    let mut utxo = UtxoSet::new();
    
    for (i, block) in chain.iter().enumerate() {
        let expected_difficulty = if i == 0 {
            INITIAL_DIFFICULTY_BITS
        } else {
            crate::difficulty::calculate_next_difficulty(&chain[..i])
        };
        
        let chain_so_far = &chain[..i];
        
        if let Err(e) = validate_block(block, chain_so_far, &utxo, expected_difficulty) {
            return Err((i, e));
        }
        
        utxo.apply_block(block);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{TxIn, TxOut};

    #[test]
    fn test_validate_coinbase() {
        let utxo = UtxoSet::new();
        let coinbase = Tx::new_coinbase("MCtest".to_string(), 50_00000000, 0);
        
        assert!(validate_transaction(&coinbase, &utxo, 0, true).is_ok());
        assert!(validate_transaction(&coinbase, &utxo, 0, false).is_err());
    }

    #[test]
    fn test_validate_missing_utxo() {
        let utxo = UtxoSet::new();
        let tx = Tx {
            inputs: vec![TxIn {
                prev_tx_hash: "nonexistent".to_string(),
                prev_index: 0,
                signature: vec![1, 2, 3],
                pubkey: vec![4, 5, 6],
            }],
            outputs: vec![TxOut {
                to: "MCtest".to_string(),
                amount: 100,
            }],
        };
        
        let result = validate_transaction(&tx, &utxo, 0, false);
        assert!(matches!(result, Err(ValidationError::MissingUtxo(_, _))));
    }
}
