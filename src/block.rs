// =============================================================================
// MOONCOIN v2.0 - Bloques y Minería
// =============================================================================

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::lib::*;
use crate::transaction::{Tx, tx_hash};

/// Estructura de un bloque
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Block {
    pub height: u64,
    pub timestamp: u64,
    pub prev_hash: String,
    pub merkle_root: String,
    pub difficulty_bits: u32,
    pub nonce: u64,
    pub hash: String,
    pub txs: Vec<Tx>,
}

impl Block {
    /// Calcula el hash del bloque (double SHA-256)
    pub fn calculate_hash(&self) -> String {
        let header = format!(
            "{}{}{}{}{}{}",
            self.height,
            self.prev_hash,
            self.merkle_root,
            self.timestamp,
            self.difficulty_bits,
            self.nonce
        );
        let first = Sha256::digest(header.as_bytes());
        let second = Sha256::digest(&first);
        hex::encode(second)
    }

    /// Verifica que el hash sea válido para la dificultad
    pub fn hash_meets_difficulty(&self) -> bool {
        let target = difficulty_bits_to_target(self.difficulty_bits);
        self.hash <= target
    }

    /// Verifica la integridad del bloque
    pub fn verify(&self) -> bool {
        // Verificar que el hash almacenado es correcto
        if self.hash != self.calculate_hash() {
            return false;
        }
        
        // Verificar merkle root
        if self.merkle_root != merkle_root(&self.txs) {
            return false;
        }
        
        // Verificar dificultad
        if !self.hash_meets_difficulty() {
            return false;
        }
        
        true
    }
}

/// Calcula el merkle root de las transacciones
pub fn merkle_root(txs: &[Tx]) -> String {
    if txs.is_empty() {
        return "0".repeat(64);
    }
    
    let mut hashes: Vec<String> = txs.iter().map(|t| tx_hash(t)).collect();
    
    while hashes.len() > 1 {
        // Si es impar, duplicar el último
        if hashes.len() % 2 == 1 {
            let last = hashes.last().unwrap().clone();
            hashes.push(last);
        }
        
        let mut new_level = Vec::new();
        for i in (0..hashes.len()).step_by(2) {
            let combined = format!("{}{}", hashes[i], hashes[i + 1]);
            let first = Sha256::digest(combined.as_bytes());
            let second = Sha256::digest(&first);
            new_level.push(hex::encode(second));
        }
        hashes = new_level;
    }
    
    hashes[0].clone()
}

/// Convierte difficulty_bits a target string para comparación
pub fn difficulty_bits_to_target(bits: u32) -> String {
    // bits representa cuántos bits iniciales deben ser 0
    // Para comparación de strings hex, generamos un target
    let zeros = (bits / 4) as usize;
    let remainder = bits % 4;
    
    let first_char = match remainder {
        0 => 'f',
        1 => '7',
        2 => '3',
        3 => '1',
        _ => 'f',
    };
    
    let mut target = "0".repeat(zeros);
    target.push(first_char);
    
    // Rellenar hasta 64 caracteres
    while target.len() < 64 {
        target.push('f');
    }
    
    target
}

/// Mina un bloque con la dificultad especificada
pub fn mine_block(
    height: u64,
    prev_hash: &str,
    txs: Vec<Tx>,
    difficulty_bits: u32,
) -> Block {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time error")
        .as_secs();
    
    let merkle = merkle_root(&txs);
    let target = difficulty_bits_to_target(difficulty_bits);
    
    let mut nonce = 0u64;
    let hash;
    
    loop {
        let header = format!(
            "{}{}{}{}{}{}",
            height, prev_hash, merkle, timestamp, difficulty_bits, nonce
        );
        let first = Sha256::digest(header.as_bytes());
        let second = Sha256::digest(&first);
        let h = hex::encode(second);
        
        if h <= target {
            hash = h;
            break;
        }
        
        nonce += 1;
    }
    
    Block {
        height,
        timestamp,
        prev_hash: prev_hash.to_string(),
        merkle_root: merkle,
        difficulty_bits,
        nonce,
        hash,
        txs,
    }
}

/// Crea el bloque génesis
pub fn create_genesis_block(miner_address: &str) -> Block {
    let coinbase = Tx::new_coinbase(miner_address.to_string(), INITIAL_REWARD, 0);
    
    let txs = vec![coinbase];
    let merkle = merkle_root(&txs);
    
    let timestamp = GENESIS_TIMESTAMP;
    let difficulty_bits = INITIAL_DIFFICULTY_BITS;
    let target = difficulty_bits_to_target(difficulty_bits);
    
    let mut nonce = 0u64;
    let hash;
    
    loop {
        let header = format!(
            "{}{}{}{}{}{}",
            0, GENESIS_PREV_HASH, merkle, timestamp, difficulty_bits, nonce
        );
        let first = Sha256::digest(header.as_bytes());
        let second = Sha256::digest(&first);
        let h = hex::encode(second);
        
        if h <= target {
            hash = h;
            break;
        }
        nonce += 1;
    }
    
    Block {
        height: 0,
        timestamp,
        prev_hash: GENESIS_PREV_HASH.to_string(),
        merkle_root: merkle,
        difficulty_bits,
        nonce,
        hash,
        txs,
    }
}

// =============================================================================
// Persistencia de la cadena
// =============================================================================

/// Carga la cadena desde disco
pub fn load_chain() -> Vec<Block> {
    if let Ok(data) = fs::read(DATA_FILE) {
        bincode::deserialize(&data).unwrap_or_else(|e| {
            log::error!("Error deserializando cadena: {}", e);
            vec![]
        })
    } else {
        vec![]
    }
}

/// Guarda la cadena a disco con backup
pub fn save_chain(chain: &[Block]) {
    let data = bincode::serialize(chain).expect("Failed to serialize chain");
    
    // Backup del archivo anterior
    if fs::metadata(DATA_FILE).is_ok() {
        let _ = fs::copy(DATA_FILE, DATA_FILE_BACKUP);
    }
    
    fs::write(DATA_FILE, &data).expect("Failed to save chain");
    log::debug!("Cadena guardada: {} bloques", chain.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_single() {
        let tx = Tx::new_coinbase("MCtest".to_string(), 50, 0);
        let root = merkle_root(&[tx.clone()]);
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn test_merkle_root_multiple() {
        let tx1 = Tx::new_coinbase("MC1".to_string(), 50, 0);
        let tx2 = Tx::new_coinbase("MC2".to_string(), 25, 1);
        let root = merkle_root(&[tx1, tx2]);
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn test_difficulty_target() {
        let target = difficulty_bits_to_target(16);
        assert!(target.starts_with("0000"));
    }

    #[test]
    fn test_block_verify() {
        let block = mine_block(
            1,
            &"0".repeat(64),
            vec![Tx::new_coinbase("MCtest".to_string(), 50, 1)],
            16,
        );
        assert!(block.verify());
    }
}
