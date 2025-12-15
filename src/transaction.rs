// =============================================================================
// MOONCOIN v2.0 - Transacciones (UTXO Model)
// =============================================================================

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Salida de transacción (a quién y cuánto)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TxOut {
    pub to: String,      // Address del destinatario
    pub amount: u64,     // Cantidad en satoshis
}

/// Entrada de transacción (referencia a UTXO anterior)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TxIn {
    pub prev_tx_hash: String,  // Hash de la transacción anterior
    pub prev_index: u32,       // Índice del output en esa transacción
    pub signature: Vec<u8>,    // Firma DER
    pub pubkey: Vec<u8>,       // Clave pública serializada (33 bytes compressed)
}

/// Transacción completa
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Tx {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
}

impl Tx {
    /// Crea una transacción coinbase (sin inputs)
    pub fn new_coinbase(to: String, amount: u64, height: u64) -> Self {
        // Coinbase tiene un input "vacío" con datos del bloque
        let coinbase_data = format!("coinbase:{}", height);
        Tx {
            inputs: vec![TxIn {
                prev_tx_hash: "0".repeat(64),
                prev_index: 0xFFFFFFFF,  // Marker de coinbase
                signature: coinbase_data.as_bytes().to_vec(),
                pubkey: vec![],
            }],
            outputs: vec![TxOut { to, amount }],
        }
    }

    /// Verifica si es una transacción coinbase
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 
            && self.inputs[0].prev_tx_hash == "0".repeat(64)
            && self.inputs[0].prev_index == 0xFFFFFFFF
    }

    /// Suma total de outputs
    pub fn output_sum(&self) -> u64 {
        self.outputs.iter().map(|o| o.amount).sum()
    }
}

/// Serializa la transacción para firmar (sin firmas ni pubkeys)
pub fn tx_serialize_for_signing(tx: &Tx) -> Vec<u8> {
    let mut tx_copy = tx.clone();
    for inp in &mut tx_copy.inputs {
        inp.signature = vec![];
        inp.pubkey = vec![];
    }
    bincode::serialize(&tx_copy).expect("Failed to serialize tx for signing")
}

/// Calcula el hash de una transacción (double SHA-256, como Bitcoin)
pub fn tx_hash(tx: &Tx) -> String {
    let data = bincode::serialize(tx).expect("Failed to serialize tx");
    let first_hash = Sha256::digest(&data);
    let second_hash = Sha256::digest(&first_hash);
    hex::encode(second_hash)
}

/// Calcula el txid (usado para referencias)
pub fn txid(tx: &Tx) -> String {
    tx_hash(tx)
}

/// Calcula el tamaño en bytes de una transacción
pub fn tx_size(tx: &Tx) -> usize {
    bincode::serialize(tx).map(|d| d.len()).unwrap_or(0)
}

/// Calcula el fee de una transacción dado el input_sum y output_sum
pub fn calculate_fee(input_sum: u64, output_sum: u64) -> u64 {
    input_sum.saturating_sub(output_sum)
}

/// Calcula el fee por byte de una transacción
pub fn fee_per_byte(fee: u64, size: usize) -> u64 {
    if size == 0 { 0 } else { fee / size as u64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coinbase() {
        let cb = Tx::new_coinbase("MCtest123".to_string(), 50_00000000, 0);
        assert!(cb.is_coinbase());
        assert_eq!(cb.output_sum(), 50_00000000);
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let tx = Tx {
            inputs: vec![],
            outputs: vec![TxOut { to: "MCtest".to_string(), amount: 100 }],
        };
        let h1 = tx_hash(&tx);
        let h2 = tx_hash(&tx);
        assert_eq!(h1, h2);
    }
}
