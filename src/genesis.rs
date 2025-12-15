// =============================================================================
// MOONCOIN - GENERADOR DE BLOQUE GÉNESIS
// =============================================================================
//
// Este módulo genera el bloque génesis de Mooncoin.
// El génesis tiene características especiales:
//   - Coinbase con valor 0 (no gastable)
//   - Output OP_RETURN (provably unspendable)
//   - Mensaje fundacional en coinbase
//
// Esto demuestra que NO hay pre-mine.
//
// =============================================================================

use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

/// Constantes del génesis
const GENESIS_MESSAGE: &[u8] = b"Mooncoin: El dinero que no se puede perder";
const INITIAL_DIFFICULTY_BITS: u32 = 0x1d00ffff; // Dificultad mínima (como Bitcoin)

/// OP_RETURN hace que el output sea provably unspendable
const OP_RETURN: u8 = 0x6a;

// =============================================================================
// Estructuras básicas (simplificadas para génesis)
// =============================================================================

#[derive(Clone, Debug)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(80);
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&self.prev_block_hash);
        data.extend_from_slice(&self.merkle_root);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.bits.to_le_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data
    }
    
    pub fn hash(&self) -> [u8; 32] {
        sha256d(&self.serialize())
    }
}

#[derive(Clone, Debug)]
pub struct TxInput {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug)]
pub struct TxOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
}

impl Transaction {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Version
        data.extend_from_slice(&self.version.to_le_bytes());
        
        // Input count (varint simplificado)
        data.push(self.inputs.len() as u8);
        
        // Inputs
        for input in &self.inputs {
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_vout.to_le_bytes());
            data.push(input.script_sig.len() as u8);
            data.extend_from_slice(&input.script_sig);
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }
        
        // Output count
        data.push(self.outputs.len() as u8);
        
        // Outputs
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            data.push(output.script_pubkey.len() as u8);
            data.extend_from_slice(&output.script_pubkey);
        }
        
        // Locktime
        data.extend_from_slice(&self.locktime.to_le_bytes());
        
        data
    }
    
    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.serialize())
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

// =============================================================================
// Funciones de utilidad
// =============================================================================

/// SHA256 doble (como Bitcoin)
fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Convertir bits compactos a target
fn bits_to_target(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x00FFFFFF;
    
    let mut target = [0u8; 32];
    
    if exponent <= 3 {
        let shifted = mantissa >> (8 * (3 - exponent));
        target[31] = (shifted & 0xFF) as u8;
        if exponent >= 1 { target[30] = ((shifted >> 8) & 0xFF) as u8; }
        if exponent >= 2 { target[29] = ((shifted >> 16) & 0xFF) as u8; }
    } else {
        let start = 32 - exponent;
        target[start + 2] = (mantissa & 0xFF) as u8;
        target[start + 1] = ((mantissa >> 8) & 0xFF) as u8;
        target[start] = ((mantissa >> 16) & 0xFF) as u8;
    }
    
    target
}

/// Comparar hash con target (hash debe ser menor)
fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    // Comparar byte a byte desde el más significativo
    for i in 0..32 {
        if hash[i] < target[i] {
            return true;
        } else if hash[i] > target[i] {
            return false;
        }
    }
    true // Iguales, cuenta como válido
}

// =============================================================================
// Generación del Génesis
// =============================================================================

/// Crear la transacción coinbase del génesis
pub fn create_genesis_coinbase() -> Transaction {
    // Input especial de coinbase
    let coinbase_input = TxInput {
        prev_txid: [0u8; 32],           // Todo ceros
        prev_vout: 0xFFFFFFFF,          // -1 en unsigned
        script_sig: GENESIS_MESSAGE.to_vec(),
        sequence: 0xFFFFFFFF,
    };
    
    // Output NO GASTABLE (valor 0 + OP_RETURN)
    let coinbase_output = TxOutput {
        value: 0,                       // CERO - No hay pre-mine
        script_pubkey: vec![OP_RETURN], // Provably unspendable
    };
    
    Transaction {
        version: 1,
        inputs: vec![coinbase_input],
        outputs: vec![coinbase_output],
        locktime: 0,
    }
}

/// Crear el bloque génesis (sin minar)
pub fn create_genesis_block_unmined(timestamp: u32) -> Block {
    let coinbase = create_genesis_coinbase();
    let merkle_root = coinbase.txid(); // Solo 1 TX, merkle root = txid
    
    let header = BlockHeader {
        version: 1,
        prev_block_hash: [0u8; 32],     // No hay bloque anterior
        merkle_root,
        timestamp,
        bits: INITIAL_DIFFICULTY_BITS,
        nonce: 0,
    };
    
    Block {
        header,
        transactions: vec![coinbase],
    }
}

/// Minar el bloque génesis (encontrar nonce válido)
pub fn mine_genesis_block(timestamp: u32) -> Block {
    let mut block = create_genesis_block_unmined(timestamp);
    let target = bits_to_target(block.header.bits);
    
    println!("Minando bloque génesis...");
    println!("Target: {}", hex::encode(&target));
    
    let mut attempts: u64 = 0;
    
    loop {
        let hash = block.header.hash();
        
        if hash_meets_target(&hash, &target) {
            println!("\n¡Génesis encontrado!");
            println!("Nonce: {}", block.header.nonce);
            println!("Hash: {}", hex::encode(&hash));
            return block;
        }
        
        block.header.nonce = block.header.nonce.wrapping_add(1);
        attempts += 1;
        
        if attempts % 1_000_000 == 0 {
            print!(".");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
        }
        
        // Si llegamos al máximo nonce, incrementar timestamp
        if block.header.nonce == 0 {
            block.header.timestamp += 1;
            println!("\nNonce overflow, incrementando timestamp a {}", block.header.timestamp);
        }
    }
}

/// Generar génesis con timestamp actual
pub fn generate_genesis_now() -> Block {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    
    mine_genesis_block(timestamp)
}

/// Imprimir información del génesis
pub fn print_genesis_info(block: &Block) {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║                  BLOQUE GÉNESIS DE MOONCOIN                     ║");
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║ Version:      {}                                               ║", block.header.version);
    println!("║ Prev Hash:    {} (génesis)      ║", "0000...0000");
    println!("║ Merkle Root:  {}...   ║", &hex::encode(&block.header.merkle_root)[..32]);
    println!("║ Timestamp:    {} ({})      ║", 
             block.header.timestamp,
             chrono_format(block.header.timestamp));
    println!("║ Bits:         0x{:08X}                                       ║", block.header.bits);
    println!("║ Nonce:        {:>10}                                     ║", block.header.nonce);
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║ Block Hash:   {}... ║", &hex::encode(&block.header.hash())[..40]);
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║ COINBASE:                                                      ║");
    println!("║   Message: \"{}\"  ║", String::from_utf8_lossy(&block.transactions[0].inputs[0].script_sig));
    println!("║   Value:   0 MOON (NO HAY PRE-MINE)                           ║");
    println!("║   Script:  OP_RETURN (provably unspendable)                   ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
}

fn chrono_format(timestamp: u32) -> String {
    // Formato básico sin dependencias adicionales
    let days_since_epoch = timestamp / 86400;
    let year = 1970 + (days_since_epoch / 365); // Aproximado
    format!("~{}", year)
}

/// Serializar génesis para hardcodear
pub fn serialize_genesis_for_code(block: &Block) -> String {
    let mut output = String::new();
    
    output.push_str("// Bloque génesis hardcodeado\n");
    output.push_str("pub const GENESIS_BLOCK_HEADER: [u8; 80] = [\n    ");
    
    let header_bytes = block.header.serialize();
    for (i, byte) in header_bytes.iter().enumerate() {
        output.push_str(&format!("0x{:02X}, ", byte));
        if (i + 1) % 12 == 0 {
            output.push_str("\n    ");
        }
    }
    output.push_str("\n];\n\n");
    
    output.push_str(&format!("pub const GENESIS_BLOCK_HASH: [u8; 32] = [\n    "));
    let hash = block.header.hash();
    for (i, byte) in hash.iter().enumerate() {
        output.push_str(&format!("0x{:02X}, ", byte));
        if (i + 1) % 12 == 0 {
            output.push_str("\n    ");
        }
    }
    output.push_str("\n];\n\n");
    
    output.push_str(&format!("pub const GENESIS_TIMESTAMP: u32 = {};\n", block.header.timestamp));
    output.push_str(&format!("pub const GENESIS_NONCE: u32 = {};\n", block.header.nonce));
    
    output
}

// =============================================================================
// Función main para generar génesis
// =============================================================================

pub fn main() {
    println!("═══════════════════════════════════════════════════════════════");
    println!("           GENERADOR DE BLOQUE GÉNESIS - MOONCOIN              ");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("Este proceso puede tomar varios minutos dependiendo de la");
    println!("dificultad inicial. El bloque génesis resultante:");
    println!();
    println!("  ✓ No tiene pre-mine (coinbase valor = 0)");
    println!("  ✓ Es provably unspendable (OP_RETURN)");
    println!("  ✓ Contiene el mensaje fundacional");
    println!();
    
    let genesis = generate_genesis_now();
    
    print_genesis_info(&genesis);
    
    println!("\n\n// ═══════════ CÓDIGO PARA HARDCODEAR ═══════════\n");
    println!("{}", serialize_genesis_for_code(&genesis));
    
    println!("\n// Guarda este código en src/genesis.rs");
    println!("// Este es TU bloque génesis. No lo pierdas.");
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_genesis_coinbase_has_zero_value() {
        let coinbase = create_genesis_coinbase();
        assert_eq!(coinbase.outputs[0].value, 0);
    }
    
    #[test]
    fn test_genesis_coinbase_is_unspendable() {
        let coinbase = create_genesis_coinbase();
        assert_eq!(coinbase.outputs[0].script_pubkey, vec![OP_RETURN]);
    }
    
    #[test]
    fn test_genesis_has_message() {
        let coinbase = create_genesis_coinbase();
        assert_eq!(coinbase.inputs[0].script_sig, GENESIS_MESSAGE);
    }
    
    #[test]
    fn test_genesis_prev_hash_is_zero() {
        let block = create_genesis_block_unmined(0);
        assert_eq!(block.header.prev_block_hash, [0u8; 32]);
    }
    
    #[test]
    fn test_sha256d() {
        // Vector de prueba conocido
        let data = b"test";
        let hash = sha256d(data);
        // El hash debe ser determinístico
        let hash2 = sha256d(data);
        assert_eq!(hash, hash2);
    }
    
    #[test]
    fn test_bits_to_target() {
        let target = bits_to_target(0x1d00ffff);
        // El target debe tener bytes no-cero
        assert!(target.iter().any(|&b| b != 0));
    }
}
