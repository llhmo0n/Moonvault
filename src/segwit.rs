// =============================================================================
// MOONCOIN v2.0 - SegWit (Segregated Witness)
// =============================================================================
//
// Implementación de SegWit (BIP141, BIP143, BIP173):
// - Witness data separado de scriptSig
// - Nuevo formato de serialización para firmas
// - Direcciones Bech32 (mc1...)
// - P2WPKH (Pay to Witness Public Key Hash)
// - P2WSH (Pay to Witness Script Hash)
//
// =============================================================================

use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use serde::{Serialize, Deserialize};

use crate::transaction::{Tx, TxIn, TxOut};
use crate::script::{Script, OpCode};

// =============================================================================
// Constants
// =============================================================================

/// Witness version 0 (para P2WPKH y P2WSH)
pub const WITNESS_V0: u8 = 0x00;

/// Witness version 1 (para Taproot - futuro)
pub const WITNESS_V1: u8 = 0x01;

/// Human-readable part para direcciones Bech32 mainnet
pub const BECH32_HRP: &str = "mc";

/// Tamaño de witness program para P2WPKH (20 bytes)
pub const P2WPKH_PROGRAM_SIZE: usize = 20;

/// Tamaño de witness program para P2WSH (32 bytes)
pub const P2WSH_PROGRAM_SIZE: usize = 32;

// =============================================================================
// Witness Data
// =============================================================================

/// Witness stack para un input
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Witness {
    /// Stack de witness items
    pub stack: Vec<Vec<u8>>,
}

impl Witness {
    pub fn new() -> Self {
        Witness { stack: Vec::new() }
    }
    
    /// Crea witness para P2WPKH (signature + pubkey)
    pub fn p2wpkh(signature: Vec<u8>, pubkey: Vec<u8>) -> Self {
        Witness {
            stack: vec![signature, pubkey],
        }
    }
    
    /// Crea witness para P2WSH (items + redeem_script)
    pub fn p2wsh(items: Vec<Vec<u8>>, redeem_script: Vec<u8>) -> Self {
        let mut stack = items;
        stack.push(redeem_script);
        Witness { stack }
    }
    
    /// Verifica si el witness está vacío
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
    
    /// Número de items en el witness
    pub fn len(&self) -> usize {
        self.stack.len()
    }
    
    /// Serializa el witness
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Número de items (varint)
        bytes.push(self.stack.len() as u8);
        
        // Cada item
        for item in &self.stack {
            // Longitud del item (varint)
            if item.len() < 0xfd {
                bytes.push(item.len() as u8);
            } else {
                bytes.push(0xfd);
                bytes.extend(&(item.len() as u16).to_le_bytes());
            }
            bytes.extend(item);
        }
        
        bytes
    }
    
    /// Deserializa el witness
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), String> {
        if data.is_empty() {
            return Ok((Witness::new(), 0));
        }
        
        let mut pos = 0;
        let count = data[pos] as usize;
        pos += 1;
        
        let mut stack = Vec::new();
        
        for _ in 0..count {
            if pos >= data.len() {
                return Err("Unexpected end of witness data".to_string());
            }
            
            let len = if data[pos] < 0xfd {
                let l = data[pos] as usize;
                pos += 1;
                l
            } else {
                pos += 1;
                if pos + 2 > data.len() {
                    return Err("Invalid witness length".to_string());
                }
                let l = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                l
            };
            
            if pos + len > data.len() {
                return Err("Witness item exceeds data".to_string());
            }
            
            stack.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        
        Ok((Witness { stack }, pos))
    }
}

// =============================================================================
// SegWit Transaction
// =============================================================================

/// Transacción con soporte SegWit
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SegWitTx {
    /// Version (típicamente 1 o 2)
    pub version: i32,
    /// Marker (0x00 para SegWit)
    pub marker: u8,
    /// Flag (0x01 para SegWit)
    pub flag: u8,
    /// Inputs
    pub inputs: Vec<TxIn>,
    /// Outputs
    pub outputs: Vec<TxOut>,
    /// Witness data (uno por input)
    pub witness: Vec<Witness>,
    /// Locktime
    pub locktime: u32,
}

impl SegWitTx {
    /// Crea una nueva transacción SegWit
    pub fn new() -> Self {
        SegWitTx {
            version: 2,
            marker: 0x00,
            flag: 0x01,
            inputs: Vec::new(),
            outputs: Vec::new(),
            witness: Vec::new(),
            locktime: 0,
        }
    }
    
    /// Convierte desde transacción legacy
    pub fn from_legacy(tx: &Tx) -> Self {
        SegWitTx {
            version: 2,
            marker: 0x00,
            flag: 0x01,
            inputs: tx.inputs.clone(),
            outputs: tx.outputs.clone(),
            witness: vec![Witness::new(); tx.inputs.len()],
            locktime: 0,
        }
    }
    
    /// Convierte a transacción legacy (pierde witness)
    pub fn to_legacy(&self) -> Tx {
        Tx {
            inputs: self.inputs.clone(),
            outputs: self.outputs.clone(),
        }
    }
    
    /// Verifica si tiene witness data
    pub fn has_witness(&self) -> bool {
        self.witness.iter().any(|w| !w.is_empty())
    }
    
    /// Calcula el txid (sin witness)
    pub fn txid(&self) -> String {
        let legacy = self.to_legacy();
        let data = bincode::serialize(&legacy).expect("Failed to serialize");
        let hash1 = Sha256::digest(&data);
        let hash2 = Sha256::digest(&hash1);
        hex::encode(hash2)
    }
    
    /// Calcula el wtxid (con witness)
    pub fn wtxid(&self) -> String {
        if !self.has_witness() {
            return self.txid();
        }
        
        let data = self.serialize_with_witness();
        let hash1 = Sha256::digest(&data);
        let hash2 = Sha256::digest(&hash1);
        hex::encode(hash2)
    }
    
    /// Serializa sin witness (para txid)
    pub fn serialize_without_witness(&self) -> Vec<u8> {
        let legacy = self.to_legacy();
        bincode::serialize(&legacy).expect("Failed to serialize")
    }
    
    /// Serializa con witness (para wtxid y transmisión)
    pub fn serialize_with_witness(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Version
        data.extend(&self.version.to_le_bytes());
        
        // Marker y flag para SegWit
        if self.has_witness() {
            data.push(self.marker);
            data.push(self.flag);
        }
        
        // Inputs count (varint)
        data.push(self.inputs.len() as u8);
        
        // Inputs
        for input in &self.inputs {
            // Previous outpoint
            data.extend(hex::decode(&input.prev_tx_hash).unwrap_or_default());
            data.extend(&input.prev_index.to_le_bytes());
            // ScriptSig length y contenido
            let script_len = input.signature.len() + input.pubkey.len();
            data.push(script_len as u8);
            data.extend(&input.signature);
            data.extend(&input.pubkey);
            // Sequence
            data.extend(&0xffffffffu32.to_le_bytes());
        }
        
        // Outputs count (varint)
        data.push(self.outputs.len() as u8);
        
        // Outputs
        for output in &self.outputs {
            data.extend(&output.amount.to_le_bytes());
            let script = output.to.as_bytes();
            data.push(script.len() as u8);
            data.extend(script);
        }
        
        // Witness
        if self.has_witness() {
            for w in &self.witness {
                data.extend(w.to_bytes());
            }
        }
        
        // Locktime
        data.extend(&self.locktime.to_le_bytes());
        
        data
    }
    
    /// Calcula el peso de la transacción (weight units)
    pub fn weight(&self) -> usize {
        let base_size = self.serialize_without_witness().len();
        let total_size = self.serialize_with_witness().len();
        let witness_size = total_size - base_size;
        
        // Weight = base_size * 4 + witness_size
        base_size * 4 + witness_size
    }
    
    /// Calcula el virtual size (vbytes)
    pub fn vsize(&self) -> usize {
        (self.weight() + 3) / 4
    }
}

impl Default for SegWitTx {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// BIP143 - SegWit Signature Hash
// =============================================================================

/// Calcula el hash para firmar en SegWit (BIP143)
pub fn segwit_sighash(
    tx: &SegWitTx,
    input_index: usize,
    script_code: &[u8],
    value: u64,
    sighash_type: u32,
) -> [u8; 32] {
    let mut preimage = Vec::new();
    
    // 1. nVersion
    preimage.extend(&tx.version.to_le_bytes());
    
    // 2. hashPrevouts
    let prevouts_hash = if sighash_type & 0x80 == 0 {
        let mut prevouts = Vec::new();
        for input in &tx.inputs {
            prevouts.extend(hex::decode(&input.prev_tx_hash).unwrap_or_default());
            prevouts.extend(&input.prev_index.to_le_bytes());
        }
        double_sha256(&prevouts)
    } else {
        [0u8; 32]
    };
    preimage.extend(&prevouts_hash);
    
    // 3. hashSequence
    let sequence_hash = if sighash_type & 0x80 == 0 && sighash_type & 0x1f != 0x02 && sighash_type & 0x1f != 0x03 {
        let mut sequences = Vec::new();
        for _ in &tx.inputs {
            sequences.extend(&0xffffffffu32.to_le_bytes());
        }
        double_sha256(&sequences)
    } else {
        [0u8; 32]
    };
    preimage.extend(&sequence_hash);
    
    // 4. outpoint
    preimage.extend(hex::decode(&tx.inputs[input_index].prev_tx_hash).unwrap_or_default());
    preimage.extend(&tx.inputs[input_index].prev_index.to_le_bytes());
    
    // 5. scriptCode
    preimage.push(script_code.len() as u8);
    preimage.extend(script_code);
    
    // 6. value
    preimage.extend(&value.to_le_bytes());
    
    // 7. nSequence
    preimage.extend(&0xffffffffu32.to_le_bytes());
    
    // 8. hashOutputs
    let outputs_hash = if sighash_type & 0x1f != 0x02 && sighash_type & 0x1f != 0x03 {
        let mut outputs = Vec::new();
        for output in &tx.outputs {
            outputs.extend(&output.amount.to_le_bytes());
            let script = output.to.as_bytes();
            outputs.push(script.len() as u8);
            outputs.extend(script);
        }
        double_sha256(&outputs)
    } else if sighash_type & 0x1f == 0x03 && input_index < tx.outputs.len() {
        let mut outputs = Vec::new();
        outputs.extend(&tx.outputs[input_index].amount.to_le_bytes());
        let script = tx.outputs[input_index].to.as_bytes();
        outputs.push(script.len() as u8);
        outputs.extend(script);
        double_sha256(&outputs)
    } else {
        [0u8; 32]
    };
    preimage.extend(&outputs_hash);
    
    // 9. nLockTime
    preimage.extend(&tx.locktime.to_le_bytes());
    
    // 10. sighash type
    preimage.extend(&sighash_type.to_le_bytes());
    
    double_sha256(&preimage)
}

// =============================================================================
// Bech32 Encoding (BIP173)
// =============================================================================

const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Codifica datos en Bech32
pub fn bech32_encode(hrp: &str, data: &[u8], witness_version: u8) -> Result<String, String> {
    // Convertir a 5-bit groups
    let mut values = vec![witness_version];
    values.extend(convert_bits(data, 8, 5, true)?);
    
    // Calcular checksum
    let checksum = bech32_create_checksum(hrp, &values);
    values.extend(checksum);
    
    // Construir resultado
    let mut result = String::from(hrp);
    result.push('1'); // Separador
    
    for v in values {
        result.push(BECH32_CHARSET[v as usize] as char);
    }
    
    Ok(result)
}

/// Decodifica una dirección Bech32
pub fn bech32_decode(addr: &str) -> Result<(String, u8, Vec<u8>), String> {
    // Encontrar separador
    let pos = addr.rfind('1').ok_or("No separator found")?;
    if pos < 1 || pos + 7 > addr.len() {
        return Err("Invalid length".to_string());
    }
    
    let hrp = &addr[..pos];
    let data_part = &addr[pos + 1..];
    
    // Decodificar caracteres
    let mut values = Vec::new();
    for c in data_part.chars() {
        let idx = BECH32_CHARSET.iter().position(|&x| x as char == c.to_ascii_lowercase())
            .ok_or("Invalid character")?;
        values.push(idx as u8);
    }
    
    // Verificar checksum
    if !bech32_verify_checksum(hrp, &values) {
        return Err("Invalid checksum".to_string());
    }
    
    // Extraer witness version y program
    let witness_version = values[0];
    let program = convert_bits(&values[1..values.len() - 6], 5, 8, false)?;
    
    Ok((hrp.to_string(), witness_version, program))
}

fn bech32_polymod(values: &[u8]) -> u32 {
    let generator: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (*v as u32);
        for (i, g) in generator.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut ret = Vec::new();
    for c in hrp.chars() {
        ret.push((c as u8) >> 5);
    }
    ret.push(0);
    for c in hrp.chars() {
        ret.push((c as u8) & 31);
    }
    ret
}

fn bech32_create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = bech32_hrp_expand(hrp);
    values.extend(data);
    values.extend(vec![0u8; 6]);
    
    let polymod = bech32_polymod(&values) ^ 1;
    
    (0..6).map(|i| ((polymod >> (5 * (5 - i))) & 31) as u8).collect()
}

fn bech32_verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = bech32_hrp_expand(hrp);
    values.extend(data);
    bech32_polymod(&values) == 1
}

fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>, String> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv: u32 = (1 << to_bits) - 1;
    
    for value in data {
        acc = (acc << from_bits) | (*value as u32);
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    
    if pad {
        if bits > 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err("Invalid padding".to_string());
    }
    
    Ok(ret)
}

// =============================================================================
// SegWit Address Functions
// =============================================================================

/// Crea una dirección P2WPKH (native SegWit) desde un pubkey hash
pub fn create_p2wpkh_address(pubkey_hash: &[u8]) -> Result<String, String> {
    if pubkey_hash.len() != P2WPKH_PROGRAM_SIZE {
        return Err(format!("Invalid pubkey hash length: {}", pubkey_hash.len()));
    }
    bech32_encode(BECH32_HRP, pubkey_hash, WITNESS_V0)
}

/// Crea una dirección P2WSH (native SegWit) desde un script hash
pub fn create_p2wsh_address(script_hash: &[u8]) -> Result<String, String> {
    if script_hash.len() != P2WSH_PROGRAM_SIZE {
        return Err(format!("Invalid script hash length: {}", script_hash.len()));
    }
    bech32_encode(BECH32_HRP, script_hash, WITNESS_V0)
}

/// Crea una dirección P2WPKH desde una clave pública
pub fn pubkey_to_p2wpkh_address(pubkey: &[u8]) -> Result<String, String> {
    let sha = Sha256::digest(pubkey);
    let hash = Ripemd160::digest(&sha);
    create_p2wpkh_address(&hash)
}

/// Crea una dirección P2WSH desde un script
pub fn script_to_p2wsh_address(script: &[u8]) -> Result<String, String> {
    let hash = Sha256::digest(script);
    create_p2wsh_address(&hash)
}

/// Decodifica una dirección SegWit
pub fn decode_segwit_address(addr: &str) -> Result<(u8, Vec<u8>), String> {
    let (hrp, version, program) = bech32_decode(addr)?;
    
    if hrp != BECH32_HRP {
        return Err(format!("Invalid HRP: expected {}, got {}", BECH32_HRP, hrp));
    }
    
    // Validar witness program
    match version {
        0 => {
            if program.len() != P2WPKH_PROGRAM_SIZE && program.len() != P2WSH_PROGRAM_SIZE {
                return Err(format!("Invalid witness program length for v0: {}", program.len()));
            }
        }
        1..=16 => {
            if program.len() < 2 || program.len() > 40 {
                return Err(format!("Invalid witness program length: {}", program.len()));
            }
        }
        _ => return Err(format!("Invalid witness version: {}", version)),
    }
    
    Ok((version, program))
}

/// Verifica si una dirección es SegWit nativa
pub fn is_segwit_address(addr: &str) -> bool {
    addr.starts_with(&format!("{}1", BECH32_HRP))
}

/// Crea el scriptPubKey para P2WPKH
pub fn p2wpkh_script_pubkey(pubkey_hash: &[u8]) -> Script {
    Script {
        ops: vec![
            OpCode::Op0,
            OpCode::OpPushData(pubkey_hash.to_vec()),
        ],
    }
}

/// Crea el scriptPubKey para P2WSH
pub fn p2wsh_script_pubkey(script_hash: &[u8]) -> Script {
    Script {
        ops: vec![
            OpCode::Op0,
            OpCode::OpPushData(script_hash.to_vec()),
        ],
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(&hash1);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash2);
    result
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bech32_encode_decode() {
        let pubkey_hash = [0u8; 20];
        let addr = create_p2wpkh_address(&pubkey_hash).unwrap();
        
        assert!(addr.starts_with("mc1"));
        
        let (version, program) = decode_segwit_address(&addr).unwrap();
        assert_eq!(version, 0);
        assert_eq!(program, pubkey_hash.to_vec());
    }
    
    #[test]
    fn test_witness_serialization() {
        let sig = vec![0x30, 0x44]; // Dummy signature
        let pk = vec![0x02; 33];    // Dummy pubkey
        
        let witness = Witness::p2wpkh(sig.clone(), pk.clone());
        let bytes = witness.to_bytes();
        
        let (decoded, _) = Witness::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.stack.len(), 2);
        assert_eq!(decoded.stack[0], sig);
        assert_eq!(decoded.stack[1], pk);
    }
    
    #[test]
    fn test_segwit_tx() {
        let mut tx = SegWitTx::new();
        tx.inputs.push(TxIn {
            prev_tx_hash: "0".repeat(64),
            prev_index: 0,
            signature: vec![],
            pubkey: vec![],
        });
        tx.outputs.push(TxOut {
            to: "MCtest".to_string(),
            amount: 100,
        });
        tx.witness.push(Witness::new());
        
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        
        // Sin witness, txid == wtxid
        assert_eq!(txid, wtxid);
        
        // Con witness, son diferentes
        tx.witness[0] = Witness::p2wpkh(vec![1, 2, 3], vec![4, 5, 6]);
        let wtxid2 = tx.wtxid();
        assert_ne!(tx.txid(), wtxid2);
    }
    
    #[test]
    fn test_is_segwit_address() {
        assert!(is_segwit_address("mc1qtest"));
        assert!(!is_segwit_address("MCtest"));
    }
}
