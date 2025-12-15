// =============================================================================
// MOONCOIN v2.0 - SPV (Simplified Payment Verification)
// =============================================================================
//
// Implementación de SPV (BIP37, BIP157/158):
// - Verificación de transacciones sin blockchain completa
// - Merkle proofs para inclusión de TX
// - Bloom filters para privacidad
// - Compact Block Filters (Neutrino)
// - Headers-only sync
//
// =============================================================================

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

use crate::block::Block;
use crate::transaction::Tx;

// =============================================================================
// Merkle Tree
// =============================================================================

/// Calcula el Merkle root de una lista de transacciones
pub fn compute_merkle_root(txids: &[String]) -> String {
    if txids.is_empty() {
        return "0".repeat(64);
    }
    
    if txids.len() == 1 {
        return txids[0].clone();
    }
    
    let mut level: Vec<String> = txids.to_vec();
    
    while level.len() > 1 {
        // Si es impar, duplicar el último
        if level.len() % 2 == 1 {
            level.push(level.last().unwrap().clone());
        }
        
        let mut next_level = Vec::new();
        for i in (0..level.len()).step_by(2) {
            let combined = hash_pair(&level[i], &level[i + 1]);
            next_level.push(combined);
        }
        level = next_level;
    }
    
    level[0].clone()
}

/// Hash de dos nodos del Merkle tree
fn hash_pair(left: &str, right: &str) -> String {
    let left_bytes = hex::decode(left).unwrap_or_default();
    let right_bytes = hex::decode(right).unwrap_or_default();
    
    let mut combined = Vec::new();
    combined.extend(&left_bytes);
    combined.extend(&right_bytes);
    
    let hash1 = Sha256::digest(&combined);
    let hash2 = Sha256::digest(&hash1);
    
    hex::encode(hash2)
}

// =============================================================================
// Merkle Proof
// =============================================================================

/// Prueba de inclusión en Merkle tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// TxID de la transacción
    pub txid: String,
    /// Índice de la transacción en el bloque
    pub tx_index: usize,
    /// Hashes del camino (siblings)
    pub proof_hashes: Vec<String>,
    /// Direcciones (0 = izquierda, 1 = derecha)
    pub directions: Vec<u8>,
    /// Merkle root del bloque
    pub merkle_root: String,
    /// Hash del bloque
    pub block_hash: String,
    /// Altura del bloque
    pub block_height: u64,
}

impl MerkleProof {
    /// Genera una prueba de inclusión para una transacción
    pub fn generate(block: &Block, txid: &str) -> Option<Self> {
        let txids: Vec<String> = block.txs.iter()
            .map(|tx| crate::transaction::tx_hash(tx))
            .collect();
        
        let tx_index = txids.iter().position(|id| id == txid)?;
        
        if txids.len() == 1 {
            return Some(MerkleProof {
                txid: txid.to_string(),
                tx_index,
                proof_hashes: Vec::new(),
                directions: Vec::new(),
                merkle_root: txids[0].clone(),
                block_hash: block.hash.clone(),
                block_height: block.height,
            });
        }
        
        let mut proof_hashes = Vec::new();
        let mut directions = Vec::new();
        let mut index = tx_index;
        let mut level = txids.clone();
        
        while level.len() > 1 {
            // Si es impar, duplicar el último
            if level.len() % 2 == 1 {
                level.push(level.last().unwrap().clone());
            }
            
            // Determinar el sibling
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            proof_hashes.push(level[sibling_index].clone());
            directions.push(if index % 2 == 0 { 1 } else { 0 }); // 1 = sibling a la derecha
            
            // Siguiente nivel
            let mut next_level = Vec::new();
            for i in (0..level.len()).step_by(2) {
                next_level.push(hash_pair(&level[i], &level[i + 1]));
            }
            
            index /= 2;
            level = next_level;
        }
        
        Some(MerkleProof {
            txid: txid.to_string(),
            tx_index,
            proof_hashes,
            directions,
            merkle_root: level[0].clone(),
            block_hash: block.hash.clone(),
            block_height: block.height,
        })
    }
    
    /// Verifica la prueba de inclusión
    pub fn verify(&self) -> bool {
        let mut current = self.txid.clone();
        
        for (i, sibling) in self.proof_hashes.iter().enumerate() {
            current = if self.directions[i] == 1 {
                // Sibling a la derecha
                hash_pair(&current, sibling)
            } else {
                // Sibling a la izquierda
                hash_pair(sibling, &current)
            };
        }
        
        current == self.merkle_root
    }
    
    /// Serializa la prueba
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize proof")
    }
    
    /// Deserializa la prueba
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data)
            .map_err(|e| format!("Failed to deserialize proof: {}", e))
    }
}

// =============================================================================
// Bloom Filter (BIP37)
// =============================================================================

/// Bloom filter para filtrado de transacciones
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BloomFilter {
    /// Bits del filtro
    bits: Vec<u8>,
    /// Número de funciones hash
    num_hash_funcs: u32,
    /// Tweak para las funciones hash
    tweak: u32,
    /// Flags
    flags: u8,
}

impl BloomFilter {
    /// Crea un nuevo bloom filter
    /// n_elements: número esperado de elementos
    /// fp_rate: tasa de falsos positivos deseada (ej: 0.0001)
    pub fn new(n_elements: usize, fp_rate: f64) -> Self {
        // Calcular tamaño óptimo del filtro
        let ln2 = std::f64::consts::LN_2;
        let ln2_sq = ln2 * ln2;
        
        let size = ((-1.0 * n_elements as f64 * fp_rate.ln()) / ln2_sq).ceil() as usize;
        let size = size.min(36000 * 8); // Máximo 36KB
        let size = ((size + 7) / 8) * 8; // Redondear a bytes
        
        // Calcular número óptimo de funciones hash
        let num_hash = ((size as f64 / n_elements as f64) * ln2).ceil() as u32;
        let num_hash = num_hash.min(50).max(1);
        
        BloomFilter {
            bits: vec![0u8; size / 8],
            num_hash_funcs: num_hash,
            tweak: rand::random(),
            flags: 0,
        }
    }
    
    /// Crea un filtro vacío
    pub fn empty() -> Self {
        BloomFilter {
            bits: Vec::new(),
            num_hash_funcs: 0,
            tweak: 0,
            flags: 0,
        }
    }
    
    /// Añade un elemento al filtro
    pub fn insert(&mut self, data: &[u8]) {
        if self.bits.is_empty() {
            return;
        }
        
        let filter_size = self.bits.len() * 8;
        
        for i in 0..self.num_hash_funcs {
            let index = self.hash(data, i) % filter_size as u32;
            self.bits[index as usize / 8] |= 1 << (index % 8);
        }
    }
    
    /// Verifica si un elemento puede estar en el filtro
    pub fn contains(&self, data: &[u8]) -> bool {
        if self.bits.is_empty() {
            return true; // Filtro vacío = match all
        }
        
        let filter_size = self.bits.len() * 8;
        
        for i in 0..self.num_hash_funcs {
            let index = self.hash(data, i) % filter_size as u32;
            if self.bits[index as usize / 8] & (1 << (index % 8)) == 0 {
                return false;
            }
        }
        
        true
    }
    
    /// Función hash MurmurHash3
    fn hash(&self, data: &[u8], n: u32) -> u32 {
        let seed = n.wrapping_mul(0xfba4c795).wrapping_add(self.tweak);
        murmur3_32(data, seed)
    }
    
    /// Añade una dirección al filtro
    pub fn insert_address(&mut self, address: &str) {
        self.insert(address.as_bytes());
    }
    
    /// Añade un pubkey hash al filtro
    pub fn insert_pubkey_hash(&mut self, hash: &[u8]) {
        self.insert(hash);
    }
    
    /// Añade un outpoint al filtro
    pub fn insert_outpoint(&mut self, txid: &str, index: u32) {
        let mut data = hex::decode(txid).unwrap_or_default();
        data.extend(&index.to_le_bytes());
        self.insert(&data);
    }
    
    /// Verifica si una transacción coincide con el filtro
    pub fn matches_tx(&self, tx: &Tx) -> bool {
        // Verificar outputs
        for output in &tx.outputs {
            if self.contains(output.to.as_bytes()) {
                return true;
            }
        }
        
        // Verificar inputs (pubkeys)
        for input in &tx.inputs {
            if !input.pubkey.is_empty() && self.contains(&input.pubkey) {
                return true;
            }
        }
        
        false
    }
}

/// MurmurHash3 32-bit
fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    
    let mut h1 = seed;
    let len = data.len();
    
    // Body
    let nblocks = len / 4;
    for i in 0..nblocks {
        let mut k1 = u32::from_le_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
        
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    
    // Tail
    let tail = &data[nblocks * 4..];
    let mut k1: u32 = 0;
    
    if tail.len() >= 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }
    
    // Finalization
    h1 ^= len as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1 >> 16;
    
    h1
}

// =============================================================================
// SPV Client State
// =============================================================================

/// Estado del cliente SPV
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpvClient {
    /// Headers de la cadena
    pub headers: Vec<BlockHeader>,
    /// Bloom filter actual
    pub filter: BloomFilter,
    /// Transacciones verificadas (con pruebas)
    pub verified_txs: Vec<VerifiedTx>,
    /// Direcciones monitoreadas
    pub watched_addresses: HashSet<String>,
    /// Altura sincronizada
    pub synced_height: u64,
}

/// Header de bloque (versión ligera)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub merkle_root: String,
    pub timestamp: u64,
    pub difficulty_bits: u32,
    pub nonce: u64,
}

/// Transacción verificada con prueba
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedTx {
    pub tx: Tx,
    pub proof: MerkleProof,
    pub confirmations: u64,
}

impl Default for SpvClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SpvClient {
    /// Crea un nuevo cliente SPV
    pub fn new() -> Self {
        SpvClient {
            headers: Vec::new(),
            filter: BloomFilter::empty(),
            verified_txs: Vec::new(),
            watched_addresses: HashSet::new(),
            synced_height: 0,
        }
    }
    
    /// Añade una dirección para monitorear
    pub fn watch_address(&mut self, address: &str) {
        self.watched_addresses.insert(address.to_string());
        self.rebuild_filter();
    }
    
    /// Elimina una dirección del monitoreo
    pub fn unwatch_address(&mut self, address: &str) {
        self.watched_addresses.remove(address);
        self.rebuild_filter();
    }
    
    /// Reconstruye el bloom filter
    pub fn rebuild_filter(&mut self) {
        if self.watched_addresses.is_empty() {
            self.filter = BloomFilter::empty();
            return;
        }
        
        self.filter = BloomFilter::new(self.watched_addresses.len() * 2, 0.0001);
        
        for addr in &self.watched_addresses {
            self.filter.insert_address(addr);
        }
    }
    
    /// Procesa un header recibido
    pub fn process_header(&mut self, header: BlockHeader) -> Result<(), String> {
        // Verificar que conecta con el anterior
        if !self.headers.is_empty() {
            let last = self.headers.last().unwrap();
            if header.prev_hash != last.hash {
                return Err("Header doesn't connect".to_string());
            }
            if header.height != last.height + 1 {
                return Err("Invalid height".to_string());
            }
        }
        
        // TODO: Verificar PoW del header
        
        self.headers.push(header);
        self.synced_height = self.headers.len() as u64 - 1;
        
        Ok(())
    }
    
    /// Procesa múltiples headers
    pub fn process_headers(&mut self, headers: Vec<BlockHeader>) -> Result<usize, String> {
        let mut count = 0;
        for header in headers {
            self.process_header(header)?;
            count += 1;
        }
        Ok(count)
    }
    
    /// Verifica una transacción con su prueba Merkle
    pub fn verify_tx(&mut self, tx: Tx, proof: MerkleProof) -> Result<(), String> {
        // Verificar la prueba Merkle
        if !proof.verify() {
            return Err("Invalid Merkle proof".to_string());
        }
        
        // Verificar que el bloque existe en nuestra cadena
        let header = self.headers.get(proof.block_height as usize)
            .ok_or("Block not in chain")?;
        
        if header.hash != proof.block_hash {
            return Err("Block hash mismatch".to_string());
        }
        
        if header.merkle_root != proof.merkle_root {
            return Err("Merkle root mismatch".to_string());
        }
        
        // Calcular confirmaciones
        let confirmations = self.synced_height.saturating_sub(proof.block_height) + 1;
        
        // Guardar TX verificada
        self.verified_txs.push(VerifiedTx {
            tx,
            proof,
            confirmations,
        });
        
        Ok(())
    }
    
    /// Obtiene el balance de una dirección
    pub fn get_balance(&self, address: &str) -> u64 {
        let mut balance: i64 = 0;
        
        for vtx in &self.verified_txs {
            // Sumar outputs recibidos
            for output in &vtx.tx.outputs {
                if output.to == address {
                    balance += output.amount as i64;
                }
            }
            
            // Restar inputs gastados
            // (Simplificado - en producción necesitaríamos rastrear UTXOs)
        }
        
        balance.max(0) as u64
    }
    
    /// Obtiene transacciones de una dirección
    pub fn get_address_txs(&self, address: &str) -> Vec<&VerifiedTx> {
        self.verified_txs.iter()
            .filter(|vtx| {
                vtx.tx.outputs.iter().any(|o| o.to == address) ||
                vtx.tx.inputs.iter().any(|i| !i.pubkey.is_empty())
            })
            .collect()
    }
    
    /// Actualiza confirmaciones
    pub fn update_confirmations(&mut self) {
        for vtx in &mut self.verified_txs {
            vtx.confirmations = self.synced_height.saturating_sub(vtx.proof.block_height) + 1;
        }
    }
    
    /// Guarda el estado a disco
    pub fn save(&self, path: &str) -> Result<(), String> {
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize: {}", e))?;
        std::fs::write(path, data)
            .map_err(|e| format!("Failed to write: {}", e))
    }
    
    /// Carga el estado desde disco
    pub fn load(path: &str) -> Result<Self, String> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read: {}", e))?;
        serde_json::from_str(&data)
            .map_err(|e| format!("Failed to parse: {}", e))
    }
    
    /// Estadísticas del cliente
    pub fn stats(&self) -> SpvStats {
        SpvStats {
            headers_count: self.headers.len(),
            synced_height: self.synced_height,
            watched_addresses: self.watched_addresses.len(),
            verified_txs: self.verified_txs.len(),
            filter_size: self.filter.bits.len(),
        }
    }
}

/// Estadísticas del cliente SPV
#[derive(Debug, Clone)]
pub struct SpvStats {
    pub headers_count: usize,
    pub synced_height: u64,
    pub watched_addresses: usize,
    pub verified_txs: usize,
    pub filter_size: usize,
}

// =============================================================================
// Compact Block Filters (BIP157/158 - Neutrino)
// =============================================================================

/// Golomb-Rice coded set para compact block filters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GcsFilter {
    /// Datos codificados
    pub data: Vec<u8>,
    /// Número de elementos
    pub n: u32,
    /// Parámetro P (bits de Golomb coding)
    pub p: u8,
    /// Hash del bloque
    pub block_hash: String,
}

impl GcsFilter {
    /// Parámetro P para basic filter (BIP158)
    pub const BASIC_P: u8 = 19;
    /// Parámetro M para basic filter
    pub const BASIC_M: u64 = 784931;
    
    /// Construye un filtro desde un bloque
    pub fn from_block(block: &Block) -> Self {
        let mut elements = HashSet::new();
        
        for tx in &block.txs {
            // Añadir outputs (scriptPubKeys)
            for output in &tx.outputs {
                elements.insert(output.to.as_bytes().to_vec());
            }
            
            // Añadir outpoints gastados
            for input in &tx.inputs {
                if !input.prev_tx_hash.is_empty() && input.prev_tx_hash != "0".repeat(64) {
                    let mut outpoint = hex::decode(&input.prev_tx_hash).unwrap_or_default();
                    outpoint.extend(&input.prev_index.to_le_bytes());
                    elements.insert(outpoint);
                }
            }
        }
        
        Self::build(&block.hash, elements.into_iter().collect(), Self::BASIC_P)
    }
    
    /// Construye un filtro desde elementos
    pub fn build(block_hash: &str, elements: Vec<Vec<u8>>, p: u8) -> Self {
        if elements.is_empty() {
            return GcsFilter {
                data: Vec::new(),
                n: 0,
                p,
                block_hash: block_hash.to_string(),
            };
        }
        
        let n = elements.len() as u32;
        let key = Self::derive_key(block_hash);
        
        // Hash y ordenar elementos
        let mut hashes: Vec<u64> = elements.iter()
            .map(|e| Self::siphash(&key, e) % (n as u64 * Self::BASIC_M))
            .collect();
        hashes.sort_unstable();
        
        // Calcular deltas
        let mut deltas = Vec::new();
        let mut prev = 0u64;
        for h in hashes {
            deltas.push(h - prev);
            prev = h;
        }
        
        // Codificar con Golomb-Rice
        let data = Self::golomb_encode(&deltas, p);
        
        GcsFilter {
            data,
            n,
            p,
            block_hash: block_hash.to_string(),
        }
    }
    
    /// Verifica si un elemento puede estar en el filtro
    pub fn match_any(&self, elements: &[Vec<u8>]) -> bool {
        if self.n == 0 || elements.is_empty() {
            return false;
        }
        
        let key = Self::derive_key(&self.block_hash);
        
        // Hash de elementos a buscar
        let mut search_hashes: Vec<u64> = elements.iter()
            .map(|e| Self::siphash(&key, e) % (self.n as u64 * Self::BASIC_M))
            .collect();
        search_hashes.sort_unstable();
        
        // Decodificar filtro
        let filter_hashes = self.golomb_decode();
        
        // Buscar coincidencias
        let mut i = 0;
        let mut j = 0;
        
        while i < search_hashes.len() && j < filter_hashes.len() {
            if search_hashes[i] == filter_hashes[j] {
                return true;
            } else if search_hashes[i] < filter_hashes[j] {
                i += 1;
            } else {
                j += 1;
            }
        }
        
        false
    }
    
    /// Deriva la clave SipHash desde el block hash
    fn derive_key(block_hash: &str) -> [u8; 16] {
        let hash_bytes = hex::decode(block_hash).unwrap_or_default();
        let mut key = [0u8; 16];
        if hash_bytes.len() >= 16 {
            key.copy_from_slice(&hash_bytes[..16]);
        }
        key
    }
    
    /// SipHash simplificado
    fn siphash(key: &[u8; 16], data: &[u8]) -> u64 {
        // Simplificación - en producción usar crate siphash
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(data);
        let result = hasher.finalize();
        u64::from_le_bytes(result[..8].try_into().unwrap())
    }
    
    /// Codificación Golomb-Rice
    fn golomb_encode(values: &[u64], p: u8) -> Vec<u8> {
        let mut bits = Vec::new();
        let divisor = 1u64 << p;
        
        for &v in values {
            let q = v / divisor;
            let r = v % divisor;
            
            // Unary encoding de q (q unos seguidos de un cero)
            for _ in 0..q {
                bits.push(true);
            }
            bits.push(false);
            
            // Binary encoding de r (p bits)
            for i in (0..p).rev() {
                bits.push((r >> i) & 1 == 1);
            }
        }
        
        // Convertir bits a bytes
        let mut bytes = Vec::new();
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << (7 - i);
                }
            }
            bytes.push(byte);
        }
        
        bytes
    }
    
    /// Decodificación Golomb-Rice
    fn golomb_decode(&self) -> Vec<u64> {
        let mut values = Vec::new();
        let divisor = 1u64 << self.p;
        
        // Convertir bytes a bits
        let mut bits = Vec::new();
        for byte in &self.data {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1 == 1);
            }
        }
        
        let mut pos = 0;
        let mut cumulative = 0u64;
        
        for _ in 0..self.n {
            if pos >= bits.len() {
                break;
            }
            
            // Decodificar q (unary)
            let mut q = 0u64;
            while pos < bits.len() && bits[pos] {
                q += 1;
                pos += 1;
            }
            pos += 1; // Skip the zero
            
            // Decodificar r (binary, p bits)
            let mut r = 0u64;
            for _ in 0..self.p {
                if pos >= bits.len() {
                    break;
                }
                r = (r << 1) | if bits[pos] { 1 } else { 0 };
                pos += 1;
            }
            
            let delta = q * divisor + r;
            cumulative += delta;
            values.push(cumulative);
        }
        
        values
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{TxIn, TxOut};
    
    #[test]
    fn test_merkle_root() {
        let txids = vec![
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
        ];
        
        let root = compute_merkle_root(&txids);
        assert!(!root.is_empty());
        assert_eq!(root.len(), 64);
    }
    
    #[test]
    fn test_merkle_proof() {
        // Crear un bloque de prueba
        let mut block = Block {
            height: 1,
            hash: "blockhash".repeat(4),
            prev_hash: "0".repeat(64),
            merkle_root: String::new(),
            timestamp: 0,
            difficulty_bits: 0,
            nonce: 0,
            txs: vec![
                Tx {
                    inputs: vec![],
                    outputs: vec![TxOut { to: "addr1".to_string(), amount: 100 }],
                },
                Tx {
                    inputs: vec![],
                    outputs: vec![TxOut { to: "addr2".to_string(), amount: 200 }],
                },
            ],
        };
        
        // Calcular merkle root
        let txids: Vec<String> = block.txs.iter()
            .map(|tx| crate::transaction::tx_hash(tx))
            .collect();
        block.merkle_root = compute_merkle_root(&txids);
        
        // Generar y verificar prueba
        let proof = MerkleProof::generate(&block, &txids[0]).unwrap();
        assert!(proof.verify());
    }
    
    #[test]
    fn test_bloom_filter() {
        let mut filter = BloomFilter::new(10, 0.01);
        
        filter.insert(b"hello");
        filter.insert(b"world");
        
        assert!(filter.contains(b"hello"));
        assert!(filter.contains(b"world"));
        assert!(!filter.contains(b"foo")); // Puede dar falso positivo
    }
    
    #[test]
    fn test_spv_client() {
        let mut client = SpvClient::new();
        
        client.watch_address("MCtest123");
        assert_eq!(client.watched_addresses.len(), 1);
        
        let header = BlockHeader {
            height: 0,
            hash: "genesis".repeat(4),
            prev_hash: "0".repeat(64),
            merkle_root: "0".repeat(64),
            timestamp: 0,
            difficulty_bits: 0,
            nonce: 0,
        };
        
        client.process_header(header).unwrap();
        assert_eq!(client.synced_height, 0);
    }
}
