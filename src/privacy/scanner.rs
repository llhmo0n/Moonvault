// =============================================================================
// MOONCOIN v2.27 - Wallet Scanner
// =============================================================================
//
// Escanea la blockchain para encontrar outputs shielded que nos pertenecen.
//
// Proceso:
// 1. Para cada output shielded en un bloque:
//    a. Verificar view tag (optimización: descarta 99.6% rápidamente)
//    b. Calcular shared secret con nuestra view key
//    c. Derivar expected one-time pubkey
//    d. Comparar con el one-time pubkey del output
//    e. Si coincide → es nuestro!
//
// 2. Para outputs propios:
//    a. Desencriptar datos (monto, blinding, memo)
//    b. Guardar en wallet
//    c. Derivar spending key para cuando queramos gastar
//
// =============================================================================

use crate::privacy::pedersen::{Scalar, CompressedPoint, GENERATORS};
use crate::privacy::shielded_tx::{ShieldedOutput, ShieldedTx, decrypt_output_data};
use crate::privacy::keys::{ViewingKey, SpendKey, PrivacyKeys};

use crate::privacy::validation::ShieldedPool;

use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use std::collections::HashMap;

// =============================================================================
// Owned Output
// =============================================================================

/// Output que nos pertenece (detectado por el scanner)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnedOutput {
    /// Índice global en el shielded pool
    pub global_index: u64,
    
    /// Hash de la TX que contiene este output
    pub tx_hash: [u8; 32],
    
    /// Índice del output en la TX
    pub output_index: usize,
    
    /// Altura del bloque
    pub block_height: u64,
    
    /// Monto (desencriptado)
    pub amount: u64,
    
    /// Blinding factor (desencriptado)
    pub blinding: Scalar,
    
    /// Memo (desencriptado)
    pub memo: Vec<u8>,
    
    /// One-time public key del output
    pub one_time_pubkey: CompressedPoint,
    
    /// Derivación para calcular spending key
    pub key_derivation: Scalar,
    
    /// Si ya fue gastado
    pub spent: bool,
    
    /// Key image (si fue gastado)
    pub key_image: Option<[u8; 32]>,
}

impl OwnedOutput {
    /// Calcula la clave privada para gastar este output
    pub fn spending_key(&self, spend_key: &SpendKey) -> Scalar {
        self.key_derivation.add(&spend_key.key)
    }
    
    /// Marca como gastado
    pub fn mark_spent(&mut self, key_image: [u8; 32]) {
        self.spent = true;
        self.key_image = Some(key_image);
    }
}

// =============================================================================
// Scanner
// =============================================================================

/// Scanner de outputs shielded
pub struct WalletScanner {
    /// View key (para detectar outputs)
    view_key: Scalar,
    
    /// Spend pubkey (para verificar ownership)
    spend_pubkey: CompressedPoint,
    
    /// Estadísticas
    outputs_scanned: u64,
    outputs_found: u64,
}

impl WalletScanner {
    /// Crea un nuevo scanner
    pub fn new(view_key: &ViewingKey, spend_pubkey: CompressedPoint) -> Self {
        WalletScanner {
            view_key: view_key.key,
            spend_pubkey,
            outputs_scanned: 0,
            outputs_found: 0,
        }
    }
    
    /// Crea desde PrivacyKeys
    pub fn from_keys(keys: &PrivacyKeys) -> Self {
        Self::new(&keys.view_key, keys.spend_key.pubkey)
    }
    
    /// Escanea un output individual
    pub fn scan_output(
        &mut self,
        output: &ShieldedOutput,
        global_index: u64,
        tx_hash: [u8; 32],
        output_index: usize,
        block_height: u64,
    ) -> Option<OwnedOutput> {
        self.outputs_scanned += 1;
        
        // 1. Quick check con view tag (optimización)
        if !self.check_view_tag(output) {
            return None;
        }
        
        // 2. Calcular shared secret
        let shared_secret = self.calculate_shared_secret(&output.ephemeral_pubkey)?;
        
        // 3. Derivar expected one-time pubkey
        let key_derivation = Scalar::from_bytes_mod_order(&shared_secret);
        let expected_pubkey = self.derive_one_time_pubkey(&key_derivation)?;
        
        // 4. Comparar con el one-time pubkey del output
        if expected_pubkey.as_bytes() != output.one_time_pubkey.as_bytes() {
            return None;
        }
        
        // ¡Es nuestro!
        self.outputs_found += 1;
        
        // 5. Desencriptar datos
        let decrypted = decrypt_output_data(&output.encrypted_data, &shared_secret).ok()?;
        
        Some(OwnedOutput {
            global_index,
            tx_hash,
            output_index,
            block_height,
            amount: decrypted.amount,
            blinding: decrypted.blinding,
            memo: decrypted.memo,
            one_time_pubkey: output.one_time_pubkey,
            key_derivation,
            spent: false,
            key_image: None,
        })
    }
    
    /// Escanea una TX completa
    pub fn scan_tx(
        &mut self,
        tx: &ShieldedTx,
        tx_hash: [u8; 32],
        block_height: u64,
        start_global_index: u64,
    ) -> Vec<OwnedOutput> {
        let mut found = Vec::new();
        
        for (i, output) in tx.shielded_outputs.iter().enumerate() {
            if let Some(owned) = self.scan_output(
                output,
                start_global_index + i as u64,
                tx_hash,
                i,
                block_height,
            ) {
                found.push(owned);
            }
        }
        
        found
    }
    
    /// Escanea un bloque completo
    pub fn scan_block(
        &mut self,
        txs: &[(ShieldedTx, [u8; 32])], // (tx, tx_hash)
        block_height: u64,
        pool: &ShieldedPool,
    ) -> Vec<OwnedOutput> {
        let mut found = Vec::new();
        let mut current_index = pool.next_index();
        
        for (tx, tx_hash) in txs {
            let owned = self.scan_tx(tx, *tx_hash, block_height, current_index);
            current_index += tx.shielded_outputs.len() as u64;
            found.extend(owned);
        }
        
        found
    }
    
    /// Verifica view tag rápidamente
    fn check_view_tag(&self, output: &ShieldedOutput) -> bool {
        // Calcular el shared secret y verificar primer byte
        if let Some(ephemeral_point) = output.ephemeral_pubkey.decompress() {
            let shared_point = self.view_key.inner() * ephemeral_point;
            let hash = Self::hash_shared_point(&shared_point);
            hash[0] == output.view_tag
        } else {
            false
        }
    }
    
    /// Calcula shared secret completo
    fn calculate_shared_secret(&self, ephemeral_pubkey: &CompressedPoint) -> Option<[u8; 32]> {
        let ephemeral_point = ephemeral_pubkey.decompress()?;
        let shared_point = self.view_key.inner() * ephemeral_point;
        Some(Self::hash_shared_point(&shared_point))
    }
    
    /// Hash del punto compartido
    fn hash_shared_point(point: &curve25519_dalek::ristretto::RistrettoPoint) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Mooncoin_SharedSecret_v1");
        hasher.update(point.compress().as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }
    
    /// Deriva one-time pubkey esperado
    fn derive_one_time_pubkey(&self, key_derivation: &Scalar) -> Option<CompressedPoint> {
        let spend_point = self.spend_pubkey.decompress()?;
        let one_time_point = key_derivation.inner() * GENERATORS.g + spend_point;
        Some(CompressedPoint::from_point(&one_time_point))
    }
    
    /// Estadísticas del scanner
    pub fn stats(&self) -> ScannerStats {
        ScannerStats {
            outputs_scanned: self.outputs_scanned,
            outputs_found: self.outputs_found,
            hit_rate: if self.outputs_scanned > 0 {
                self.outputs_found as f64 / self.outputs_scanned as f64
            } else {
                0.0
            },
        }
    }
    
    /// Resetea estadísticas
    pub fn reset_stats(&mut self) {
        self.outputs_scanned = 0;
        self.outputs_found = 0;
    }
}

/// Estadísticas del scanner
#[derive(Clone, Debug)]
pub struct ScannerStats {
    pub outputs_scanned: u64,
    pub outputs_found: u64,
    pub hit_rate: f64,
}

// =============================================================================
// Shielded Wallet
// =============================================================================

/// Wallet para fondos shielded
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedWallet {
    /// Outputs propios (no gastados)
    unspent: HashMap<u64, OwnedOutput>, // global_index -> output
    
    /// Outputs gastados (para historial)
    spent: HashMap<u64, OwnedOutput>,
    
    /// Última altura escaneada
    last_scanned_height: u64,
    
    /// Balance total
    balance: u64,
}

impl ShieldedWallet {
    /// Crea un wallet vacío
    pub fn new() -> Self {
        ShieldedWallet {
            unspent: HashMap::new(),
            spent: HashMap::new(),
            last_scanned_height: 0,
            balance: 0,
        }
    }
    
    /// Agrega un output encontrado
    pub fn add_output(&mut self, output: OwnedOutput) {
        self.balance += output.amount;
        self.unspent.insert(output.global_index, output);
    }
    
    /// Marca un output como gastado
    pub fn mark_spent(&mut self, global_index: u64, key_image: [u8; 32]) -> bool {
        if let Some(mut output) = self.unspent.remove(&global_index) {
            self.balance -= output.amount;
            output.mark_spent(key_image);
            self.spent.insert(global_index, output);
            true
        } else {
            false
        }
    }
    
    /// Balance disponible
    pub fn balance(&self) -> u64 {
        self.balance
    }
    
    /// Número de outputs no gastados
    pub fn unspent_count(&self) -> usize {
        self.unspent.len()
    }
    
    /// Número de outputs gastados
    pub fn spent_count(&self) -> usize {
        self.spent.len()
    }
    
    /// Última altura escaneada
    pub fn last_scanned_height(&self) -> u64 {
        self.last_scanned_height
    }
    
    /// Actualiza última altura escaneada
    pub fn set_last_scanned_height(&mut self, height: u64) {
        self.last_scanned_height = height;
    }
    
    /// Obtiene outputs no gastados
    pub fn get_unspent(&self) -> Vec<&OwnedOutput> {
        self.unspent.values().collect()
    }
    
    /// Obtiene un output específico
    pub fn get_output(&self, global_index: u64) -> Option<&OwnedOutput> {
        self.unspent.get(&global_index).or_else(|| self.spent.get(&global_index))
    }
    
    /// Selecciona outputs para gastar un monto
    pub fn select_outputs(&self, target_amount: u64, fee: u64) -> Option<Vec<&OwnedOutput>> {
        let total_needed = target_amount + fee;
        
        // Ordenar por monto (mayor primero para minimizar inputs)
        let mut candidates: Vec<_> = self.unspent.values().collect();
        candidates.sort_by(|a, b| b.amount.cmp(&a.amount));
        
        let mut selected = Vec::new();
        let mut accumulated = 0u64;
        
        for output in candidates {
            selected.push(output);
            accumulated += output.amount;
            
            if accumulated >= total_needed {
                return Some(selected);
            }
        }
        
        // No hay suficiente balance
        None
    }
    
    /// Historial de transacciones
    pub fn history(&self) -> Vec<WalletHistoryEntry> {
        let mut entries: Vec<_> = self.unspent.values()
            .map(|o| WalletHistoryEntry {
                global_index: o.global_index,
                tx_hash: o.tx_hash,
                block_height: o.block_height,
                amount: o.amount,
                memo: o.memo.clone(),
                spent: false,
            })
            .chain(self.spent.values().map(|o| WalletHistoryEntry {
                global_index: o.global_index,
                tx_hash: o.tx_hash,
                block_height: o.block_height,
                amount: o.amount,
                memo: o.memo.clone(),
                spent: true,
            }))
            .collect();
        
        entries.sort_by(|a, b| b.block_height.cmp(&a.block_height));
        entries
    }
    
    /// Exporta wallet a JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    
    /// Importa wallet desde JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl Default for ShieldedWallet {
    fn default() -> Self {
        Self::new()
    }
}

/// Entrada de historial
#[derive(Clone, Debug)]
pub struct WalletHistoryEntry {
    pub global_index: u64,
    pub tx_hash: [u8; 32],
    pub block_height: u64,
    pub amount: u64,
    pub memo: Vec<u8>,
    pub spent: bool,
}

// =============================================================================
// Full Scan
// =============================================================================

/// Resultado de un escaneo completo
#[derive(Clone, Debug)]
pub struct ScanResult {
    pub outputs_found: Vec<OwnedOutput>,
    pub blocks_scanned: u64,
    pub outputs_scanned: u64,
    pub time_ms: u128,
}

/// Escanea un rango de bloques
pub fn scan_blocks(
    scanner: &mut WalletScanner,
    blocks: &[BlockData], // (height, txs)
    pool: &ShieldedPool,
) -> ScanResult {
    let start = std::time::Instant::now();
    let mut all_found = Vec::new();
    
    for block in blocks {
        let found = scanner.scan_block(&block.txs, block.height, pool);
        all_found.extend(found);
    }
    
    let stats = scanner.stats();
    
    ScanResult {
        outputs_found: all_found,
        blocks_scanned: blocks.len() as u64,
        outputs_scanned: stats.outputs_scanned,
        time_ms: start.elapsed().as_millis(),
    }
}

/// Datos de un bloque para escaneo
pub struct BlockData {
    pub height: u64,
    pub txs: Vec<(ShieldedTx, [u8; 32])>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::keys::PrivacyKeys;
    use crate::privacy::shielded_tx::ShieldedOutput;
    
    #[test]
    fn test_scanner_finds_own_output() {
        let keys = PrivacyKeys::generate();
        let addr = keys.stealth_address();
        
        // Crear output para nosotros
        let (output, _secrets) = ShieldedOutput::new(
            1000,
            &addr.view_pubkey,
            &addr.spend_pubkey,
            Some(b"test"),
        ).unwrap();
        
        // Escanear
        let mut scanner = WalletScanner::from_keys(&keys);
        let found = scanner.scan_output(&output, 0, [0u8; 32], 0, 1);
        
        assert!(found.is_some());
        let owned = found.unwrap();
        assert_eq!(owned.amount, 1000);
        assert_eq!(owned.memo, b"test");
    }
    
    #[test]
    fn test_scanner_ignores_others_output() {
        let our_keys = PrivacyKeys::generate();
        let other_keys = PrivacyKeys::generate();
        let other_addr = other_keys.stealth_address();
        
        // Crear output para otra persona
        let (output, _) = ShieldedOutput::new(
            1000,
            &other_addr.view_pubkey,
            &other_addr.spend_pubkey,
            None,
        ).unwrap();
        
        // Escanear con nuestras claves
        let mut scanner = WalletScanner::from_keys(&our_keys);
        let found = scanner.scan_output(&output, 0, [0u8; 32], 0, 1);
        
        assert!(found.is_none());
    }
    
    #[test]
    fn test_shielded_wallet() {
        let mut wallet = ShieldedWallet::new();
        
        let output = OwnedOutput {
            global_index: 0,
            tx_hash: [0u8; 32],
            output_index: 0,
            block_height: 1,
            amount: 1000,
            blinding: Scalar::random(),
            memo: vec![],
            one_time_pubkey: CompressedPoint::identity(),
            key_derivation: Scalar::random(),
            spent: false,
            key_image: None,
        };
        
        wallet.add_output(output);
        
        assert_eq!(wallet.balance(), 1000);
        assert_eq!(wallet.unspent_count(), 1);
        
        // Marcar como gastado
        wallet.mark_spent(0, [1u8; 32]);
        
        assert_eq!(wallet.balance(), 0);
        assert_eq!(wallet.unspent_count(), 0);
        assert_eq!(wallet.spent_count(), 1);
    }
    
    #[test]
    fn test_output_selection() {
        let mut wallet = ShieldedWallet::new();
        
        // Agregar varios outputs
        for i in 0..5 {
            wallet.add_output(OwnedOutput {
                global_index: i,
                tx_hash: [0u8; 32],
                output_index: 0,
                block_height: 1,
                amount: (i + 1) * 100,
                blinding: Scalar::random(),
                memo: vec![],
                one_time_pubkey: CompressedPoint::identity(),
                key_derivation: Scalar::random(),
                spent: false,
                key_image: None,
            });
        }
        
        // Balance = 100 + 200 + 300 + 400 + 500 = 1500
        assert_eq!(wallet.balance(), 1500);
        
        // Seleccionar para gastar 700 + 100 fee
        let selected = wallet.select_outputs(700, 100).unwrap();
        let total: u64 = selected.iter().map(|o| o.amount).sum();
        assert!(total >= 800);
    }
}
