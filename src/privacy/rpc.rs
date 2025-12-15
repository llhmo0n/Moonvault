// =============================================================================
// MOONCOIN v2.28 - Privacy RPC
// =============================================================================
//
// Comandos RPC para transacciones shielded:
// - getshieldedbalance: Ver balance privado
// - listshieldedunspent: Listar outputs no gastados
// - sendshielded: Enviar TX shielded
// - shieldcoins: Convertir transparent → shielded
// - unshieldcoins: Convertir shielded → transparent
// - getshieldedaddress: Obtener dirección stealth
// - importviewkey: Importar view key (watch-only)
// - scanblockchain: Escanear blockchain por pagos
//
// =============================================================================

use crate::privacy::pedersen::{Scalar, CompressedPoint};
use crate::privacy::keys::PrivacyKeys;
use crate::privacy::shielded_tx::{
    ShieldedTx, ShieldedOutput, ShieldedInput,
    MIN_SHIELDED_FEE,
};
use crate::privacy::scanner::{WalletScanner, ShieldedWallet};
use crate::privacy::validation::ShieldedPool;
use crate::privacy::stealth::StealthAddress;

use serde::{Serialize, Deserialize};


// =============================================================================
// RPC Request/Response Types
// =============================================================================

/// Respuesta genérica de RPC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcResponse<T> {
    pub success: bool,
    pub result: Option<T>,
    pub error: Option<String>,
}

impl<T> RpcResponse<T> {
    pub fn ok(result: T) -> Self {
        RpcResponse {
            success: true,
            result: Some(result),
            error: None,
        }
    }
    
    pub fn err(error: impl Into<String>) -> Self {
        RpcResponse {
            success: false,
            result: None,
            error: Some(error.into()),
        }
    }
}

// =============================================================================
// Balance Response
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedBalanceResponse {
    /// Balance total (en satoshis)
    pub balance: u64,
    /// Balance formateado
    pub balance_formatted: String,
    /// Número de outputs no gastados
    pub unspent_outputs: usize,
    /// Número de outputs gastados
    pub spent_outputs: usize,
    /// Última altura escaneada
    pub last_scanned_height: u64,
}

// =============================================================================
// Unspent Output Response
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnspentOutputResponse {
    pub global_index: u64,
    pub amount: u64,
    pub amount_formatted: String,
    pub block_height: u64,
    pub tx_hash: String,
    pub memo: String,
    pub confirmations: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListUnspentResponse {
    pub outputs: Vec<UnspentOutputResponse>,
    pub total: u64,
    pub total_formatted: String,
}

// =============================================================================
// Send Response
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendShieldedResponse {
    pub tx_hash: String,
    pub fee: u64,
    pub inputs_used: usize,
    pub outputs_created: usize,
    pub change_amount: u64,
}

// =============================================================================
// Address Response
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedAddressResponse {
    pub stealth_address: String,
    pub view_pubkey: String,
    pub spend_pubkey: String,
}

// =============================================================================
// Scan Response
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResponse {
    pub blocks_scanned: u64,
    pub outputs_scanned: u64,
    pub outputs_found: u64,
    pub new_balance: u64,
    pub time_ms: u128,
}

// =============================================================================
// Privacy RPC Handler
// =============================================================================

/// Handler de RPC para privacidad
pub struct PrivacyRpc {
    /// Claves de privacidad (None si watch-only)
    keys: Option<PrivacyKeys>,
    
    /// View key para escaneo (siempre presente)
    view_key: Option<crate::privacy::keys::ViewingKey>,
    
    /// Wallet shielded
    wallet: ShieldedWallet,
    
    /// Pool de outputs (referencia al estado global)
    pool: ShieldedPool,
    
    /// Altura actual de la blockchain
    current_height: u64,
}

impl PrivacyRpc {
    /// Crea un nuevo handler con claves completas
    pub fn new(keys: PrivacyKeys) -> Self {
        let view_key = keys.view_key.clone();
        PrivacyRpc {
            keys: Some(keys),
            view_key: Some(view_key),
            wallet: ShieldedWallet::new(),
            pool: ShieldedPool::new(),
            current_height: 0,
        }
    }
    
    /// Crea un handler watch-only (solo view key)
    pub fn watch_only(view_key: crate::privacy::keys::ViewingKey, _spend_pubkey: CompressedPoint) -> Self {
        PrivacyRpc {
            keys: None,
            view_key: Some(view_key),
            wallet: ShieldedWallet::new(),
            pool: ShieldedPool::new(),
            current_height: 0,
        }
    }
    
    /// Actualiza altura actual
    pub fn set_current_height(&mut self, height: u64) {
        self.current_height = height;
    }
    
    /// Actualiza pool (típicamente desde el estado global)
    pub fn set_pool(&mut self, pool: ShieldedPool) {
        self.pool = pool;
    }
    
    // =========================================================================
    // RPC: getshieldedbalance
    // =========================================================================
    
    pub fn get_shielded_balance(&self) -> RpcResponse<ShieldedBalanceResponse> {
        let balance = self.wallet.balance();
        
        RpcResponse::ok(ShieldedBalanceResponse {
            balance,
            balance_formatted: format_amount(balance),
            unspent_outputs: self.wallet.unspent_count(),
            spent_outputs: self.wallet.spent_count(),
            last_scanned_height: self.wallet.last_scanned_height(),
        })
    }
    
    // =========================================================================
    // RPC: listshieldedunspent
    // =========================================================================
    
    pub fn list_shielded_unspent(&self, min_confirmations: u64) -> RpcResponse<ListUnspentResponse> {
        let unspent = self.wallet.get_unspent();
        
        let outputs: Vec<UnspentOutputResponse> = unspent.iter()
            .filter(|o| self.current_height >= o.block_height + min_confirmations)
            .map(|o| {
                let confirmations = if self.current_height >= o.block_height {
                    self.current_height - o.block_height + 1
                } else {
                    0
                };
                
                UnspentOutputResponse {
                    global_index: o.global_index,
                    amount: o.amount,
                    amount_formatted: format_amount(o.amount),
                    block_height: o.block_height,
                    tx_hash: hex::encode(&o.tx_hash),
                    memo: String::from_utf8_lossy(&o.memo).to_string(),
                    confirmations,
                }
            })
            .collect();
        
        let total: u64 = outputs.iter().map(|o| o.amount).sum();
        
        RpcResponse::ok(ListUnspentResponse {
            outputs,
            total,
            total_formatted: format_amount(total),
        })
    }
    
    // =========================================================================
    // RPC: getshieldedaddress
    // =========================================================================
    
    pub fn get_shielded_address(&self) -> RpcResponse<ShieldedAddressResponse> {
        match &self.keys {
            Some(keys) => {
                let addr = keys.stealth_address();
                RpcResponse::ok(ShieldedAddressResponse {
                    stealth_address: addr.encode(),
                    view_pubkey: hex::encode(&addr.view_pubkey.as_bytes()),
                    spend_pubkey: hex::encode(&addr.spend_pubkey.as_bytes()),
                })
            }
            None => RpcResponse::err("No spending keys available (watch-only mode)"),
        }
    }
    
    // =========================================================================
    // RPC: sendshielded
    // =========================================================================
    
    pub fn send_shielded(
        &mut self,
        to_address: &str,
        amount: u64,
        memo: Option<&str>,
        fee: Option<u64>,
    ) -> RpcResponse<SendShieldedResponse> {
        // Verificar que tenemos claves completas
        let keys = match &self.keys {
            Some(k) => k,
            None => return RpcResponse::err("Cannot send: watch-only mode"),
        };
        
        // Parsear dirección destino
        let recipient_addr = match StealthAddress::decode(to_address) {
            Some(addr) => addr,
            None => return RpcResponse::err("Invalid stealth address"),
        };
        
        // Calcular fee
        let tx_fee = fee.unwrap_or(MIN_SHIELDED_FEE);
        if tx_fee < MIN_SHIELDED_FEE {
            return RpcResponse::err(format!("Fee too low: minimum is {}", MIN_SHIELDED_FEE));
        }
        
        // Seleccionar inputs
        let selected = match self.wallet.select_outputs(amount, tx_fee) {
            Some(s) => s,
            None => return RpcResponse::err("Insufficient shielded balance"),
        };
        
        let total_input: u64 = selected.iter().map(|o| o.amount).sum();
        let change = total_input - amount - tx_fee;
        
        // Crear output para destinatario
        let (recipient_output, recipient_blinding) = match ShieldedOutput::new(
            amount,
            &recipient_addr.view_pubkey,
            &recipient_addr.spend_pubkey,
            memo.map(|m| m.as_bytes()),
        ) {
            Ok((o, s)) => (o, s.blinding),
            Err(e) => return RpcResponse::err(format!("Failed to create output: {:?}", e)),
        };
        
        let mut outputs = vec![recipient_output];
        let mut output_blindings = vec![recipient_blinding];
        
        // Crear output de cambio si es necesario
        if change > 0 {
            let our_addr = keys.stealth_address();
            let (change_output, change_secrets) = match ShieldedOutput::new(
                change,
                &our_addr.view_pubkey,
                &our_addr.spend_pubkey,
                Some(b"change"),
            ) {
                Ok((o, s)) => (o, s),
                Err(e) => return RpcResponse::err(format!("Failed to create change: {:?}", e)),
            };
            outputs.push(change_output);
            output_blindings.push(change_secrets.blinding);
        }
        
        // Crear inputs shielded
        // Nota: En producción, esto requeriría seleccionar decoys del pool
        let shielded_inputs: Vec<ShieldedInput> = Vec::new(); // Simplificado
        let input_blindings: Vec<Scalar> = selected.iter().map(|o| o.blinding).collect();
        
        // Crear TX
        let tx = match ShieldedTx::new_fully_shielded(
            shielded_inputs,
            &input_blindings,
            outputs,
            &output_blindings,
            tx_fee,
        ) {
            Ok(t) => t,
            Err(e) => return RpcResponse::err(format!("Failed to create TX: {:?}", e)),
        };
        
        let tx_hash = tx.hash();
        
        // Marcar outputs como gastados
        for _output in &selected {
            // En producción, esto se haría después de confirmación
            // self.wallet.mark_spent(output.global_index, key_image);
        }
        
        RpcResponse::ok(SendShieldedResponse {
            tx_hash: hex::encode(&tx_hash),
            fee: tx_fee,
            inputs_used: selected.len(),
            outputs_created: if change > 0 { 2 } else { 1 },
            change_amount: change,
        })
    }
    
    // =========================================================================
    // RPC: shieldcoins (transparent → shielded)
    // =========================================================================
    
    pub fn shield_coins(
        &mut self,
        amount: u64,
        fee: Option<u64>,
    ) -> RpcResponse<SendShieldedResponse> {
        let keys = match &self.keys {
            Some(k) => k,
            None => return RpcResponse::err("Cannot shield: watch-only mode"),
        };
        
        let tx_fee = fee.unwrap_or(MIN_SHIELDED_FEE);
        let our_addr = keys.stealth_address();
        
        // Crear output shielded para nosotros
        let (output, secrets) = match ShieldedOutput::new(
            amount,
            &our_addr.view_pubkey,
            &our_addr.spend_pubkey,
            Some(b"shielded deposit"),
        ) {
            Ok((o, s)) => (o, s),
            Err(e) => return RpcResponse::err(format!("Failed to create output: {:?}", e)),
        };
        
        // Crear TX de shielding
        let tx = match ShieldedTx::new_shielding(
            vec![], // transparent inputs (se agregarían del UTXO set transparente)
            vec![output],
            &[secrets.blinding],
            tx_fee,
        ) {
            Ok(t) => t,
            Err(e) => return RpcResponse::err(format!("Failed to create TX: {:?}", e)),
        };
        
        let tx_hash = tx.hash();
        
        RpcResponse::ok(SendShieldedResponse {
            tx_hash: hex::encode(&tx_hash),
            fee: tx_fee,
            inputs_used: 0, // transparent inputs
            outputs_created: 1,
            change_amount: 0,
        })
    }
    
    // =========================================================================
    // RPC: unshieldcoins (shielded → transparent)
    // =========================================================================
    
    pub fn unshield_coins(
        &mut self,
        amount: u64,
        to_address: &str, // transparent address
        fee: Option<u64>,
    ) -> RpcResponse<SendShieldedResponse> {
        let _keys = match &self.keys {
            Some(k) => k,
            None => return RpcResponse::err("Cannot unshield: watch-only mode"),
        };
        
        let tx_fee = fee.unwrap_or(MIN_SHIELDED_FEE);
        
        // Seleccionar inputs shielded
        let selected = match self.wallet.select_outputs(amount, tx_fee) {
            Some(s) => s,
            None => return RpcResponse::err("Insufficient shielded balance"),
        };
        
        let total_input: u64 = selected.iter().map(|o| o.amount).sum();
        let change = total_input - amount - tx_fee;
        
        // Crear transparent output
        let transparent_output = crate::transaction::TxOut {
            to: to_address.to_string(),
            amount,
        };
        
        // Input blindings
        let input_blindings: Vec<Scalar> = selected.iter().map(|o| o.blinding).collect();
        
        // Crear TX de unshielding
        let tx = match ShieldedTx::new_unshielding(
            vec![], // shielded inputs (simplificado)
            &input_blindings,
            vec![transparent_output],
            tx_fee,
        ) {
            Ok(t) => t,
            Err(e) => return RpcResponse::err(format!("Failed to create TX: {:?}", e)),
        };
        
        let tx_hash = tx.hash();
        
        RpcResponse::ok(SendShieldedResponse {
            tx_hash: hex::encode(&tx_hash),
            fee: tx_fee,
            inputs_used: selected.len(),
            outputs_created: 1,
            change_amount: change,
        })
    }
    
    // =========================================================================
    // RPC: scanblockchain
    // =========================================================================
    
    pub fn scan_blockchain(
        &mut self,
        from_height: Option<u64>,
        outputs: &[ShieldedOutput],
    ) -> RpcResponse<ScanResponse> {
        let _view_key = match &self.view_key {
            Some(vk) => vk,
            None => return RpcResponse::err("No view key available"),
        };
        
        let keys = match &self.keys {
            Some(k) => k,
            None => return RpcResponse::err("Keys required for scanning"),
        };
        
        let start = std::time::Instant::now();
        let mut scanner = WalletScanner::from_keys(keys);
        
        let start_height = from_height.unwrap_or(self.wallet.last_scanned_height());
        
        // Escanear outputs proporcionados
        for (i, output) in outputs.iter().enumerate() {
            if let Some(owned) = scanner.scan_output(
                output,
                self.pool.next_index() + i as u64,
                [0u8; 32], // tx_hash placeholder
                0,
                start_height + 1,
            ) {
                self.wallet.add_output(owned);
            }
        }
        
        let stats = scanner.stats();
        self.wallet.set_last_scanned_height(self.current_height);
        
        RpcResponse::ok(ScanResponse {
            blocks_scanned: self.current_height - start_height,
            outputs_scanned: stats.outputs_scanned,
            outputs_found: stats.outputs_found,
            new_balance: self.wallet.balance(),
            time_ms: start.elapsed().as_millis(),
        })
    }
    
    // =========================================================================
    // RPC: exportviewkey
    // =========================================================================
    
    pub fn export_view_key(&self) -> RpcResponse<String> {
        match &self.keys {
            Some(keys) => RpcResponse::ok(keys.view_key.export()),
            None => match &self.view_key {
                Some(vk) => RpcResponse::ok(vk.export()),
                None => RpcResponse::err("No view key available"),
            }
        }
    }
    
    // =========================================================================
    // RPC: getwalletinfo
    // =========================================================================
    
    pub fn get_wallet_info(&self) -> RpcResponse<WalletInfo> {
        RpcResponse::ok(WalletInfo {
            mode: if self.keys.is_some() { "full" } else { "watch-only" }.to_string(),
            has_view_key: self.view_key.is_some(),
            has_spend_key: self.keys.is_some(),
            balance: self.wallet.balance(),
            balance_formatted: format_amount(self.wallet.balance()),
            unspent_count: self.wallet.unspent_count(),
            spent_count: self.wallet.spent_count(),
            last_scanned_height: self.wallet.last_scanned_height(),
            current_height: self.current_height,
            pool_size: self.pool.len(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletInfo {
    pub mode: String,
    pub has_view_key: bool,
    pub has_spend_key: bool,
    pub balance: u64,
    pub balance_formatted: String,
    pub unspent_count: usize,
    pub spent_count: usize,
    pub last_scanned_height: u64,
    pub current_height: u64,
    pub pool_size: usize,
}

// =============================================================================
// Helpers
// =============================================================================

/// Formatea cantidad en MOON
fn format_amount(satoshis: u64) -> String {
    let moon = satoshis as f64 / 1_000_000.0;
    format!("{:.6} MOON", moon)
}

/// Parsea cantidad desde string
pub fn parse_amount(s: &str) -> Option<u64> {
    // Soporta: "1.5", "1.5 MOON", "1500000" (satoshis)
    let s = s.trim().to_uppercase();
    let s = s.trim_end_matches("MOON").trim();
    
    if let Ok(sats) = s.parse::<u64>() {
        // Es un número entero, asumir satoshis si es grande
        if sats > 1_000_000 {
            return Some(sats);
        }
    }
    
    if let Ok(moon) = s.parse::<f64>() {
        return Some((moon * 1_000_000.0) as u64);
    }
    
    None
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_amount() {
        assert_eq!(format_amount(1_000_000), "1.000000 MOON");
        assert_eq!(format_amount(500_000), "0.500000 MOON");
        assert_eq!(format_amount(1), "0.000001 MOON");
    }
    
    #[test]
    fn test_parse_amount() {
        assert_eq!(parse_amount("1.5"), Some(1_500_000));
        assert_eq!(parse_amount("1.5 MOON"), Some(1_500_000));
        assert_eq!(parse_amount("0.000001"), Some(1));
    }
    
    #[test]
    fn test_rpc_balance() {
        let keys = PrivacyKeys::generate();
        let rpc = PrivacyRpc::new(keys);
        
        let response = rpc.get_shielded_balance();
        assert!(response.success);
        assert_eq!(response.result.unwrap().balance, 0);
    }
    
    #[test]
    fn test_rpc_address() {
        let keys = PrivacyKeys::generate();
        let rpc = PrivacyRpc::new(keys);
        
        let response = rpc.get_shielded_address();
        assert!(response.success);
        assert!(response.result.unwrap().stealth_address.starts_with("mzs"));
    }
}
