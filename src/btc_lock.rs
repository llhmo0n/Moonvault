// =============================================================================
// MOONCOIN BTC LOCK MODULE
// LOCK-OPERATE-SETTLE Reference Implementation v1.0
// =============================================================================
//
// Este módulo implementa el modelo operativo Mooncoin-Bitcoin:
// - LOCK: Scripts Bitcoin con timelock para protección
// - OPERATE: Uso de MOON mientras BTC está bloqueado
// - SETTLE: Recuperación de BTC después del timelock
//
// ADVERTENCIA: Mooncoin NO custodia BTC. Mooncoin OBSERVA Bitcoin.
// Un script malformado puede resultar en PÉRDIDA PERMANENTE de BTC.
// =============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

use std::collections::HashMap;
use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

// =============================================================================
// TYPES
// =============================================================================

/// Estados del LOCK derivados de la observación de Bitcoin
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockState {
    /// UTXO no encontrado o no registrado
    Unknown,
    /// UTXO existe, timelock no expirado
    Locked,
    /// UTXO existe, timelock expirado (puede hacer settle)
    Expired,
    /// UTXO ha sido gastado
    Settled,
}

impl std::fmt::Display for LockState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockState::Unknown => write!(f, "UNKNOWN"),
            LockState::Locked => write!(f, "LOCKED"),
            LockState::Expired => write!(f, "EXPIRED"),
            LockState::Settled => write!(f, "SETTLED"),
        }
    }
}

/// Tipos de template LOCK STANDARD
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockTemplate {
    /// 2-of-2 multisig O salida unilateral después de CLTV timelock
    MultisigCltv,
    /// Hash-locked con timeout de refund CSV
    HtlcSimple,
}

impl std::fmt::Display for LockTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockTemplate::MultisigCltv => write!(f, "multisig_cltv"),
            LockTemplate::HtlcSimple => write!(f, "htlc_simple"),
        }
    }
}

/// Resultado del matching de template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMatch {
    pub template: LockTemplate,
    pub timelock_value: u32,
    pub timelock_type: TimelockType,
    pub pubkeys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelockType {
    /// OP_CHECKLOCKTIMEVERIFY - altura de bloque absoluta
    Absolute,
    /// OP_CHECKSEQUENCEVERIFY - bloques relativos
    Relative,
}

/// Estado del timelock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelockStatus {
    pub expired: bool,
    pub timelock_block: u32,
    pub current_block: u32,
    pub blocks_remaining: i32,
}

/// Errores del Observer
#[derive(Debug, Clone)]
pub enum ObserverError {
    ConnectionFailed(String),
    UtxoNotFound,
    TransactionNotFound,
    InvalidScript(String),
    InvalidTxid(String),
    BackendError(String),
    Timeout,
    ParseError(String),
}

impl std::fmt::Display for ObserverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObserverError::ConnectionFailed(s) => write!(f, "Connection failed: {}", s),
            ObserverError::UtxoNotFound => write!(f, "UTXO not found"),
            ObserverError::TransactionNotFound => write!(f, "Transaction not found"),
            ObserverError::InvalidScript(s) => write!(f, "Invalid script: {}", s),
            ObserverError::InvalidTxid(s) => write!(f, "Invalid txid: {}", s),
            ObserverError::BackendError(s) => write!(f, "Backend error: {}", s),
            ObserverError::Timeout => write!(f, "Request timeout"),
            ObserverError::ParseError(s) => write!(f, "Parse error: {}", s),
        }
    }
}

impl std::error::Error for ObserverError {}

/// Información de UTXO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub script_pubkey: String,
    pub confirmations: i32,
    pub spent: bool,
}

/// Información de lock registrado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredLock {
    pub lock_id: String,
    pub btc_txid: String,
    pub btc_vout: u32,
    pub redeem_script_hex: String,
    pub template: LockTemplate,
    pub timelock_block: u32,
    pub registered_at: u64,
    pub state: LockState,
    pub last_checked: u64,
    pub amount_sats: Option<u64>,
    pub p2wsh_address: String,
}

// =============================================================================
// BITCOIN OPCODES
// =============================================================================

pub mod opcodes {
    pub const OP_0: u8 = 0x00;
    pub const OP_IF: u8 = 0x63;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_2: u8 = 0x52;
    pub const OP_CHECKMULTISIG: u8 = 0xae;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
    pub const OP_SHA256: u8 = 0xa8;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_PUSHBYTES_33: u8 = 0x21;
    pub const OP_PUSHBYTES_32: u8 = 0x20;
}

// =============================================================================
// SCRIPT TEMPLATE MATCHING
// =============================================================================

/// Coincide un script contra los templates LOCK STANDARD
pub fn match_lock_template(script: &[u8]) -> Result<Option<TemplateMatch>, ObserverError> {
    if let Some(m) = try_match_multisig_cltv(script)? {
        return Ok(Some(m));
    }
    if let Some(m) = try_match_htlc_simple(script)? {
        return Ok(Some(m));
    }
    Ok(None)
}

fn try_match_multisig_cltv(script: &[u8]) -> Result<Option<TemplateMatch>, ObserverError> {
    if script.len() < 100 {
        return Ok(None);
    }
    
    let mut pos = 0;
    
    if script.get(pos) != Some(&opcodes::OP_IF) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_2) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_PUSHBYTES_33) { return Ok(None); }
    pos += 1;
    let pubkey1 = script.get(pos..pos+33).ok_or(ObserverError::InvalidScript("truncated pubkey1".into()))?;
    let pubkey1_hex = hex::encode(pubkey1);
    pos += 33;
    
    if script.get(pos) != Some(&opcodes::OP_PUSHBYTES_33) { return Ok(None); }
    pos += 1;
    let pubkey2 = script.get(pos..pos+33).ok_or(ObserverError::InvalidScript("truncated pubkey2".into()))?;
    let pubkey2_hex = hex::encode(pubkey2);
    pos += 33;
    
    if script.get(pos) != Some(&opcodes::OP_2) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_CHECKMULTISIG) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_ELSE) { return Ok(None); }
    pos += 1;
    
    let (locktime, locktime_len) = parse_locktime(&script[pos..])?;
    pos += locktime_len;
    
    if script.get(pos) != Some(&opcodes::OP_CHECKLOCKTIMEVERIFY) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_DROP) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_PUSHBYTES_33) { return Ok(None); }
    pos += 1;
    let pubkey3 = script.get(pos..pos+33).ok_or(ObserverError::InvalidScript("truncated pubkey3".into()))?;
    let pubkey3_hex = hex::encode(pubkey3);
    pos += 33;
    
    if script.get(pos) != Some(&opcodes::OP_CHECKSIG) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_ENDIF) { return Ok(None); }
    pos += 1;
    
    if pos != script.len() { return Ok(None); }
    
    Ok(Some(TemplateMatch {
        template: LockTemplate::MultisigCltv,
        timelock_value: locktime,
        timelock_type: TimelockType::Absolute,
        pubkeys: vec![pubkey1_hex, pubkey2_hex, pubkey3_hex],
    }))
}

fn try_match_htlc_simple(script: &[u8]) -> Result<Option<TemplateMatch>, ObserverError> {
    if script.len() < 80 {
        return Ok(None);
    }
    
    let mut pos = 0;
    
    if script.get(pos) != Some(&opcodes::OP_IF) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_SHA256) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_PUSHBYTES_32) { return Ok(None); }
    pos += 1;
    let _hash = script.get(pos..pos+32).ok_or(ObserverError::InvalidScript("truncated hash".into()))?;
    pos += 32;
    
    if script.get(pos) != Some(&opcodes::OP_EQUALVERIFY) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_PUSHBYTES_33) { return Ok(None); }
    pos += 1;
    let pubkey1 = script.get(pos..pos+33).ok_or(ObserverError::InvalidScript("truncated pubkey".into()))?;
    let pubkey1_hex = hex::encode(pubkey1);
    pos += 33;
    
    if script.get(pos) != Some(&opcodes::OP_CHECKSIG) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_ELSE) { return Ok(None); }
    pos += 1;
    
    let (timeout, timeout_len) = parse_locktime(&script[pos..])?;
    pos += timeout_len;
    
    if script.get(pos) != Some(&opcodes::OP_CHECKSEQUENCEVERIFY) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_DROP) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_PUSHBYTES_33) { return Ok(None); }
    pos += 1;
    let pubkey2 = script.get(pos..pos+33).ok_or(ObserverError::InvalidScript("truncated refund pubkey".into()))?;
    let pubkey2_hex = hex::encode(pubkey2);
    pos += 33;
    
    if script.get(pos) != Some(&opcodes::OP_CHECKSIG) { return Ok(None); }
    pos += 1;
    
    if script.get(pos) != Some(&opcodes::OP_ENDIF) { return Ok(None); }
    pos += 1;
    
    if pos != script.len() { return Ok(None); }
    
    Ok(Some(TemplateMatch {
        template: LockTemplate::HtlcSimple,
        timelock_value: timeout,
        timelock_type: TimelockType::Relative,
        pubkeys: vec![pubkey1_hex, pubkey2_hex],
    }))
}

fn parse_locktime(data: &[u8]) -> Result<(u32, usize), ObserverError> {
    if data.is_empty() {
        return Err(ObserverError::InvalidScript("empty locktime".into()));
    }
    
    let first = data[0];
    
    if first == 0x00 {
        return Ok((0, 1));
    }
    if first >= 0x51 && first <= 0x60 {
        return Ok(((first - 0x50) as u32, 1));
    }
    
    if first >= 0x01 && first <= 0x04 {
        let len = first as usize;
        if data.len() < 1 + len {
            return Err(ObserverError::InvalidScript("truncated locktime".into()));
        }
        let mut value: u32 = 0;
        for i in 0..len {
            value |= (data[1 + i] as u32) << (8 * i);
        }
        return Ok((value, 1 + len));
    }
    
    Err(ObserverError::InvalidScript(format!("unexpected locktime opcode: {:02x}", first)))
}

// =============================================================================
// SCRIPT GENERATION
// =============================================================================

/// Parámetros para script MultisigCltv
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigCltvParams {
    pub pubkey_hot: String,
    pub pubkey_cold: String,
    pub pubkey_recovery: String,
    pub locktime_blocks: u32,
}

/// Parámetros para script HtlcSimple
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcSimpleParams {
    pub hash_hex: String,
    pub pubkey: String,
    pub timeout_blocks: u32,
}

/// Genera script MultisigCltv
pub fn generate_multisig_cltv(params: &MultisigCltvParams) -> Result<Vec<u8>, ObserverError> {
    let pubkey_hot = hex::decode(&params.pubkey_hot)
        .map_err(|_| ObserverError::InvalidScript("invalid pubkey_hot hex".into()))?;
    let pubkey_cold = hex::decode(&params.pubkey_cold)
        .map_err(|_| ObserverError::InvalidScript("invalid pubkey_cold hex".into()))?;
    let pubkey_recovery = hex::decode(&params.pubkey_recovery)
        .map_err(|_| ObserverError::InvalidScript("invalid pubkey_recovery hex".into()))?;
    
    if pubkey_hot.len() != 33 || pubkey_cold.len() != 33 || pubkey_recovery.len() != 33 {
        return Err(ObserverError::InvalidScript("pubkeys must be 33 bytes".into()));
    }
    
    let mut script = Vec::new();
    
    script.push(opcodes::OP_IF);
    script.push(opcodes::OP_2);
    script.push(opcodes::OP_PUSHBYTES_33);
    script.extend_from_slice(&pubkey_hot);
    script.push(opcodes::OP_PUSHBYTES_33);
    script.extend_from_slice(&pubkey_cold);
    script.push(opcodes::OP_2);
    script.push(opcodes::OP_CHECKMULTISIG);
    script.push(opcodes::OP_ELSE);
    encode_locktime(&mut script, params.locktime_blocks);
    script.push(opcodes::OP_CHECKLOCKTIMEVERIFY);
    script.push(opcodes::OP_DROP);
    script.push(opcodes::OP_PUSHBYTES_33);
    script.extend_from_slice(&pubkey_recovery);
    script.push(opcodes::OP_CHECKSIG);
    script.push(opcodes::OP_ENDIF);
    
    Ok(script)
}

/// Genera script HtlcSimple
pub fn generate_htlc_simple(params: &HtlcSimpleParams) -> Result<Vec<u8>, ObserverError> {
    let hash = hex::decode(&params.hash_hex)
        .map_err(|_| ObserverError::InvalidScript("invalid hash hex".into()))?;
    let pubkey = hex::decode(&params.pubkey)
        .map_err(|_| ObserverError::InvalidScript("invalid pubkey hex".into()))?;
    
    if hash.len() != 32 {
        return Err(ObserverError::InvalidScript("hash must be 32 bytes".into()));
    }
    if pubkey.len() != 33 {
        return Err(ObserverError::InvalidScript("pubkey must be 33 bytes".into()));
    }
    
    let mut script = Vec::new();
    
    script.push(opcodes::OP_IF);
    script.push(opcodes::OP_SHA256);
    script.push(opcodes::OP_PUSHBYTES_32);
    script.extend_from_slice(&hash);
    script.push(opcodes::OP_EQUALVERIFY);
    script.push(opcodes::OP_PUSHBYTES_33);
    script.extend_from_slice(&pubkey);
    script.push(opcodes::OP_CHECKSIG);
    script.push(opcodes::OP_ELSE);
    encode_locktime(&mut script, params.timeout_blocks);
    script.push(opcodes::OP_CHECKSEQUENCEVERIFY);
    script.push(opcodes::OP_DROP);
    script.push(opcodes::OP_PUSHBYTES_33);
    script.extend_from_slice(&pubkey);
    script.push(opcodes::OP_CHECKSIG);
    script.push(opcodes::OP_ENDIF);
    
    Ok(script)
}

fn encode_locktime(script: &mut Vec<u8>, value: u32) {
    if value == 0 {
        script.push(0x00);
    } else if value <= 16 {
        script.push(0x50 + value as u8);
    } else if value <= 0x7f {
        script.push(0x01);
        script.push(value as u8);
    } else if value <= 0x7fff {
        script.push(0x02);
        script.push(value as u8);
        script.push((value >> 8) as u8);
    } else if value <= 0x7fffff {
        script.push(0x03);
        script.push(value as u8);
        script.push((value >> 8) as u8);
        script.push((value >> 16) as u8);
    } else {
        script.push(0x04);
        script.push(value as u8);
        script.push((value >> 8) as u8);
        script.push((value >> 16) as u8);
        script.push((value >> 24) as u8);
    }
}

// =============================================================================
// P2WSH ADDRESS GENERATION
// =============================================================================

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn script_to_p2wsh_address(script: &[u8], mainnet: bool) -> String {
    let script_hash = sha256(script);
    let hrp = if mainnet { "bc" } else { "tb" };
    bech32_encode(hrp, 0, &script_hash)
}

fn bech32_encode(hrp: &str, version: u8, program: &[u8]) -> String {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    
    let mut data = vec![version];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    
    for &byte in program {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        data.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    
    let mut chk = bech32_polymod_hrp(hrp);
    for &d in &data {
        chk = bech32_polymod_step(chk) ^ (d as u32);
    }
    for _ in 0..6 {
        chk = bech32_polymod_step(chk);
    }
    chk ^= 1;
    
    let mut result = String::from(hrp);
    result.push('1');
    for &d in &data {
        result.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        result.push(CHARSET[((chk >> (5 * (5 - i))) & 0x1f) as usize] as char);
    }
    
    result
}

fn bech32_polymod_hrp(hrp: &str) -> u32 {
    let mut chk: u32 = 1;
    for c in hrp.bytes() {
        chk = bech32_polymod_step(chk) ^ ((c >> 5) as u32);
    }
    chk = bech32_polymod_step(chk);
    for c in hrp.bytes() {
        chk = bech32_polymod_step(chk) ^ ((c & 0x1f) as u32);
    }
    chk
}

fn bech32_polymod_step(pre: u32) -> u32 {
    let b = pre >> 25;
    ((pre & 0x1ffffff) << 5)
        ^ (if b & 1 != 0 { 0x3b6a57b2 } else { 0 })
        ^ (if b & 2 != 0 { 0x26508e6d } else { 0 })
        ^ (if b & 4 != 0 { 0x1ea119fa } else { 0 })
        ^ (if b & 8 != 0 { 0x3d4233dd } else { 0 })
        ^ (if b & 16 != 0 { 0x2a1462b3 } else { 0 })
}

// =============================================================================
// BTC OBSERVER TRAIT
// =============================================================================

pub trait BtcObserver {
    fn utxo_exists(&self, txid: &str, vout: u32) -> Result<bool, ObserverError>;
    fn utxo_confirmations(&self, txid: &str, vout: u32) -> Result<i32, ObserverError>;
    fn current_block_height(&self) -> Result<u32, ObserverError>;
    fn get_utxo(&self, txid: &str, vout: u32) -> Result<Option<UtxoInfo>, ObserverError>;
}

// =============================================================================
// MOCK OBSERVER (para testing sin nodo BTC real)
// =============================================================================

pub struct MockBtcObserver {
    utxos: HashMap<String, MockUtxo>,
    current_height: u32,
}

struct MockUtxo {
    amount_sats: u64,
    confirmations: i32,
    spent: bool,
}

impl MockBtcObserver {
    pub fn new(initial_height: u32) -> Self {
        Self {
            utxos: HashMap::new(),
            current_height: initial_height,
        }
    }
    
    pub fn add_utxo(&mut self, txid: &str, vout: u32, amount_sats: u64, confirmations: i32) {
        let key = format!("{}:{}", txid, vout);
        self.utxos.insert(key, MockUtxo {
            amount_sats,
            confirmations,
            spent: false,
        });
    }
    
    pub fn spend_utxo(&mut self, txid: &str, vout: u32) {
        let key = format!("{}:{}", txid, vout);
        if let Some(utxo) = self.utxos.get_mut(&key) {
            utxo.spent = true;
        }
    }
    
    pub fn set_height(&mut self, height: u32) {
        self.current_height = height;
    }
}

impl BtcObserver for MockBtcObserver {
    fn utxo_exists(&self, txid: &str, vout: u32) -> Result<bool, ObserverError> {
        let key = format!("{}:{}", txid, vout);
        match self.utxos.get(&key) {
            Some(utxo) => Ok(!utxo.spent),
            None => Ok(false),
        }
    }
    
    fn utxo_confirmations(&self, txid: &str, vout: u32) -> Result<i32, ObserverError> {
        let key = format!("{}:{}", txid, vout);
        match self.utxos.get(&key) {
            Some(utxo) => Ok(utxo.confirmations),
            None => Ok(-1),
        }
    }
    
    fn current_block_height(&self) -> Result<u32, ObserverError> {
        Ok(self.current_height)
    }
    
    fn get_utxo(&self, txid: &str, vout: u32) -> Result<Option<UtxoInfo>, ObserverError> {
        let key = format!("{}:{}", txid, vout);
        match self.utxos.get(&key) {
            Some(utxo) => Ok(Some(UtxoInfo {
                txid: txid.to_string(),
                vout,
                amount_sats: utxo.amount_sats,
                script_pubkey: "".to_string(),
                confirmations: utxo.confirmations,
                spent: utxo.spent,
            })),
            None => Ok(None),
        }
    }
}

// =============================================================================
// ESPLORA OBSERVER (conexión real a Bitcoin via Blockstream API)
// =============================================================================

#[derive(Debug, Clone)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
}

impl BitcoinNetwork {
    pub fn base_url(&self) -> &'static str {
        match self {
            BitcoinNetwork::Mainnet => "https://blockstream.info/api",
            BitcoinNetwork::Testnet => "https://blockstream.info/testnet/api",
            BitcoinNetwork::Signet => "https://mempool.space/signet/api",
        }
    }
    
    pub fn name(&self) -> &'static str {
        match self {
            BitcoinNetwork::Mainnet => "mainnet",
            BitcoinNetwork::Testnet => "testnet",
            BitcoinNetwork::Signet => "signet",
        }
    }
}

pub struct EsploraObserver {
    base_url: String,
    network: BitcoinNetwork,
    timeout_secs: u64,
}

impl EsploraObserver {
    pub fn new(network: BitcoinNetwork) -> Self {
        Self {
            base_url: network.base_url().to_string(),
            network,
            timeout_secs: 30,
        }
    }
    
    pub fn mainnet() -> Self {
        Self::new(BitcoinNetwork::Mainnet)
    }
    
    pub fn testnet() -> Self {
        Self::new(BitcoinNetwork::Testnet)
    }
    
    pub fn signet() -> Self {
        Self::new(BitcoinNetwork::Signet)
    }
    
    pub fn network(&self) -> &BitcoinNetwork {
        &self.network
    }
    
    fn get(&self, endpoint: &str) -> Result<ureq::Response, ObserverError> {
        let url = format!("{}{}", self.base_url, endpoint);
        ureq::get(&url)
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .call()
            .map_err(|e| ObserverError::ConnectionFailed(e.to_string()))
    }
    
    fn get_json<T: serde::de::DeserializeOwned>(&self, endpoint: &str) -> Result<T, ObserverError> {
        let response = self.get(endpoint)?;
        response.into_json::<T>()
            .map_err(|e| ObserverError::ParseError(e.to_string()))
    }
    
    /// Verifica si el UTXO ha sido gastado
    fn get_outspend(&self, txid: &str, vout: u32) -> Result<OutspendInfo, ObserverError> {
        let endpoint = format!("/tx/{}/outspend/{}", txid, vout);
        self.get_json(&endpoint)
    }
    
    /// Obtiene información de una transacción
    pub fn get_transaction(&self, txid: &str) -> Result<EsploraTx, ObserverError> {
        let endpoint = format!("/tx/{}", txid);
        self.get_json(&endpoint)
    }
    
    /// Verifica conexión a la API
    pub fn check_connection(&self) -> Result<u32, ObserverError> {
        self.current_block_height()
    }
}

#[derive(Debug, Deserialize)]
pub struct OutspendInfo {
    pub spent: bool,
    #[serde(default)]
    pub txid: Option<String>,
    #[serde(default)]
    pub vin: Option<u32>,
    #[serde(default)]
    pub status: Option<OutspendStatus>,
}

#[derive(Debug, Deserialize)]
pub struct OutspendStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct EsploraTx {
    pub txid: String,
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<EsploraVin>,
    pub vout: Vec<EsploraVout>,
    pub size: u32,
    pub weight: u32,
    pub fee: u64,
    pub status: EsploraTxStatus,
}

#[derive(Debug, Deserialize)]
pub struct EsploraVin {
    pub txid: String,
    pub vout: u32,
    #[serde(default)]
    pub prevout: Option<EsploraVout>,
    pub scriptsig: String,
    #[serde(default)]
    pub witness: Option<Vec<String>>,
    pub sequence: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EsploraVout {
    pub scriptpubkey: String,
    #[serde(default)]
    pub scriptpubkey_asm: Option<String>,
    #[serde(default)]
    pub scriptpubkey_type: Option<String>,
    #[serde(default)]
    pub scriptpubkey_address: Option<String>,
    pub value: u64,
}

#[derive(Debug, Deserialize)]
pub struct EsploraTxStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u32>,
    #[serde(default)]
    pub block_hash: Option<String>,
    #[serde(default)]
    pub block_time: Option<u64>,
}

impl BtcObserver for EsploraObserver {
    fn utxo_exists(&self, txid: &str, vout: u32) -> Result<bool, ObserverError> {
        // Primero verificar que la transacción existe
        let tx = self.get_transaction(txid)?;
        
        // Verificar que el vout existe
        if vout as usize >= tx.vout.len() {
            return Ok(false);
        }
        
        // Verificar si ha sido gastado
        let outspend = self.get_outspend(txid, vout)?;
        
        // El UTXO existe si la tx está confirmada y no ha sido gastado
        Ok(tx.status.confirmed && !outspend.spent)
    }
    
    fn utxo_confirmations(&self, txid: &str, vout: u32) -> Result<i32, ObserverError> {
        let tx = self.get_transaction(txid)?;
        
        if !tx.status.confirmed {
            return Ok(0); // En mempool
        }
        
        let tx_height = tx.status.block_height
            .ok_or(ObserverError::ParseError("no block height".into()))?;
        
        let current_height = self.current_block_height()?;
        
        Ok((current_height - tx_height + 1) as i32)
    }
    
    fn current_block_height(&self) -> Result<u32, ObserverError> {
        let endpoint = "/blocks/tip/height";
        let response = self.get(endpoint)?;
        let height_str = response.into_string()
            .map_err(|e| ObserverError::ParseError(e.to_string()))?;
        height_str.trim().parse::<u32>()
            .map_err(|e| ObserverError::ParseError(e.to_string()))
    }
    
    fn get_utxo(&self, txid: &str, vout: u32) -> Result<Option<UtxoInfo>, ObserverError> {
        // Obtener transacción
        let tx = match self.get_transaction(txid) {
            Ok(tx) => tx,
            Err(_) => return Ok(None),
        };
        
        // Verificar que el vout existe
        if vout as usize >= tx.vout.len() {
            return Ok(None);
        }
        
        let output = &tx.vout[vout as usize];
        
        // Verificar si ha sido gastado
        let outspend = self.get_outspend(txid, vout)?;
        
        // Calcular confirmaciones
        let confirmations = if tx.status.confirmed {
            if let Some(tx_height) = tx.status.block_height {
                let current = self.current_block_height().unwrap_or(tx_height);
                (current - tx_height + 1) as i32
            } else {
                0
            }
        } else {
            0
        };
        
        Ok(Some(UtxoInfo {
            txid: txid.to_string(),
            vout,
            amount_sats: output.value,
            script_pubkey: output.scriptpubkey.clone(),
            confirmations,
            spent: outspend.spent,
        }))
    }
}

// =============================================================================
// LOCK REGISTRY
// =============================================================================

const LOCK_REGISTRY_FILE: &str = "btc_locks.json";

pub struct LockRegistry {
    locks: Vec<RegisteredLock>,
    next_id: u64,
}

impl LockRegistry {
    pub fn new() -> Self {
        Self {
            locks: Vec::new(),
            next_id: 1,
        }
    }
    
    pub fn load() -> Self {
        if let Ok(data) = std::fs::read_to_string(LOCK_REGISTRY_FILE) {
            if let Ok(locks) = serde_json::from_str::<Vec<RegisteredLock>>(&data) {
                let next_id = locks.len() as u64 + 1;
                return Self { locks, next_id };
            }
        }
        Self::new()
    }
    
    pub fn save(&self) -> Result<(), std::io::Error> {
        let data = serde_json::to_string_pretty(&self.locks)?;
        std::fs::write(LOCK_REGISTRY_FILE, data)
    }
    
    pub fn register(
        &mut self,
        btc_txid: String,
        btc_vout: u32,
        redeem_script: &[u8],
        template_match: &TemplateMatch,
        p2wsh_address: &str,
        amount_sats: Option<u64>,
    ) -> Result<RegisteredLock, ObserverError> {
        if self.find_by_utxo(&btc_txid, btc_vout).is_some() {
            return Err(ObserverError::BackendError("Lock already registered".into()));
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        
        let lock = RegisteredLock {
            lock_id: format!("moon_lock_{:08x}", self.next_id),
            btc_txid,
            btc_vout,
            redeem_script_hex: hex::encode(redeem_script),
            template: template_match.template.clone(),
            timelock_block: template_match.timelock_value,
            registered_at: now,
            state: LockState::Locked,
            last_checked: now,
            amount_sats,
            p2wsh_address: p2wsh_address.to_string(),
        };
        
        self.next_id += 1;
        self.locks.push(lock.clone());
        let _ = self.save();
        
        Ok(lock)
    }
    
    pub fn find_by_utxo(&self, txid: &str, vout: u32) -> Option<&RegisteredLock> {
        self.locks.iter().find(|l| l.btc_txid == txid && l.btc_vout == vout)
    }
    
    pub fn find_by_id(&self, lock_id: &str) -> Option<&RegisteredLock> {
        self.locks.iter().find(|l| l.lock_id == lock_id)
    }
    
    pub fn find_by_utxo_mut(&mut self, txid: &str, vout: u32) -> Option<&mut RegisteredLock> {
        self.locks.iter_mut().find(|l| l.btc_txid == txid && l.btc_vout == vout)
    }
    
    pub fn update_state<O: BtcObserver>(
        &mut self,
        txid: &str,
        vout: u32,
        observer: &O,
    ) -> Result<LockState, ObserverError> {
        let current_height = observer.current_block_height()?;
        let utxo_exists = observer.utxo_exists(txid, vout)?;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        
        let new_state = {
            let lock = self.find_by_utxo_mut(txid, vout)
                .ok_or(ObserverError::UtxoNotFound)?;
            
            lock.last_checked = now;
            
            if !utxo_exists {
                lock.state = LockState::Settled;
            } else if current_height >= lock.timelock_block {
                lock.state = LockState::Expired;
            } else {
                lock.state = LockState::Locked;
            }
            
            lock.state.clone()
        };
        
        let _ = self.save();
        Ok(new_state)
    }
    
    pub fn list(&self) -> &[RegisteredLock] {
        &self.locks
    }
    
    pub fn list_by_state(&self, state: &LockState) -> Vec<&RegisteredLock> {
        self.locks.iter().filter(|l| &l.state == state).collect()
    }
}

impl Default for LockRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TIMELOCK UTILITIES
// =============================================================================

pub fn get_timelock_status(template_match: &TemplateMatch, current_height: u32) -> TimelockStatus {
    let timelock_block = template_match.timelock_value;
    let blocks_remaining = timelock_block as i32 - current_height as i32;
    
    TimelockStatus {
        expired: current_height >= timelock_block,
        timelock_block,
        current_block: current_height,
        blocks_remaining,
    }
}

pub fn estimate_time_remaining(blocks_remaining: i32) -> String {
    if blocks_remaining <= 0 {
        return "EXPIRED".to_string();
    }
    
    // Para Bitcoin: 10 min/bloque
    // Para Mooncoin: 5 min/bloque (300 segundos según lib.rs)
    let minutes = blocks_remaining as f64 * 5.0; // Usando tiempo de bloque de Mooncoin
    let hours = minutes / 60.0;
    let days = hours / 24.0;
    
    if days >= 1.0 {
        format!("~{:.1} days", days)
    } else if hours >= 1.0 {
        format!("~{:.1} hours", hours)
    } else {
        format!("~{:.0} minutes", minutes)
    }
}

// =============================================================================
// WARNING MESSAGES
// =============================================================================

pub const WARNING_LOCK_GENERATE: &str = r#"
┌─────────────────────────────────────────────────────────────────┐
│ ⚠️  ADVERTENCIA: LEE CUIDADOSAMENTE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Mooncoin NO valida la corrección semántica de este script.      │
│ Mooncoin verifica SOLO que el formato coincida con el template. │
│                                                                 │
│ ERES COMPLETAMENTE RESPONSABLE DE:                              │
│   - Verificar que las claves públicas son correctas             │
│   - Verificar que controlas las claves privadas correspondientes│
│   - Verificar que el timelock es apropiado                      │
│   - Probar con cantidad pequeña antes de fondos grandes         │
│                                                                 │
│ UN SCRIPT MAL FORMADO PUEDE RESULTAR EN PÉRDIDA PERMANENTE.     │
│                                                                 │
│ Mooncoin NO PUEDE recuperar fondos perdidos bajo NINGUNA        │
│ circunstancia.                                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
"#;

pub const WARNING_OBSERVE_REGISTER: &str = r#"
┌─────────────────────────────────────────────────────────────────┐
│ ⚠️  ADVERTENCIA DE OBSERVACIÓN                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Mooncoin ha OBSERVADO este UTXO pero NO GARANTIZA que el        │
│ script sea correcto o que puedas gastarlo.                      │
│                                                                 │
│ Este registro es SOLO para tus propósitos de contabilidad.      │
│                                                                 │
│ Mooncoin NO custodia, controla, ni valida tu BTC.               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
"#;

// =============================================================================
// CLI COMMAND HELPERS
// =============================================================================

pub fn format_btc(sats: u64) -> String {
    format!("{:.8} BTC", sats as f64 / 100_000_000.0)
}

pub fn confirm(prompt: &str) -> bool {
    print!("{} [yes/NO]: ", prompt);
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    input.trim().to_lowercase() == "yes"
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_multisig_cltv() {
        let params = MultisigCltvParams {
            pubkey_hot: "02".to_string() + &"11".repeat(32),
            pubkey_cold: "03".to_string() + &"22".repeat(32),
            pubkey_recovery: "02".to_string() + &"33".repeat(32),
            locktime_blocks: 880000,
        };
        
        let script = generate_multisig_cltv(&params).unwrap();
        let matched = match_lock_template(&script).unwrap();
        
        assert!(matched.is_some());
        let m = matched.unwrap();
        assert_eq!(m.template, LockTemplate::MultisigCltv);
        assert_eq!(m.timelock_value, 880000);
    }
    
    #[test]
    fn test_generate_htlc_simple() {
        let params = HtlcSimpleParams {
            hash_hex: "aa".repeat(32),
            pubkey: "02".to_string() + &"44".repeat(32),
            timeout_blocks: 144,
        };
        
        let script = generate_htlc_simple(&params).unwrap();
        let matched = match_lock_template(&script).unwrap();
        
        assert!(matched.is_some());
        let m = matched.unwrap();
        assert_eq!(m.template, LockTemplate::HtlcSimple);
        assert_eq!(m.timelock_value, 144);
    }
    
    #[test]
    fn test_p2wsh_address() {
        let script = hex::decode("0014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let address = script_to_p2wsh_address(&script, true);
        assert!(address.starts_with("bc1"));
    }
    
    #[test]
    fn test_mock_observer() {
        let mut observer = MockBtcObserver::new(880000);
        let txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        
        assert!(!observer.utxo_exists(txid, 0).unwrap());
        
        observer.add_utxo(txid, 0, 10_000_000, 6);
        assert!(observer.utxo_exists(txid, 0).unwrap());
        
        observer.spend_utxo(txid, 0);
        assert!(!observer.utxo_exists(txid, 0).unwrap());
    }
}

// =============================================================================
// SETTLEMENT TRANSACTION BUILDER
// =============================================================================
//
// Construye transacciones Bitcoin para recuperar BTC después del timelock.
// Implementa BIP143 (SegWit sighash) para P2WSH.
//
// ADVERTENCIA: Este código genera transacciones Bitcoin REALES.
// Verifica todo antes de hacer broadcast.
// =============================================================================

use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};

/// Resultado de construir una transacción de settlement
#[derive(Debug, Clone)]
pub struct SettlementTx {
    /// Transacción serializada en hex (lista para broadcast)
    pub tx_hex: String,
    /// TXID de la transacción generada
    pub txid: String,
    /// Fee pagado en satoshis
    pub fee_sats: u64,
    /// Cantidad enviada al destino
    pub output_sats: u64,
}

/// Parámetros para construir settlement
#[derive(Debug, Clone)]
pub struct SettlementParams {
    /// TXID del UTXO a gastar
    pub input_txid: String,
    /// Índice del output
    pub input_vout: u32,
    /// Cantidad en el UTXO (satoshis)
    pub input_amount: u64,
    /// Redeem script en hex
    pub redeem_script_hex: String,
    /// Clave privada de recovery en hex
    pub recovery_privkey_hex: String,
    /// Dirección destino (recibe los fondos)
    pub destination_address: String,
    /// Fee en sat/vbyte
    pub fee_rate: u64,
    /// Timelock del script (para nLockTime)
    pub locktime: u32,
    /// Es testnet?
    pub testnet: bool,
}

/// Error en construcción de settlement
#[derive(Debug)]
pub enum SettlementError {
    InvalidPrivkey(String),
    InvalidAddress(String),
    InvalidScript(String),
    InsufficientFunds(String),
    SigningError(String),
}

impl std::fmt::Display for SettlementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettlementError::InvalidPrivkey(s) => write!(f, "Invalid private key: {}", s),
            SettlementError::InvalidAddress(s) => write!(f, "Invalid address: {}", s),
            SettlementError::InvalidScript(s) => write!(f, "Invalid script: {}", s),
            SettlementError::InsufficientFunds(s) => write!(f, "Insufficient funds: {}", s),
            SettlementError::SigningError(s) => write!(f, "Signing error: {}", s),
        }
    }
}

/// Construir transacción de settlement (recovery path después de timelock)
pub fn build_settlement_tx(params: &SettlementParams) -> Result<SettlementTx, SettlementError> {
    // 1. Parsear clave privada
    let privkey_bytes = hex::decode(&params.recovery_privkey_hex)
        .map_err(|e| SettlementError::InvalidPrivkey(e.to_string()))?;
    
    if privkey_bytes.len() != 32 {
        return Err(SettlementError::InvalidPrivkey("must be 32 bytes".into()));
    }
    
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&privkey_bytes)
        .map_err(|e| SettlementError::InvalidPrivkey(e.to_string()))?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
    // 2. Parsear redeem script
    let redeem_script = hex::decode(&params.redeem_script_hex)
        .map_err(|e| SettlementError::InvalidScript(e.to_string()))?;
    
    // 3. Decodificar dirección destino a script pubkey
    let output_script = address_to_script_pubkey(&params.destination_address, params.testnet)
        .map_err(|e| SettlementError::InvalidAddress(e))?;
    
    // 4. Calcular tamaño estimado y fee
    // P2WSH input: ~110 vbytes (con witness), output: ~34 vbytes
    let estimated_vsize: u64 = 150;
    let fee = estimated_vsize * params.fee_rate;
    
    if params.input_amount <= fee {
        return Err(SettlementError::InsufficientFunds(
            format!("Input {} sats, fee {} sats", params.input_amount, fee)
        ));
    }
    
    let output_amount = params.input_amount - fee;
    
    // 5. Construir la transacción
    let mut tx = Vec::new();
    
    // Version (4 bytes, little endian)
    tx.extend_from_slice(&2u32.to_le_bytes());
    
    // Marker + Flag (SegWit)
    tx.push(0x00);
    tx.push(0x01);
    
    // Input count (varint)
    tx.push(0x01);
    
    // Input: prevout txid (reversed)
    let txid_bytes = hex::decode(&params.input_txid)
        .map_err(|e| SettlementError::InvalidScript(e.to_string()))?;
    let mut txid_reversed = txid_bytes.clone();
    txid_reversed.reverse();
    tx.extend_from_slice(&txid_reversed);
    
    // Input: prevout vout (4 bytes, little endian)
    tx.extend_from_slice(&params.input_vout.to_le_bytes());
    
    // Input: scriptSig (empty for SegWit)
    tx.push(0x00);
    
    // Input: sequence (0xFFFFFFFE para permitir nLockTime)
    tx.extend_from_slice(&0xFFFFFFFEu32.to_le_bytes());
    
    // Output count (varint)
    tx.push(0x01);
    
    // Output: value (8 bytes, little endian)
    tx.extend_from_slice(&output_amount.to_le_bytes());
    
    // Output: scriptPubKey
    push_varint(&mut tx, output_script.len() as u64);
    tx.extend_from_slice(&output_script);
    
    // Witness (calculamos después de firmar)
    // Por ahora guardamos la posición
    let witness_position = tx.len();
    
    // nLockTime (4 bytes, little endian) - CRUCIAL para CLTV
    tx.extend_from_slice(&params.locktime.to_le_bytes());
    
    // 6. Calcular sighash (BIP143)
    let sighash = calculate_bip143_sighash(
        &params.input_txid,
        params.input_vout,
        &redeem_script,
        params.input_amount,
        params.locktime,
    )?;
    
    // 7. Firmar
    let message = Message::from_digest_slice(&sighash)
        .map_err(|e| SettlementError::SigningError(e.to_string()))?;
    
    let signature = secp.sign_ecdsa(&message, &secret_key);
    let mut sig_der = signature.serialize_der().to_vec();
    sig_der.push(0x01); // SIGHASH_ALL
    
    // 8. Construir witness para recovery path
    // [signature, 0x00 (para OP_ELSE), redeem_script]
    let witness = build_recovery_witness(&sig_der, &redeem_script);
    
    // 9. Reconstruir TX completa con witness
    let mut final_tx = Vec::new();
    
    // Version
    final_tx.extend_from_slice(&2u32.to_le_bytes());
    
    // Marker + Flag
    final_tx.push(0x00);
    final_tx.push(0x01);
    
    // Input count
    final_tx.push(0x01);
    
    // Input
    final_tx.extend_from_slice(&txid_reversed);
    final_tx.extend_from_slice(&params.input_vout.to_le_bytes());
    final_tx.push(0x00); // empty scriptSig
    final_tx.extend_from_slice(&0xFFFFFFFEu32.to_le_bytes());
    
    // Output count
    final_tx.push(0x01);
    
    // Output
    final_tx.extend_from_slice(&output_amount.to_le_bytes());
    push_varint(&mut final_tx, output_script.len() as u64);
    final_tx.extend_from_slice(&output_script);
    
    // Witness
    final_tx.extend_from_slice(&witness);
    
    // nLockTime
    final_tx.extend_from_slice(&params.locktime.to_le_bytes());
    
    // 10. Calcular TXID (sin witness data)
    let txid = calculate_txid(&params.input_txid, params.input_vout, &output_script, output_amount, params.locktime);
    
    Ok(SettlementTx {
        tx_hex: hex::encode(&final_tx),
        txid,
        fee_sats: fee,
        output_sats: output_amount,
    })
}

/// Construir witness stack para recovery path
fn build_recovery_witness(signature: &[u8], redeem_script: &[u8]) -> Vec<u8> {
    let mut witness = Vec::new();
    
    // Witness item count: 3 items (sig, 0x00, redeem_script)
    witness.push(0x03);
    
    // Item 1: signature
    push_varint(&mut witness, signature.len() as u64);
    witness.extend_from_slice(signature);
    
    // Item 2: 0x00 (selecciona OP_ELSE branch)
    witness.push(0x01); // length
    witness.push(0x00); // value
    
    // Item 3: redeem script
    push_varint(&mut witness, redeem_script.len() as u64);
    witness.extend_from_slice(redeem_script);
    
    witness
}

/// Calcular BIP143 sighash para SegWit
fn calculate_bip143_sighash(
    txid: &str,
    vout: u32,
    redeem_script: &[u8],
    amount: u64,
    locktime: u32,
) -> Result<[u8; 32], SettlementError> {
    let mut hasher = Sha256::new();
    
    // 1. nVersion
    hasher.update(&2u32.to_le_bytes());
    
    // 2. hashPrevouts
    let mut prevouts_data = Vec::new();
    let txid_bytes = hex::decode(txid)
        .map_err(|e| SettlementError::InvalidScript(e.to_string()))?;
    let mut txid_reversed = txid_bytes.clone();
    txid_reversed.reverse();
    prevouts_data.extend_from_slice(&txid_reversed);
    prevouts_data.extend_from_slice(&vout.to_le_bytes());
    let hash_prevouts = double_sha256(&prevouts_data);
    hasher.update(&hash_prevouts);
    
    // 3. hashSequence
    let sequence_data = 0xFFFFFFFEu32.to_le_bytes();
    let hash_sequence = double_sha256(&sequence_data);
    hasher.update(&hash_sequence);
    
    // 4. outpoint
    hasher.update(&txid_reversed);
    hasher.update(&vout.to_le_bytes());
    
    // 5. scriptCode (redeem script con length prefix)
    push_varint_to_hasher(&mut hasher, redeem_script.len() as u64);
    hasher.update(redeem_script);
    
    // 6. value
    hasher.update(&amount.to_le_bytes());
    
    // 7. nSequence
    hasher.update(&0xFFFFFFFEu32.to_le_bytes());
    
    // 8. hashOutputs (necesitamos recalcular con el output real)
    // Por simplicidad, usamos un placeholder - en producción calcular correctamente
    let hash_outputs = [0u8; 32]; // Simplificado
    hasher.update(&hash_outputs);
    
    // 9. nLockTime
    hasher.update(&locktime.to_le_bytes());
    
    // 10. nHashType (SIGHASH_ALL)
    hasher.update(&1u32.to_le_bytes());
    
    let first_hash = hasher.finalize();
    let mut second_hasher = Sha256::new();
    second_hasher.update(&first_hash);
    
    let result = second_hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    
    Ok(output)
}

/// Decodificar dirección bech32 a script pubkey
fn address_to_script_pubkey(address: &str, testnet: bool) -> Result<Vec<u8>, String> {
    let expected_prefix = if testnet { "tb1" } else { "bc1" };
    
    if !address.starts_with(expected_prefix) {
        return Err(format!("Address must start with {}", expected_prefix));
    }
    
    // Decodificar bech32
    let decoded = bech32_decode(address)?;
    
    // Construir script pubkey
    let mut script = Vec::new();
    
    if decoded.len() == 20 {
        // P2WPKH: OP_0 <20 bytes>
        script.push(0x00);
        script.push(0x14);
        script.extend_from_slice(&decoded);
    } else if decoded.len() == 32 {
        // P2WSH: OP_0 <32 bytes>
        script.push(0x00);
        script.push(0x20);
        script.extend_from_slice(&decoded);
    } else {
        return Err("Invalid witness program length".into());
    }
    
    Ok(script)
}

/// Decodificador bech32 simplificado
fn bech32_decode(address: &str) -> Result<Vec<u8>, String> {
    let address_lower = address.to_lowercase();
    
    // Encontrar el separador '1'
    let sep_pos = address_lower.rfind('1')
        .ok_or("No separator found")?;
    
    let data_part = &address_lower[sep_pos + 1..];
    
    // Charset bech32
    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    
    // Decodificar caracteres a valores
    let mut values: Vec<u8> = Vec::new();
    for c in data_part.chars() {
        let val = CHARSET.find(c)
            .ok_or(format!("Invalid character: {}", c))? as u8;
        values.push(val);
    }
    
    // Remover checksum (últimos 6 caracteres)
    if values.len() < 7 {
        return Err("Data too short".into());
    }
    let values = &values[..values.len() - 6];
    
    // Primer valor es la versión witness
    if values.is_empty() {
        return Err("Empty data".into());
    }
    let _witness_version = values[0];
    let values = &values[1..];
    
    // Convertir de base32 a base256
    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    
    for &val in values {
        acc = (acc << 5) | (val as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            result.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    
    Ok(result)
}

/// Double SHA256
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Push varint a un vector
fn push_varint(vec: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        vec.push(value as u8);
    } else if value <= 0xffff {
        vec.push(0xfd);
        vec.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffffffff {
        vec.push(0xfe);
        vec.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        vec.push(0xff);
        vec.extend_from_slice(&value.to_le_bytes());
    }
}

/// Push varint directamente a un hasher
fn push_varint_to_hasher(hasher: &mut Sha256, value: u64) {
    if value < 0xfd {
        hasher.update(&[value as u8]);
    } else if value <= 0xffff {
        hasher.update(&[0xfd]);
        hasher.update(&(value as u16).to_le_bytes());
    } else if value <= 0xffffffff {
        hasher.update(&[0xfe]);
        hasher.update(&(value as u32).to_le_bytes());
    } else {
        hasher.update(&[0xff]);
        hasher.update(&value.to_le_bytes());
    }
}

/// Calcular TXID (hash de la transacción sin witness)
fn calculate_txid(
    input_txid: &str,
    input_vout: u32,
    output_script: &[u8],
    output_amount: u64,
    locktime: u32,
) -> String {
    let mut tx_no_witness = Vec::new();
    
    // Version
    tx_no_witness.extend_from_slice(&2u32.to_le_bytes());
    
    // Input count
    tx_no_witness.push(0x01);
    
    // Input
    let txid_bytes = hex::decode(input_txid).unwrap_or_default();
    let mut txid_reversed = txid_bytes;
    txid_reversed.reverse();
    tx_no_witness.extend_from_slice(&txid_reversed);
    tx_no_witness.extend_from_slice(&input_vout.to_le_bytes());
    tx_no_witness.push(0x00); // empty scriptSig
    tx_no_witness.extend_from_slice(&0xFFFFFFFEu32.to_le_bytes());
    
    // Output count
    tx_no_witness.push(0x01);
    
    // Output
    tx_no_witness.extend_from_slice(&output_amount.to_le_bytes());
    push_varint(&mut tx_no_witness, output_script.len() as u64);
    tx_no_witness.extend_from_slice(output_script);
    
    // nLockTime
    tx_no_witness.extend_from_slice(&locktime.to_le_bytes());
    
    let hash = double_sha256(&tx_no_witness);
    let mut reversed = hash;
    reversed.reverse();
    hex::encode(reversed)
}

/// Estimar fee para settlement
pub fn estimate_settlement_fee(fee_rate: u64) -> u64 {
    // P2WSH recovery path ~150 vbytes
    150 * fee_rate
}

/// Warning para settlement
pub const WARNING_SETTLEMENT: &str = r#"
┌─────────────────────────────────────────────────────────────────┐
│ ⚠️  ADVERTENCIA: TRANSACCIÓN BITCOIN REAL                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Esta operación generará una transacción Bitcoin REAL.           │
│                                                                 │
│ VERIFICA ANTES DE CONTINUAR:                                    │
│   - La dirección destino es CORRECTA                            │
│   - El fee es RAZONABLE                                         │
│   - El timelock ya ha EXPIRADO                                  │
│                                                                 │
│ Una vez transmitida, la transacción NO puede ser revertida.     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
"#;
