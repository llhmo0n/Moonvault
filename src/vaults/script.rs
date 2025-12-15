// =============================================================================
// MOONCOIN - Vault Scripts (Spending Conditions)
// =============================================================================
//
// Scripts que implementan la lógica del vault usando los opcodes existentes.
//
// =============================================================================

use serde::{Serialize, Deserialize};

/// Bytes de opcodes necesarios
mod opcode_bytes {
    pub const OP_IF: u8 = 0x63;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_HASH160: u8 = 0xA9;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_CHECKSIG: u8 = 0xAC;
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xB2;
    pub const OP_0: u8 = 0x00;
    pub const OP_1: u8 = 0x51;
}

use opcode_bytes::*;

// =============================================================================
// Serde helpers para arrays
// =============================================================================

mod serde_pubkey {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    
    pub fn serialize<S>(data: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(data).serialize(serializer)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        if bytes.len() != 33 {
            return Err(serde::de::Error::custom("Expected 33 bytes"));
        }
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

mod serde_hash20 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    
    pub fn serialize<S>(data: &[u8; 20], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(data).serialize(serializer)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        if bytes.len() != 20 {
            return Err(serde::de::Error::custom("Expected 20 bytes"));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// =============================================================================
// Vault Script
// =============================================================================

/// Script de vault compilado
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultScript {
    /// Script serializado (bytes)
    pub script: Vec<u8>,
    
    /// Hash del script (para P2SH)
    #[serde(with = "serde_hash20")]
    pub script_hash: [u8; 20],
    
    /// Delay en bloques
    pub delay_blocks: u32,
    
    /// Hot pubkey (comprimida, 33 bytes)
    #[serde(with = "serde_pubkey")]
    pub hot_pubkey: [u8; 33],
    
    /// Cold pubkey (comprimida, 33 bytes)
    #[serde(with = "serde_pubkey")]
    pub cold_pubkey: [u8; 33],
}

impl VaultScript {
    /// Crear script de vault
    pub fn new(hot_pubkey: [u8; 33], cold_pubkey: [u8; 33], delay_blocks: u32) -> Self {
        let script = VaultScriptBuilder::build_vault_script(&hot_pubkey, &cold_pubkey, delay_blocks);
        let script_hash = Self::hash160(&script);
        
        VaultScript {
            script,
            script_hash,
            delay_blocks,
            hot_pubkey,
            cold_pubkey,
        }
    }
    
    /// Hash160 del script
    fn hash160(data: &[u8]) -> [u8; 20] {
        use sha2::{Sha256, Digest as Sha2Digest};
        use ripemd::{Ripemd160, Digest as RipemdDigest};
        
        let sha = Sha256::digest(data);
        let ripemd = Ripemd160::digest(&sha);
        
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&ripemd);
        hash
    }
    
    /// Obtener dirección P2SH del vault
    pub fn p2sh_address(&self) -> String {
        use sha2::{Sha256, Digest};
        
        let mut data = vec![0x05];
        data.extend_from_slice(&self.script_hash);
        
        let hash1 = Sha256::digest(&data);
        let hash2 = Sha256::digest(&hash1);
        data.extend_from_slice(&hash2[..4]);
        
        format!("MV{}", bs58::encode(&data).into_string())
    }
    
    /// Crear scriptSig para retiro normal (path A)
    pub fn create_withdrawal_scriptsig(&self, signature: &[u8]) -> Vec<u8> {
        let mut script_sig = Vec::new();
        script_sig.push(signature.len() as u8);
        script_sig.extend_from_slice(signature);
        script_sig.push(OP_1);
        script_sig
    }
    
    /// Crear scriptSig para cancelación (path B)
    pub fn create_cancel_scriptsig(&self, cold_signature: &[u8]) -> Vec<u8> {
        let mut script_sig = Vec::new();
        script_sig.push(cold_signature.len() as u8);
        script_sig.extend_from_slice(cold_signature);
        script_sig.push(OP_0);
        script_sig
    }
    
    /// Serializar para almacenamiento
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    
    /// Deserializar
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
    
    /// Tamaño del script en bytes
    pub fn script_size(&self) -> usize {
        self.script.len()
    }
}

// =============================================================================
// Script Builder
// =============================================================================

/// Constructor de scripts de vault
pub struct VaultScriptBuilder;

impl VaultScriptBuilder {
    /// Construir el script completo del vault
    pub fn build_vault_script(
        hot_pubkey: &[u8; 33],
        cold_pubkey: &[u8; 33],
        delay_blocks: u32,
    ) -> Vec<u8> {
        let mut script = Vec::new();
        
        // OP_IF
        script.push(OP_IF);
        
        // Push delay
        let delay_bytes = Self::encode_number(delay_blocks as i64);
        script.push(delay_bytes.len() as u8);
        script.extend_from_slice(&delay_bytes);
        
        // OP_CHECKSEQUENCEVERIFY
        script.push(OP_CHECKSEQUENCEVERIFY);
        
        // OP_DROP
        script.push(OP_DROP);
        
        // Push hot pubkey
        script.push(33);
        script.extend_from_slice(hot_pubkey);
        
        // OP_CHECKSIG
        script.push(OP_CHECKSIG);
        
        // OP_ELSE
        script.push(OP_ELSE);
        
        // Push cold pubkey
        script.push(33);
        script.extend_from_slice(cold_pubkey);
        
        // OP_CHECKSIG
        script.push(OP_CHECKSIG);
        
        // OP_ENDIF
        script.push(OP_ENDIF);
        
        script
    }
    
    /// Construir script P2SH
    pub fn build_p2sh_output(script_hash: &[u8; 20]) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(OP_HASH160);
        script.push(20);
        script.extend_from_slice(script_hash);
        script.push(0x87); // OP_EQUAL
        script
    }
    
    /// Construir script P2PKH
    pub fn build_recovery_output(pubkey_hash: &[u8; 20]) -> Vec<u8> {
        let mut script = Vec::new();
        script.push(OP_DUP);
        script.push(OP_HASH160);
        script.push(20);
        script.extend_from_slice(pubkey_hash);
        script.push(OP_EQUALVERIFY);
        script.push(OP_CHECKSIG);
        script
    }
    
    /// Codificar número para script
    fn encode_number(num: i64) -> Vec<u8> {
        if num == 0 {
            return vec![];
        }
        
        let negative = num < 0;
        let mut abs_val = num.abs() as u64;
        let mut result = Vec::new();
        
        while abs_val > 0 {
            result.push((abs_val & 0xFF) as u8);
            abs_val >>= 8;
        }
        
        if result.last().map_or(false, |&b| b & 0x80 != 0) {
            result.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            let len = result.len();
            result[len - 1] |= 0x80;
        }
        
        result
    }
    
    /// Decodificar número de script
    pub fn decode_number(data: &[u8]) -> i64 {
        if data.is_empty() {
            return 0;
        }
        
        let mut result = 0i64;
        for (i, &byte) in data.iter().enumerate() {
            result |= (byte as i64) << (8 * i);
        }
        
        if data.last().map_or(false, |&b| b & 0x80 != 0) {
            let len = data.len();
            result &= !((0x80i64) << (8 * (len - 1)));
            result = -result;
        }
        
        result
    }
}

// =============================================================================
// Vault Witness
// =============================================================================

/// Datos de witness para vault SegWit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultWitness {
    /// Firmas
    pub signatures: Vec<Vec<u8>>,
    
    /// Script de redeem
    pub redeem_script: Vec<u8>,
    
    /// Path seleccionado
    pub is_withdrawal_path: bool,
}

impl VaultWitness {
    /// Crear witness para retiro normal
    pub fn for_withdrawal(signature: Vec<u8>, redeem_script: Vec<u8>) -> Self {
        VaultWitness {
            signatures: vec![signature],
            redeem_script,
            is_withdrawal_path: true,
        }
    }
    
    /// Crear witness para cancelación
    pub fn for_cancel(cold_signature: Vec<u8>, redeem_script: Vec<u8>) -> Self {
        VaultWitness {
            signatures: vec![cold_signature],
            redeem_script,
            is_withdrawal_path: false,
        }
    }
    
    /// Serializar witness stack
    pub fn to_witness_stack(&self) -> Vec<Vec<u8>> {
        let mut stack = Vec::new();
        
        for sig in &self.signatures {
            stack.push(sig.clone());
        }
        
        stack.push(vec![if self.is_withdrawal_path { 0x01 } else { 0x00 }]);
        stack.push(self.redeem_script.clone());
        
        stack
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    fn sample_pubkey(seed: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        pk[1] = seed;
        pk[32] = seed.wrapping_mul(17);
        pk
    }
    
    #[test]
    fn test_vault_script_creation() {
        let hot = sample_pubkey(1);
        let cold = sample_pubkey(2);
        let delay = 144;
        
        let vault = VaultScript::new(hot, cold, delay);
        
        assert!(!vault.script.is_empty());
        assert_eq!(vault.delay_blocks, delay);
        assert_eq!(vault.hot_pubkey, hot);
        assert_eq!(vault.cold_pubkey, cold);
    }
    
    #[test]
    fn test_vault_script_structure() {
        let hot = sample_pubkey(1);
        let cold = sample_pubkey(2);
        let vault = VaultScript::new(hot, cold, 144);
        
        assert!(vault.script.contains(&OP_IF));
        assert!(vault.script.contains(&OP_ELSE));
        assert!(vault.script.contains(&OP_ENDIF));
        assert!(vault.script.contains(&OP_CHECKSEQUENCEVERIFY));
        assert!(vault.script.contains(&OP_CHECKSIG));
    }
    
    #[test]
    fn test_p2sh_address() {
        let hot = sample_pubkey(1);
        let cold = sample_pubkey(2);
        let vault = VaultScript::new(hot, cold, 144);
        
        let address = vault.p2sh_address();
        
        assert!(address.starts_with("MV"));
        assert!(address.len() > 20);
    }
    
    #[test]
    fn test_scriptsig_withdrawal() {
        let hot = sample_pubkey(1);
        let cold = sample_pubkey(2);
        let vault = VaultScript::new(hot, cold, 144);
        
        let fake_sig = vec![0x30, 0x44];
        let scriptsig = vault.create_withdrawal_scriptsig(&fake_sig);
        
        assert!(scriptsig.contains(&OP_1));
    }
    
    #[test]
    fn test_scriptsig_cancel() {
        let hot = sample_pubkey(1);
        let cold = sample_pubkey(2);
        let vault = VaultScript::new(hot, cold, 144);
        
        let fake_sig = vec![0x30, 0x44];
        let scriptsig = vault.create_cancel_scriptsig(&fake_sig);
        
        assert!(scriptsig.contains(&OP_0));
    }
    
    #[test]
    fn test_encode_decode_number() {
        assert_eq!(VaultScriptBuilder::decode_number(&VaultScriptBuilder::encode_number(0)), 0);
        assert_eq!(VaultScriptBuilder::decode_number(&VaultScriptBuilder::encode_number(1)), 1);
        assert_eq!(VaultScriptBuilder::decode_number(&VaultScriptBuilder::encode_number(144)), 144);
        assert_eq!(VaultScriptBuilder::decode_number(&VaultScriptBuilder::encode_number(2016)), 2016);
        assert_eq!(VaultScriptBuilder::decode_number(&VaultScriptBuilder::encode_number(-1)), -1);
    }
    
    #[test]
    fn test_witness_creation() {
        let hot = sample_pubkey(1);
        let cold = sample_pubkey(2);
        let vault = VaultScript::new(hot, cold, 144);
        
        let sig = vec![0x30, 0x44, 0x02, 0x20];
        
        let withdrawal_witness = VaultWitness::for_withdrawal(sig.clone(), vault.script.clone());
        assert!(withdrawal_witness.is_withdrawal_path);
        
        let cancel_witness = VaultWitness::for_cancel(sig, vault.script);
        assert!(!cancel_witness.is_withdrawal_path);
    }
    
    #[test]
    fn test_witness_stack() {
        let sig = vec![0x30, 0x44];
        let script = vec![0x63, 0x67, 0x68];
        
        let witness = VaultWitness::for_withdrawal(sig, script);
        let stack = witness.to_witness_stack();
        
        assert_eq!(stack.len(), 3);
    }
    
    #[test]
    fn test_vault_script_json_serialization() {
        let hot = sample_pubkey(1);
        let cold = sample_pubkey(2);
        let vault = VaultScript::new(hot, cold, 144);
        
        let json = serde_json::to_string(&vault).unwrap();
        let restored: VaultScript = serde_json::from_str(&json).unwrap();
        
        assert_eq!(vault.script, restored.script);
        assert_eq!(vault.hot_pubkey, restored.hot_pubkey);
        assert_eq!(vault.delay_blocks, restored.delay_blocks);
    }
}
