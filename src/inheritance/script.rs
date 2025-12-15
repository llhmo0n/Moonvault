// =============================================================================
// MOONCOIN - Herencia Digital: Scripts
// =============================================================================
//
// Scripts que implementan la lógica de herencia con timelock.
//
// ESTRUCTURA:
//   - Path A (Normal): Dueño gasta cuando quiera
//   - Path B (Herencia): Herederos después del timelock
//
// =============================================================================

use serde::{Serialize, Deserialize};
use super::heir::HeirSet;

// Opcodes
mod opcodes {
    pub const OP_IF: u8 = 0x63;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_HASH160: u8 = 0xA9;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_CHECKSIG: u8 = 0xAC;
    pub const OP_CHECKMULTISIG: u8 = 0xAE;
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xB2;
    pub const OP_0: u8 = 0x00;
    pub const OP_1: u8 = 0x51;
    pub const OP_TRUE: u8 = 0x51;
}

use opcodes::*;

// Serde helpers
mod serde_pubkey33 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    
    pub fn serialize<S>(data: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        hex::encode(data).serialize(serializer)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where D: Deserializer<'de> {
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
    where S: Serializer {
        hex::encode(data).serialize(serializer)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
    where D: Deserializer<'de> {
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
// Inheritance Script
// =============================================================================

/// Script de herencia compilado
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InheritanceScript {
    /// Script completo
    pub script: Vec<u8>,
    
    /// Hash del script (P2SH)
    #[serde(with = "serde_hash20")]
    pub script_hash: [u8; 20],
    
    /// Clave pública del dueño
    #[serde(with = "serde_pubkey33")]
    pub owner_pubkey: [u8; 33],
    
    /// Período de inactividad en bloques
    pub inactivity_blocks: u32,
    
    /// Número de herederos
    pub heir_count: usize,
}

impl InheritanceScript {
    /// Crear script de herencia
    ///
    /// Para simplificar, usamos un script donde:
    /// - Path A: Dueño puede gastar siempre
    /// - Path B: Después del timelock, cualquiera puede gastar (herederos crean TX)
    ///
    /// En producción, cada heredero tendría su propio output con su porcentaje.
    pub fn new(
        owner_pubkey: [u8; 33],
        heirs: &HeirSet,
        inactivity_blocks: u32,
    ) -> Self {
        let script = InheritanceScriptBuilder::build_inheritance_script(
            &owner_pubkey,
            inactivity_blocks,
        );
        
        let script_hash = Self::hash160(&script);
        
        InheritanceScript {
            script,
            script_hash,
            owner_pubkey,
            inactivity_blocks,
            heir_count: heirs.count(),
        }
    }
    
    fn hash160(data: &[u8]) -> [u8; 20] {
        use sha2::{Sha256, Digest as Sha2Digest};
        use ripemd::{Ripemd160, Digest as RipemdDigest};
        
        let sha = Sha256::digest(data);
        let ripemd = Ripemd160::digest(&sha);
        
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&ripemd);
        hash
    }
    
    /// Dirección P2SH
    pub fn p2sh_address(&self) -> String {
        use sha2::{Sha256, Digest};
        
        let mut data = vec![0x05];
        data.extend_from_slice(&self.script_hash);
        
        let hash1 = Sha256::digest(&data);
        let hash2 = Sha256::digest(&hash1);
        data.extend_from_slice(&hash2[..4]);
        
        format!("MI{}", bs58::encode(&data).into_string()) // MI = Mooncoin Inheritance
    }
    
    /// ScriptSig para gasto normal (dueño)
    pub fn create_owner_scriptsig(&self, signature: &[u8]) -> Vec<u8> {
        let mut script_sig = Vec::new();
        
        // Push signature
        script_sig.push(signature.len() as u8);
        script_sig.extend_from_slice(signature);
        
        // Push OP_1 (seleccionar path A)
        script_sig.push(OP_1);
        
        script_sig
    }
    
    /// ScriptSig para herencia (después del timelock)
    pub fn create_inheritance_scriptsig(&self) -> Vec<u8> {
        let mut script_sig = Vec::new();
        
        // Push OP_0 (seleccionar path B)
        script_sig.push(OP_0);
        
        script_sig
    }
    
    /// Tamaño del script
    pub fn script_size(&self) -> usize {
        self.script.len()
    }
}

// =============================================================================
// Script Builder
// =============================================================================

/// Constructor de scripts de herencia
pub struct InheritanceScriptBuilder;

impl InheritanceScriptBuilder {
    /// Construir script de herencia
    ///
    /// Estructura:
    /// ```text
    /// OP_IF
    ///   <owner_pubkey> OP_CHECKSIG           // Path A: Dueño normal
    /// OP_ELSE
    ///   <inactivity_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP
    ///   OP_TRUE                               // Path B: Herencia (cualquiera)
    /// OP_ENDIF
    /// ```
    ///
    /// Nota: En producción, path B requeriría firma de herederos.
    /// Este diseño simplificado asume que la TX de herencia tiene
    /// outputs específicos para cada heredero.
    pub fn build_inheritance_script(
        owner_pubkey: &[u8; 33],
        inactivity_blocks: u32,
    ) -> Vec<u8> {
        let mut script = Vec::new();
        
        // OP_IF - Path A (dueño normal)
        script.push(OP_IF);
        
        // Push owner pubkey
        script.push(33);
        script.extend_from_slice(owner_pubkey);
        
        // OP_CHECKSIG
        script.push(OP_CHECKSIG);
        
        // OP_ELSE - Path B (herencia)
        script.push(OP_ELSE);
        
        // Push inactivity period
        let delay_bytes = Self::encode_number(inactivity_blocks as i64);
        script.push(delay_bytes.len() as u8);
        script.extend_from_slice(&delay_bytes);
        
        // OP_CHECKSEQUENCEVERIFY
        script.push(OP_CHECKSEQUENCEVERIFY);
        
        // OP_DROP
        script.push(OP_DROP);
        
        // OP_TRUE (herencia puede ser gastada)
        script.push(OP_TRUE);
        
        // OP_ENDIF
        script.push(OP_ENDIF);
        
        script
    }
    
    /// Construir script de output para un heredero específico (P2PKH)
    pub fn build_heir_output(heir_pubkey_hash: &[u8; 20]) -> Vec<u8> {
        let mut script = Vec::new();
        
        script.push(OP_DUP);
        script.push(OP_HASH160);
        script.push(20);
        script.extend_from_slice(heir_pubkey_hash);
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
}

// =============================================================================
// Check-in Transaction
// =============================================================================

/// Información para crear una TX de check-in
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckinInfo {
    /// UTXO a gastar (del script de herencia)
    pub utxo_txid: String,
    pub utxo_vout: u32,
    pub utxo_amount: u64,
    
    /// Nuevo script de herencia (con timer reseteado)
    pub new_script_hash: Vec<u8>,
    
    /// Fee estimado
    pub estimated_fee: u64,
}

impl CheckinInfo {
    /// Calcular monto del output (input - fee)
    pub fn output_amount(&self) -> u64 {
        self.utxo_amount.saturating_sub(self.estimated_fee)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::heir::{Heir, HeirShare, HeirSet};
    
    fn sample_pubkey(seed: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        pk[1] = seed;
        pk
    }
    
    fn sample_heir_set() -> HeirSet {
        HeirSet::new(vec![
            Heir::new("MC1heir1".to_string(), HeirShare::new(50).unwrap()),
            Heir::new("MC1heir2".to_string(), HeirShare::new(50).unwrap()),
        ]).unwrap()
    }
    
    #[test]
    fn test_inheritance_script_creation() {
        let owner = sample_pubkey(1);
        let heirs = sample_heir_set();
        let inactivity = 105120; // 1 año
        
        let script = InheritanceScript::new(owner, &heirs, inactivity);
        
        assert!(!script.script.is_empty());
        assert_eq!(script.inactivity_blocks, inactivity);
        assert_eq!(script.heir_count, 2);
    }
    
    #[test]
    fn test_script_structure() {
        let owner = sample_pubkey(1);
        let heirs = sample_heir_set();
        
        let script = InheritanceScript::new(owner, &heirs, 105120);
        
        // Verificar opcodes presentes
        assert!(script.script.contains(&OP_IF));
        assert!(script.script.contains(&OP_ELSE));
        assert!(script.script.contains(&OP_ENDIF));
        assert!(script.script.contains(&OP_CHECKSIG));
        assert!(script.script.contains(&OP_CHECKSEQUENCEVERIFY));
    }
    
    #[test]
    fn test_p2sh_address() {
        let owner = sample_pubkey(1);
        let heirs = sample_heir_set();
        
        let script = InheritanceScript::new(owner, &heirs, 105120);
        let address = script.p2sh_address();
        
        // Debe empezar con MI (Mooncoin Inheritance)
        assert!(address.starts_with("MI"));
        assert!(address.len() > 20);
    }
    
    #[test]
    fn test_owner_scriptsig() {
        let owner = sample_pubkey(1);
        let heirs = sample_heir_set();
        
        let script = InheritanceScript::new(owner, &heirs, 105120);
        let fake_sig = vec![0x30, 0x44, 0x02, 0x20];
        
        let scriptsig = script.create_owner_scriptsig(&fake_sig);
        
        // Debe contener OP_1 para seleccionar path A
        assert!(scriptsig.contains(&OP_1));
    }
    
    #[test]
    fn test_inheritance_scriptsig() {
        let owner = sample_pubkey(1);
        let heirs = sample_heir_set();
        
        let script = InheritanceScript::new(owner, &heirs, 105120);
        let scriptsig = script.create_inheritance_scriptsig();
        
        // Debe contener OP_0 para seleccionar path B
        assert!(scriptsig.contains(&OP_0));
    }
    
    #[test]
    fn test_script_serialization() {
        let owner = sample_pubkey(1);
        let heirs = sample_heir_set();
        
        let script = InheritanceScript::new(owner, &heirs, 105120);
        
        let json = serde_json::to_string(&script).unwrap();
        let restored: InheritanceScript = serde_json::from_str(&json).unwrap();
        
        assert_eq!(script.script, restored.script);
        assert_eq!(script.inactivity_blocks, restored.inactivity_blocks);
    }
    
    #[test]
    fn test_checkin_info() {
        let info = CheckinInfo {
            utxo_txid: "abc123".to_string(),
            utxo_vout: 0,
            utxo_amount: 100_000,
            new_script_hash: vec![0xAB; 20],
            estimated_fee: 1_000,
        };
        
        assert_eq!(info.output_amount(), 99_000);
    }
}
