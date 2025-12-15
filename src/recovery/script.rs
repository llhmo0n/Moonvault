// =============================================================================
// MOONCOIN - Recovery Social: Scripts
// =============================================================================
//
// Scripts que implementan la lógica de recovery social.
//
// ESTRUCTURA:
//   - Path A (Normal): Usuario gasta con su clave (1-of-1)
//   - Path B (Recovery): M-of-N guardianes + timelock
//
// =============================================================================

use serde::{Serialize, Deserialize};
use super::guardian::GuardianSet;

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
// Recovery Script
// =============================================================================

/// Script de recovery social compilado
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryScript {
    /// Script completo
    pub script: Vec<u8>,
    
    /// Hash del script (P2SH)
    #[serde(with = "serde_hash20")]
    pub script_hash: [u8; 20],
    
    /// Clave pública del usuario
    #[serde(with = "serde_pubkey33")]
    pub user_pubkey: [u8; 33],
    
    /// Claves públicas de los guardianes (ordenadas)
    pub guardian_pubkeys: Vec<Vec<u8>>,
    
    /// Threshold requerido
    pub threshold: usize,
    
    /// Delay en bloques
    pub delay_blocks: u32,
}

impl RecoveryScript {
    /// Crear script de recovery
    pub fn new(
        user_pubkey: [u8; 33],
        guardians: &GuardianSet,
        delay_blocks: u32,
    ) -> Self {
        let guardian_pubkeys = guardians.sorted_pubkeys();
        let guardian_vecs: Vec<Vec<u8>> = guardian_pubkeys.iter().map(|p| p.to_vec()).collect();
        
        let script = RecoveryScriptBuilder::build_recovery_script(
            &user_pubkey,
            &guardian_pubkeys,
            guardians.threshold,
            delay_blocks,
        );
        
        let script_hash = Self::hash160(&script);
        
        RecoveryScript {
            script,
            script_hash,
            user_pubkey,
            guardian_pubkeys: guardian_vecs,
            threshold: guardians.threshold,
            delay_blocks,
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
        
        format!("MR{}", bs58::encode(&data).into_string())
    }
    
    /// ScriptSig para gasto normal (usuario)
    pub fn create_user_scriptsig(&self, signature: &[u8]) -> Vec<u8> {
        let mut script_sig = Vec::new();
        
        // Push signature
        script_sig.push(signature.len() as u8);
        script_sig.extend_from_slice(signature);
        
        // Push OP_1 (seleccionar path A)
        script_sig.push(OP_1);
        
        script_sig
    }
    
    /// ScriptSig para recovery (guardianes)
    pub fn create_recovery_scriptsig(&self, signatures: &[Vec<u8>]) -> Vec<u8> {
        let mut script_sig = Vec::new();
        
        // OP_0 para bug de CHECKMULTISIG
        script_sig.push(OP_0);
        
        // Push signatures
        for sig in signatures {
            script_sig.push(sig.len() as u8);
            script_sig.extend_from_slice(sig);
        }
        
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

/// Constructor de scripts de recovery
pub struct RecoveryScriptBuilder;

impl RecoveryScriptBuilder {
    /// Construir script de recovery
    ///
    /// Estructura:
    /// ```text
    /// OP_IF
    ///   <user_pubkey> OP_CHECKSIG           // Path A: Usuario normal
    /// OP_ELSE
    ///   <delay> OP_CHECKSEQUENCEVERIFY OP_DROP
    ///   <threshold> <pk1> <pk2> ... <pkN> <N> OP_CHECKMULTISIG  // Path B: Recovery
    /// OP_ENDIF
    /// ```
    pub fn build_recovery_script(
        user_pubkey: &[u8; 33],
        guardian_pubkeys: &[[u8; 33]],
        threshold: usize,
        delay_blocks: u32,
    ) -> Vec<u8> {
        let mut script = Vec::new();
        
        // OP_IF - Path A (usuario normal)
        script.push(OP_IF);
        
        // Push user pubkey
        script.push(33);
        script.extend_from_slice(user_pubkey);
        
        // OP_CHECKSIG
        script.push(OP_CHECKSIG);
        
        // OP_ELSE - Path B (recovery)
        script.push(OP_ELSE);
        
        // Push delay
        let delay_bytes = Self::encode_number(delay_blocks as i64);
        script.push(delay_bytes.len() as u8);
        script.extend_from_slice(&delay_bytes);
        
        // OP_CHECKSEQUENCEVERIFY
        script.push(OP_CHECKSEQUENCEVERIFY);
        
        // OP_DROP
        script.push(OP_DROP);
        
        // Push threshold (OP_1 to OP_16 for small numbers)
        script.push(Self::small_int_opcode(threshold));
        
        // Push guardian pubkeys
        for pk in guardian_pubkeys {
            script.push(33);
            script.extend_from_slice(pk);
        }
        
        // Push N (número de guardianes)
        script.push(Self::small_int_opcode(guardian_pubkeys.len()));
        
        // OP_CHECKMULTISIG
        script.push(OP_CHECKMULTISIG);
        
        // OP_ENDIF
        script.push(OP_ENDIF);
        
        script
    }
    
    /// Opcode para números pequeños (1-16)
    fn small_int_opcode(n: usize) -> u8 {
        if n == 0 {
            OP_0
        } else if n <= 16 {
            0x50 + n as u8 // OP_1 = 0x51, OP_2 = 0x52, etc.
        } else {
            panic!("Number too large for small int opcode");
        }
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
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::guardian::Guardian;
    
    fn sample_pubkey(seed: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        pk[1] = seed;
        pk
    }
    
    fn sample_guardian_set() -> GuardianSet {
        let guardians = vec![
            Guardian::new("Alice".to_string(), sample_pubkey(1)),
            Guardian::new("Bob".to_string(), sample_pubkey(2)),
            Guardian::new("Carol".to_string(), sample_pubkey(3)),
        ];
        GuardianSet::new(guardians, 2).unwrap()
    }
    
    #[test]
    fn test_recovery_script_creation() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        
        let script = RecoveryScript::new(user_pk, &guardians, 8640);
        
        assert!(!script.script.is_empty());
        assert_eq!(script.threshold, 2);
        assert_eq!(script.delay_blocks, 8640);
        assert_eq!(script.guardian_pubkeys.len(), 3);
    }
    
    #[test]
    fn test_script_structure() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        
        let script = RecoveryScript::new(user_pk, &guardians, 8640);
        
        // Verificar opcodes presentes
        assert!(script.script.contains(&OP_IF));
        assert!(script.script.contains(&OP_ELSE));
        assert!(script.script.contains(&OP_ENDIF));
        assert!(script.script.contains(&OP_CHECKSIG));
        assert!(script.script.contains(&OP_CHECKMULTISIG));
        assert!(script.script.contains(&OP_CHECKSEQUENCEVERIFY));
    }
    
    #[test]
    fn test_p2sh_address() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        
        let script = RecoveryScript::new(user_pk, &guardians, 8640);
        let address = script.p2sh_address();
        
        // Debe empezar con MR (Mooncoin Recovery)
        assert!(address.starts_with("MR"));
        assert!(address.len() > 20);
    }
    
    #[test]
    fn test_user_scriptsig() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        
        let script = RecoveryScript::new(user_pk, &guardians, 8640);
        let fake_sig = vec![0x30, 0x44, 0x02, 0x20];
        
        let scriptsig = script.create_user_scriptsig(&fake_sig);
        
        // Debe contener OP_1 para seleccionar path A
        assert!(scriptsig.contains(&OP_1));
    }
    
    #[test]
    fn test_recovery_scriptsig() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        
        let script = RecoveryScript::new(user_pk, &guardians, 8640);
        let sigs = vec![
            vec![0x30, 0x44],
            vec![0x30, 0x45],
        ];
        
        let scriptsig = script.create_recovery_scriptsig(&sigs);
        
        // Debe empezar con OP_0 (bug de CHECKMULTISIG)
        assert_eq!(scriptsig[0], OP_0);
    }
    
    #[test]
    fn test_small_int_opcode() {
        assert_eq!(RecoveryScriptBuilder::small_int_opcode(0), OP_0);
        assert_eq!(RecoveryScriptBuilder::small_int_opcode(1), 0x51);
        assert_eq!(RecoveryScriptBuilder::small_int_opcode(2), 0x52);
        assert_eq!(RecoveryScriptBuilder::small_int_opcode(16), 0x60);
    }
    
    #[test]
    fn test_script_serialization() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        
        let script = RecoveryScript::new(user_pk, &guardians, 8640);
        
        let json = serde_json::to_string(&script).unwrap();
        let restored: RecoveryScript = serde_json::from_str(&json).unwrap();
        
        assert_eq!(script.script, restored.script);
        assert_eq!(script.threshold, restored.threshold);
    }
}
