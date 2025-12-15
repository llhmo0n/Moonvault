// =============================================================================
// MOONCOIN v2.36 - VAULTS: Protección Humana contra Errores y Robos
// =============================================================================
//
// "El dinero que perdona errores humanos"
//
// Un vault es una dirección especial donde los fondos tienen un período de
// enfriamiento antes de poder gastarse. Si detectas un robo o error, puedes
// cancelar el retiro y enviar los fondos a una dirección de recuperación segura.
//
// =============================================================================

pub mod config;
pub mod script;
pub mod state;
pub mod manager;

// Re-exports públicos
pub use config::{VaultConfig, VaultTier};
pub use script::{VaultScript, VaultScriptBuilder};
pub use state::{VaultState, VaultStatus, WithdrawalRequest};
pub use manager::{VaultManager, VaultInfo, VaultError};

use serde::{Serialize, Deserialize};

// =============================================================================
// Constantes del Protocolo
// =============================================================================

/// Delay mínimo permitido (seguridad: no permitir vaults "instantáneos")
pub const MIN_DELAY_BLOCKS: u32 = 6; // ~30 minutos

/// Delay por defecto (12 horas con bloques de 5 min)
pub const DEFAULT_DELAY_BLOCKS: u32 = 144; // 144 * 5 min = 12 horas

/// Delay máximo permitido (evitar fondos bloqueados por años)
pub const MAX_DELAY_BLOCKS: u32 = 52560; // ~6 meses

/// Versión del protocolo de vaults
pub const VAULT_VERSION: u8 = 1;

// =============================================================================
// Serde Helpers para arrays de 33 bytes
// =============================================================================

mod serde_pubkey {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    
    pub fn serialize<S>(data: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = hex::encode(data);
        hex_str.serialize(serializer)
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

// =============================================================================
// Tipos Principales
// =============================================================================

/// Identificador único de un vault
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VaultId(#[serde(with = "serde_hash")] pub [u8; 32]);

mod serde_hash {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    
    pub fn serialize<S>(data: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(data).serialize(serializer)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl VaultId {
    /// Crear VaultId desde hash
    pub fn from_hash(hash: [u8; 32]) -> Self {
        VaultId(hash)
    }
    
    /// Crear VaultId desde script del vault
    pub fn from_script(script: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"vault:");
        hasher.update(script);
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        VaultId(id)
    }
    
    /// Representación hexadecimal corta (primeros 8 chars)
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }
    
    /// Representación hexadecimal completa
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl std::fmt::Display for VaultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vault:{}", self.short_hex())
    }
}

/// Claves asociadas a un vault
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultKeys {
    /// Hot key - Para uso diario (puede estar en dispositivo conectado)
    #[serde(with = "serde_pubkey")]
    pub hot_pubkey: [u8; 33],
    
    /// Cold key - Para emergencias (debe estar offline/hardware wallet)
    #[serde(with = "serde_pubkey")]
    pub cold_pubkey: [u8; 33],
    
    /// Recovery address - Donde van los fondos si se cancela
    pub recovery_address: String,
}

impl VaultKeys {
    /// Crear nuevo set de claves para vault
    pub fn new(hot_pubkey: [u8; 33], cold_pubkey: [u8; 33], recovery_address: String) -> Self {
        VaultKeys {
            hot_pubkey,
            cold_pubkey,
            recovery_address,
        }
    }
    
    /// Validar que las claves son diferentes
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.hot_pubkey == self.cold_pubkey {
            return Err("Hot and cold keys must be different");
        }
        if self.recovery_address.is_empty() {
            return Err("Recovery address cannot be empty");
        }
        Ok(())
    }
}

/// Resultado de una operación de vault
#[derive(Clone, Debug)]
pub enum VaultOperation {
    /// Vault creado exitosamente
    Created {
        vault_id: VaultId,
        address: String,
        delay_blocks: u32,
    },
    
    /// Retiro iniciado (en período de espera)
    WithdrawalInitiated {
        vault_id: VaultId,
        amount: u64,
        destination: String,
        blocks_remaining: u32,
        cancel_deadline: u64,
    },
    
    /// Retiro completado
    WithdrawalCompleted {
        vault_id: VaultId,
        txid: String,
        amount: u64,
    },
    
    /// Retiro cancelado (fondos enviados a recovery)
    WithdrawalCancelled {
        vault_id: VaultId,
        recovery_txid: String,
        amount: u64,
        recovery_address: String,
    },
    
    /// Fondos depositados en vault
    Deposited {
        vault_id: VaultId,
        txid: String,
        amount: u64,
        new_balance: u64,
    },
}

// =============================================================================
// Utilidades
// =============================================================================

/// Calcular tiempo estimado dado número de bloques
pub fn blocks_to_time_estimate(blocks: u32) -> String {
    let minutes = blocks as u64 * 5;
    
    if minutes < 60 {
        format!("{} minutos", minutes)
    } else if minutes < 1440 {
        format!("{} horas", minutes / 60)
    } else {
        format!("{} días", minutes / 1440)
    }
}

/// Validar que un delay está en rango permitido
pub fn validate_delay(blocks: u32) -> Result<(), &'static str> {
    if blocks < MIN_DELAY_BLOCKS {
        return Err("Delay too short (minimum 6 blocks / ~30 minutes)");
    }
    if blocks > MAX_DELAY_BLOCKS {
        return Err("Delay too long (maximum ~6 months)");
    }
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vault_id_creation() {
        let script = vec![0x51, 0x52, 0x93];
        let id = VaultId::from_script(&script);
        
        assert_eq!(id.0.len(), 32);
        assert!(!id.short_hex().is_empty());
        assert_eq!(id.to_hex().len(), 64);
    }
    
    #[test]
    fn test_vault_id_deterministic() {
        let script = vec![0x51, 0x52];
        let id1 = VaultId::from_script(&script);
        let id2 = VaultId::from_script(&script);
        
        assert_eq!(id1, id2);
    }
    
    #[test]
    fn test_vault_keys_validation() {
        let hot = [0x02; 33];
        let cold = [0x03; 33];
        let recovery = "MC1recovery123".to_string();
        
        let keys = VaultKeys::new(hot, cold, recovery);
        assert!(keys.validate().is_ok());
        
        let bad_keys = VaultKeys::new(hot, hot, "MC1test".to_string());
        assert!(bad_keys.validate().is_err());
        
        let bad_keys2 = VaultKeys::new(hot, cold, "".to_string());
        assert!(bad_keys2.validate().is_err());
    }
    
    #[test]
    fn test_blocks_to_time() {
        assert_eq!(blocks_to_time_estimate(6), "30 minutos");
        assert_eq!(blocks_to_time_estimate(12), "1 horas");
        assert_eq!(blocks_to_time_estimate(144), "12 horas");
        assert_eq!(blocks_to_time_estimate(288), "1 días");
        assert_eq!(blocks_to_time_estimate(2016), "7 días");
    }
    
    #[test]
    fn test_validate_delay() {
        assert!(validate_delay(MIN_DELAY_BLOCKS).is_ok());
        assert!(validate_delay(DEFAULT_DELAY_BLOCKS).is_ok());
        assert!(validate_delay(MAX_DELAY_BLOCKS).is_ok());
        
        assert!(validate_delay(MIN_DELAY_BLOCKS - 1).is_err());
        assert!(validate_delay(MAX_DELAY_BLOCKS + 1).is_err());
    }
    
    #[test]
    fn test_vault_keys_serialization() {
        let hot = [0x02; 33];
        let cold = [0x03; 33];
        let keys = VaultKeys::new(hot, cold, "MC1test".to_string());
        
        let json = serde_json::to_string(&keys).unwrap();
        let restored: VaultKeys = serde_json::from_str(&json).unwrap();
        
        assert_eq!(keys.hot_pubkey, restored.hot_pubkey);
        assert_eq!(keys.cold_pubkey, restored.cold_pubkey);
    }
}
