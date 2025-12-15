// =============================================================================
// MOONCOIN v2.37 - RECOVERY SOCIAL
// =============================================================================
//
// "Tu familia puede ayudarte sin controlar tus fondos"
//
// Recovery Social permite designar un grupo de contactos de confianza que,
// actuando juntos (ej: 3 de 5), pueden recuperar tus fondos si pierdes acceso.
//
// CARACTERÍSTICAS:
//   - Usuario mantiene control total en situación normal
//   - Recovery requiere múltiples firmas (M-of-N)
//   - Período de espera obligatorio (protección contra colusión)
//   - Usuario puede cancelar recovery si reaparece
//   - Compatible con privacidad (direcciones stealth para recovery)
//
// FLUJO:
//   1. Usuario configura trusted circle (5 contactos)
//   2. Define threshold (3 de 5) y delay (30 días)
//   3. En caso de pérdida, contactos inician recovery
//   4. Espera de 30 días (usuario puede cancelar)
//   5. Después del delay, fondos se liberan a dirección designada
//
// =============================================================================

pub mod config;
pub mod guardian;
pub mod script;
pub mod process;

pub use config::{RecoveryConfig, RecoveryTier};
pub use guardian::{Guardian, GuardianSet, GuardianStatus};
pub use script::{RecoveryScript, RecoveryScriptBuilder};
pub use process::{RecoveryProcess, RecoveryState, RecoveryManager};

use serde::{Serialize, Deserialize};

// =============================================================================
// Constantes
// =============================================================================

/// Mínimo de guardianes requeridos
pub const MIN_GUARDIANS: usize = 2;

/// Máximo de guardianes permitidos
pub const MAX_GUARDIANS: usize = 15;

/// Delay mínimo de recovery (protección contra colusión)
pub const MIN_RECOVERY_DELAY_BLOCKS: u32 = 4320; // ~15 días

/// Delay por defecto
pub const DEFAULT_RECOVERY_DELAY_BLOCKS: u32 = 8640; // ~30 días

/// Delay máximo
pub const MAX_RECOVERY_DELAY_BLOCKS: u32 = 52560; // ~6 meses

/// Versión del protocolo
pub const RECOVERY_VERSION: u8 = 1;

// =============================================================================
// Tipos Principales
// =============================================================================

/// ID único de un recovery setup
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecoveryId(#[serde(with = "serde_hex32")] pub [u8; 32]);

mod serde_hex32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    
    pub fn serialize<S>(data: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        hex::encode(data).serialize(serializer)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where D: Deserializer<'de> {
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

impl RecoveryId {
    pub fn from_hash(hash: [u8; 32]) -> Self {
        RecoveryId(hash)
    }
    
    pub fn generate(user_pubkey: &[u8], guardians: &[Guardian]) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"recovery:");
        hasher.update(user_pubkey);
        for g in guardians {
            hasher.update(&g.pubkey);
        }
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        RecoveryId(id)
    }
    
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }
    
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl std::fmt::Display for RecoveryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recovery:{}", self.short_hex())
    }
}

// =============================================================================
// Errores
// =============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    /// No hay suficientes guardianes
    NotEnoughGuardians { have: usize, need: usize },
    
    /// Demasiados guardianes
    TooManyGuardians { have: usize, max: usize },
    
    /// Threshold inválido
    InvalidThreshold { threshold: usize, guardians: usize },
    
    /// Delay inválido
    InvalidDelay { blocks: u32, min: u32, max: u32 },
    
    /// Guardián duplicado
    DuplicateGuardian(String),
    
    /// Recovery ya en progreso
    RecoveryAlreadyActive,
    
    /// No hay recovery activo
    NoActiveRecovery,
    
    /// No hay suficientes firmas
    NotEnoughSignatures { have: usize, need: usize },
    
    /// Delay no cumplido
    DelayNotMet { blocks_remaining: u64 },
    
    /// Firma inválida
    InvalidSignature(String),
    
    /// Usuario canceló el recovery
    CancelledByUser,
    
    /// Recovery expirado
    Expired,
    
    /// Error genérico
    Other(String),
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryError::NotEnoughGuardians { have, need } => 
                write!(f, "Not enough guardians: have {}, need {}", have, need),
            RecoveryError::TooManyGuardians { have, max } => 
                write!(f, "Too many guardians: have {}, max {}", have, max),
            RecoveryError::InvalidThreshold { threshold, guardians } => 
                write!(f, "Invalid threshold: {} of {} guardians", threshold, guardians),
            RecoveryError::InvalidDelay { blocks, min, max } => 
                write!(f, "Invalid delay: {} blocks (min: {}, max: {})", blocks, min, max),
            RecoveryError::DuplicateGuardian(name) => 
                write!(f, "Duplicate guardian: {}", name),
            RecoveryError::RecoveryAlreadyActive => 
                write!(f, "Recovery already in progress"),
            RecoveryError::NoActiveRecovery => 
                write!(f, "No active recovery"),
            RecoveryError::NotEnoughSignatures { have, need } => 
                write!(f, "Not enough signatures: have {}, need {}", have, need),
            RecoveryError::DelayNotMet { blocks_remaining } => 
                write!(f, "Delay not met: {} blocks remaining", blocks_remaining),
            RecoveryError::InvalidSignature(msg) => 
                write!(f, "Invalid signature: {}", msg),
            RecoveryError::CancelledByUser => 
                write!(f, "Recovery cancelled by user"),
            RecoveryError::Expired => 
                write!(f, "Recovery expired"),
            RecoveryError::Other(msg) => 
                write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for RecoveryError {}

// =============================================================================
// Utilidades
// =============================================================================

/// Convertir bloques a tiempo legible
pub fn blocks_to_days(blocks: u32) -> u32 {
    // ~288 bloques por día (5 min/bloque)
    blocks / 288
}

/// Convertir días a bloques
pub fn days_to_blocks(days: u32) -> u32 {
    days * 288
}

/// Validar configuración de threshold
pub fn validate_threshold(threshold: usize, total_guardians: usize) -> Result<(), RecoveryError> {
    if total_guardians < MIN_GUARDIANS {
        return Err(RecoveryError::NotEnoughGuardians { 
            have: total_guardians, 
            need: MIN_GUARDIANS 
        });
    }
    
    if total_guardians > MAX_GUARDIANS {
        return Err(RecoveryError::TooManyGuardians { 
            have: total_guardians, 
            max: MAX_GUARDIANS 
        });
    }
    
    if threshold < 1 || threshold > total_guardians {
        return Err(RecoveryError::InvalidThreshold { 
            threshold, 
            guardians: total_guardians 
        });
    }
    
    // Threshold debe ser al menos la mitad + 1 para seguridad
    let min_threshold = (total_guardians / 2) + 1;
    if threshold < min_threshold {
        return Err(RecoveryError::InvalidThreshold { 
            threshold, 
            guardians: total_guardians 
        });
    }
    
    Ok(())
}

/// Validar delay
pub fn validate_delay(blocks: u32) -> Result<(), RecoveryError> {
    if blocks < MIN_RECOVERY_DELAY_BLOCKS {
        return Err(RecoveryError::InvalidDelay { 
            blocks, 
            min: MIN_RECOVERY_DELAY_BLOCKS, 
            max: MAX_RECOVERY_DELAY_BLOCKS 
        });
    }
    
    if blocks > MAX_RECOVERY_DELAY_BLOCKS {
        return Err(RecoveryError::InvalidDelay { 
            blocks, 
            min: MIN_RECOVERY_DELAY_BLOCKS, 
            max: MAX_RECOVERY_DELAY_BLOCKS 
        });
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
    fn test_recovery_id_generation() {
        let user_pubkey = [0x02; 33];
        let guardians = vec![
            Guardian::new("Alice".to_string(), [0x03; 33]),
            Guardian::new("Bob".to_string(), [0x04; 33]),
        ];
        
        let id1 = RecoveryId::generate(&user_pubkey, &guardians);
        let id2 = RecoveryId::generate(&user_pubkey, &guardians);
        
        assert_eq!(id1, id2); // Determinístico
        assert!(!id1.short_hex().is_empty());
    }
    
    #[test]
    fn test_validate_threshold() {
        // 3-of-5 válido
        assert!(validate_threshold(3, 5).is_ok());
        
        // 2-of-3 válido
        assert!(validate_threshold(2, 3).is_ok());
        
        // 1-of-3 inválido (menos de la mitad)
        assert!(validate_threshold(1, 3).is_err());
        
        // 6-of-5 inválido
        assert!(validate_threshold(6, 5).is_err());
        
        // 1 guardián insuficiente
        assert!(validate_threshold(1, 1).is_err());
    }
    
    #[test]
    fn test_validate_delay() {
        assert!(validate_delay(MIN_RECOVERY_DELAY_BLOCKS).is_ok());
        assert!(validate_delay(DEFAULT_RECOVERY_DELAY_BLOCKS).is_ok());
        assert!(validate_delay(MAX_RECOVERY_DELAY_BLOCKS).is_ok());
        
        assert!(validate_delay(MIN_RECOVERY_DELAY_BLOCKS - 1).is_err());
        assert!(validate_delay(MAX_RECOVERY_DELAY_BLOCKS + 1).is_err());
    }
    
    #[test]
    fn test_blocks_to_days() {
        assert_eq!(blocks_to_days(288), 1);
        assert_eq!(blocks_to_days(8640), 30);
        assert_eq!(blocks_to_days(4320), 15);
    }
    
    #[test]
    fn test_days_to_blocks() {
        assert_eq!(days_to_blocks(1), 288);
        assert_eq!(days_to_blocks(30), 8640);
        assert_eq!(days_to_blocks(15), 4320);
    }
}
