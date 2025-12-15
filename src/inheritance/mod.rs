// =============================================================================
// MOONCOIN v2.38 - HERENCIA DIGITAL
// =============================================================================
//
// "Tu dinero sobrevive contigo, no muere contigo"
//
// La herencia digital permite que tus fondos pasen automáticamente a tus
// herederos si dejas de hacer check-in por un período determinado.
//
// PROBLEMA QUE RESUELVE:
//   - ~4 millones de BTC perdidos por muerte de holders
//   - No hay forma nativa de "si muero, va a mis hijos"
//   - Soluciones tradicionales requieren abogados o custodios
//
// CÓMO FUNCIONA:
//   1. Usuario configura herederos y período de inactividad
//   2. Usuario hace check-in periódico (TX simple)
//   3. Cada check-in resetea el timer
//   4. Si no hay check-in por el período → fondos a herederos
//
// SEGURIDAD:
//   - Usuario siempre puede gastar normalmente
//   - Check-in es una TX simple (bajo costo)
//   - Múltiples herederos con porcentajes
//   - Sin custodios ni terceros de confianza
//
// =============================================================================

pub mod config;
pub mod heir;
pub mod script;
pub mod process;

pub use config::{InheritanceConfig, InactivityPeriod};
pub use heir::{Heir, HeirSet, HeirShare};
pub use script::{InheritanceScript, InheritanceScriptBuilder};
pub use process::{InheritanceProcess, InheritanceState, InheritanceManager};

use serde::{Serialize, Deserialize};

// =============================================================================
// Constantes
// =============================================================================

/// Período mínimo de inactividad (~3 meses)
pub const MIN_INACTIVITY_BLOCKS: u32 = 25920;

/// Período por defecto (~1 año)
pub const DEFAULT_INACTIVITY_BLOCKS: u32 = 105120;

/// Período máximo (~5 años)
pub const MAX_INACTIVITY_BLOCKS: u32 = 525600;

/// Intervalo mínimo de check-in (~1 mes)
pub const MIN_CHECKIN_INTERVAL: u32 = 8640;

/// Intervalo por defecto de check-in (~6 meses)
pub const DEFAULT_CHECKIN_INTERVAL: u32 = 52560;

/// Máximo de herederos
pub const MAX_HEIRS: usize = 10;

/// Versión del protocolo
pub const INHERITANCE_VERSION: u8 = 1;

// =============================================================================
// Tipos Principales
// =============================================================================

/// ID único de una configuración de herencia
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InheritanceId(#[serde(with = "serde_hex32")] pub [u8; 32]);

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

impl InheritanceId {
    pub fn from_hash(hash: [u8; 32]) -> Self {
        InheritanceId(hash)
    }
    
    pub fn generate(owner_pubkey: &[u8], heirs: &[Heir]) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"inheritance:");
        hasher.update(owner_pubkey);
        for h in heirs {
            hasher.update(&h.address);
            hasher.update(h.share.0.to_le_bytes());
        }
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        InheritanceId(id)
    }
    
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }
    
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl std::fmt::Display for InheritanceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "inheritance:{}", self.short_hex())
    }
}

// =============================================================================
// Errores
// =============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InheritanceError {
    /// No hay herederos
    NoHeirs,
    
    /// Demasiados herederos
    TooManyHeirs { have: usize, max: usize },
    
    /// Porcentajes no suman 100%
    InvalidShares { total: u32 },
    
    /// Período de inactividad inválido
    InvalidInactivityPeriod { blocks: u32, min: u32, max: u32 },
    
    /// Intervalo de check-in inválido
    InvalidCheckinInterval { blocks: u32 },
    
    /// Heredero duplicado
    DuplicateHeir(String),
    
    /// Herencia ya ejecutada
    AlreadyExecuted,
    
    /// Período no cumplido
    InactivityNotMet { blocks_remaining: u64 },
    
    /// Check-in demasiado pronto
    CheckinTooEarly { blocks_until_recommended: u64 },
    
    /// Error genérico
    Other(String),
}

impl std::fmt::Display for InheritanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InheritanceError::NoHeirs => write!(f, "No heirs defined"),
            InheritanceError::TooManyHeirs { have, max } => 
                write!(f, "Too many heirs: {} (max: {})", have, max),
            InheritanceError::InvalidShares { total } => 
                write!(f, "Shares must sum to 100%, got {}%", total),
            InheritanceError::InvalidInactivityPeriod { blocks, min, max } => 
                write!(f, "Invalid inactivity period: {} (min: {}, max: {})", blocks, min, max),
            InheritanceError::InvalidCheckinInterval { blocks } => 
                write!(f, "Invalid check-in interval: {} blocks", blocks),
            InheritanceError::DuplicateHeir(addr) => 
                write!(f, "Duplicate heir: {}", addr),
            InheritanceError::AlreadyExecuted => 
                write!(f, "Inheritance already executed"),
            InheritanceError::InactivityNotMet { blocks_remaining } => 
                write!(f, "Inactivity period not met: {} blocks remaining", blocks_remaining),
            InheritanceError::CheckinTooEarly { blocks_until_recommended } => 
                write!(f, "Check-in too early: {} blocks until recommended", blocks_until_recommended),
            InheritanceError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for InheritanceError {}

// =============================================================================
// Utilidades
// =============================================================================

/// Convertir bloques a meses aproximados
pub fn blocks_to_months(blocks: u32) -> u32 {
    blocks / 8640 // ~30 días
}

/// Convertir meses a bloques
pub fn months_to_blocks(months: u32) -> u32 {
    months * 8640
}

/// Convertir bloques a años aproximados
pub fn blocks_to_years(blocks: u32) -> f32 {
    blocks as f32 / 105120.0
}

/// Convertir años a bloques
pub fn years_to_blocks(years: u32) -> u32 {
    years * 105120
}

/// Validar período de inactividad
pub fn validate_inactivity_period(blocks: u32) -> Result<(), InheritanceError> {
    if blocks < MIN_INACTIVITY_BLOCKS {
        return Err(InheritanceError::InvalidInactivityPeriod { 
            blocks, 
            min: MIN_INACTIVITY_BLOCKS, 
            max: MAX_INACTIVITY_BLOCKS 
        });
    }
    if blocks > MAX_INACTIVITY_BLOCKS {
        return Err(InheritanceError::InvalidInactivityPeriod { 
            blocks, 
            min: MIN_INACTIVITY_BLOCKS, 
            max: MAX_INACTIVITY_BLOCKS 
        });
    }
    Ok(())
}

/// Validar intervalo de check-in
pub fn validate_checkin_interval(interval: u32, inactivity: u32) -> Result<(), InheritanceError> {
    if interval < MIN_CHECKIN_INTERVAL {
        return Err(InheritanceError::InvalidCheckinInterval { blocks: interval });
    }
    // Intervalo debe ser menor que el período de inactividad
    if interval >= inactivity {
        return Err(InheritanceError::InvalidCheckinInterval { blocks: interval });
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
    fn test_inheritance_id_generation() {
        let owner = [0x02; 33];
        let heirs = vec![
            Heir::new("MC1heir1".to_string(), HeirShare::new(50).unwrap()),
            Heir::new("MC1heir2".to_string(), HeirShare::new(50).unwrap()),
        ];
        
        let id1 = InheritanceId::generate(&owner, &heirs);
        let id2 = InheritanceId::generate(&owner, &heirs);
        
        assert_eq!(id1, id2);
        assert!(!id1.short_hex().is_empty());
    }
    
    #[test]
    fn test_blocks_to_months() {
        assert_eq!(blocks_to_months(8640), 1);
        assert_eq!(blocks_to_months(25920), 3);
        assert_eq!(blocks_to_months(105120), 12);
    }
    
    #[test]
    fn test_months_to_blocks() {
        assert_eq!(months_to_blocks(1), 8640);
        assert_eq!(months_to_blocks(6), 51840);
        assert_eq!(months_to_blocks(12), 103680);
    }
    
    #[test]
    fn test_validate_inactivity_period() {
        assert!(validate_inactivity_period(MIN_INACTIVITY_BLOCKS).is_ok());
        assert!(validate_inactivity_period(DEFAULT_INACTIVITY_BLOCKS).is_ok());
        assert!(validate_inactivity_period(MAX_INACTIVITY_BLOCKS).is_ok());
        
        assert!(validate_inactivity_period(MIN_INACTIVITY_BLOCKS - 1).is_err());
        assert!(validate_inactivity_period(MAX_INACTIVITY_BLOCKS + 1).is_err());
    }
    
    #[test]
    fn test_validate_checkin_interval() {
        let inactivity = DEFAULT_INACTIVITY_BLOCKS;
        
        assert!(validate_checkin_interval(DEFAULT_CHECKIN_INTERVAL, inactivity).is_ok());
        assert!(validate_checkin_interval(MIN_CHECKIN_INTERVAL, inactivity).is_ok());
        
        // Intervalo >= inactividad es inválido
        assert!(validate_checkin_interval(inactivity, inactivity).is_err());
        assert!(validate_checkin_interval(inactivity + 1, inactivity).is_err());
    }
}
