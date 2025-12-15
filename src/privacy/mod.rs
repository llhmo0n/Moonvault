// =============================================================================
// MOONCOIN v2.23 - Privacy Module
// =============================================================================
//
// Primitivas criptográficas para transacciones privadas:
// - Pedersen Commitments (ocultar montos)
// - Range Proofs (probar que monto está en rango válido)
// - Stealth Addresses (ocultar receptor)
// - Privacy Keys (viewing keys, spend keys)
//
// =============================================================================

use crate::privacy::rangeproof::RangeProofError;
use crate::privacy::ring::RingError;
use crate::privacy::shielded_tx::ShieldedTxError;
use crate::privacy::validation::ValidationError;
pub mod pedersen;
pub mod rangeproof;
pub mod stealth;
pub mod keys;
pub mod ring;
pub mod shielded_tx;
pub mod validation;
pub mod scanner;
pub mod rpc;
pub mod integration;
pub mod e2e_tests;

// Re-exports principales

// =============================================================================
// Constantes
// =============================================================================

/// Bits para range proofs (64 bits = hasta 2^64 - 1)
pub const RANGE_PROOF_BITS: usize = 64;

/// Versión del protocolo de privacidad
pub const PRIVACY_PROTOCOL_VERSION: u8 = 1;

// =============================================================================
// Tipos Comunes
// =============================================================================

/// Resultado de operación de privacidad
pub type PrivacyResult<T> = Result<T, PrivacyError>;

/// Error general del módulo de privacidad
#[derive(Clone, Debug)]
pub enum PrivacyError {
    /// Error en Pedersen commitment
    Commitment(String),
    /// Error en range proof
    RangeProof(RangeProofError),
    /// Error en stealth address
    Stealth(String),
    /// Error en ring signature
    Ring(RingError),
    /// Error en transacción shielded
    ShieldedTx(ShieldedTxError),
    /// Error de validación
    Validation(ValidationError),
    /// Error genérico
    Other(String),
}

impl std::fmt::Display for PrivacyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivacyError::Commitment(s) => write!(f, "Commitment error: {}", s),
            PrivacyError::RangeProof(e) => write!(f, "Range proof error: {:?}", e),
            PrivacyError::Stealth(s) => write!(f, "Stealth error: {}", s),
            PrivacyError::Ring(e) => write!(f, "Ring signature error: {:?}", e),
            PrivacyError::ShieldedTx(e) => write!(f, "Shielded TX error: {:?}", e),
            PrivacyError::Validation(e) => write!(f, "Validation error: {:?}", e),
            PrivacyError::Other(s) => write!(f, "Privacy error: {}", s),
        }
    }
}

impl std::error::Error for PrivacyError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::pedersen::Scalar;
    use crate::privacy::keys::PrivacyKeys;
    
    #[test]
    fn test_module_exports() {
        // Verificar que los re-exports funcionan
        let _scalar = Scalar::from(42u64);
        let _keys = PrivacyKeys::generate();
    }
}
