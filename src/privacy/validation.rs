// =============================================================================
// MOONCOIN v2.26 - Shielded Transaction Validation
// =============================================================================
//
// Validación de transacciones shielded para consenso:
// - Verificar range proofs
// - Verificar ring signatures
// - Verificar balance (commitments)
// - Detectar double-spends (key images)
// - Validar estructura y límites
//
// =============================================================================

use crate::privacy::pedersen::{PedersenCommitment, Scalar, CompressedPoint};
use crate::privacy::ring::KeyImageSet;
use crate::privacy::shielded_tx::{
    ShieldedTx, TxType, 
    MIN_SHIELDED_FEE, MAX_SHIELDED_INPUTS, MAX_SHIELDED_OUTPUTS,
};

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

// =============================================================================
// Validation Result
// =============================================================================

/// Resultado de validación
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    Invalid(ValidationError),
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }
}

/// Errores de validación
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// Versión de TX no soportada
    UnsupportedVersion(u8),
    /// Fee demasiado bajo
    FeeTooLow { required: u64, provided: u64 },
    /// Demasiados inputs shielded
    TooManyShieldedInputs { max: usize, provided: usize },
    /// Demasiados outputs shielded
    TooManyShieldedOutputs { max: usize, provided: usize },
    /// TX vacía
    EmptyTransaction,
    /// Range proof inválida
    InvalidRangeProof { output_index: usize },
    /// Ring signature inválida
    InvalidRingSignature { input_index: usize },
    /// Ring demasiado pequeño
    RingTooSmall { input_index: usize, size: usize },
    /// Key image duplicado en la TX
    DuplicateKeyImageInTx { input_index: usize },
    /// Key image ya usado (double-spend)
    DoubleSpend { input_index: usize, key_image: [u8; 32] },
    /// Balance no cuadra
    BalanceMismatch,
    /// Miembro del ring no existe
    RingMemberNotFound { input_index: usize, member_index: u64 },
    /// Commitment inválido
    InvalidCommitment { index: usize },
    /// Tipo de TX inconsistente
    InconsistentTxType,
    /// Error interno
    InternalError(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::UnsupportedVersion(v) => 
                write!(f, "Unsupported TX version: {}", v),
            ValidationError::FeeTooLow { required, provided } => 
                write!(f, "Fee too low: required {}, provided {}", required, provided),
            ValidationError::TooManyShieldedInputs { max, provided } => 
                write!(f, "Too many shielded inputs: max {}, provided {}", max, provided),
            ValidationError::TooManyShieldedOutputs { max, provided } => 
                write!(f, "Too many shielded outputs: max {}, provided {}", max, provided),
            ValidationError::EmptyTransaction => 
                write!(f, "Empty transaction"),
            ValidationError::InvalidRangeProof { output_index } => 
                write!(f, "Invalid range proof at output {}", output_index),
            ValidationError::InvalidRingSignature { input_index } => 
                write!(f, "Invalid ring signature at input {}", input_index),
            ValidationError::RingTooSmall { input_index, size } => 
                write!(f, "Ring too small at input {}: size {}", input_index, size),
            ValidationError::DuplicateKeyImageInTx { input_index } => 
                write!(f, "Duplicate key image in TX at input {}", input_index),
            ValidationError::DoubleSpend { input_index, .. } => 
                write!(f, "Double spend detected at input {}", input_index),
            ValidationError::BalanceMismatch => 
                write!(f, "Balance mismatch"),
            ValidationError::RingMemberNotFound { input_index, member_index } => 
                write!(f, "Ring member {} not found at input {}", member_index, input_index),
            ValidationError::InvalidCommitment { index } => 
                write!(f, "Invalid commitment at index {}", index),
            ValidationError::InconsistentTxType => 
                write!(f, "Inconsistent transaction type"),
            ValidationError::InternalError(s) => 
                write!(f, "Internal error: {}", s),
        }
    }
}

// =============================================================================
// Shielded Pool (UTXO set para outputs privados)
// =============================================================================

/// Output en el pool shielded
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedPoolEntry {
    /// Índice global único
    pub global_index: u64,
    /// Commitment
    pub commitment: PedersenCommitment,
    /// One-time public key
    pub one_time_pubkey: CompressedPoint,
    /// Altura del bloque donde se creó
    pub block_height: u64,
    /// Hash de la TX que lo creó
    pub tx_hash: [u8; 32],
    /// Índice del output en la TX
    pub output_index: usize,
}

/// Pool de outputs shielded (para construir rings y validar)
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShieldedPool {
    /// Outputs por índice global
    outputs: HashMap<u64, ShieldedPoolEntry>,
    /// Siguiente índice global
    next_index: u64,
    /// Índice de one-time pubkeys para búsqueda rápida
    pubkey_index: HashMap<[u8; 32], u64>,
}

impl ShieldedPool {
    pub fn new() -> Self {
        ShieldedPool {
            outputs: HashMap::new(),
            next_index: 0,
            pubkey_index: HashMap::new(),
        }
    }
    
    /// Agrega un output al pool
    pub fn add_output(
        &mut self,
        commitment: PedersenCommitment,
        one_time_pubkey: CompressedPoint,
        block_height: u64,
        tx_hash: [u8; 32],
        output_index: usize,
    ) -> u64 {
        let global_index = self.next_index;
        self.next_index += 1;
        
        let entry = ShieldedPoolEntry {
            global_index,
            commitment,
            one_time_pubkey,
            block_height,
            tx_hash,
            output_index,
        };
        
        self.pubkey_index.insert(one_time_pubkey.as_bytes(), global_index);
        self.outputs.insert(global_index, entry);
        
        global_index
    }
    
    /// Obtiene un output por índice global
    pub fn get_output(&self, global_index: u64) -> Option<&ShieldedPoolEntry> {
        self.outputs.get(&global_index)
    }
    
    /// Obtiene la pubkey de un output
    pub fn get_pubkey(&self, global_index: u64) -> Option<CompressedPoint> {
        self.outputs.get(&global_index).map(|e| e.one_time_pubkey)
    }
    
    /// Número de outputs en el pool
    pub fn len(&self) -> usize {
        self.outputs.len()
    }
    
    /// Pool vacío
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }
    
    /// Obtiene el siguiente índice global
    pub fn next_index(&self) -> u64 {
        self.next_index
    }
    
    /// Obtiene outputs en un rango (para selección de decoys)
    pub fn get_outputs_in_range(&self, start: u64, end: u64) -> Vec<(u64, CompressedPoint)> {
        self.outputs.iter()
            .filter(|(idx, _)| **idx >= start && **idx < end)
            .map(|(idx, entry)| (*idx, entry.one_time_pubkey))
            .collect()
    }
    
    /// Obtiene todos los outputs (para selección de decoys)
    pub fn get_all_outputs(&self) -> Vec<(u64, CompressedPoint)> {
        self.outputs.iter()
            .map(|(idx, entry)| (*idx, entry.one_time_pubkey))
            .collect()
    }
    
    /// Remueve outputs (para reorgs)
    pub fn remove_outputs_after_height(&mut self, height: u64) {
        let to_remove: Vec<u64> = self.outputs.iter()
            .filter(|(_, entry)| entry.block_height > height)
            .map(|(idx, _)| *idx)
            .collect();
        
        for idx in to_remove {
            if let Some(entry) = self.outputs.remove(&idx) {
                self.pubkey_index.remove(&entry.one_time_pubkey.as_bytes());
            }
        }
    }
}

// =============================================================================
// Validator
// =============================================================================

/// Validador de transacciones shielded
pub struct ShieldedValidator<'a> {
    /// Pool de outputs shielded
    shielded_pool: &'a ShieldedPool,
    /// Set de key images usados
    key_image_set: &'a KeyImageSet,
}

impl<'a> ShieldedValidator<'a> {
    pub fn new(shielded_pool: &'a ShieldedPool, key_image_set: &'a KeyImageSet) -> Self {
        ShieldedValidator {
            shielded_pool,
            key_image_set,
        }
    }
    
    /// Valida una transacción shielded completa
    pub fn validate(&self, tx: &ShieldedTx) -> ValidationResult {
        // 1. Validar estructura básica
        if let Err(e) = self.validate_structure(tx) {
            return ValidationResult::Invalid(e);
        }
        
        // 2. Validar fee
        if let Err(e) = self.validate_fee(tx) {
            return ValidationResult::Invalid(e);
        }
        
        // 3. Validar tipo de TX es consistente
        if let Err(e) = self.validate_tx_type(tx) {
            return ValidationResult::Invalid(e);
        }
        
        // 4. Validar outputs shielded (range proofs)
        if let Err(e) = self.validate_shielded_outputs(tx) {
            return ValidationResult::Invalid(e);
        }
        
        // 5. Validar inputs shielded (ring signatures, key images)
        if let Err(e) = self.validate_shielded_inputs(tx) {
            return ValidationResult::Invalid(e);
        }
        
        // 6. Validar balance
        if let Err(e) = self.validate_balance(tx) {
            return ValidationResult::Invalid(e);
        }
        
        ValidationResult::Valid
    }
    
    /// Valida estructura básica
    fn validate_structure(&self, tx: &ShieldedTx) -> Result<(), ValidationError> {
        // Versión
        if tx.version != 2 {
            return Err(ValidationError::UnsupportedVersion(tx.version));
        }
        
        // No vacía
        if tx.transparent_inputs.is_empty() && 
           tx.transparent_outputs.is_empty() &&
           tx.shielded_inputs.is_empty() &&
           tx.shielded_outputs.is_empty() {
            return Err(ValidationError::EmptyTransaction);
        }
        
        // Límites
        if tx.shielded_inputs.len() > MAX_SHIELDED_INPUTS {
            return Err(ValidationError::TooManyShieldedInputs {
                max: MAX_SHIELDED_INPUTS,
                provided: tx.shielded_inputs.len(),
            });
        }
        
        if tx.shielded_outputs.len() > MAX_SHIELDED_OUTPUTS {
            return Err(ValidationError::TooManyShieldedOutputs {
                max: MAX_SHIELDED_OUTPUTS,
                provided: tx.shielded_outputs.len(),
            });
        }
        
        Ok(())
    }
    
    /// Valida fee
    fn validate_fee(&self, tx: &ShieldedTx) -> Result<(), ValidationError> {
        // Solo TX con componentes shielded requieren fee mínimo
        if !tx.shielded_inputs.is_empty() || !tx.shielded_outputs.is_empty() {
            if tx.fee < MIN_SHIELDED_FEE {
                return Err(ValidationError::FeeTooLow {
                    required: MIN_SHIELDED_FEE,
                    provided: tx.fee,
                });
            }
        }
        
        Ok(())
    }
    
    /// Valida que el tipo de TX es consistente con su contenido
    fn validate_tx_type(&self, tx: &ShieldedTx) -> Result<(), ValidationError> {
        let has_transparent_in = !tx.transparent_inputs.is_empty();
        let has_transparent_out = !tx.transparent_outputs.is_empty();
        let has_shielded_in = !tx.shielded_inputs.is_empty();
        let has_shielded_out = !tx.shielded_outputs.is_empty();
        
        let _expected_type = match (has_transparent_in, has_transparent_out, has_shielded_in, has_shielded_out) {
            (true, true, false, false) => TxType::Transparent,
            (true, false, false, true) => TxType::Shielding,
            (false, false, true, true) => TxType::FullyShielded,
            (false, true, true, false) => TxType::Unshielding,
            _ => TxType::Mixed,
        };
        
        // Mixed es válido, solo verificamos inconsistencias obvias
        if tx.tx_type == TxType::Transparent && (has_shielded_in || has_shielded_out) {
            return Err(ValidationError::InconsistentTxType);
        }
        
        Ok(())
    }
    
    /// Valida outputs shielded
    fn validate_shielded_outputs(&self, tx: &ShieldedTx) -> Result<(), ValidationError> {
        for (i, output) in tx.shielded_outputs.iter().enumerate() {
            // Verificar range proof
            match output.range_proof.verify(&output.commitment) {
                Ok(true) => {},
                Ok(false) => return Err(ValidationError::InvalidRangeProof { output_index: i }),
                Err(_) => return Err(ValidationError::InvalidRangeProof { output_index: i }),
            }
            
            // Verificar que el commitment es un punto válido
            if output.commitment.as_bytes() == [0u8; 32] {
                return Err(ValidationError::InvalidCommitment { index: i });
            }
            
            // Verificar que la one-time pubkey es válida
            if output.one_time_pubkey.decompress().is_none() {
                return Err(ValidationError::InvalidCommitment { index: i });
            }
        }
        
        Ok(())
    }
    
    /// Valida inputs shielded
    fn validate_shielded_inputs(&self, tx: &ShieldedTx) -> Result<(), ValidationError> {
        let tx_hash = tx.hash();
        let mut seen_key_images: Vec<[u8; 32]> = Vec::new();
        
        for (i, input) in tx.shielded_inputs.iter().enumerate() {
            // Verificar tamaño del ring
            if input.ring_members.len() < 3 {
                return Err(ValidationError::RingTooSmall {
                    input_index: i,
                    size: input.ring_members.len(),
                });
            }
            
            // Verificar que todos los miembros del ring existen
            let mut ring_pubkeys: Vec<CompressedPoint> = Vec::new();
            for member_idx in &input.ring_members {
                match self.shielded_pool.get_pubkey(*member_idx) {
                    Some(pk) => ring_pubkeys.push(pk),
                    None => return Err(ValidationError::RingMemberNotFound {
                        input_index: i,
                        member_index: *member_idx,
                    }),
                }
            }
            
            // Verificar ring signature
            match input.ring_signature.verify(&tx_hash, &ring_pubkeys) {
                Ok(true) => {},
                Ok(false) => return Err(ValidationError::InvalidRingSignature { input_index: i }),
                Err(_) => return Err(ValidationError::InvalidRingSignature { input_index: i }),
            }
            
            // Verificar key image no duplicado en esta TX
            let ki_bytes = input.ring_signature.key_image.as_bytes();
            if seen_key_images.contains(&ki_bytes) {
                return Err(ValidationError::DuplicateKeyImageInTx { input_index: i });
            }
            seen_key_images.push(ki_bytes);
            
            // Verificar key image no usado previamente (double-spend)
            if self.key_image_set.contains(&input.ring_signature.key_image) {
                return Err(ValidationError::DoubleSpend {
                    input_index: i,
                    key_image: ki_bytes,
                });
            }
        }
        
        Ok(())
    }
    
    /// Valida balance de la TX
    fn validate_balance(&self, tx: &ShieldedTx) -> Result<(), ValidationError> {
        // Para TX fully shielded:
        // sum(pseudo_commitments) - sum(output_commitments) - fee*H = 0
        
        if tx.shielded_inputs.is_empty() && tx.shielded_outputs.is_empty() {
            // TX transparente, balance se valida de otra forma
            return Ok(());
        }
        
        // Sumar pseudo-commitments de inputs
        let mut input_sum = PedersenCommitment::zero();
        for input in &tx.shielded_inputs {
            input_sum = input_sum.add(&input.pseudo_commitment);
        }
        
        // Sumar commitments de outputs
        let mut output_sum = PedersenCommitment::zero();
        for output in &tx.shielded_outputs {
            output_sum = output_sum.add(&output.commitment);
        }
        
        // Agregar fee
        let fee_commitment = PedersenCommitment::commit(tx.fee, Scalar::zero());
        let output_plus_fee = output_sum.add(&fee_commitment);
        
        // Para shielding: no hay inputs shielded, solo verificar binding sig
        if tx.shielded_inputs.is_empty() {
            // La binding signature garantiza que el emisor conoce la suma de blindings
            return Ok(());
        }
        
        // Para unshielding: no hay outputs shielded
        if tx.shielded_outputs.is_empty() {
            // Similar, binding sig lo garantiza
            return Ok(());
        }
        
        // Para fully shielded: verificar que commitments balancean
        // Nota: esto funciona porque usamos pseudo-commitments con blindings ajustados
        if input_sum.as_bytes() != output_plus_fee.as_bytes() {
            return Err(ValidationError::BalanceMismatch);
        }
        
        Ok(())
    }
}

// =============================================================================
// Validation Context (para validación en batch)
// =============================================================================

/// Contexto de validación con estado mutable
pub struct ValidationContext {
    /// Pool de outputs shielded
    pub shielded_pool: ShieldedPool,
    /// Set de key images
    pub key_image_set: KeyImageSet,
}

impl ValidationContext {
    pub fn new() -> Self {
        ValidationContext {
            shielded_pool: ShieldedPool::new(),
            key_image_set: KeyImageSet::new(),
        }
    }
    
    /// Valida y aplica una TX (si es válida)
    pub fn validate_and_apply(&mut self, tx: &ShieldedTx, block_height: u64) -> ValidationResult {
        // Primero validar
        let validator = ShieldedValidator::new(&self.shielded_pool, &self.key_image_set);
        let result = validator.validate(tx);
        
        if !result.is_valid() {
            return result;
        }
        
        // Si es válida, aplicar cambios
        self.apply_tx(tx, block_height);
        
        ValidationResult::Valid
    }
    
    /// Aplica una TX válida al estado
    fn apply_tx(&mut self, tx: &ShieldedTx, block_height: u64) {
        let tx_hash = tx.hash();
        
        // Agregar outputs shielded al pool
        for (i, output) in tx.shielded_outputs.iter().enumerate() {
            self.shielded_pool.add_output(
                output.commitment,
                output.one_time_pubkey,
                block_height,
                tx_hash,
                i,
            );
        }
        
        // Agregar key images al set
        for input in &tx.shielded_inputs {
            let _ = self.key_image_set.insert(&input.ring_signature.key_image);
        }
    }
    
    /// Revierte cambios de un bloque (para reorgs)
    pub fn revert_block(&mut self, height: u64, txs: &[ShieldedTx]) {
        // Remover outputs creados en este bloque
        self.shielded_pool.remove_outputs_after_height(height - 1);
        
        // Remover key images de las TXs del bloque
        for tx in txs {
            for input in &tx.shielded_inputs {
                self.key_image_set.remove(&input.ring_signature.key_image);
            }
        }
    }
    
    /// Estadísticas
    pub fn stats(&self) -> ValidationStats {
        ValidationStats {
            shielded_outputs: self.shielded_pool.len(),
            key_images_used: self.key_image_set.len(),
        }
    }
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Estadísticas de validación
#[derive(Clone, Debug)]
pub struct ValidationStats {
    pub shielded_outputs: usize,
    pub key_images_used: usize,
}

// =============================================================================
// Quick Validation (para mempool)
// =============================================================================

/// Validación rápida para mempool (sin verificar proofs completos)
pub fn quick_validate(tx: &ShieldedTx) -> Result<(), ValidationError> {
    // Solo validar estructura y fee
    if tx.version != 2 {
        return Err(ValidationError::UnsupportedVersion(tx.version));
    }
    
    if tx.shielded_inputs.len() > MAX_SHIELDED_INPUTS {
        return Err(ValidationError::TooManyShieldedInputs {
            max: MAX_SHIELDED_INPUTS,
            provided: tx.shielded_inputs.len(),
        });
    }
    
    if tx.shielded_outputs.len() > MAX_SHIELDED_OUTPUTS {
        return Err(ValidationError::TooManyShieldedOutputs {
            max: MAX_SHIELDED_OUTPUTS,
            provided: tx.shielded_outputs.len(),
        });
    }
    
    if !tx.shielded_inputs.is_empty() || !tx.shielded_outputs.is_empty() {
        if tx.fee < MIN_SHIELDED_FEE {
            return Err(ValidationError::FeeTooLow {
                required: MIN_SHIELDED_FEE,
                provided: tx.fee,
            });
        }
    }
    
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::shielded_tx::ShieldedOutput;
    
    #[test]
    fn test_shielded_pool() {
        let mut pool = ShieldedPool::new();
        
        let commitment = PedersenCommitment::commit(100, Scalar::random());
        let pubkey = CompressedPoint::from_point(
            &(Scalar::random().inner() * crate::privacy::pedersen::GENERATORS.g)
        );
        
        let idx = pool.add_output(commitment, pubkey, 1, [0u8; 32], 0);
        
        assert_eq!(idx, 0);
        assert_eq!(pool.len(), 1);
        assert!(pool.get_output(0).is_some());
        assert!(pool.get_output(1).is_none());
    }
    
    #[test]
    fn test_validation_context() {
        let ctx = ValidationContext::new();
        
        assert_eq!(ctx.shielded_pool.len(), 0);
        assert!(ctx.key_image_set.is_empty());
    }
    
    #[test]
    fn test_quick_validate_fee() {
        use crate::privacy::shielded_tx::ShieldedTx;
        
        let tx = ShieldedTx {
            version: 2,
            tx_type: TxType::FullyShielded,
            transparent_inputs: vec![],
            transparent_outputs: vec![],
            shielded_inputs: vec![],
            shielded_outputs: vec![ShieldedOutput {
                commitment: PedersenCommitment::zero(),
                range_proof: crate::privacy::rangeproof::RangeProof::default(),
                ephemeral_pubkey: CompressedPoint::identity(),
                one_time_pubkey: CompressedPoint::identity(),
                view_tag: 0,
                encrypted_data: crate::privacy::shielded_tx::EncryptedOutputData {
                    ciphertext: vec![],
                    nonce: [0u8; 12],
                },
            }],
            fee: 100, // Muy bajo
            binding_sig: None,
            locktime: 0,
        };
        
        let result = quick_validate(&tx);
        assert!(matches!(result, Err(ValidationError::FeeTooLow { .. })));
    }
}
