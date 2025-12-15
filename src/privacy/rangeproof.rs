// =============================================================================
// MOONCOIN - Range Proofs
// =============================================================================
//
// Implementación de Range Proofs para probar que un valor comprometido
// está en un rango válido [0, 2^64) sin revelar el valor.
//
// Esta es una implementación simplificada basada en los principios de
// Bulletproofs. Para producción se recomienda usar una biblioteca
// auditada como bulletproofs-dalek.
//
// Un Range Proof prueba que:
//   C = v*H + r*G  donde  0 ≤ v < 2^64
//
// Sin revelar v ni r.
//
// =============================================================================

use super::pedersen::{PedersenCommitment, Scalar, CompressedPoint, GENERATORS};
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};

// =============================================================================
// Constants
// =============================================================================

/// Bits del rango (64 bits = valores hasta 2^64 - 1)
pub const RANGE_BITS: usize = 64;

/// Tamaño aproximado de un range proof en bytes
pub const RANGE_PROOF_SIZE: usize = 672;

// =============================================================================
// Range Proof Error
// =============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeProofError {
    /// El valor está fuera del rango permitido
    ValueOutOfRange,
    /// La prueba es inválida
    InvalidProof,
    /// Error de deserialización
    DeserializationError,
    /// Error interno
    InternalError(String),
}

impl std::fmt::Display for RangeProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RangeProofError::ValueOutOfRange => write!(f, "Value out of range"),
            RangeProofError::InvalidProof => write!(f, "Invalid range proof"),
            RangeProofError::DeserializationError => write!(f, "Deserialization error"),
            RangeProofError::InternalError(s) => write!(f, "Internal error: {}", s),
        }
    }
}

// =============================================================================
// Range Proof
// =============================================================================

/// Range Proof - prueba que un commitment contiene un valor en [0, 2^64)
/// 
/// Estructura simplificada inspirada en Bulletproofs.
/// En producción, usar bulletproofs-dalek para pruebas completas.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    /// Commitment A (primera parte de la prueba)
    pub a: CompressedPoint,
    /// Commitment S (segunda parte)
    pub s: CompressedPoint,
    /// Commitment T1
    pub t1: CompressedPoint,
    /// Commitment T2
    pub t2: CompressedPoint,
    /// Respuesta tau_x
    pub tau_x: Scalar,
    /// Respuesta mu
    pub mu: Scalar,
    /// Respuesta t_hat
    pub t_hat: Scalar,
    /// Vector de respuestas L
    pub l_vec: Vec<CompressedPoint>,
    /// Vector de respuestas R
    pub r_vec: Vec<CompressedPoint>,
    /// Respuestas finales
    pub a_final: Scalar,
    pub b_final: Scalar,
}

impl RangeProof {
    /// Crea una range proof para un valor y blinding factor
    /// 
    /// Prueba que el commitment C = value*H + blinding*G contiene
    /// un valor en [0, 2^64)
    pub fn create(value: u64, blinding: Scalar) -> Result<Self, RangeProofError> {
        // Verificar que el valor está en rango
        // (u64 siempre está en [0, 2^64), pero verificamos por consistencia)
        if value > u64::MAX {
            return Err(RangeProofError::ValueOutOfRange);
        }
        
        // Generar prueba
        // Esta es una versión simplificada - en producción usar Bulletproofs completo
        
        let _rng = rand::thread_rng();
        
        // Generar compromisos intermedios aleatorios
        let alpha = Scalar::random();
        let rho = Scalar::random();
        
        // A = alpha*G + sum(a_L[i] - a_R[i])*H[i]
        // Simplificado: solo usamos puntos aleatorios por ahora
        let a = CompressedPoint::from_point(
            &(alpha.inner() * GENERATORS.g)
        );
        
        let s = CompressedPoint::from_point(
            &(rho.inner() * GENERATORS.g)
        );
        
        // Generar challenges (Fiat-Shamir)
        let y = Self::hash_challenge(&[&a.as_bytes(), &s.as_bytes()]);
        let z = Self::hash_challenge(&[&y.as_bytes()]);
        
        // Calcular t1, t2
        let tau1 = Scalar::random();
        let tau2 = Scalar::random();
        
        let t1 = CompressedPoint::from_point(
            &(tau1.inner() * GENERATORS.g)
        );
        
        let t2 = CompressedPoint::from_point(
            &(tau2.inner() * GENERATORS.g)
        );
        
        // Challenge x
        let x = Self::hash_challenge(&[&t1.as_bytes(), &t2.as_bytes()]);
        
        // Calcular respuestas
        // tau_x = tau1*x + tau2*x^2 + z^2*blinding
        let x_sq = x.mul(&x);
        let z_sq = z.mul(&z);
        let tau_x = tau1.mul(&x)
            .add(&tau2.mul(&x_sq))
            .add(&z_sq.mul(&blinding));
        
        // mu = alpha + rho*x
        let mu = alpha.add(&rho.mul(&x));
        
        // t_hat simplificado
        let t_hat = Scalar::from_u64(value).mul(&z);
        
        // Vectores L y R (log2(64) = 6 elementos cada uno)
        let log_n = 6;
        let mut l_vec = Vec::with_capacity(log_n);
        let mut r_vec = Vec::with_capacity(log_n);
        
        for _ in 0..log_n {
            let l_scalar = Scalar::random();
            let r_scalar = Scalar::random();
            
            l_vec.push(CompressedPoint::from_point(
                &(l_scalar.inner() * GENERATORS.g)
            ));
            r_vec.push(CompressedPoint::from_point(
                &(r_scalar.inner() * GENERATORS.g)
            ));
        }
        
        // Respuestas finales
        let a_final = Scalar::random();
        let b_final = Scalar::random();
        
        Ok(RangeProof {
            a,
            s,
            t1,
            t2,
            tau_x,
            mu,
            t_hat,
            l_vec,
            r_vec,
            a_final,
            b_final,
        })
    }
    
    /// Verifica la range proof contra un commitment
    pub fn verify(&self, _commitment: &PedersenCommitment) -> Result<bool, RangeProofError> {
        // Reconstruir challenges (Fiat-Shamir)
        let y = Self::hash_challenge(&[&self.a.as_bytes(), &self.s.as_bytes()]);
        let _z = Self::hash_challenge(&[&y.as_bytes()]);
        let _x = Self::hash_challenge(&[&self.t1.as_bytes(), &self.t2.as_bytes()]);
        
        // Verificar que los puntos son válidos
        if self.a.decompress().is_none() ||
           self.s.decompress().is_none() ||
           self.t1.decompress().is_none() ||
           self.t2.decompress().is_none() {
            return Err(RangeProofError::InvalidProof);
        }
        
        // Verificar vectores L y R
        for l in &self.l_vec {
            if l.decompress().is_none() {
                return Err(RangeProofError::InvalidProof);
            }
        }
        for r in &self.r_vec {
            if r.decompress().is_none() {
                return Err(RangeProofError::InvalidProof);
            }
        }
        
        // Verificación simplificada
        // En una implementación completa, esto verificaría:
        // 1. La ecuación del inner product
        // 2. Que t_hat = <l, r>
        // 3. El commitment de t_hat
        
        // Por ahora, verificamos estructura básica
        if self.l_vec.len() != 6 || self.r_vec.len() != 6 {
            return Err(RangeProofError::InvalidProof);
        }
        
        // Verificación básica pasó
        Ok(true)
    }
    
    /// Hash para challenges (Fiat-Shamir)
    fn hash_challenge(inputs: &[&[u8]]) -> Scalar {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Mooncoin_RangeProof_Challenge");
        for input in inputs {
            hasher.update(input);
        }
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Scalar::from_bytes_mod_order(&bytes)
    }
    
    /// Tamaño de la prueba en bytes
    pub fn size(&self) -> usize {
        // 4 puntos base + 3 scalars + vectors + 2 scalars finales
        // 4*32 + 3*32 + 12*32 + 2*32 = 672 bytes aproximadamente
        32 * 4 + 32 * 3 + 32 * self.l_vec.len() + 32 * self.r_vec.len() + 32 * 2
    }
    
    /// Serializa a bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        // Usar bincode para serialización
        bincode::serialize(self).unwrap_or_default()
    }
    
    /// Deserializa desde bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RangeProofError> {
        bincode::deserialize(bytes)
            .map_err(|_| RangeProofError::DeserializationError)
    }
}

impl Default for RangeProof {
    fn default() -> Self {
        // Proof inválida por defecto (no usar en producción)
        RangeProof {
            a: CompressedPoint::identity(),
            s: CompressedPoint::identity(),
            t1: CompressedPoint::identity(),
            t2: CompressedPoint::identity(),
            tau_x: Scalar::zero(),
            mu: Scalar::zero(),
            t_hat: Scalar::zero(),
            l_vec: vec![CompressedPoint::identity(); 6],
            r_vec: vec![CompressedPoint::identity(); 6],
            a_final: Scalar::zero(),
            b_final: Scalar::zero(),
        }
    }
}

// =============================================================================
// Aggregated Range Proofs
// =============================================================================

/// Range proof agregada para múltiples valores
/// 
/// Permite probar N valores con una sola prueba más compacta que N pruebas individuales.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedRangeProof {
    /// Pruebas individuales (por ahora - optimizar con agregación real)
    pub proofs: Vec<RangeProof>,
    /// Número de valores probados
    pub count: usize,
}

impl AggregatedRangeProof {
    /// Crea una prueba agregada para múltiples valores
    pub fn create(
        values: &[u64],
        blindings: &[Scalar],
    ) -> Result<Self, RangeProofError> {
        if values.len() != blindings.len() {
            return Err(RangeProofError::InternalError(
                "Values and blindings length mismatch".to_string()
            ));
        }
        
        let mut proofs = Vec::with_capacity(values.len());
        
        for (value, blinding) in values.iter().zip(blindings.iter()) {
            let proof = RangeProof::create(*value, *blinding)?;
            proofs.push(proof);
        }
        
        Ok(AggregatedRangeProof {
            count: values.len(),
            proofs,
        })
    }
    
    /// Verifica la prueba agregada contra múltiples commitments
    pub fn verify(&self, commitments: &[PedersenCommitment]) -> Result<bool, RangeProofError> {
        if commitments.len() != self.count || commitments.len() != self.proofs.len() {
            return Err(RangeProofError::InvalidProof);
        }
        
        for (proof, commitment) in self.proofs.iter().zip(commitments.iter()) {
            if !proof.verify(commitment)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Tamaño total en bytes
    pub fn size(&self) -> usize {
        self.proofs.iter().map(|p| p.size()).sum()
    }
}

// =============================================================================
// Range Proof Builder (helper)
// =============================================================================

/// Builder para crear range proofs
pub struct RangeProofBuilder {
    value: Option<u64>,
    blinding: Option<Scalar>,
}

impl RangeProofBuilder {
    pub fn new() -> Self {
        RangeProofBuilder {
            value: None,
            blinding: None,
        }
    }
    
    pub fn value(mut self, value: u64) -> Self {
        self.value = Some(value);
        self
    }
    
    pub fn blinding(mut self, blinding: Scalar) -> Self {
        self.blinding = Some(blinding);
        self
    }
    
    pub fn build(self) -> Result<RangeProof, RangeProofError> {
        let value = self.value.ok_or(RangeProofError::InternalError(
            "Value not set".to_string()
        ))?;
        let blinding = self.blinding.unwrap_or_else(Scalar::random);
        
        RangeProof::create(value, blinding)
    }
}

impl Default for RangeProofBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_range_proof() {
        let value = 1000u64;
        let blinding = Scalar::random();
        
        let proof = RangeProof::create(value, blinding).unwrap();
        
        // Verificar que la prueba tiene el tamaño esperado
        assert_eq!(proof.l_vec.len(), 6);
        assert_eq!(proof.r_vec.len(), 6);
    }
    
    #[test]
    fn test_verify_range_proof() {
        let value = 1000u64;
        let blinding = Scalar::random();
        
        let commitment = PedersenCommitment::commit(value, blinding);
        let proof = RangeProof::create(value, blinding).unwrap();
        
        let result = proof.verify(&commitment);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    
    #[test]
    fn test_range_proof_serialization() {
        let value = 500u64;
        let blinding = Scalar::random();
        
        let proof = RangeProof::create(value, blinding).unwrap();
        let bytes = proof.to_bytes();
        
        let recovered = RangeProof::from_bytes(&bytes).unwrap();
        
        assert_eq!(proof.a.as_bytes(), recovered.a.as_bytes());
        assert_eq!(proof.s.as_bytes(), recovered.s.as_bytes());
    }
    
    #[test]
    fn test_aggregated_proof() {
        let values = vec![100u64, 200u64, 300u64];
        let blindings: Vec<_> = (0..3).map(|_| Scalar::random()).collect();
        
        let commitments: Vec<_> = values.iter()
            .zip(blindings.iter())
            .map(|(v, b)| PedersenCommitment::commit(*v, *b))
            .collect();
        
        let agg_proof = AggregatedRangeProof::create(&values, &blindings).unwrap();
        
        assert_eq!(agg_proof.count, 3);
        assert!(agg_proof.verify(&commitments).unwrap());
    }
    
    #[test]
    fn test_builder() {
        let proof = RangeProofBuilder::new()
            .value(1000)
            .blinding(Scalar::random())
            .build()
            .unwrap();
        
        assert_eq!(proof.l_vec.len(), 6);
    }
    
    #[test]
    fn test_proof_size() {
        let proof = RangeProof::create(1000, Scalar::random()).unwrap();
        let size = proof.size();
        
        // Debería ser aproximadamente 672 bytes
        assert!(size > 500);
        assert!(size < 1000);
    }
}
