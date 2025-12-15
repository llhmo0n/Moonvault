// =============================================================================
// MOONCOIN - Pedersen Commitments
// =============================================================================
//
// Implementación de Pedersen Commitments usando curve25519-dalek.
//
// Un Pedersen Commitment permite comprometerse a un valor sin revelarlo:
//   C = v*H + r*G
//
// Donde:
//   v = valor (monto)
//   r = blinding factor (secreto aleatorio)
//   G, H = generadores independientes de la curva
//
// Propiedades:
//   - Hiding: Sin conocer r, no se puede determinar v
//   - Binding: No se puede encontrar (v', r') tal que C = v'*H + r'*G
//   - Homomórfico: C(a) + C(b) = C(a+b)
//
// =============================================================================

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as DalekScalar;
use curve25519_dalek::traits::Identity;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use sha3::{Sha3_512, Digest};
use rand::RngCore;

// =============================================================================
// Generators
// =============================================================================

/// Generadores para Pedersen Commitments
pub struct Generators {
    /// G: basepoint estándar (para blinding factor)
    pub g: RistrettoPoint,
    /// H: segundo generador (para valor)
    pub h: RistrettoPoint,
}

impl Generators {
    /// Crea los generadores
    pub fn new() -> Self {
        // G es el basepoint estándar de Ristretto
        let g = RISTRETTO_BASEPOINT_POINT;
        
        // H se deriva de forma determinística de G
        // usando hash-to-curve para garantizar que nadie
        // conoce el logaritmo discreto de H respecto a G
        let h = Self::derive_h();
        
        Generators { g, h }
    }
    
    /// Deriva H de forma segura
    fn derive_h() -> RistrettoPoint {
        // Hash del string "Mooncoin_Pedersen_H" al punto
        let mut hasher = Sha3_512::new();
        hasher.update(b"Mooncoin_Pedersen_H_v1");
        let hash = hasher.finalize();
        
        // Convertir hash a punto Ristretto (requiere 64 bytes)
        RistrettoPoint::hash_from_bytes::<Sha3_512>(&hash)
    }
}

impl Default for Generators {
    fn default() -> Self {
        Self::new()
    }
}

// Generadores globales (lazy)
lazy_static::lazy_static! {
    pub static ref GENERATORS: Generators = Generators::new();
}

// =============================================================================
// Scalar
// =============================================================================

/// Scalar de 256 bits para la curva
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar(DalekScalar);

impl Scalar {
    /// Scalar cero
    pub fn zero() -> Self {
        Scalar(DalekScalar::ZERO)
    }
    
    /// Scalar uno
    pub fn one() -> Self {
        Scalar(DalekScalar::ONE)
    }
    
    /// Crea desde u64
    pub fn from_u64(value: u64) -> Self {
        Scalar(DalekScalar::from(value))
    }
    
    /// Genera scalar aleatorio
    pub fn random() -> Self {
        let mut bytes = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut bytes);
        Scalar(DalekScalar::from_bytes_mod_order_wide(&bytes))
    }
    
    /// Crea desde bytes (mod order)
    pub fn from_bytes_mod_order(bytes: &[u8; 32]) -> Self {
        Scalar(DalekScalar::from_bytes_mod_order(*bytes))
    }
    
    /// Intenta crear desde bytes canónicos
    pub fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
        DalekScalar::from_canonical_bytes(*bytes)
            .map(Scalar)
            .into()
    }
    
    /// Convierte a bytes
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    
    /// Suma de scalars
    pub fn add(&self, other: &Scalar) -> Self {
        Scalar(self.0 + other.0)
    }
    
    /// Resta de scalars
    pub fn sub(&self, other: &Scalar) -> Self {
        Scalar(self.0 - other.0)
    }
    
    /// Multiplicación de scalars
    pub fn mul(&self, other: &Scalar) -> Self {
        Scalar(self.0 * other.0)
    }
    
    /// Negación
    pub fn neg(&self) -> Self {
        Scalar(-self.0)
    }
    
    /// Obtiene el scalar interno (para operaciones avanzadas)
    pub fn inner(&self) -> &DalekScalar {
        &self.0
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Scalar::from_u64(value)
    }
}

impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid scalar length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Scalar::from_bytes_mod_order(&arr))
    }
}

// =============================================================================
// Compressed Point
// =============================================================================

/// Punto comprimido de la curva (32 bytes)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressedPoint(CompressedRistretto);

impl CompressedPoint {
    /// Punto identidad (infinito)
    pub fn identity() -> Self {
        CompressedPoint(RistrettoPoint::identity().compress())
    }
    
    /// Crea desde bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let compressed = CompressedRistretto::from_slice(bytes).ok()?;
        // Verificar que es un punto válido
        if compressed.decompress().is_some() {
            Some(CompressedPoint(compressed))
        } else {
            None
        }
    }
    
    /// Convierte a bytes
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    
    /// Descomprime el punto
    pub fn decompress(&self) -> Option<RistrettoPoint> {
        self.0.decompress()
    }
    
    /// Crea desde punto descomprimido
    pub fn from_point(point: &RistrettoPoint) -> Self {
        CompressedPoint(point.compress())
    }
}

impl Serialize for CompressedPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for CompressedPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid point length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        CompressedPoint::from_bytes(&arr)
            .ok_or_else(|| serde::de::Error::custom("Invalid curve point"))
    }
}

impl Default for CompressedPoint {
    fn default() -> Self {
        Self::identity()
    }
}

// =============================================================================
// Pedersen Commitment
// =============================================================================

/// Pedersen Commitment
/// 
/// C = v*H + r*G
/// 
/// Donde:
/// - v = valor (monto)
/// - r = blinding factor
/// - H, G = generadores
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PedersenCommitment {
    /// Punto comprimido del commitment
    point: CompressedPoint,
}

impl PedersenCommitment {
    /// Commitment cero (identidad)
    pub fn zero() -> Self {
        PedersenCommitment {
            point: CompressedPoint::identity(),
        }
    }
    
    /// Crea un commitment
    /// C = value * H + blinding * G
    pub fn commit(value: u64, blinding: Scalar) -> Self {
        let v = DalekScalar::from(value);
        let r = blinding.0;
        
        // C = v*H + r*G
        let point = v * GENERATORS.h + r * GENERATORS.g;
        
        PedersenCommitment {
            point: CompressedPoint::from_point(&point),
        }
    }
    
    /// Crea desde valor y blinding scalar
    pub fn commit_scalar(value: Scalar, blinding: Scalar) -> Self {
        let v = value.0;
        let r = blinding.0;
        
        let point = v * GENERATORS.h + r * GENERATORS.g;
        
        PedersenCommitment {
            point: CompressedPoint::from_point(&point),
        }
    }
    
    /// Suma de commitments (homomórfico)
    /// C(a) + C(b) = C(a+b) si los blinding factors también suman
    pub fn add(&self, other: &PedersenCommitment) -> Self {
        let p1 = self.point.decompress().unwrap_or_else(RistrettoPoint::identity);
        let p2 = other.point.decompress().unwrap_or_else(RistrettoPoint::identity);
        
        PedersenCommitment {
            point: CompressedPoint::from_point(&(p1 + p2)),
        }
    }
    
    /// Resta de commitments
    pub fn sub(&self, other: &PedersenCommitment) -> Self {
        let p1 = self.point.decompress().unwrap_or_else(RistrettoPoint::identity);
        let p2 = other.point.decompress().unwrap_or_else(RistrettoPoint::identity);
        
        PedersenCommitment {
            point: CompressedPoint::from_point(&(p1 - p2)),
        }
    }
    
    /// Negación del commitment
    pub fn neg(&self) -> Self {
        let p = self.point.decompress().unwrap_or_else(RistrettoPoint::identity);
        
        PedersenCommitment {
            point: CompressedPoint::from_point(&(-p)),
        }
    }
    
    /// Obtiene el punto comprimido
    pub fn as_bytes(&self) -> [u8; 32] {
        self.point.as_bytes()
    }
    
    /// Crea desde bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        CompressedPoint::from_bytes(bytes).map(|point| PedersenCommitment { point })
    }
    
    /// Obtiene el punto comprimido
    pub fn compressed(&self) -> &CompressedPoint {
        &self.point
    }
    
    /// Verifica que el commitment abre a un valor específico
    pub fn verify_opening(&self, value: u64, blinding: Scalar) -> bool {
        let expected = Self::commit(value, blinding);
        self.point == expected.point
    }
}

impl Serialize for PedersenCommitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.point.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PedersenCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let point = CompressedPoint::deserialize(deserializer)?;
        Ok(PedersenCommitment { point })
    }
}

impl Default for PedersenCommitment {
    fn default() -> Self {
        Self::zero()
    }
}

// =============================================================================
// Blinding Factor Generation
// =============================================================================

/// Genera un blinding factor aleatorio
pub fn random_blinding() -> Scalar {
    Scalar::random()
}

/// Calcula el blinding factor de cambio para que la TX balance
/// 
/// change_blind = sum(input_blinds) - sum(output_blinds)
pub fn calculate_change_blinding(
    input_blindings: &[Scalar],
    output_blindings: &[Scalar],
) -> Scalar {
    let mut sum_in = Scalar::zero();
    for b in input_blindings {
        sum_in = sum_in.add(b);
    }
    
    let mut sum_out = Scalar::zero();
    for b in output_blindings {
        sum_out = sum_out.add(b);
    }
    
    sum_in.sub(&sum_out)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_commit_and_verify() {
        let value = 100u64;
        let blinding = Scalar::random();
        
        let commitment = PedersenCommitment::commit(value, blinding);
        
        // Verificar que abre correctamente
        assert!(commitment.verify_opening(value, blinding));
        
        // No debe abrir con valor incorrecto
        assert!(!commitment.verify_opening(101, blinding));
        
        // No debe abrir con blinding incorrecto
        let wrong_blind = Scalar::random();
        assert!(!commitment.verify_opening(value, wrong_blind));
    }
    
    #[test]
    fn test_homomorphic_addition() {
        // C(a) + C(b) = C(a+b) cuando los blindings suman
        let a = 100u64;
        let b = 50u64;
        let r1 = Scalar::random();
        let r2 = Scalar::random();
        let r3 = r1.add(&r2);
        
        let c1 = PedersenCommitment::commit(a, r1);
        let c2 = PedersenCommitment::commit(b, r2);
        let c3 = PedersenCommitment::commit(a + b, r3);
        
        let sum = c1.add(&c2);
        
        assert_eq!(sum.as_bytes(), c3.as_bytes());
    }
    
    #[test]
    fn test_balance_check() {
        // Simular TX: 100 + 50 = 140 + 10 (fee)
        let in1_value = 100u64;
        let in2_value = 50u64;
        let out_value = 140u64;
        let fee = 10u64;
        
        let r1 = Scalar::random();
        let r2 = Scalar::random();
        // r_out = r1 + r2 (fee tiene blinding 0)
        let r_out = r1.add(&r2);
        
        let c_in1 = PedersenCommitment::commit(in1_value, r1);
        let c_in2 = PedersenCommitment::commit(in2_value, r2);
        let c_out = PedersenCommitment::commit(out_value, r_out);
        let c_fee = PedersenCommitment::commit(fee, Scalar::zero());
        
        // Verificar: sum(in) = sum(out) + fee
        let sum_in = c_in1.add(&c_in2);
        let sum_out = c_out.add(&c_fee);
        
        assert_eq!(sum_in.as_bytes(), sum_out.as_bytes());
    }
    
    #[test]
    fn test_scalar_operations() {
        let a = Scalar::from_u64(100);
        let b = Scalar::from_u64(50);
        
        let sum = a.add(&b);
        let expected = Scalar::from_u64(150);
        
        assert_eq!(sum.as_bytes(), expected.as_bytes());
        
        let diff = a.sub(&b);
        let expected_diff = Scalar::from_u64(50);
        
        assert_eq!(diff.as_bytes(), expected_diff.as_bytes());
    }
    
    #[test]
    fn test_serialization() {
        let value = 100u64;
        let blinding = Scalar::random();
        let commitment = PedersenCommitment::commit(value, blinding);
        
        // Serializar
        let bytes = commitment.as_bytes();
        
        // Deserializar
        let recovered = PedersenCommitment::from_bytes(&bytes).unwrap();
        
        assert_eq!(commitment.as_bytes(), recovered.as_bytes());
    }
    
    #[test]
    fn test_change_blinding() {
        let r1 = Scalar::random();
        let r2 = Scalar::random();
        let r3 = Scalar::random();
        
        // change_blind debe hacer que la suma balance
        let change_blind = calculate_change_blinding(
            &[r1, r2],
            &[r3],
        );
        
        // r1 + r2 = r3 + change_blind
        let left = r1.add(&r2);
        let right = r3.add(&change_blind);
        
        assert_eq!(left.as_bytes(), right.as_bytes());
    }
}
