// =============================================================================
// MOONCOIN v2.24 - Ring Signatures (MLSAG)
// =============================================================================
//
// Implementación de Ring Signatures para ocultar al emisor de una TX.
//
// Concepto:
// - En lugar de firmar con UNA clave, el emisor firma con un ANILLO
//   de posibles claves, sin revelar cuál es la real.
// - Incluye "decoys" (señuelos) de otros UTXOs reales del blockchain.
// - Key Images previenen double-spending sin revelar el firmante.
//
// Protocolo MLSAG (Multilayered Linkable Spontaneous Anonymous Group):
// - Linkable: Detecta si la misma clave firma dos veces (double-spend)
// - Spontaneous: No requiere setup entre participantes
// - Anonymous: No revela cuál miembro del anillo firmó
//
// =============================================================================

use super::pedersen::{Scalar, CompressedPoint, GENERATORS};
use curve25519_dalek::ristretto::RistrettoPoint;

use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};

// =============================================================================
// Constants
// =============================================================================

/// Tamaño del anillo por defecto (11 = 1 real + 10 decoys)
pub const DEFAULT_RING_SIZE: usize = 11;

/// Tamaño mínimo del anillo
pub const MIN_RING_SIZE: usize = 3;

/// Tamaño máximo del anillo
pub const MAX_RING_SIZE: usize = 64;

/// Dominio para hash de key image
const KEY_IMAGE_DOMAIN: &[u8] = b"Mooncoin_KeyImage_v1";

/// Dominio para hash del challenge
const CHALLENGE_DOMAIN: &[u8] = b"Mooncoin_RingSignature_Challenge_v1";

// =============================================================================
// Key Image
// =============================================================================

/// Key Image: identificador único de un input que permite detectar double-spend
/// sin revelar qué miembro del anillo es el real.
///
/// I = x * H_p(P)
///
/// Donde:
/// - x = clave privada
/// - P = clave pública
/// - H_p = hash-to-point
///
/// Propiedades:
/// - Único por cada par (x, P)
/// - No revela x ni cuál P del anillo
/// - Si I aparece dos veces = double-spend
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyImage(CompressedPoint);

impl KeyImage {
    /// Genera el key image para una clave privada y su pública
    pub fn generate(private_key: &Scalar, public_key: &CompressedPoint) -> Self {
        // H_p(P) - hash the public key to a point
        let hp = hash_to_point(public_key);
        
        // I = x * H_p(P)
        let image = private_key.inner() * hp;
        
        KeyImage(CompressedPoint::from_point(&image))
    }
    
    /// Obtiene los bytes del key image
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.as_bytes()
    }
    
    /// Crea desde bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        CompressedPoint::from_bytes(bytes).map(KeyImage)
    }
    
    /// Obtiene el punto comprimido
    pub fn compressed(&self) -> &CompressedPoint {
        &self.0
    }
}

impl Default for KeyImage {
    fn default() -> Self {
        KeyImage(CompressedPoint::identity())
    }
}

// =============================================================================
// Ring Signature
// =============================================================================

/// Ring Signature (MLSAG simplificado para una clave)
///
/// Prueba que el firmante controla UNA de las claves del anillo,
/// sin revelar cuál.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RingSignature {
    /// Key image (para detectar double-spend)
    pub key_image: KeyImage,
    
    /// Challenge inicial
    pub c: Scalar,
    
    /// Respuestas (una por cada miembro del anillo)
    pub s: Vec<Scalar>,
}

impl RingSignature {
    /// Crea una ring signature
    ///
    /// # Arguments
    /// * `message` - Mensaje a firmar (típicamente hash de la TX)
    /// * `ring` - Anillo de claves públicas (debe incluir la real)
    /// * `private_key` - Clave privada del firmante
    /// * `real_index` - Índice de nuestra clave en el anillo
    ///
    /// # Returns
    /// Ring signature o error
    pub fn sign(
        message: &[u8],
        ring: &[CompressedPoint],
        private_key: &Scalar,
        real_index: usize,
    ) -> Result<Self, RingError> {
        let n = ring.len();
        
        // Validaciones
        if n < MIN_RING_SIZE {
            return Err(RingError::RingTooSmall);
        }
        if n > MAX_RING_SIZE {
            return Err(RingError::RingTooLarge);
        }
        if real_index >= n {
            return Err(RingError::InvalidIndex);
        }
        
        // Verificar que nuestra clave pública corresponde
        let our_pubkey = CompressedPoint::from_point(
            &(private_key.inner() * GENERATORS.g)
        );
        if our_pubkey.as_bytes() != ring[real_index].as_bytes() {
            return Err(RingError::KeyMismatch);
        }
        
        // Generar key image
        let key_image = KeyImage::generate(private_key, &ring[real_index]);
        
        // Descomprimir el anillo
        let ring_points: Vec<RistrettoPoint> = ring.iter()
            .map(|p| p.decompress().ok_or(RingError::InvalidRingMember))
            .collect::<Result<Vec<_>, _>>()?;
        
        // Calcular H_p para cada miembro del anillo
        let hp_points: Vec<RistrettoPoint> = ring.iter()
            .map(|p| hash_to_point(p))
            .collect();
        
        // Generar valores aleatorios
        let alpha = Scalar::random();
        let mut s: Vec<Scalar> = (0..n).map(|_| Scalar::random()).collect();
        
        // Calcular L_real = alpha * G y R_real = alpha * H_p(P_real)
        let l_real = alpha.inner() * GENERATORS.g;
        let r_real = alpha.inner() * hp_points[real_index];
        
        // Calcular challenges en orden circular empezando desde real_index + 1
        let mut c: Vec<Scalar> = vec![Scalar::zero(); n];
        
        // c[real_index + 1] = H(m, L_real, R_real)
        let next_idx = (real_index + 1) % n;
        c[next_idx] = hash_challenge(message, &l_real, &r_real, &key_image);
        
        // Calcular el resto de challenges y L, R
        for i in 1..n {
            let idx = (real_index + 1 + i) % n;
            let prev_idx = (idx + n - 1) % n;
            
            // L_i = s_i * G + c_i * P_i
            let l_i = s[prev_idx].inner() * GENERATORS.g + c[prev_idx].inner() * ring_points[prev_idx];
            
            // R_i = s_i * H_p(P_i) + c_i * I
            let key_image_point = key_image.0.decompress()
                .ok_or(RingError::InvalidKeyImage)?;
            let r_i = s[prev_idx].inner() * hp_points[prev_idx] + c[prev_idx].inner() * key_image_point;
            
            // c[idx] = H(m, L_i, R_i)
            if idx != next_idx {
                c[idx] = hash_challenge(message, &l_i, &r_i, &key_image);
            }
        }
        
        // Cerrar el anillo: calcular s[real_index]
        // s_real = alpha - c_real * x
        s[real_index] = alpha.sub(&c[real_index].mul(private_key));
        
        Ok(RingSignature {
            key_image,
            c: c[0], // Guardar solo c[0] como punto de inicio
            s,
        })
    }
    
    /// Verifica una ring signature
    ///
    /// # Arguments
    /// * `message` - Mensaje firmado
    /// * `ring` - Anillo de claves públicas
    ///
    /// # Returns
    /// true si la firma es válida
    pub fn verify(&self, message: &[u8], ring: &[CompressedPoint]) -> Result<bool, RingError> {
        let n = ring.len();
        
        // Validaciones
        if n < MIN_RING_SIZE {
            return Err(RingError::RingTooSmall);
        }
        if n > MAX_RING_SIZE {
            return Err(RingError::RingTooLarge);
        }
        if self.s.len() != n {
            return Err(RingError::SizeMismatch);
        }
        
        // Descomprimir anillo
        let ring_points: Vec<RistrettoPoint> = ring.iter()
            .map(|p| p.decompress().ok_or(RingError::InvalidRingMember))
            .collect::<Result<Vec<_>, _>>()?;
        
        // Descomprimir key image
        let key_image_point = self.key_image.0.decompress()
            .ok_or(RingError::InvalidKeyImage)?;
        
        // Calcular H_p para cada miembro
        let hp_points: Vec<RistrettoPoint> = ring.iter()
            .map(|p| hash_to_point(p))
            .collect();
        
        // Reconstruir challenges
        let mut c_current = self.c;
        
        for i in 0..n {
            // L_i = s_i * G + c_i * P_i
            let l_i = self.s[i].inner() * GENERATORS.g + c_current.inner() * ring_points[i];
            
            // R_i = s_i * H_p(P_i) + c_i * I
            let r_i = self.s[i].inner() * hp_points[i] + c_current.inner() * key_image_point;
            
            // c_next = H(m, L_i, R_i)
            c_current = hash_challenge(message, &l_i, &r_i, &self.key_image);
        }
        
        // La firma es válida si llegamos al mismo c inicial
        Ok(c_current.as_bytes() == self.c.as_bytes())
    }
    
    /// Tamaño de la firma en bytes (aproximado)
    pub fn size(&self) -> usize {
        32 + 32 + self.s.len() * 32 // key_image + c + s[]
    }
}

// =============================================================================
// Ring Error
// =============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RingError {
    /// Anillo demasiado pequeño
    RingTooSmall,
    /// Anillo demasiado grande
    RingTooLarge,
    /// Índice inválido
    InvalidIndex,
    /// Clave no coincide con posición en anillo
    KeyMismatch,
    /// Miembro del anillo inválido (punto no válido)
    InvalidRingMember,
    /// Key image inválido
    InvalidKeyImage,
    /// Tamaño no coincide
    SizeMismatch,
    /// Double spend detectado
    DoubleSpend,
}

impl std::fmt::Display for RingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RingError::RingTooSmall => write!(f, "Ring too small (min {})", MIN_RING_SIZE),
            RingError::RingTooLarge => write!(f, "Ring too large (max {})", MAX_RING_SIZE),
            RingError::InvalidIndex => write!(f, "Invalid index in ring"),
            RingError::KeyMismatch => write!(f, "Private key doesn't match public key in ring"),
            RingError::InvalidRingMember => write!(f, "Invalid ring member (not on curve)"),
            RingError::InvalidKeyImage => write!(f, "Invalid key image"),
            RingError::SizeMismatch => write!(f, "Size mismatch"),
            RingError::DoubleSpend => write!(f, "Double spend detected"),
        }
    }
}

impl std::error::Error for RingError {}

// =============================================================================
// Key Image Set (para detectar double-spends)
// =============================================================================

/// Set de key images usados (para consenso)
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KeyImageSet {
    images: std::collections::HashSet<[u8; 32]>,
}

impl KeyImageSet {
    /// Crea un set vacío
    pub fn new() -> Self {
        KeyImageSet {
            images: std::collections::HashSet::new(),
        }
    }
    
    /// Verifica si un key image ya fue usado
    pub fn contains(&self, key_image: &KeyImage) -> bool {
        self.images.contains(&key_image.as_bytes())
    }
    
    /// Intenta agregar un key image (falla si ya existe)
    pub fn insert(&mut self, key_image: &KeyImage) -> Result<(), RingError> {
        if self.images.contains(&key_image.as_bytes()) {
            return Err(RingError::DoubleSpend);
        }
        self.images.insert(key_image.as_bytes());
        Ok(())
    }
    
    /// Número de key images
    pub fn len(&self) -> usize {
        self.images.len()
    }
    
    /// Está vacío
    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }
    
    /// Remueve un key image (para reorgs)
    pub fn remove(&mut self, key_image: &KeyImage) {
        self.images.remove(&key_image.as_bytes());
    }
}

// =============================================================================
// Decoy Selection
// =============================================================================

/// Selector de decoys para construir anillos
pub struct DecoySelector {
    /// Outputs disponibles para usar como decoys
    available_outputs: Vec<(u64, CompressedPoint)>, // (global_index, pubkey)
}

impl DecoySelector {
    /// Crea un selector con outputs disponibles
    pub fn new(outputs: Vec<(u64, CompressedPoint)>) -> Self {
        DecoySelector {
            available_outputs: outputs,
        }
    }
    
    /// Selecciona decoys para un anillo
    ///
    /// Usa distribución gamma para parecer más natural
    /// (outputs recientes son más probables)
    pub fn select_decoys(
        &self,
        real_output_index: u64,
        ring_size: usize,
    ) -> Result<Vec<(u64, CompressedPoint)>, RingError> {
        if self.available_outputs.len() < ring_size {
            return Err(RingError::RingTooSmall);
        }
        
        let mut selected = Vec::with_capacity(ring_size);
        let mut used_indices = std::collections::HashSet::new();
        
        // Agregar el output real
        if let Some(real) = self.available_outputs.iter()
            .find(|(idx, _)| *idx == real_output_index) {
            selected.push(*real);
            used_indices.insert(real_output_index);
        } else {
            return Err(RingError::InvalidIndex);
        }
        
        // Seleccionar decoys con distribución gamma
        let mut rng = rand::thread_rng();
        let mut attempts = 0;
        
        while selected.len() < ring_size && attempts < 1000 {
            // Gamma distribution favorece outputs recientes
            let idx = self.sample_gamma(&mut rng);
            
            if idx < self.available_outputs.len() {
                let (global_idx, pubkey) = self.available_outputs[idx];
                
                if !used_indices.contains(&global_idx) {
                    selected.push((global_idx, pubkey));
                    used_indices.insert(global_idx);
                }
            }
            
            attempts += 1;
        }
        
        if selected.len() < ring_size {
            return Err(RingError::RingTooSmall);
        }
        
        // Ordenar por índice global (para consistencia)
        selected.sort_by_key(|(idx, _)| *idx);
        
        Ok(selected)
    }
    
    /// Samplea usando distribución gamma (favorece índices altos = recientes)
    fn sample_gamma(&self, rng: &mut impl rand::Rng) -> usize {
        
        let n = self.available_outputs.len();
        if n == 0 {
            return 0;
        }
        
        // Gamma simplificada: exponencial con sesgo hacia recientes
        // shape ~19.28, scale ~1/1.61 (parámetros de Monero)
        let u: f64 = rng.gen();
        let gamma_sample = -19.28_f64.ln() * (1.0 - u).powf(1.0 / 1.61);
        
        // Mapear a índice (desde el final = más reciente)
        let offset = (gamma_sample * 10.0) as usize;
        if offset >= n {
            n - 1
        } else {
            n - 1 - offset
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Hash a point (para key image)
fn hash_to_point(pubkey: &CompressedPoint) -> RistrettoPoint {
    let mut hasher = Sha3_256::new();
    hasher.update(KEY_IMAGE_DOMAIN);
    hasher.update(&pubkey.as_bytes());
    let hash = hasher.finalize();
    
    // Convertir hash a punto usando método determinístico
    let mut extended = [0u8; 64];
    extended[..32].copy_from_slice(&hash);
    
    // Hash adicional para los segundos 32 bytes
    let mut hasher2 = Sha3_256::new();
    hasher2.update(&hash);
    hasher2.update(b"extend");
    let hash2 = hasher2.finalize();
    extended[32..].copy_from_slice(&hash2);
    
    RistrettoPoint::from_uniform_bytes(&extended)
}

/// Hash para challenge
fn hash_challenge(
    message: &[u8],
    l: &RistrettoPoint,
    r: &RistrettoPoint,
    key_image: &KeyImage,
) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update(message);
    hasher.update(l.compress().as_bytes());
    hasher.update(r.compress().as_bytes());
    hasher.update(&key_image.as_bytes());
    let hash = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order(&bytes)
}

// =============================================================================
// Display
// =============================================================================

/// Imprime información sobre ring signatures
pub fn print_ring_info() {
    println!("Ring Signature Configuration");
    println!("────────────────────────────");
    println!("  Default ring size:  {} (1 real + {} decoys)", DEFAULT_RING_SIZE, DEFAULT_RING_SIZE - 1);
    println!("  Minimum ring size:  {}", MIN_RING_SIZE);
    println!("  Maximum ring size:  {}", MAX_RING_SIZE);
    println!();
    println!("  Signature size (ring=11): ~{} bytes", 32 + 32 + 11 * 32);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    fn generate_keypair() -> (Scalar, CompressedPoint) {
        let private = Scalar::random();
        let public = CompressedPoint::from_point(
            &(private.inner() * GENERATORS.g)
        );
        (private, public)
    }
    
    #[test]
    fn test_key_image_unique() {
        let (sk1, pk1) = generate_keypair();
        let (sk2, pk2) = generate_keypair();
        
        let ki1 = KeyImage::generate(&sk1, &pk1);
        let ki2 = KeyImage::generate(&sk2, &pk2);
        
        // Key images deben ser diferentes para diferentes claves
        assert_ne!(ki1.as_bytes(), ki2.as_bytes());
        
        // Mismo key para misma clave
        let ki1_again = KeyImage::generate(&sk1, &pk1);
        assert_eq!(ki1.as_bytes(), ki1_again.as_bytes());
    }
    
    #[test]
    fn test_ring_signature() {
        // Generar anillo de 5 miembros
        let keypairs: Vec<_> = (0..5).map(|_| generate_keypair()).collect();
        let ring: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
        
        // Nosotros somos el índice 2
        let real_index = 2;
        let (our_sk, _) = &keypairs[real_index];
        
        let message = b"test message";
        
        // Firmar
        let sig = RingSignature::sign(message, &ring, our_sk, real_index).unwrap();
        
        // Verificar
        assert!(sig.verify(message, &ring).unwrap());
        
        // Mensaje diferente debe fallar
        assert!(!sig.verify(b"wrong message", &ring).unwrap());
    }
    
    #[test]
    fn test_ring_signature_different_positions() {
        // Probar firma en diferentes posiciones del anillo
        for real_index in 0..5 {
            let keypairs: Vec<_> = (0..5).map(|_| generate_keypair()).collect();
            let ring: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
            let (our_sk, _) = &keypairs[real_index];
            
            let sig = RingSignature::sign(b"test", &ring, our_sk, real_index).unwrap();
            assert!(sig.verify(b"test", &ring).unwrap());
        }
    }
    
    #[test]
    fn test_key_image_set() {
        let mut set = KeyImageSet::new();
        
        let (sk, pk) = generate_keypair();
        let ki = KeyImage::generate(&sk, &pk);
        
        // Primera inserción debe funcionar
        assert!(set.insert(&ki).is_ok());
        assert!(set.contains(&ki));
        
        // Segunda inserción debe fallar (double-spend)
        assert_eq!(set.insert(&ki), Err(RingError::DoubleSpend));
    }
    
    #[test]
    fn test_ring_too_small() {
        let keypairs: Vec<_> = (0..2).map(|_| generate_keypair()).collect();
        let ring: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
        let (our_sk, _) = &keypairs[0];
        
        let result = RingSignature::sign(b"test", &ring, our_sk, 0);
        assert_eq!(result, Err(RingError::RingTooSmall));
    }
    
    #[test]
    fn test_wrong_key() {
        let keypairs: Vec<_> = (0..5).map(|_| generate_keypair()).collect();
        let ring: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
        
        // Intentar firmar con clave incorrecta para la posición
        let (wrong_sk, _) = generate_keypair();
        
        let result = RingSignature::sign(b"test", &ring, &wrong_sk, 0);
        assert_eq!(result, Err(RingError::KeyMismatch));
    }
}
