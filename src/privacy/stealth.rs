// =============================================================================
// MOONCOIN - Stealth Addresses
// =============================================================================
//
// Implementación de Stealth Addresses para ocultar el receptor de una TX.
//
// Protocolo (DKSAP - Dual-Key Stealth Address Protocol):
//
// SETUP (receptor):
//   - Genera (b, B) para viewing: B = b*G
//   - Genera (s, S) para spending: S = s*G
//   - Publica stealth meta-address: (B, S)
//
// ENVÍO (emisor):
//   1. Obtiene meta-address (B, S)
//   2. Genera efímero: (r, R) donde R = r*G
//   3. Calcula shared secret: ss = H(r*B)
//   4. Deriva one-time pubkey: P = H(ss)*G + S
//   5. Envía a dirección derivada de P
//   6. Incluye R en la TX
//
// ESCANEO (receptor):
//   1. Ve R en cada TX
//   2. Calcula: ss' = H(b*R)
//   3. Deriva: P' = H(ss')*G + S
//   4. Si P' == dirección del output → es suyo
//
// GASTO (receptor):
//   - Clave privada one-time: p = H(ss') + s
//
// =============================================================================

use super::pedersen::{Scalar, CompressedPoint, GENERATORS};
use curve25519_dalek::ristretto::RistrettoPoint;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};

// =============================================================================
// Constants
// =============================================================================

/// Prefijo para direcciones stealth
pub const STEALTH_ADDRESS_PREFIX: &str = "mzs";

/// Longitud del view tag (para optimizar escaneo)
pub const VIEW_TAG_LENGTH: usize = 1;

// =============================================================================
// Stealth Meta-Address
// =============================================================================

/// Stealth Meta-Address: dirección pública que otros usan para derivar
/// direcciones one-time únicas.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthAddress {
    /// Clave pública de viewing: B = b*G
    pub view_pubkey: CompressedPoint,
    /// Clave pública de spending: S = s*G
    pub spend_pubkey: CompressedPoint,
}

impl StealthAddress {
    /// Crea una stealth address desde claves públicas
    pub fn new(view_pubkey: CompressedPoint, spend_pubkey: CompressedPoint) -> Self {
        StealthAddress {
            view_pubkey,
            spend_pubkey,
        }
    }
    
    /// Crea desde keypairs privados
    pub fn from_private_keys(view_key: &Scalar, spend_key: &Scalar) -> Self {
        let view_pubkey = CompressedPoint::from_point(
            &(view_key.inner() * GENERATORS.g)
        );
        let spend_pubkey = CompressedPoint::from_point(
            &(spend_key.inner() * GENERATORS.g)
        );
        
        StealthAddress {
            view_pubkey,
            spend_pubkey,
        }
    }
    
    /// Codifica la stealth address como string
    pub fn encode(&self) -> String {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&self.view_pubkey.as_bytes());
        data.extend_from_slice(&self.spend_pubkey.as_bytes());
        
        // Agregar checksum
        let checksum = Self::calculate_checksum(&data);
        data.extend_from_slice(&checksum[..4]);
        
        format!("{}{}", STEALTH_ADDRESS_PREFIX, bs58::encode(&data).into_string())
    }
    
    /// Decodifica una stealth address desde string
    pub fn decode(s: &str) -> Option<Self> {
        if !s.starts_with(STEALTH_ADDRESS_PREFIX) {
            return None;
        }
        
        let data_str = &s[STEALTH_ADDRESS_PREFIX.len()..];
        let data = bs58::decode(data_str).into_vec().ok()?;
        
        if data.len() != 68 {
            return None;
        }
        
        // Verificar checksum
        let checksum = Self::calculate_checksum(&data[..64]);
        if &checksum[..4] != &data[64..68] {
            return None;
        }
        
        let mut view_bytes = [0u8; 32];
        let mut spend_bytes = [0u8; 32];
        
        view_bytes.copy_from_slice(&data[0..32]);
        spend_bytes.copy_from_slice(&data[32..64]);
        
        let view_pubkey = CompressedPoint::from_bytes(&view_bytes)?;
        let spend_pubkey = CompressedPoint::from_bytes(&spend_bytes)?;
        
        Some(StealthAddress {
            view_pubkey,
            spend_pubkey,
        })
    }
    
    /// Calcula checksum SHA3
    fn calculate_checksum(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Mooncoin_StealthAddress_Checksum");
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }
}

// =============================================================================
// Ephemeral Key
// =============================================================================

/// Clave efímera generada por el emisor
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphemeralKey {
    /// Clave pública: R = r*G
    pub public: CompressedPoint,
    /// Clave privada: r (solo conocida por el emisor)
    #[serde(skip_serializing)]
    pub private: Option<Scalar>,
}

impl EphemeralKey {
    /// Genera un nuevo par efímero
    pub fn generate() -> Self {
        let private = Scalar::random();
        let public = CompressedPoint::from_point(
            &(private.inner() * GENERATORS.g)
        );
        
        EphemeralKey {
            public,
            private: Some(private),
        }
    }
    
    /// Crea solo desde parte pública (para receptor/verificador)
    pub fn from_public(public: CompressedPoint) -> Self {
        EphemeralKey {
            public,
            private: None,
        }
    }
}

// =============================================================================
// Stealth Payment
// =============================================================================

/// Pago stealth: información necesaria para enviar a una stealth address
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthPayment {
    /// Clave pública one-time derivada: P = H(ss)*G + S
    pub one_time_pubkey: CompressedPoint,
    /// Clave efímera pública: R (incluida en TX)
    pub ephemeral_pubkey: CompressedPoint,
    /// View tag (primer byte del shared secret, para optimizar escaneo)
    pub view_tag: u8,
    /// Shared secret (solo para el emisor, no se transmite)
    #[serde(skip)]
    pub shared_secret: Option<[u8; 32]>,
}

impl StealthPayment {
    /// Crea un pago stealth para una stealth address
    /// 
    /// Llamado por el EMISOR
    pub fn create(stealth_addr: &StealthAddress) -> Option<Self> {
        // 1. Generar clave efímera
        let ephemeral = EphemeralKey::generate();
        let r = ephemeral.private?;
        
        // 2. Calcular shared secret: ss = H(r * B)
        let b_point = stealth_addr.view_pubkey.decompress()?;
        let shared_point = r.inner() * b_point;
        let shared_secret = Self::derive_shared_secret(&shared_point);
        
        // 3. Derivar one-time pubkey: P = H(ss)*G + S
        let ss_scalar = Scalar::from_bytes_mod_order(&shared_secret);
        let s_point = stealth_addr.spend_pubkey.decompress()?;
        let one_time_point = ss_scalar.inner() * GENERATORS.g + s_point;
        
        // 4. Calcular view tag (primer byte del shared secret)
        let view_tag = shared_secret[0];
        
        Some(StealthPayment {
            one_time_pubkey: CompressedPoint::from_point(&one_time_point),
            ephemeral_pubkey: ephemeral.public,
            view_tag,
            shared_secret: Some(shared_secret),
        })
    }
    
    /// Verifica si este pago es para nosotros (receptor)
    /// 
    /// Llamado por el RECEPTOR durante escaneo
    pub fn check_ownership(
        ephemeral_pubkey: &CompressedPoint,
        one_time_pubkey: &CompressedPoint,
        view_key: &Scalar,
        spend_pubkey: &CompressedPoint,
    ) -> Option<OwnedStealthOutput> {
        // 1. Calcular shared secret: ss' = H(b * R)
        let r_point = ephemeral_pubkey.decompress()?;
        let shared_point = view_key.inner() * r_point;
        let shared_secret = Self::derive_shared_secret(&shared_point);
        
        // 2. Derivar expected one-time pubkey: P' = H(ss')*G + S
        let ss_scalar = Scalar::from_bytes_mod_order(&shared_secret);
        let s_point = spend_pubkey.decompress()?;
        let expected_point = ss_scalar.inner() * GENERATORS.g + s_point;
        let expected_pubkey = CompressedPoint::from_point(&expected_point);
        
        // 3. Comparar con one_time_pubkey
        if expected_pubkey.as_bytes() != one_time_pubkey.as_bytes() {
            return None;
        }
        
        // Es nuestro! Retornar información para gastar
        Some(OwnedStealthOutput {
            one_time_pubkey: *one_time_pubkey,
            shared_secret,
            // La clave privada se calculará cuando se necesite gastar
            one_time_private_derivation: ss_scalar,
        })
    }
    
    /// Verifica rápida usando view tag (optimización)
    pub fn quick_check_view_tag(
        ephemeral_pubkey: &CompressedPoint,
        view_key: &Scalar,
        expected_view_tag: u8,
    ) -> bool {
        if let Some(r_point) = ephemeral_pubkey.decompress() {
            let shared_point = view_key.inner() * r_point;
            let shared_secret = Self::derive_shared_secret(&shared_point);
            shared_secret[0] == expected_view_tag
        } else {
            false
        }
    }
    
    /// Deriva el shared secret desde un punto
    fn derive_shared_secret(point: &RistrettoPoint) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Mooncoin_StealthPayment_SharedSecret");
        hasher.update(point.compress().as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        bytes
    }
}

// =============================================================================
// Owned Stealth Output
// =============================================================================

/// Output stealth que nos pertenece (resultado del escaneo)
#[derive(Clone, Debug)]
pub struct OwnedStealthOutput {
    /// Clave pública one-time
    pub one_time_pubkey: CompressedPoint,
    /// Shared secret (para derivar la clave privada)
    pub shared_secret: [u8; 32],
    /// Scalar derivado del shared secret
    pub one_time_private_derivation: Scalar,
}

impl OwnedStealthOutput {
    /// Calcula la clave privada one-time para gastar este output
    /// 
    /// one_time_private = H(ss) + spend_key
    pub fn derive_spending_key(&self, spend_key: &Scalar) -> Scalar {
        self.one_time_private_derivation.add(spend_key)
    }
    
    /// Verifica que la clave privada corresponde a la pública
    pub fn verify_key(&self, spend_key: &Scalar) -> bool {
        let private_key = self.derive_spending_key(spend_key);
        let expected_pubkey = CompressedPoint::from_point(
            &(private_key.inner() * GENERATORS.g)
        );
        expected_pubkey.as_bytes() == self.one_time_pubkey.as_bytes()
    }
}

// =============================================================================
// Stealth Scanner
// =============================================================================

/// Escáner de outputs stealth
pub struct StealthScanner {
    /// Clave de viewing
    view_key: Scalar,
    /// Clave pública de spending
    spend_pubkey: CompressedPoint,
}

impl StealthScanner {
    /// Crea un nuevo escáner
    pub fn new(view_key: Scalar, spend_pubkey: CompressedPoint) -> Self {
        StealthScanner {
            view_key,
            spend_pubkey,
        }
    }
    
    /// Escanea un output para ver si nos pertenece
    pub fn scan_output(
        &self,
        ephemeral_pubkey: &CompressedPoint,
        one_time_pubkey: &CompressedPoint,
        view_tag: Option<u8>,
    ) -> Option<OwnedStealthOutput> {
        // Optimización: verificar view tag primero
        if let Some(tag) = view_tag {
            if !StealthPayment::quick_check_view_tag(ephemeral_pubkey, &self.view_key, tag) {
                return None;
            }
        }
        
        // Verificación completa
        StealthPayment::check_ownership(
            ephemeral_pubkey,
            one_time_pubkey,
            &self.view_key,
            &self.spend_pubkey,
        )
    }
    
    /// Escanea múltiples outputs
    pub fn scan_outputs(
        &self,
        outputs: &[(CompressedPoint, CompressedPoint, Option<u8>)], // (ephemeral, one_time, view_tag)
    ) -> Vec<(usize, OwnedStealthOutput)> {
        outputs.iter()
            .enumerate()
            .filter_map(|(i, (eph, otp, tag))| {
                self.scan_output(eph, otp, *tag)
                    .map(|owned| (i, owned))
            })
            .collect()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stealth_address_encode_decode() {
        let view_key = Scalar::random();
        let spend_key = Scalar::random();
        
        let addr = StealthAddress::from_private_keys(&view_key, &spend_key);
        let encoded = addr.encode();
        
        assert!(encoded.starts_with(STEALTH_ADDRESS_PREFIX));
        
        let decoded = StealthAddress::decode(&encoded).unwrap();
        
        assert_eq!(addr.view_pubkey.as_bytes(), decoded.view_pubkey.as_bytes());
        assert_eq!(addr.spend_pubkey.as_bytes(), decoded.spend_pubkey.as_bytes());
    }
    
    #[test]
    fn test_stealth_payment_flow() {
        // 1. Receptor genera stealth address
        let view_key = Scalar::random();
        let spend_key = Scalar::random();
        let stealth_addr = StealthAddress::from_private_keys(&view_key, &spend_key);
        
        // 2. Emisor crea pago stealth
        let payment = StealthPayment::create(&stealth_addr).unwrap();
        
        // 3. Receptor escanea y encuentra el pago
        let owned = StealthPayment::check_ownership(
            &payment.ephemeral_pubkey,
            &payment.one_time_pubkey,
            &view_key,
            &stealth_addr.spend_pubkey,
        ).expect("Should find owned output");
        
        // 4. Verificar que puede gastar
        assert!(owned.verify_key(&spend_key));
    }
    
    #[test]
    fn test_stealth_scanner() {
        // Setup
        let view_key = Scalar::random();
        let spend_key = Scalar::random();
        let stealth_addr = StealthAddress::from_private_keys(&view_key, &spend_key);
        let spend_pubkey = stealth_addr.spend_pubkey;
        
        // Crear múltiples pagos (solo uno para nosotros)
        let our_payment = StealthPayment::create(&stealth_addr).unwrap();
        
        // Crear pago para otra persona
        let other_view = Scalar::random();
        let other_spend = Scalar::random();
        let other_addr = StealthAddress::from_private_keys(&other_view, &other_spend);
        let other_payment = StealthPayment::create(&other_addr).unwrap();
        
        // Escanear
        let scanner = StealthScanner::new(view_key, spend_pubkey);
        
        let outputs = vec![
            (other_payment.ephemeral_pubkey, other_payment.one_time_pubkey, Some(other_payment.view_tag)),
            (our_payment.ephemeral_pubkey, our_payment.one_time_pubkey, Some(our_payment.view_tag)),
        ];
        
        let found = scanner.scan_outputs(&outputs);
        
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 1); // Segundo output es nuestro
    }
    
    #[test]
    fn test_view_tag_optimization() {
        let view_key = Scalar::random();
        let spend_key = Scalar::random();
        let stealth_addr = StealthAddress::from_private_keys(&view_key, &spend_key);
        
        let payment = StealthPayment::create(&stealth_addr).unwrap();
        
        // View tag correcto
        assert!(StealthPayment::quick_check_view_tag(
            &payment.ephemeral_pubkey,
            &view_key,
            payment.view_tag,
        ));
        
        // View tag incorrecto
        assert!(!StealthPayment::quick_check_view_tag(
            &payment.ephemeral_pubkey,
            &view_key,
            payment.view_tag.wrapping_add(1),
        ));
    }
    
    #[test]
    fn test_spending_key_derivation() {
        let view_key = Scalar::random();
        let spend_key = Scalar::random();
        let stealth_addr = StealthAddress::from_private_keys(&view_key, &spend_key);
        
        let payment = StealthPayment::create(&stealth_addr).unwrap();
        
        let owned = StealthPayment::check_ownership(
            &payment.ephemeral_pubkey,
            &payment.one_time_pubkey,
            &view_key,
            &stealth_addr.spend_pubkey,
        ).unwrap();
        
        // Derivar clave de gasto
        let spending_key = owned.derive_spending_key(&spend_key);
        
        // Verificar que corresponde
        let derived_pubkey = CompressedPoint::from_point(
            &(spending_key.inner() * GENERATORS.g)
        );
        
        assert_eq!(derived_pubkey.as_bytes(), payment.one_time_pubkey.as_bytes());
    }
}
