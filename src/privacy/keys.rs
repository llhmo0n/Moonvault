// =============================================================================
// MOONCOIN - Privacy Keys
// =============================================================================
//
// Gestión de claves para transacciones privadas:
// - ViewingKey: permite ver transacciones entrantes
// - SpendKey: permite gastar fondos
// - FullViewingKey: permite ver todas las transacciones
//
// Jerarquía de claves:
//   Master Seed
//       ├── View Key (b) → View Pubkey (B = b*G)
//       └── Spend Key (s) → Spend Pubkey (S = s*G)
//
// =============================================================================

use super::pedersen::{Scalar, CompressedPoint, GENERATORS};
use super::stealth::StealthAddress;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use rand::RngCore;

// =============================================================================
// View Key
// =============================================================================

/// Clave de viewing - permite ver transacciones entrantes
/// 
/// Con esta clave se puede:
/// - Escanear la blockchain para encontrar outputs propios
/// - Ver los montos recibidos (si están encriptados con ECDH)
/// - NO se puede gastar
/// 
/// Útil para:
/// - Auditorías (dar a auditor sin riesgo de pérdida)
/// - Watch-only wallets privados
/// - Servicios de notificación
#[derive(Clone, Debug)]
pub struct ViewingKey {
    /// Clave privada de viewing
    pub key: Scalar,
    /// Clave pública derivada
    pub pubkey: CompressedPoint,
}

impl ViewingKey {
    /// Genera una nueva viewing key aleatoria
    pub fn generate() -> Self {
        let key = Scalar::random();
        let pubkey = CompressedPoint::from_point(
            &(key.inner() * GENERATORS.g)
        );
        
        ViewingKey { key, pubkey }
    }
    
    /// Crea desde una clave privada existente
    pub fn from_scalar(key: Scalar) -> Self {
        let pubkey = CompressedPoint::from_point(
            &(key.inner() * GENERATORS.g)
        );
        
        ViewingKey { key, pubkey }
    }
    
    /// Deriva desde seed usando un path específico
    pub fn from_seed(seed: &[u8], path: &str) -> Self {
        let key = derive_key_from_seed(seed, path, "view");
        Self::from_scalar(key)
    }
    
    /// Exporta la viewing key (para compartir)
    pub fn export(&self) -> String {
        let bytes = self.key.as_bytes();
        format!("mvk{}", bs58::encode(&bytes).into_string())
    }
    
    /// Importa una viewing key
    pub fn import(s: &str) -> Option<Self> {
        if !s.starts_with("mvk") {
            return None;
        }
        
        let bytes = bs58::decode(&s[3..]).into_vec().ok()?;
        if bytes.len() != 32 {
            return None;
        }
        
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        
        let key = Scalar::from_canonical_bytes(&arr)?;
        Some(Self::from_scalar(key))
    }
}

// =============================================================================
// Spend Key
// =============================================================================

/// Clave de spending - permite gastar fondos
/// 
/// CRÍTICA: Esta clave permite gastar. Mantener segura.
#[derive(Clone)]
pub struct SpendKey {
    /// Clave privada de spending
    pub key: Scalar,
    /// Clave pública derivada
    pub pubkey: CompressedPoint,
}

impl SpendKey {
    /// Genera una nueva spend key aleatoria
    pub fn generate() -> Self {
        let key = Scalar::random();
        let pubkey = CompressedPoint::from_point(
            &(key.inner() * GENERATORS.g)
        );
        
        SpendKey { key, pubkey }
    }
    
    /// Crea desde una clave privada existente
    pub fn from_scalar(key: Scalar) -> Self {
        let pubkey = CompressedPoint::from_point(
            &(key.inner() * GENERATORS.g)
        );
        
        SpendKey { key, pubkey }
    }
    
    /// Deriva desde seed usando un path específico
    pub fn from_seed(seed: &[u8], path: &str) -> Self {
        let key = derive_key_from_seed(seed, path, "spend");
        Self::from_scalar(key)
    }
    
    /// Firma un mensaje (para autenticación)
    pub fn sign(&self, message: &[u8]) -> Signature {
        // Schnorr signature simplificada
        let k = Scalar::random();
        let r = CompressedPoint::from_point(&(k.inner() * GENERATORS.g));
        
        // e = H(R || P || m)
        let e = hash_for_signature(&r, &self.pubkey, message);
        
        // s = k + e * x
        let s = k.add(&e.mul(&self.key));
        
        Signature { r, s }
    }
    
    // NO implementar export por seguridad
    // La spend key solo debe salir encriptada en backups
}

impl std::fmt::Debug for SpendKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpendKey")
            .field("pubkey", &self.pubkey)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// Full Viewing Key
// =============================================================================

/// Full Viewing Key - permite ver TODAS las transacciones (entrantes Y salientes)
/// 
/// Combina viewing key con información adicional para trackear gastos.
#[derive(Clone, Debug)]
pub struct FullViewingKey {
    /// Viewing key
    pub view_key: ViewingKey,
    /// Clave pública de spending (para verificar ownership)
    pub spend_pubkey: CompressedPoint,
    /// Key image secret (permite ver gastos sin poder gastar)
    pub key_image_key: Scalar,
}

impl FullViewingKey {
    /// Crea desde view key y spend pubkey
    pub fn new(view_key: ViewingKey, spend_pubkey: CompressedPoint, spend_key: &SpendKey) -> Self {
        // Derivar key image key de forma determinística
        let key_image_key = derive_key_image_key(&spend_key.key);
        
        FullViewingKey {
            view_key,
            spend_pubkey,
            key_image_key,
        }
    }
    
    /// Exporta el FVK
    pub fn export(&self) -> String {
        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(&self.view_key.key.as_bytes());
        data.extend_from_slice(&self.spend_pubkey.as_bytes());
        data.extend_from_slice(&self.key_image_key.as_bytes());
        
        format!("mfvk{}", bs58::encode(&data).into_string())
    }
    
    /// Importa un FVK
    pub fn import(s: &str) -> Option<Self> {
        if !s.starts_with("mfvk") {
            return None;
        }
        
        let data = bs58::decode(&s[4..]).into_vec().ok()?;
        if data.len() != 96 {
            return None;
        }
        
        let mut view_bytes = [0u8; 32];
        let mut spend_bytes = [0u8; 32];
        let mut ki_bytes = [0u8; 32];
        
        view_bytes.copy_from_slice(&data[0..32]);
        spend_bytes.copy_from_slice(&data[32..64]);
        ki_bytes.copy_from_slice(&data[64..96]);
        
        let view_scalar = Scalar::from_canonical_bytes(&view_bytes)?;
        let spend_pubkey = CompressedPoint::from_bytes(&spend_bytes)?;
        let key_image_key = Scalar::from_canonical_bytes(&ki_bytes)?;
        
        Some(FullViewingKey {
            view_key: ViewingKey::from_scalar(view_scalar),
            spend_pubkey,
            key_image_key,
        })
    }
    
    /// Calcula key image para un output (permite detectar gastos)
    pub fn calculate_key_image(&self, one_time_private_derivation: &Scalar) -> CompressedPoint {
        // Key image: I = (H(ss) + s) * H_p(P)
        // Usando key_image_key en lugar de s
        let combined = one_time_private_derivation.add(&self.key_image_key);
        
        // H_p(P) - hash to point
        let mut hasher = Sha3_256::new();
        hasher.update(b"Mooncoin_KeyImage");
        hasher.update(&self.spend_pubkey.as_bytes());
        let hash = hasher.finalize();
        
        // Derivar punto
        let scalar = Scalar::from_bytes_mod_order(&hash.into());
        CompressedPoint::from_point(&(combined.inner() * scalar.inner() * GENERATORS.g))
    }
}

// =============================================================================
// Privacy Keys Bundle
// =============================================================================

/// Bundle completo de claves de privacidad
#[derive(Clone)]
pub struct PrivacyKeys {
    /// Viewing key
    pub view_key: ViewingKey,
    /// Spending key
    pub spend_key: SpendKey,
}

impl PrivacyKeys {
    /// Genera nuevas claves de privacidad
    pub fn generate() -> Self {
        PrivacyKeys {
            view_key: ViewingKey::generate(),
            spend_key: SpendKey::generate(),
        }
    }
    
    /// Deriva desde un seed (para integración con HD wallet)
    pub fn from_seed(seed: &[u8]) -> Self {
        let view_key = ViewingKey::from_seed(seed, "m/44'/0'/0'/0");
        let spend_key = SpendKey::from_seed(seed, "m/44'/0'/0'/1");
        
        PrivacyKeys { view_key, spend_key }
    }
    
    /// Obtiene la stealth address para recibir pagos
    pub fn stealth_address(&self) -> StealthAddress {
        StealthAddress::new(
            self.view_key.pubkey,
            self.spend_key.pubkey,
        )
    }
    
    /// Obtiene solo la viewing key (para compartir)
    pub fn viewing_key(&self) -> &ViewingKey {
        &self.view_key
    }
    
    /// Crea full viewing key
    pub fn full_viewing_key(&self) -> FullViewingKey {
        FullViewingKey::new(
            self.view_key.clone(),
            self.spend_key.pubkey,
            &self.spend_key,
        )
    }
    
    /// Encripta las claves con una contraseña
    pub fn encrypt(&self, password: &str) -> EncryptedPrivacyKeys {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        
        // Derivar clave de encriptación
        let key = derive_encryption_key(password, &salt);
        
        // Serializar claves
        let mut plaintext = Vec::with_capacity(64);
        plaintext.extend_from_slice(&self.view_key.key.as_bytes());
        plaintext.extend_from_slice(&self.spend_key.key.as_bytes());
        
        // Encriptar
        let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid key length");
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .expect("encryption failure");
        
        EncryptedPrivacyKeys {
            salt,
            nonce: nonce_bytes,
            ciphertext,
        }
    }
    
    /// Desencripta claves
    pub fn decrypt(encrypted: &EncryptedPrivacyKeys, password: &str) -> Option<Self> {
        let key = derive_encryption_key(password, &encrypted.salt);
        let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
        let nonce = Nonce::from_slice(&encrypted.nonce);
        
        let plaintext = cipher.decrypt(nonce, encrypted.ciphertext.as_ref()).ok()?;
        
        if plaintext.len() != 64 {
            return None;
        }
        
        let mut view_bytes = [0u8; 32];
        let mut spend_bytes = [0u8; 32];
        
        view_bytes.copy_from_slice(&plaintext[0..32]);
        spend_bytes.copy_from_slice(&plaintext[32..64]);
        
        let view_scalar = Scalar::from_canonical_bytes(&view_bytes)?;
        let spend_scalar = Scalar::from_canonical_bytes(&spend_bytes)?;
        
        Some(PrivacyKeys {
            view_key: ViewingKey::from_scalar(view_scalar),
            spend_key: SpendKey::from_scalar(spend_scalar),
        })
    }
}

impl std::fmt::Debug for PrivacyKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivacyKeys")
            .field("view_key", &self.view_key)
            .field("spend_key", &"[REDACTED]")
            .field("stealth_address", &self.stealth_address().encode())
            .finish()
    }
}

// =============================================================================
// Encrypted Keys
// =============================================================================

/// Claves encriptadas para almacenamiento
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedPrivacyKeys {
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

// =============================================================================
// Signature
// =============================================================================

/// Firma Schnorr simplificada
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub r: CompressedPoint,
    pub s: Scalar,
}

impl Signature {
    /// Verifica la firma
    pub fn verify(&self, pubkey: &CompressedPoint, message: &[u8]) -> bool {
        let p = match pubkey.decompress() {
            Some(p) => p,
            None => return false,
        };
        
        let r_point = match self.r.decompress() {
            Some(r) => r,
            None => return false,
        };
        
        // e = H(R || P || m)
        let e = hash_for_signature(&self.r, pubkey, message);
        
        // Verificar: s*G == R + e*P
        let left = self.s.inner() * GENERATORS.g;
        let right = r_point + e.inner() * p;
        
        left == right
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Deriva una clave desde seed
fn derive_key_from_seed(seed: &[u8], path: &str, key_type: &str) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(b"Mooncoin_PrivacyKey_Derivation");
    hasher.update(seed);
    hasher.update(path.as_bytes());
    hasher.update(key_type.as_bytes());
    let result = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Scalar::from_bytes_mod_order(&bytes)
}

/// Deriva key image key desde spend key
fn derive_key_image_key(spend_key: &Scalar) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(b"Mooncoin_KeyImage_Derivation");
    hasher.update(&spend_key.as_bytes());
    let result = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Scalar::from_bytes_mod_order(&bytes)
}

/// Hash para firma Schnorr
fn hash_for_signature(r: &CompressedPoint, pubkey: &CompressedPoint, message: &[u8]) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(b"Mooncoin_Schnorr_Signature");
    hasher.update(&r.as_bytes());
    hasher.update(&pubkey.as_bytes());
    hasher.update(message);
    let result = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Scalar::from_bytes_mod_order(&bytes)
}

/// Deriva clave de encriptación desde contraseña
fn derive_encryption_key(password: &str, salt: &[u8]) -> [u8; 32] {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        100_000,
        &mut key,
    );
    key
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_viewing_key_export_import() {
        let vk = ViewingKey::generate();
        let exported = vk.export();
        
        assert!(exported.starts_with("mvk"));
        
        let imported = ViewingKey::import(&exported).unwrap();
        
        assert_eq!(vk.key.as_bytes(), imported.key.as_bytes());
        assert_eq!(vk.pubkey.as_bytes(), imported.pubkey.as_bytes());
    }
    
    #[test]
    fn test_privacy_keys_generation() {
        let keys = PrivacyKeys::generate();
        
        // Verificar que la stealth address es válida
        let addr = keys.stealth_address();
        let encoded = addr.encode();
        
        assert!(encoded.starts_with("mzs"));
        
        let decoded = StealthAddress::decode(&encoded).unwrap();
        assert_eq!(addr.view_pubkey.as_bytes(), decoded.view_pubkey.as_bytes());
    }
    
    #[test]
    fn test_privacy_keys_encryption() {
        let keys = PrivacyKeys::generate();
        let password = "super_secret_password_123";
        
        let encrypted = keys.encrypt(password);
        
        // Desencriptar con contraseña correcta
        let decrypted = PrivacyKeys::decrypt(&encrypted, password).unwrap();
        
        assert_eq!(keys.view_key.key.as_bytes(), decrypted.view_key.key.as_bytes());
        assert_eq!(keys.spend_key.key.as_bytes(), decrypted.spend_key.key.as_bytes());
        
        // Contraseña incorrecta debe fallar
        let wrong = PrivacyKeys::decrypt(&encrypted, "wrong_password");
        assert!(wrong.is_none());
    }
    
    #[test]
    fn test_signature() {
        let spend_key = SpendKey::generate();
        let message = b"test message";
        
        let signature = spend_key.sign(message);
        
        // Verificar firma correcta
        assert!(signature.verify(&spend_key.pubkey, message));
        
        // Verificar mensaje incorrecto falla
        assert!(!signature.verify(&spend_key.pubkey, b"wrong message"));
        
        // Verificar clave incorrecta falla
        let other_key = SpendKey::generate();
        assert!(!signature.verify(&other_key.pubkey, message));
    }
    
    #[test]
    fn test_full_viewing_key() {
        let keys = PrivacyKeys::generate();
        let fvk = keys.full_viewing_key();
        
        let exported = fvk.export();
        assert!(exported.starts_with("mfvk"));
        
        let imported = FullViewingKey::import(&exported).unwrap();
        
        assert_eq!(fvk.view_key.key.as_bytes(), imported.view_key.key.as_bytes());
        assert_eq!(fvk.spend_pubkey.as_bytes(), imported.spend_pubkey.as_bytes());
    }
    
    #[test]
    fn test_derivation_from_seed() {
        let seed = b"test seed for key derivation";
        
        let keys1 = PrivacyKeys::from_seed(seed);
        let keys2 = PrivacyKeys::from_seed(seed);
        
        // Derivación debe ser determinística
        assert_eq!(keys1.view_key.key.as_bytes(), keys2.view_key.key.as_bytes());
        assert_eq!(keys1.spend_key.key.as_bytes(), keys2.spend_key.key.as_bytes());
        
        // Diferente seed = diferentes claves
        let keys3 = PrivacyKeys::from_seed(b"different seed");
        assert_ne!(keys1.view_key.key.as_bytes(), keys3.view_key.key.as_bytes());
    }
}
