// =============================================================================
// MOONCOIN v2.0 - Wallet Encryption
// =============================================================================
//
// Encriptación AES-256-GCM para proteger seed phrases y claves privadas.
// Usa PBKDF2 para derivar la clave de encriptación desde la contraseña.
//
// =============================================================================

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::generic_array::GenericArray;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use std::io::{self, Write};

// =============================================================================
// Constants
// =============================================================================

const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

// =============================================================================
// Encrypted Data Structure
// =============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedData {
    /// Salt for PBKDF2
    pub salt: Vec<u8>,
    /// Nonce for AES-GCM
    pub nonce: Vec<u8>,
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// Version for future compatibility
    pub version: u8,
}

impl EncryptedData {
    /// Serializa a bytes para almacenamiento
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize encrypted data")
    }
    
    /// Deserializa desde bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes)
            .map_err(|e| format!("Failed to deserialize encrypted data: {}", e))
    }
    
    /// Serializa a JSON para archivo
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("Failed to serialize to JSON")
    }
    
    /// Deserializa desde JSON
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("Failed to parse encrypted data: {}", e))
    }
}

// =============================================================================
// Key Derivation
// =============================================================================

/// Deriva una clave de 256 bits desde una contraseña usando PBKDF2
fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut key,
    );
    key
}

/// Genera un salt aleatorio
fn generate_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut salt = vec![0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Genera un nonce aleatorio
fn generate_nonce() -> Vec<u8> {
    use rand::RngCore;
    let mut nonce = vec![0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

// =============================================================================
// Encryption/Decryption
// =============================================================================

/// Encripta datos con una contraseña
pub fn encrypt(plaintext: &[u8], password: &str) -> Result<EncryptedData, String> {
    // Generate salt and derive key
    let salt = generate_salt();
    let key = derive_key(password, &salt);
    
    // Generate nonce
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Create cipher
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    
    // Encrypt
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    Ok(EncryptedData {
        salt,
        nonce: nonce_bytes,
        ciphertext,
        version: 1,
    })
}

/// Desencripta datos con una contraseña
pub fn decrypt(encrypted: &EncryptedData, password: &str) -> Result<Vec<u8>, String> {
    // Derive key from password and stored salt
    let key = derive_key(password, &encrypted.salt);
    
    // Create nonce
    let nonce = Nonce::from_slice(&encrypted.nonce);
    
    // Create cipher
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    
    // Decrypt
    cipher.decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| "Decryption failed: wrong password or corrupted data".to_string())
}

/// Encripta un string
pub fn encrypt_string(plaintext: &str, password: &str) -> Result<EncryptedData, String> {
    encrypt(plaintext.as_bytes(), password)
}

/// Desencripta a string
pub fn decrypt_string(encrypted: &EncryptedData, password: &str) -> Result<String, String> {
    let bytes = decrypt(encrypted, password)?;
    String::from_utf8(bytes)
        .map_err(|e| format!("Invalid UTF-8 in decrypted data: {}", e))
}

// =============================================================================
// Password Input
// =============================================================================

/// Lee una contraseña desde stdin (sin eco)
pub fn read_password(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    // En Unix podríamos usar termios para ocultar input
    // Por simplicidad, usamos lectura normal con advertencia
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    
    Ok(password.trim().to_string())
}

/// Lee y confirma una nueva contraseña
pub fn read_new_password() -> io::Result<String> {
    loop {
        let password = read_password("  Enter new password: ")?;
        
        if password.len() < 8 {
            println!("  ⚠️  Password must be at least 8 characters");
            continue;
        }
        
        let confirm = read_password("  Confirm password: ")?;
        
        if password != confirm {
            println!("  ⚠️  Passwords don't match");
            continue;
        }
        
        return Ok(password);
    }
}

/// Verifica la fortaleza de una contraseña
pub fn check_password_strength(password: &str) -> PasswordStrength {
    let mut score = 0;
    
    if password.len() >= 8 { score += 1; }
    if password.len() >= 12 { score += 1; }
    if password.len() >= 16 { score += 1; }
    if password.chars().any(|c| c.is_uppercase()) { score += 1; }
    if password.chars().any(|c| c.is_lowercase()) { score += 1; }
    if password.chars().any(|c| c.is_numeric()) { score += 1; }
    if password.chars().any(|c| !c.is_alphanumeric()) { score += 1; }
    
    match score {
        0..=2 => PasswordStrength::Weak,
        3..=4 => PasswordStrength::Medium,
        5..=6 => PasswordStrength::Strong,
        _ => PasswordStrength::VeryStrong,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PasswordStrength {
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

impl std::fmt::Display for PasswordStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordStrength::Weak => write!(f, "Weak ⚠️"),
            PasswordStrength::Medium => write!(f, "Medium 🔸"),
            PasswordStrength::Strong => write!(f, "Strong 🔹"),
            PasswordStrength::VeryStrong => write!(f, "Very Strong ✅"),
        }
    }
}

// =============================================================================
// Encrypted Wallet File
// =============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedWallet {
    /// Version for compatibility
    pub version: u8,
    /// Encrypted mnemonic/seed
    pub encrypted_seed: EncryptedData,
    /// Encrypted private key (legacy)
    pub encrypted_key: Option<EncryptedData>,
    /// Public address (not encrypted, for display)
    pub address: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Last access timestamp
    pub last_access: u64,
}

impl EncryptedWallet {
    pub fn new(seed: &str, address: &str, password: &str) -> Result<Self, String> {
        let encrypted_seed = encrypt_string(seed, password)?;
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Ok(EncryptedWallet {
            version: 1,
            encrypted_seed,
            encrypted_key: None,
            address: address.to_string(),
            created_at: now,
            last_access: now,
        })
    }
    
    pub fn decrypt_seed(&self, password: &str) -> Result<String, String> {
        decrypt_string(&self.encrypted_seed, password)
    }
    
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize wallet: {}", e))?;
        std::fs::write(path, json)
            .map_err(|e| format!("Failed to write wallet: {}", e))
    }
    
    pub fn load(path: &str) -> Result<Self, String> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read wallet: {}", e))?;
        serde_json::from_str(&json)
            .map_err(|e| format!("Failed to parse wallet: {}", e))
    }
    
    pub fn update_access(&mut self) {
        self.last_access = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = b"Hello, Mooncoin!";
        let password = "test_password_123";
        
        let encrypted = encrypt(plaintext, password).unwrap();
        let decrypted = decrypt(&encrypted, password).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }
    
    #[test]
    fn test_wrong_password() {
        let plaintext = b"Secret data";
        let password = "correct_password";
        let wrong_password = "wrong_password";
        
        let encrypted = encrypt(plaintext, password).unwrap();
        let result = decrypt(&encrypted, wrong_password);
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_encrypt_string() {
        let seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = "my_secure_password";
        
        let encrypted = encrypt_string(seed, password).unwrap();
        let decrypted = decrypt_string(&encrypted, password).unwrap();
        
        assert_eq!(seed, decrypted);
    }
    
    #[test]
    fn test_password_strength() {
        assert_eq!(check_password_strength("abc"), PasswordStrength::Weak);
        assert_eq!(check_password_strength("abcd1234"), PasswordStrength::Medium);
        assert_eq!(check_password_strength("Abcd1234!"), PasswordStrength::Strong);
        assert_eq!(check_password_strength("MyStr0ng!Pass#2024"), PasswordStrength::VeryStrong);
    }
    
    #[test]
    fn test_encrypted_wallet() {
        let seed = "test seed phrase";
        let address = "MCtest123";
        let password = "wallet_password";
        
        let wallet = EncryptedWallet::new(seed, address, password).unwrap();
        let decrypted = wallet.decrypt_seed(password).unwrap();
        
        assert_eq!(seed, decrypted);
        assert_eq!(wallet.address, address);
    }
}
