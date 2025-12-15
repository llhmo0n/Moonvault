// =============================================================================
// MOONCOIN v2.0 - HD Wallet (BIP39/BIP32)
// =============================================================================

use std::fs;
use std::path::Path;
use bip39::{Mnemonic, MnemonicType, Language, Seed};
use hmac::{Hmac, Mac};
use sha2::{Sha512, Sha256, Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey};

const WALLET_FILE: &str = "wallet.dat";
const LEGACY_WALLET_FILE: &str = "wallet.key";

/// HD Wallet con soporte para múltiples direcciones
#[derive(Clone)]
pub struct HdWallet {
    /// Mnemonic (12 o 24 palabras)
    mnemonic: Mnemonic,
    /// Seed derivada del mnemonic
    seed: [u8; 64],
    /// Master private key
    master_key: [u8; 32],
    /// Master chain code
    chain_code: [u8; 32],
    /// Índice actual para derivación
    pub current_index: u32,
}

/// Información de una dirección derivada
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DerivedAddress {
    pub index: u32,
    pub address: String,
    pub path: String,
}

/// Datos guardados del wallet
#[derive(serde::Serialize, serde::Deserialize)]
struct WalletData {
    mnemonic_phrase: String,
    current_index: u32,
    addresses: Vec<DerivedAddress>,
}

impl HdWallet {
    /// Crea un nuevo wallet con mnemonic aleatorio (24 palabras)
    pub fn new() -> Result<Self, String> {
        Self::new_with_words(24)
    }
    
    /// Crea un nuevo wallet con número específico de palabras (12 o 24)
    pub fn new_with_words(word_count: usize) -> Result<Self, String> {
        let mtype = match word_count {
            12 => MnemonicType::Words12,
            24 => MnemonicType::Words24,
            _ => return Err("Word count must be 12 or 24".to_string()),
        };
        
        let mnemonic = Mnemonic::new(mtype, Language::English);
        Self::from_mnemonic(mnemonic)
    }
    
    /// Restaura un wallet desde una frase mnemonic
    pub fn from_phrase(phrase: &str) -> Result<Self, String> {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|e| format!("Invalid mnemonic: {:?}", e))?;
        
        Self::from_mnemonic(mnemonic)
    }
    
    /// Crea un wallet desde un Mnemonic
    fn from_mnemonic(mnemonic: Mnemonic) -> Result<Self, String> {
        // Derivar seed (BIP39)
        let seed_obj = Seed::new(&mnemonic, ""); // Sin passphrase
        let seed_bytes = seed_obj.as_bytes();
        
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&seed_bytes[..64]);
        
        // Derivar master key (BIP32)
        let (master_key, chain_code) = Self::derive_master_key(&seed)?;
        
        Ok(HdWallet {
            mnemonic,
            seed,
            master_key,
            chain_code,
            current_index: 0,
        })
    }
    
    /// Deriva la master key desde la seed (BIP32)
    fn derive_master_key(seed: &[u8; 64]) -> Result<([u8; 32], [u8; 32]), String> {
        type HmacSha512 = Hmac<Sha512>;
        
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
            .map_err(|_| "HMAC error")?;
        mac.update(seed);
        let result = mac.finalize().into_bytes();
        
        let mut master_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        
        master_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);
        
        Ok((master_key, chain_code))
    }
    
    /// Obtiene la frase mnemonic (¡GUARDAR EN LUGAR SEGURO!)
    pub fn get_phrase(&self) -> String {
        self.mnemonic.phrase().to_string()
    }
    
    /// Deriva una clave privada para un índice específico
    /// Usa derivación simplificada: SHA256(master_key || index)
    pub fn derive_private_key(&self, index: u32) -> Result<SecretKey, String> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.master_key);
        data.extend_from_slice(&self.chain_code);
        data.extend_from_slice(&index.to_be_bytes());
        
        let hash = Sha256::digest(&data);
        
        SecretKey::from_slice(&hash)
            .map_err(|e| format!("Invalid derived key: {}", e))
    }
    
    /// Deriva una clave pública para un índice específico
    pub fn derive_public_key(&self, index: u32) -> Result<PublicKey, String> {
        let secp = Secp256k1::new();
        let secret_key = self.derive_private_key(index)?;
        Ok(PublicKey::from_secret_key(&secp, &secret_key))
    }
    
    /// Deriva una dirección para un índice específico
    pub fn derive_address(&self, index: u32) -> Result<DerivedAddress, String> {
        let pubkey = self.derive_public_key(index)?;
        let address = pubkey_to_address(&pubkey);
        
        Ok(DerivedAddress {
            index,
            address,
            path: format!("m/44'/0'/0'/0/{}", index),
        })
    }
    
    /// Obtiene la dirección principal (índice 0)
    pub fn get_main_address(&self) -> Result<String, String> {
        Ok(self.derive_address(0)?.address)
    }
    
    /// Genera una nueva dirección (incrementa el índice)
    pub fn new_address(&mut self) -> Result<DerivedAddress, String> {
        let addr = self.derive_address(self.current_index)?;
        self.current_index += 1;
        Ok(addr)
    }
    
    /// Lista todas las direcciones derivadas hasta el índice actual
    pub fn list_addresses(&self) -> Result<Vec<DerivedAddress>, String> {
        let mut addresses = Vec::new();
        for i in 0..=self.current_index {
            addresses.push(self.derive_address(i)?);
        }
        Ok(addresses)
    }
    
    /// Obtiene la clave privada para firmar (dirección principal)
    pub fn get_signing_key(&self) -> Result<SecretKey, String> {
        self.derive_private_key(0)
    }
    
    /// Obtiene la clave privada para una dirección específica
    pub fn get_key_for_address(&self, address: &str) -> Result<Option<SecretKey>, String> {
        // Buscar en todas las direcciones derivadas
        for i in 0..=self.current_index + 100 {  // Buscar un poco más allá
            let derived = self.derive_address(i)?;
            if derived.address == address {
                return Ok(Some(self.derive_private_key(i)?));
            }
        }
        Ok(None)
    }
    
    /// Guarda el wallet a disco
    pub fn save(&self) -> Result<(), String> {
        let addresses = self.list_addresses()?;
        
        let data = WalletData {
            mnemonic_phrase: self.get_phrase(),
            current_index: self.current_index,
            addresses,
        };
        
        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| format!("Serialize error: {}", e))?;
        
        fs::write(WALLET_FILE, json)
            .map_err(|e| format!("Write error: {}", e))?;
        
        Ok(())
    }
    
    /// Carga el wallet desde disco
    pub fn load() -> Result<Option<Self>, String> {
        if !Path::new(WALLET_FILE).exists() {
            return Ok(None);
        }
        
        let json = fs::read_to_string(WALLET_FILE)
            .map_err(|e| format!("Read error: {}", e))?;
        
        let data: WalletData = serde_json::from_str(&json)
            .map_err(|e| format!("Parse error: {}", e))?;
        
        let mut wallet = Self::from_phrase(&data.mnemonic_phrase)?;
        wallet.current_index = data.current_index;
        
        Ok(Some(wallet))
    }
    
    /// Carga o crea un nuevo wallet
    pub fn load_or_create() -> Result<(Self, bool), String> {
        // Intentar cargar wallet existente
        if let Some(wallet) = Self::load()? {
            return Ok((wallet, false));
        }
        
        // Verificar si existe wallet legacy
        if Path::new(LEGACY_WALLET_FILE).exists() {
            println!("⚠️  Found legacy wallet (wallet.key)");
            println!("   Creating new HD wallet. Your old key remains in wallet.key");
            println!("   You may need to transfer funds to your new addresses.");
        }
        
        // Crear nuevo wallet
        let wallet = Self::new()?;
        wallet.save()?;
        
        Ok((wallet, true))
    }
}

// =============================================================================
// Funciones de utilidad
// =============================================================================

/// Convierte una clave pública a dirección Mooncoin
pub fn pubkey_to_address(pubkey: &PublicKey) -> String {
    use ripemd::Ripemd160;
    
    let pubkey_bytes = pubkey.serialize(); // 33 bytes (compressed)
    
    // SHA256
    let sha_hash = Sha256::digest(&pubkey_bytes);
    
    // RIPEMD160
    let ripe_hash = Ripemd160::digest(&sha_hash);
    
    // Agregar prefijo de versión (0x00 para mainnet, usamos 0x32 para 'M')
    let mut versioned = vec![0x32]; // 'M' en base58
    versioned.extend_from_slice(&ripe_hash);
    
    // Checksum (primeros 4 bytes del doble SHA256)
    let checksum_full = Sha256::digest(&Sha256::digest(&versioned));
    let checksum = &checksum_full[..4];
    
    // Concatenar y codificar en Base58
    versioned.extend_from_slice(checksum);
    bs58::encode(versioned).into_string()
}

/// Muestra información del wallet de forma segura
pub fn display_wallet_info(wallet: &HdWallet, show_phrase: bool) -> Result<(), String> {
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                    HD WALLET INFO                         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    if show_phrase {
        println!("  🔐 SEED PHRASE (KEEP SECRET!):");
        println!("  ┌─────────────────────────────────────────────────────────┐");
        let phrase = wallet.get_phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        for (i, chunk) in words.chunks(6).enumerate() {
            let line: Vec<String> = chunk.iter()
                .enumerate()
                .map(|(j, w)| format!("{}. {}", i * 6 + j + 1, w))
                .collect();
            println!("  │  {}  │", line.join("  "));
        }
        println!("  └─────────────────────────────────────────────────────────┘");
        println!();
        println!("  ⚠️  Write these words down and store safely!");
        println!("  ⚠️  Anyone with these words can access your funds!");
        println!();
    }
    
    println!("  📍 Main Address: {}", wallet.get_main_address()?);
    println!("  🔢 Derived Addresses: {}", wallet.current_index + 1);
    println!();
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_wallet() {
        let wallet = HdWallet::new_with_words(12).unwrap();
        let phrase = wallet.get_phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }
    
    #[test]
    fn test_restore_wallet() {
        let wallet1 = HdWallet::new_with_words(12).unwrap();
        let phrase = wallet1.get_phrase();
        let addr1 = wallet1.get_main_address().unwrap();
        
        let wallet2 = HdWallet::from_phrase(&phrase).unwrap();
        let addr2 = wallet2.get_main_address().unwrap();
        
        assert_eq!(addr1, addr2);
    }
    
    #[test]
    fn test_derive_addresses() {
        let wallet = HdWallet::new_with_words(12).unwrap();
        
        let addr0 = wallet.derive_address(0).unwrap();
        let addr1 = wallet.derive_address(1).unwrap();
        
        assert_ne!(addr0.address, addr1.address);
        assert!(addr0.address.starts_with("M"));
        assert!(addr1.address.starts_with("M"));
    }
}
