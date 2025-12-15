// =============================================================================
// MOONCOIN v2.0 - Wallet (ECDSA secp256k1)
// =============================================================================

use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use secp256k1::ecdsa::Signature;
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use std::fs;

use crate::lib::{WALLET_FILE, ADDRESS_VERSION};
use crate::transaction::{Tx, tx_serialize_for_signing};

/// Carga o crea una clave privada
pub fn load_or_create_key() -> SecretKey {
    if let Ok(data) = fs::read(WALLET_FILE) {
        if data.len() == 32 {
            SecretKey::from_slice(&data).expect("Invalid key in wallet file")
        } else {
            create_new_key()
        }
    } else {
        create_new_key()
    }
}

/// Crea una nueva clave privada y la guarda
fn create_new_key() -> SecretKey {
    let secp = Secp256k1::new();
    let (sk, _pk) = secp.generate_keypair(&mut rand::thread_rng());
    fs::write(WALLET_FILE, sk.secret_bytes()).expect("Failed to save wallet key");
    log::info!("Nueva wallet creada: {}", WALLET_FILE);
    sk
}

/// Obtiene la clave pública desde la privada
pub fn get_pubkey(sk: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, sk)
}

/// Deriva la dirección desde una clave pública (Bitcoin-style)
/// SHA256 -> RIPEMD160 -> Version + Checksum -> Base58
pub fn get_address(pubkey: &PublicKey) -> String {
    // 1. Serializar pubkey (compressed, 33 bytes)
    let pk_bytes = pubkey.serialize();
    
    // 2. SHA256
    let sha_hash = Sha256::digest(&pk_bytes);
    
    // 3. RIPEMD160
    let ripemd_hash = Ripemd160::digest(&sha_hash);
    
    // 4. Agregar version byte
    let mut versioned = vec![ADDRESS_VERSION];
    versioned.extend_from_slice(&ripemd_hash);
    
    // 5. Calcular checksum (double SHA256, primeros 4 bytes)
    let checksum_full = Sha256::digest(&Sha256::digest(&versioned));
    let checksum = &checksum_full[0..4];
    
    // 6. Concatenar version + hash + checksum
    versioned.extend_from_slice(checksum);
    
    // 7. Base58 encode
    let b58 = bs58::encode(&versioned).into_string();
    
    // 8. Agregar prefijo "MC"
    format!("MC{}", b58)
}

/// Verifica que una address sea válida
pub fn validate_address(address: &str) -> bool {
    if !address.starts_with("MC") || address.len() < 26 {
        return false;
    }
    
    let without_prefix = &address[2..];
    
    if let Ok(decoded) = bs58::decode(without_prefix).into_vec() {
        if decoded.len() != 25 {
            return false;
        }
        
        // Verificar checksum
        let payload = &decoded[0..21];
        let checksum = &decoded[21..25];
        
        let checksum_calc = Sha256::digest(&Sha256::digest(payload));
        &checksum_calc[0..4] == checksum
    } else {
        false
    }
}

/// Firma una transacción con la clave privada
pub fn sign_tx(tx: &mut Tx, sk: &SecretKey) {
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, sk);
    let pk_bytes = pubkey.serialize().to_vec();
    
    // Serializar tx para firmar (sin firmas previas)
    let msg_bytes = tx_serialize_for_signing(tx);
    
    // Double SHA256 para el mensaje
    let first_hash = Sha256::digest(&msg_bytes);
    let digest = Sha256::digest(&first_hash);
    
    // Crear Message para secp256k1
    let msg = Message::from_digest_slice(&digest)
        .expect("Invalid digest for secp256k1 message");
    
    // Firmar
    let sig = secp.sign_ecdsa(&msg, sk);
    let sig_der = sig.serialize_der().to_vec();
    
    // Insertar firma y pubkey en todos los inputs
    for inp in &mut tx.inputs {
        inp.signature = sig_der.clone();
        inp.pubkey = pk_bytes.clone();
    }
}

/// Verifica la firma de un input
pub fn verify_signature(tx: &Tx, input_index: usize) -> bool {
    if input_index >= tx.inputs.len() {
        return false;
    }
    
    let inp = &tx.inputs[input_index];
    
    // Coinbase no tiene firma real
    if tx.is_coinbase() {
        return true;
    }
    
    if inp.signature.is_empty() || inp.pubkey.is_empty() {
        return false;
    }
    
    let secp = Secp256k1::verification_only();
    
    // Parsear pubkey
    let pubkey = match PublicKey::from_slice(&inp.pubkey) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    
    // Parsear firma
    let sig = match Signature::from_der(&inp.signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    
    // Reconstruir mensaje para verificar
    let msg_bytes = tx_serialize_for_signing(tx);
    let first_hash = Sha256::digest(&msg_bytes);
    let digest = Sha256::digest(&first_hash);
    
    let msg = match Message::from_digest_slice(&digest) {
        Ok(m) => m,
        Err(_) => return false,
    };
    
    // Verificar
    secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok()
}

/// Deriva la address desde una pubkey serializada
pub fn address_from_pubkey_bytes(pubkey_bytes: &[u8]) -> Option<String> {
    if let Ok(pubkey) = PublicKey::from_slice(pubkey_bytes) {
        Some(get_address(&pubkey))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{TxIn, TxOut};

    #[test]
    fn test_address_derivation() {
        let secp = Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());
        let pk = get_pubkey(&sk);
        let addr = get_address(&pk);
        
        assert!(addr.starts_with("MC"));
        assert!(validate_address(&addr));
    }

    #[test]
    fn test_sign_and_verify() {
        let secp = Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());
        
        let mut tx = Tx {
            inputs: vec![TxIn {
                prev_tx_hash: "abc123".to_string(),
                prev_index: 0,
                signature: vec![],
                pubkey: vec![],
            }],
            outputs: vec![TxOut {
                to: "MCtest".to_string(),
                amount: 100,
            }],
        };
        
        sign_tx(&mut tx, &sk);
        assert!(verify_signature(&tx, 0));
    }
}
