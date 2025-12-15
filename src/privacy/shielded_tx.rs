// =============================================================================
// MOONCOIN v2.25 - Shielded Transactions
// =============================================================================
//
// Transacciones privadas que integran todas las primitivas:
// - Pedersen Commitments (ocultar montos)
// - Range Proofs (probar validez)
// - Ring Signatures (ocultar emisor)
// - Stealth Addresses (ocultar receptor)
//
// Tipos de transacción:
// - Type 0: Transparent → Transparent (legacy, compatible)
// - Type 1: Transparent → Shielded (shielding/entrada al pool privado)
// - Type 2: Shielded → Shielded (full privacy)
// - Type 3: Shielded → Transparent (unshielding/salida del pool)
//
// =============================================================================

use crate::privacy::pedersen::{PedersenCommitment, Scalar, CompressedPoint, GENERATORS};
use crate::privacy::rangeproof::RangeProof;
use crate::privacy::ring::{RingSignature, KeyImage, RingError};
use crate::privacy::stealth::EphemeralKey;
use crate::transaction::{Tx, TxIn, TxOut};

use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;

// =============================================================================
// Constants
// =============================================================================

/// Versión de TX shielded
pub const SHIELDED_TX_VERSION: u8 = 2;

/// Tamaño del ring por defecto
pub const DEFAULT_RING_SIZE: usize = 11;

/// Fee mínimo para TX shielded (más grandes que transparentes)
pub const MIN_SHIELDED_FEE: u64 = 1000; // 0.00001 MOON

/// Máximo de inputs shielded por TX
pub const MAX_SHIELDED_INPUTS: usize = 16;

/// Máximo de outputs shielded por TX
pub const MAX_SHIELDED_OUTPUTS: usize = 16;

// =============================================================================
// Shielded Output
// =============================================================================

/// Output shielded (privado)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedOutput {
    /// Commitment al monto: C = v*H + r*G
    pub commitment: PedersenCommitment,
    
    /// Range proof (prueba que v ∈ [0, 2^64))
    pub range_proof: RangeProof,
    
    /// Clave pública efímera (R) para ECDH
    pub ephemeral_pubkey: CompressedPoint,
    
    /// Clave pública one-time (P) derivada via stealth
    pub one_time_pubkey: CompressedPoint,
    
    /// View tag (primer byte de shared secret, para escaneo rápido)
    pub view_tag: u8,
    
    /// Datos encriptados (monto, blinding factor, memo)
    pub encrypted_data: EncryptedOutputData,
}

impl ShieldedOutput {
    /// Crea un nuevo output shielded
    pub fn new(
        amount: u64,
        recipient_view_pubkey: &CompressedPoint,
        recipient_spend_pubkey: &CompressedPoint,
        memo: Option<&[u8]>,
    ) -> Result<(Self, OutputSecrets), ShieldedTxError> {
        // 1. Generar blinding factor aleatorio
        let blinding = Scalar::random();
        
        // 2. Crear commitment
        let commitment = PedersenCommitment::commit(amount, blinding);
        
        // 3. Crear range proof
        let range_proof = RangeProof::create(amount, blinding)
            .map_err(|_| ShieldedTxError::RangeProofError)?;
        
        // 4. Generar clave efímera
        let ephemeral = EphemeralKey::generate();
        let ephemeral_private = ephemeral.private.ok_or(ShieldedTxError::KeyError)?;
        
        // 5. Calcular shared secret: ss = H(r * B)
        let view_point = recipient_view_pubkey.decompress()
            .ok_or(ShieldedTxError::InvalidKey)?;
        let shared_point = ephemeral_private.inner() * view_point;
        let shared_secret = derive_shared_secret(&shared_point);
        
        // 6. Derivar one-time pubkey: P = H(ss)*G + S
        let ss_scalar = Scalar::from_bytes_mod_order(&shared_secret);
        let spend_point = recipient_spend_pubkey.decompress()
            .ok_or(ShieldedTxError::InvalidKey)?;
        let one_time_point = ss_scalar.inner() * GENERATORS.g + spend_point;
        let one_time_pubkey = CompressedPoint::from_point(&one_time_point);
        
        // 7. View tag
        let view_tag = shared_secret[0];
        
        // 8. Encriptar datos del output
        let encrypted_data = encrypt_output_data(
            amount,
            &blinding,
            memo.unwrap_or(&[]),
            &shared_secret,
        )?;
        
        let output = ShieldedOutput {
            commitment,
            range_proof,
            ephemeral_pubkey: ephemeral.public,
            one_time_pubkey,
            view_tag,
            encrypted_data,
        };
        
        let secrets = OutputSecrets {
            amount,
            blinding,
            shared_secret,
        };
        
        Ok((output, secrets))
    }
    
    /// Tamaño aproximado en bytes
    pub fn size(&self) -> usize {
        32 + // commitment
        self.range_proof.size() +
        32 + // ephemeral
        32 + // one_time
        1 +  // view_tag
        self.encrypted_data.size()
    }
}

/// Secretos de un output (para el emisor)
#[derive(Clone, Debug)]
pub struct OutputSecrets {
    pub amount: u64,
    pub blinding: Scalar,
    pub shared_secret: [u8; 32],
}

// =============================================================================
// Shielded Input
// =============================================================================

/// Input shielded (gasta un output privado)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedInput {
    /// Índices globales de los miembros del ring
    pub ring_members: Vec<u64>,
    
    /// Ring signature
    pub ring_signature: RingSignature,
    
    /// Pseudo-output commitment (para balance)
    /// C' = v*H + r'*G donde r' es diferente del original
    pub pseudo_commitment: PedersenCommitment,
}

impl ShieldedInput {
    /// Crea un input shielded
    pub fn new(
        // El output que estamos gastando
        real_output_index: u64,
        _real_output_pubkey: &CompressedPoint,
        amount: u64,
        _original_blinding: &Scalar,
        one_time_private_key: &Scalar,
        // Ring members (incluye el real)
        ring: &[(u64, CompressedPoint)],
        // Mensaje a firmar (TX hash)
        message: &[u8],
        // Nuevo blinding para pseudo-commitment
        pseudo_blinding: &Scalar,
    ) -> Result<Self, ShieldedTxError> {
        // Encontrar posición del output real en el ring
        let real_index = ring.iter()
            .position(|(idx, _)| *idx == real_output_index)
            .ok_or(ShieldedTxError::InvalidRing)?;
        
        // Extraer solo las pubkeys del ring
        let ring_pubkeys: Vec<CompressedPoint> = ring.iter()
            .map(|(_, pk)| *pk)
            .collect();
        
        // Crear ring signature
        let ring_signature = RingSignature::sign(
            message,
            &ring_pubkeys,
            one_time_private_key,
            real_index,
        ).map_err(ShieldedTxError::RingError)?;
        
        // Crear pseudo-commitment con nuevo blinding
        let pseudo_commitment = PedersenCommitment::commit(amount, *pseudo_blinding);
        
        // Índices de los miembros del ring
        let ring_members: Vec<u64> = ring.iter().map(|(idx, _)| *idx).collect();
        
        Ok(ShieldedInput {
            ring_members,
            ring_signature,
            pseudo_commitment,
        })
    }
    
    /// Tamaño aproximado en bytes
    pub fn size(&self) -> usize {
        self.ring_members.len() * 8 + // índices
        self.ring_signature.size() +
        32 // pseudo_commitment
    }
}

// =============================================================================
// Shielded Transaction
// =============================================================================

/// Tipo de transacción
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxType {
    /// Transparent → Transparent (legacy)
    Transparent,
    /// Transparent → Shielded (shielding)
    Shielding,
    /// Shielded → Shielded (full privacy)
    FullyShielded,
    /// Shielded → Transparent (unshielding)
    Unshielding,
    /// Mixed (tiene componentes de ambos)
    Mixed,
}

/// Transacción shielded (v2)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedTx {
    /// Versión (2 para shielded)
    pub version: u8,
    
    /// Tipo de transacción
    pub tx_type: TxType,
    
    /// Inputs transparentes (pueden estar vacíos)
    pub transparent_inputs: Vec<TxIn>,
    
    /// Outputs transparentes (pueden estar vacíos)
    pub transparent_outputs: Vec<TxOut>,
    
    /// Inputs shielded (pueden estar vacíos)
    pub shielded_inputs: Vec<ShieldedInput>,
    
    /// Outputs shielded (pueden estar vacíos)
    pub shielded_outputs: Vec<ShieldedOutput>,
    
    /// Fee (siempre visible, necesario para mineros)
    pub fee: u64,
    
    /// Binding signature (prueba que balance cuadra)
    pub binding_sig: Option<BindingSignature>,
    
    /// Locktime
    pub locktime: u32,
}

impl ShieldedTx {
    /// Crea una TX de shielding (transparent → shielded)
    pub fn new_shielding(
        transparent_inputs: Vec<TxIn>,
        shielded_outputs: Vec<ShieldedOutput>,
        output_blindings: &[Scalar],
        fee: u64,
    ) -> Result<Self, ShieldedTxError> {
        if shielded_outputs.len() != output_blindings.len() {
            return Err(ShieldedTxError::BlindingMismatch);
        }
        
        // Calcular binding signature
        // Para shielding: sum(output_blindings) debe balancear
        let binding_sig = BindingSignature::create_for_shielding(output_blindings)?;
        
        Ok(ShieldedTx {
            version: SHIELDED_TX_VERSION,
            tx_type: TxType::Shielding,
            transparent_inputs,
            transparent_outputs: vec![],
            shielded_inputs: vec![],
            shielded_outputs,
            fee,
            binding_sig: Some(binding_sig),
            locktime: 0,
        })
    }
    
    /// Crea una TX fully shielded
    pub fn new_fully_shielded(
        shielded_inputs: Vec<ShieldedInput>,
        input_blindings: &[Scalar],
        shielded_outputs: Vec<ShieldedOutput>,
        output_blindings: &[Scalar],
        fee: u64,
    ) -> Result<Self, ShieldedTxError> {
        // Calcular binding signature
        let binding_sig = BindingSignature::create(
            input_blindings,
            output_blindings,
        )?;
        
        Ok(ShieldedTx {
            version: SHIELDED_TX_VERSION,
            tx_type: TxType::FullyShielded,
            transparent_inputs: vec![],
            transparent_outputs: vec![],
            shielded_inputs,
            shielded_outputs,
            fee,
            binding_sig: Some(binding_sig),
            locktime: 0,
        })
    }
    
    /// Crea una TX de unshielding (shielded → transparent)
    pub fn new_unshielding(
        shielded_inputs: Vec<ShieldedInput>,
        input_blindings: &[Scalar],
        transparent_outputs: Vec<TxOut>,
        fee: u64,
    ) -> Result<Self, ShieldedTxError> {
        let binding_sig = BindingSignature::create_for_unshielding(input_blindings)?;
        
        Ok(ShieldedTx {
            version: SHIELDED_TX_VERSION,
            tx_type: TxType::Unshielding,
            transparent_inputs: vec![],
            transparent_outputs,
            shielded_inputs,
            shielded_outputs: vec![],
            fee,
            binding_sig: Some(binding_sig),
            locktime: 0,
        })
    }
    
    /// Calcula el hash de la TX (para firmar)
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Mooncoin_ShieldedTx_Hash");
        hasher.update(&[self.version]);
        hasher.update(&(self.tx_type as u8).to_le_bytes());
        
        // Hash de inputs transparentes
        for input in &self.transparent_inputs {
            hasher.update(input.prev_tx_hash.as_bytes());
            hasher.update(&input.prev_index.to_le_bytes());
        }
        
        // Hash de outputs transparentes
        for output in &self.transparent_outputs {
            hasher.update(output.to.as_bytes());
            hasher.update(&output.amount.to_le_bytes());
        }
        
        // Hash de inputs shielded
        for input in &self.shielded_inputs {
            hasher.update(&input.ring_signature.key_image.as_bytes());
            hasher.update(&input.pseudo_commitment.as_bytes());
        }
        
        // Hash de outputs shielded
        for output in &self.shielded_outputs {
            hasher.update(&output.commitment.as_bytes());
            hasher.update(&output.one_time_pubkey.as_bytes());
        }
        
        hasher.update(&self.fee.to_le_bytes());
        hasher.update(&self.locktime.to_le_bytes());
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Convierte a TX legacy (para compatibilidad)
    pub fn to_legacy_tx(&self) -> Option<Tx> {
        if self.tx_type != TxType::Transparent {
            return None;
        }
        
        Some(Tx {
            inputs: self.transparent_inputs.clone(),
            outputs: self.transparent_outputs.clone(),
        })
    }
    
    /// Tamaño aproximado en bytes
    pub fn size(&self) -> usize {
        let mut size = 1 + 1 + 8 + 4; // version + type + fee + locktime
        
        for input in &self.transparent_inputs {
            size += 32 + 4 + input.signature.len() + input.pubkey.len();
        }
        
        for output in &self.transparent_outputs {
            size += output.to.len() + 8;
        }
        
        for input in &self.shielded_inputs {
            size += input.size();
        }
        
        for output in &self.shielded_outputs {
            size += output.size();
        }
        
        if self.binding_sig.is_some() {
            size += 64;
        }
        
        size
    }
    
    /// Obtiene todos los key images (para verificar double-spend)
    pub fn key_images(&self) -> Vec<KeyImage> {
        self.shielded_inputs.iter()
            .map(|i| i.ring_signature.key_image)
            .collect()
    }
}

// =============================================================================
// Binding Signature
// =============================================================================

/// Binding signature: prueba que los commitments balancean
/// sin revelar los blinding factors individuales
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindingSignature {
    /// Suma de blinding factors (para verificación de balance)
    pub blinding_sum: Scalar,
}

impl BindingSignature {
    /// Crea binding signature para TX shielding
    pub fn create_for_shielding(output_blindings: &[Scalar]) -> Result<Self, ShieldedTxError> {
        let mut sum = Scalar::zero();
        for b in output_blindings {
            sum = sum.add(b);
        }
        Ok(BindingSignature { blinding_sum: sum })
    }
    
    /// Crea binding signature para TX unshielding
    pub fn create_for_unshielding(input_blindings: &[Scalar]) -> Result<Self, ShieldedTxError> {
        let mut sum = Scalar::zero();
        for b in input_blindings {
            sum = sum.add(b);
        }
        Ok(BindingSignature { blinding_sum: sum })
    }
    
    /// Crea binding signature para TX fully shielded
    pub fn create(
        input_blindings: &[Scalar],
        output_blindings: &[Scalar],
    ) -> Result<Self, ShieldedTxError> {
        let mut input_sum = Scalar::zero();
        for b in input_blindings {
            input_sum = input_sum.add(b);
        }
        
        let mut output_sum = Scalar::zero();
        for b in output_blindings {
            output_sum = output_sum.add(b);
        }
        
        // blinding_sum = input_sum - output_sum
        let blinding_sum = input_sum.sub(&output_sum);
        
        Ok(BindingSignature { blinding_sum })
    }
}

// =============================================================================
// Encrypted Output Data
// =============================================================================

/// Datos encriptados de un output
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedOutputData {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

impl EncryptedOutputData {
    pub fn size(&self) -> usize {
        self.ciphertext.len() + 12
    }
}

/// Datos desencriptados de un output
#[derive(Clone, Debug)]
pub struct DecryptedOutputData {
    pub amount: u64,
    pub blinding: Scalar,
    pub memo: Vec<u8>,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Deriva shared secret desde punto ECDH
fn derive_shared_secret(point: &curve25519_dalek::ristretto::RistrettoPoint) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"Mooncoin_SharedSecret_v1");
    hasher.update(point.compress().as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Encripta datos del output
fn encrypt_output_data(
    amount: u64,
    blinding: &Scalar,
    memo: &[u8],
    shared_secret: &[u8; 32],
) -> Result<EncryptedOutputData, ShieldedTxError> {
    // Serializar datos
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&amount.to_le_bytes());
    plaintext.extend_from_slice(&blinding.as_bytes());
    
    // Memo (máx 256 bytes)
    let memo_len = memo.len().min(256);
    plaintext.push(memo_len as u8);
    plaintext.extend_from_slice(&memo[..memo_len]);
    
    // Derivar clave de encriptación
    let mut hasher = Sha3_256::new();
    hasher.update(b"Mooncoin_OutputEncryption_v1");
    hasher.update(shared_secret);
    let key: [u8; 32] = hasher.finalize().into();
    
    // Encriptar
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| ShieldedTxError::EncryptionError)?;
    
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| ShieldedTxError::EncryptionError)?;
    
    Ok(EncryptedOutputData { ciphertext, nonce })
}

/// Desencripta datos del output
pub fn decrypt_output_data(
    encrypted: &EncryptedOutputData,
    shared_secret: &[u8; 32],
) -> Result<DecryptedOutputData, ShieldedTxError> {
    // Derivar clave
    let mut hasher = Sha3_256::new();
    hasher.update(b"Mooncoin_OutputEncryption_v1");
    hasher.update(shared_secret);
    let key: [u8; 32] = hasher.finalize().into();
    
    // Desencriptar
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| ShieldedTxError::DecryptionError)?;
    
    let plaintext = cipher.decrypt(Nonce::from_slice(&encrypted.nonce), encrypted.ciphertext.as_ref())
        .map_err(|_| ShieldedTxError::DecryptionError)?;
    
    if plaintext.len() < 41 { // 8 + 32 + 1
        return Err(ShieldedTxError::DecryptionError);
    }
    
    // Parsear
    let amount = u64::from_le_bytes(plaintext[0..8].try_into().unwrap());
    
    let mut blinding_bytes = [0u8; 32];
    blinding_bytes.copy_from_slice(&plaintext[8..40]);
    let blinding = Scalar::from_bytes_mod_order(&blinding_bytes);
    
    let memo_len = plaintext[40] as usize;
    let memo = if memo_len > 0 && plaintext.len() > 41 {
        plaintext[41..41 + memo_len.min(plaintext.len() - 41)].to_vec()
    } else {
        vec![]
    };
    
    Ok(DecryptedOutputData { amount, blinding, memo })
}

// =============================================================================
// Errors
// =============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShieldedTxError {
    InvalidKey,
    KeyError,
    RangeProofError,
    InvalidRing,
    RingError(RingError),
    BlindingMismatch,
    BalanceMismatch,
    EncryptionError,
    DecryptionError,
    InvalidSignature,
    DoubleSpend,
    TooManyInputs,
    TooManyOutputs,
    FeeTooLow,
}

impl std::fmt::Display for ShieldedTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShieldedTxError::InvalidKey => write!(f, "Invalid key"),
            ShieldedTxError::KeyError => write!(f, "Key error"),
            ShieldedTxError::RangeProofError => write!(f, "Range proof error"),
            ShieldedTxError::InvalidRing => write!(f, "Invalid ring"),
            ShieldedTxError::RingError(e) => write!(f, "Ring error: {}", e),
            ShieldedTxError::BlindingMismatch => write!(f, "Blinding factor mismatch"),
            ShieldedTxError::BalanceMismatch => write!(f, "Balance mismatch"),
            ShieldedTxError::EncryptionError => write!(f, "Encryption error"),
            ShieldedTxError::DecryptionError => write!(f, "Decryption error"),
            ShieldedTxError::InvalidSignature => write!(f, "Invalid signature"),
            ShieldedTxError::DoubleSpend => write!(f, "Double spend detected"),
            ShieldedTxError::TooManyInputs => write!(f, "Too many inputs"),
            ShieldedTxError::TooManyOutputs => write!(f, "Too many outputs"),
            ShieldedTxError::FeeTooLow => write!(f, "Fee too low"),
        }
    }
}

impl std::error::Error for ShieldedTxError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::keys::PrivacyKeys;
    
    #[test]
    fn test_shielded_output_creation() {
        let recipient = PrivacyKeys::generate();
        let stealth_addr = recipient.stealth_address();
        
        let (output, secrets) = ShieldedOutput::new(
            1000,
            &stealth_addr.view_pubkey,
            &stealth_addr.spend_pubkey,
            Some(b"test memo"),
        ).unwrap();
        
        assert_eq!(secrets.amount, 1000);
        assert!(output.size() > 0);
    }
    
    #[test]
    fn test_encrypted_output_data() {
        let amount = 12345u64;
        let blinding = Scalar::random();
        let memo = b"Hello, Mooncoin!";
        let shared_secret = [42u8; 32];
        
        let encrypted = encrypt_output_data(amount, &blinding, memo, &shared_secret).unwrap();
        let decrypted = decrypt_output_data(&encrypted, &shared_secret).unwrap();
        
        assert_eq!(decrypted.amount, amount);
        assert_eq!(decrypted.blinding.as_bytes(), blinding.as_bytes());
        assert_eq!(decrypted.memo, memo);
    }
    
    #[test]
    fn test_tx_hash() {
        let tx = ShieldedTx {
            version: SHIELDED_TX_VERSION,
            tx_type: TxType::Transparent,
            transparent_inputs: vec![],
            transparent_outputs: vec![],
            shielded_inputs: vec![],
            shielded_outputs: vec![],
            fee: 1000,
            binding_sig: None,
            locktime: 0,
        };
        
        let hash1 = tx.hash();
        let hash2 = tx.hash();
        
        // Hash debe ser determinístico
        assert_eq!(hash1, hash2);
    }
}
