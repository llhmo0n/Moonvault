// =============================================================================
// MOONCOIN v2.0 - Transaction Builder (Script-enabled)
// =============================================================================
//
// Funciones para crear transacciones usando el sistema de scripts.
// Mantiene compatibilidad con el formato existente mientras añade
// soporte para P2PKH, P2SH, multisig y timelocks.
//
// =============================================================================

use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};

use crate::script::{Script, ScriptEngine, ScriptContext, OpCode, hash160};
use crate::transaction::{Tx, TxIn, TxOut, tx_serialize_for_signing};
use crate::utxo::{UtxoSet, UtxoEntry};

// =============================================================================
// Script-enhanced Transaction Output
// =============================================================================

/// Output extendido con script
#[derive(Clone, Debug)]
pub struct ScriptTxOut {
    pub amount: u64,
    pub script_pubkey: Script,
}

impl ScriptTxOut {
    /// Crea un output P2PKH desde una dirección
    pub fn p2pkh_from_address(amount: u64, address: &str) -> Result<Self, String> {
        let pubkey_hash = address_to_pubkey_hash(address)?;
        Ok(ScriptTxOut {
            amount,
            script_pubkey: Script::p2pkh(&pubkey_hash),
        })
    }
    
    /// Crea un output P2SH desde un script
    pub fn p2sh(amount: u64, redeem_script: &Script) -> Self {
        let script_bytes = redeem_script.to_bytes();
        let script_hash = hash160(&script_bytes);
        ScriptTxOut {
            amount,
            script_pubkey: Script::p2sh(&script_hash),
        }
    }
    
    /// Crea un output multisig directo (no P2SH)
    pub fn multisig(amount: u64, required: u8, pubkeys: &[Vec<u8>]) -> Self {
        ScriptTxOut {
            amount,
            script_pubkey: Script::multisig(required, pubkeys),
        }
    }
    
    /// Crea un output con timelock CLTV
    pub fn with_cltv(amount: u64, locktime: u32, inner_script: Script) -> Self {
        ScriptTxOut {
            amount,
            script_pubkey: Script::with_cltv(locktime, inner_script),
        }
    }
    
    /// Crea un output OP_RETURN (datos, no gastable)
    pub fn op_return(data: &[u8]) -> Self {
        ScriptTxOut {
            amount: 0,
            script_pubkey: Script {
                ops: vec![
                    OpCode::OpReturn,
                    OpCode::OpPushData(data.to_vec()),
                ],
            },
        }
    }
    
    /// Convierte a TxOut estándar (para compatibilidad)
    /// El script se codifica en el campo 'to' como hex
    pub fn to_standard(&self) -> TxOut {
        // Para P2PKH, extraemos la dirección
        if let Some(pubkey_hash) = self.script_pubkey.get_p2pkh_hash() {
            let address = pubkey_hash_to_address(&pubkey_hash);
            return TxOut {
                to: address,
                amount: self.amount,
            };
        }
        
        // Para otros scripts, codificamos como hex con prefijo
        let script_hex = hex::encode(self.script_pubkey.to_bytes());
        TxOut {
            to: format!("SCRIPT:{}", script_hex),
            amount: self.amount,
        }
    }
}

// =============================================================================
// Script-enhanced Transaction Input
// =============================================================================

/// Input extendido con script
#[derive(Clone, Debug)]
pub struct ScriptTxIn {
    pub prev_tx_hash: String,
    pub prev_index: u32,
    pub script_sig: Script,
    pub sequence: u32,
}

impl ScriptTxIn {
    /// Crea un input básico (sin firma aún)
    pub fn new(prev_tx_hash: String, prev_index: u32) -> Self {
        ScriptTxIn {
            prev_tx_hash,
            prev_index,
            script_sig: Script::new(),
            sequence: 0xffffffff,
        }
    }
    
    /// Crea un input con sequence para timelock
    pub fn with_sequence(prev_tx_hash: String, prev_index: u32, sequence: u32) -> Self {
        ScriptTxIn {
            prev_tx_hash,
            prev_index,
            script_sig: Script::new(),
            sequence,
        }
    }
    
    /// Convierte a TxIn estándar
    pub fn to_standard(&self) -> TxIn {
        // Extraer signature y pubkey del scriptSig si es P2PKH
        let (signature, pubkey) = self.extract_p2pkh_sig();
        
        TxIn {
            prev_tx_hash: self.prev_tx_hash.clone(),
            prev_index: self.prev_index,
            signature,
            pubkey,
        }
    }
    
    /// Extrae signature y pubkey de un scriptSig P2PKH
    fn extract_p2pkh_sig(&self) -> (Vec<u8>, Vec<u8>) {
        if self.script_sig.ops.len() >= 2 {
            let sig = match &self.script_sig.ops[0] {
                OpCode::OpPushData(d) => d.clone(),
                _ => vec![],
            };
            let pk = match &self.script_sig.ops[1] {
                OpCode::OpPushData(d) => d.clone(),
                _ => vec![],
            };
            return (sig, pk);
        }
        (vec![], vec![])
    }
}

// =============================================================================
// Transaction Builder
// =============================================================================

/// Constructor de transacciones con soporte de scripts
pub struct TxBuilder {
    inputs: Vec<ScriptTxIn>,
    outputs: Vec<ScriptTxOut>,
    locktime: u32,
}

impl TxBuilder {
    pub fn new() -> Self {
        TxBuilder {
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
        }
    }
    
    /// Añade un input
    pub fn add_input(mut self, prev_tx_hash: String, prev_index: u32) -> Self {
        self.inputs.push(ScriptTxIn::new(prev_tx_hash, prev_index));
        self
    }
    
    /// Añade un input con sequence específico
    pub fn add_input_with_sequence(mut self, prev_tx_hash: String, prev_index: u32, sequence: u32) -> Self {
        self.inputs.push(ScriptTxIn::with_sequence(prev_tx_hash, prev_index, sequence));
        self
    }
    
    /// Añade un output P2PKH
    pub fn add_p2pkh_output(mut self, amount: u64, address: &str) -> Result<Self, String> {
        self.outputs.push(ScriptTxOut::p2pkh_from_address(amount, address)?);
        Ok(self)
    }
    
    /// Añade un output P2SH
    pub fn add_p2sh_output(mut self, amount: u64, redeem_script: &Script) -> Self {
        self.outputs.push(ScriptTxOut::p2sh(amount, redeem_script));
        self
    }
    
    /// Añade un output multisig
    pub fn add_multisig_output(mut self, amount: u64, required: u8, pubkeys: &[Vec<u8>]) -> Self {
        self.outputs.push(ScriptTxOut::multisig(amount, required, pubkeys));
        self
    }
    
    /// Añade un output con timelock
    pub fn add_timelocked_output(mut self, amount: u64, locktime: u32, address: &str) -> Result<Self, String> {
        let pubkey_hash = address_to_pubkey_hash(address)?;
        let inner = Script::p2pkh(&pubkey_hash);
        self.outputs.push(ScriptTxOut::with_cltv(amount, locktime, inner));
        Ok(self)
    }
    
    /// Añade un output OP_RETURN
    pub fn add_op_return(mut self, data: &[u8]) -> Self {
        self.outputs.push(ScriptTxOut::op_return(data));
        self
    }
    
    /// Establece el locktime
    pub fn set_locktime(mut self, locktime: u32) -> Self {
        self.locktime = locktime;
        self
    }
    
    /// Construye la transacción sin firmar
    pub fn build_unsigned(&self) -> Tx {
        Tx {
            inputs: self.inputs.iter().map(|i| i.to_standard()).collect(),
            outputs: self.outputs.iter().map(|o| o.to_standard()).collect(),
        }
    }
    
    /// Firma un input específico con una clave privada (P2PKH)
    pub fn sign_input(&mut self, input_index: usize, secret_key: &SecretKey, _utxo: &UtxoEntry) -> Result<(), String> {
        if input_index >= self.inputs.len() {
            return Err("Input index out of bounds".to_string());
        }
        
        // Obtener pubkey
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_secret_key(&secp, secret_key);
        let pubkey_bytes = pubkey.serialize().to_vec();
        
        // Crear el hash para firmar
        let tx = self.build_unsigned();
        let tx_data = tx_serialize_for_signing(&tx);
        let hash = Sha256::digest(&Sha256::digest(&tx_data));
        
        // Firmar
        let message = Message::from_digest(hash.into());
        let sig = secp.sign_ecdsa(&message, secret_key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL
        
        // Crear scriptSig P2PKH
        self.inputs[input_index].script_sig = Script::p2pkh_sig(&sig_bytes, &pubkey_bytes);
        
        Ok(())
    }
    
    /// Firma todos los inputs con la misma clave (para transacciones simples)
    pub fn sign_all_inputs(&mut self, secret_key: &SecretKey) -> Result<(), String> {
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_secret_key(&secp, secret_key);
        let pubkey_bytes = pubkey.serialize().to_vec();
        
        let tx = self.build_unsigned();
        let tx_data = tx_serialize_for_signing(&tx);
        let hash = Sha256::digest(&Sha256::digest(&tx_data));
        
        let message = Message::from_digest(hash.into());
        let sig = secp.sign_ecdsa(&message, secret_key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01);
        
        for input in &mut self.inputs {
            input.script_sig = Script::p2pkh_sig(&sig_bytes, &pubkey_bytes);
        }
        
        Ok(())
    }
    
    /// Construye la transacción firmada
    pub fn build(self) -> Tx {
        Tx {
            inputs: self.inputs.iter().map(|i| i.to_standard()).collect(),
            outputs: self.outputs.iter().map(|o| o.to_standard()).collect(),
        }
    }
}

// =============================================================================
// Script Verification
// =============================================================================

/// Verifica un input de transacción contra su UTXO
pub fn verify_input_script(
    tx: &Tx,
    input_index: usize,
    utxo_entry: &UtxoEntry,
    block_height: u64,
) -> Result<bool, String> {
    if input_index >= tx.inputs.len() {
        return Err("Input index out of bounds".to_string());
    }
    
    let input = &tx.inputs[input_index];
    
    // Construir scriptSig desde el input
    let script_sig = Script::p2pkh_sig(&input.signature, &input.pubkey);
    
    // Construir scriptPubKey desde el UTXO
    let script_pubkey = if utxo_entry.output.to.starts_with("SCRIPT:") {
        // Script codificado
        let hex = &utxo_entry.output.to[7..];
        let bytes = hex::decode(hex).map_err(|e| format!("Invalid script hex: {}", e))?;
        Script::from_bytes(&bytes)?
    } else {
        // Dirección P2PKH estándar
        let pubkey_hash = address_to_pubkey_hash(&utxo_entry.output.to)?;
        Script::p2pkh(&pubkey_hash)
    };
    
    // Crear hash de la transacción para verificación de firma
    let tx_data = tx_serialize_for_signing(tx);
    let hash = Sha256::digest(&Sha256::digest(&tx_data));
    let mut tx_hash_bytes = [0u8; 32];
    tx_hash_bytes.copy_from_slice(&hash);
    
    // Crear contexto de ejecución
    let context = ScriptContext {
        tx_hash: tx_hash_bytes,
        locktime: 0, // TODO: Añadir locktime a Tx
        sequence: 0xffffffff, // TODO: Añadir sequence a TxIn
        block_height,
    };
    
    // Ejecutar scripts
    let mut engine = ScriptEngine::new(context);
    engine.verify(&script_sig, &script_pubkey)
}

/// Verifica todos los inputs de una transacción
pub fn verify_transaction_scripts(
    tx: &Tx,
    utxo_set: &UtxoSet,
    block_height: u64,
) -> Result<bool, String> {
    // Coinbase no tiene scripts que verificar
    if tx.is_coinbase() {
        return Ok(true);
    }
    
    for (i, input) in tx.inputs.iter().enumerate() {
        let key = (input.prev_tx_hash.clone(), input.prev_index);
        
        let utxo_entry = utxo_set.utxos.get(&key)
            .ok_or_else(|| format!("UTXO not found for input {}", i))?;
        
        if !verify_input_script(tx, i, utxo_entry, block_height)? {
            return Ok(false);
        }
    }
    
    Ok(true)
}

// =============================================================================
// Multisig Helpers
// =============================================================================

/// Crea un script de redeem para multisig m-of-n
pub fn create_multisig_redeem_script(required: u8, pubkeys: &[Vec<u8>]) -> Script {
    Script::multisig(required, pubkeys)
}

/// Crea una dirección P2SH para un script multisig
pub fn create_multisig_address(required: u8, pubkeys: &[Vec<u8>]) -> String {
    let redeem_script = create_multisig_redeem_script(required, pubkeys);
    let script_bytes = redeem_script.to_bytes();
    let script_hash = hash160(&script_bytes);
    
    // Crear dirección P2SH (prefijo diferente)
    let mut versioned = vec![0x35]; // Prefijo para P2SH ('M' diferente)
    versioned.extend_from_slice(&script_hash);
    
    let checksum = Sha256::digest(&Sha256::digest(&versioned));
    versioned.extend_from_slice(&checksum[..4]);
    
    bs58::encode(versioned).into_string()
}

/// Firma parcial para multisig
pub fn sign_multisig_input(
    tx: &Tx,
    _input_index: usize,
    secret_key: &SecretKey,
) -> Result<Vec<u8>, String> {
    let secp = Secp256k1::new();
    
    let tx_data = tx_serialize_for_signing(tx);
    let hash = Sha256::digest(&Sha256::digest(&tx_data));
    
    let message = Message::from_digest(hash.into());
    let sig = secp.sign_ecdsa(&message, secret_key);
    
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(0x01); // SIGHASH_ALL
    
    Ok(sig_bytes)
}

/// Combina firmas parciales para crear scriptSig multisig
pub fn create_multisig_script_sig(signatures: &[Vec<u8>], redeem_script: &Script) -> Script {
    let mut ops = vec![OpCode::Op0]; // Dummy element (Bitcoin bug compatibility)
    
    for sig in signatures {
        ops.push(OpCode::OpPushData(sig.clone()));
    }
    
    ops.push(OpCode::OpPushData(redeem_script.to_bytes()));
    
    Script { ops }
}

// =============================================================================
// Address Utilities
// =============================================================================

/// Convierte una dirección Mooncoin a pubkey hash (20 bytes)
pub fn address_to_pubkey_hash(address: &str) -> Result<Vec<u8>, String> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|e| format!("Invalid address encoding: {}", e))?;
    
    if decoded.len() != 25 {
        return Err(format!("Invalid address length: {}", decoded.len()));
    }
    
    // Verificar checksum
    let payload = &decoded[..21];
    let checksum = &decoded[21..];
    let computed = Sha256::digest(&Sha256::digest(payload));
    
    if &computed[..4] != checksum {
        return Err("Invalid address checksum".to_string());
    }
    
    // Extraer pubkey hash (bytes 1-20)
    Ok(decoded[1..21].to_vec())
}

/// Convierte un pubkey hash a dirección Mooncoin
pub fn pubkey_hash_to_address(pubkey_hash: &[u8]) -> String {
    let mut versioned = vec![0x32]; // Version byte para 'M'
    versioned.extend_from_slice(pubkey_hash);
    
    let checksum = Sha256::digest(&Sha256::digest(&versioned));
    versioned.extend_from_slice(&checksum[..4]);
    
    bs58::encode(versioned).into_string()
}

/// Convierte una clave pública a pubkey hash
pub fn pubkey_to_hash(pubkey: &PublicKey) -> Vec<u8> {
    let pubkey_bytes = pubkey.serialize();
    let sha = Sha256::digest(&pubkey_bytes);
    Ripemd160::digest(&sha).to_vec()
}

/// Convierte una clave pública a dirección
pub fn pubkey_to_address(pubkey: &PublicKey) -> String {
    let hash = pubkey_to_hash(pubkey);
    pubkey_hash_to_address(&hash)
}

// =============================================================================
// HTLC (Hash Time Locked Contracts)
// =============================================================================

/// Crea un script HTLC para atomic swaps
/// El destinatario puede gastar con preimage, o el sender después del timeout
pub fn create_htlc_script(
    recipient_pubkey_hash: &[u8],
    sender_pubkey_hash: &[u8],
    payment_hash: &[u8],      // SHA256 del secret
    timeout_blocks: u32,
) -> Script {
    // OP_IF
    //   OP_SHA256 <payment_hash> OP_EQUALVERIFY OP_DUP OP_HASH160 <recipient_hash>
    // OP_ELSE
    //   <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <sender_hash>
    // OP_ENDIF
    // OP_EQUALVERIFY OP_CHECKSIG
    
    Script {
        ops: vec![
            OpCode::OpIf,
            OpCode::OpSha256,
            OpCode::OpPushData(payment_hash.to_vec()),
            OpCode::OpEqualVerify,
            OpCode::OpDup,
            OpCode::OpHash160,
            OpCode::OpPushData(recipient_pubkey_hash.to_vec()),
            OpCode::OpElse,
            OpCode::OpPushData(timeout_blocks.to_le_bytes().to_vec()),
            OpCode::OpCheckLockTimeVerify,
            OpCode::OpDrop,
            OpCode::OpDup,
            OpCode::OpHash160,
            OpCode::OpPushData(sender_pubkey_hash.to_vec()),
            OpCode::OpEndIf,
            OpCode::OpEqualVerify,
            OpCode::OpCheckSig,
        ],
    }
}

/// Crea scriptSig para reclamar HTLC con preimage
pub fn create_htlc_claim_script(signature: &[u8], pubkey: &[u8], preimage: &[u8]) -> Script {
    Script {
        ops: vec![
            OpCode::OpPushData(signature.to_vec()),
            OpCode::OpPushData(pubkey.to_vec()),
            OpCode::OpPushData(preimage.to_vec()),
            OpCode::OpTrue, // Para tomar la rama IF
        ],
    }
}

/// Crea scriptSig para reclamar HTLC después del timeout
pub fn create_htlc_refund_script(signature: &[u8], pubkey: &[u8]) -> Script {
    Script {
        ops: vec![
            OpCode::OpPushData(signature.to_vec()),
            OpCode::OpPushData(pubkey.to_vec()),
            OpCode::OpFalse, // Para tomar la rama ELSE
        ],
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_address_conversion() {
        // Crear una dirección de prueba
        let pubkey_hash = vec![0u8; 20];
        let address = pubkey_hash_to_address(&pubkey_hash);
        
        assert!(address.starts_with("M"));
        
        // Convertir de vuelta
        let recovered = address_to_pubkey_hash(&address).unwrap();
        assert_eq!(recovered, pubkey_hash);
    }
    
    #[test]
    fn test_tx_builder() {
        let builder = TxBuilder::new()
            .add_input("abc123".repeat(11), 0);
        
        let builder = builder.add_p2pkh_output(
            100_000_000,
            &pubkey_hash_to_address(&[0u8; 20])
        ).unwrap();
        
        let tx = builder.build_unsigned();
        
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].amount, 100_000_000);
    }
    
    #[test]
    fn test_multisig_address() {
        let pk1 = vec![0u8; 33];
        let pk2 = vec![1u8; 33];
        let pk3 = vec![2u8; 33];
        
        let address = create_multisig_address(2, &[pk1, pk2, pk3]);
        
        // Debe empezar con un prefijo diferente
        assert!(!address.is_empty());
    }
}
