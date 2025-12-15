// =============================================================================
// MOONCOIN v2.34 - HTLC Scripts for Atomic Swaps
// =============================================================================
//
// Bitcoin Script templates for Hash Time Lock Contracts used in atomic swaps.
//
// HTLC Script Structure:
// OP_IF
//     OP_SHA256 <hash> OP_EQUALVERIFY
//     <recipient_pubkey> OP_CHECKSIG
// OP_ELSE
//     <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
//     <refund_pubkey> OP_CHECKSIG
// OP_ENDIF
//
// To claim with secret:
//     <signature> <preimage> OP_TRUE
//
// To refund after timeout:
//     <signature> OP_FALSE
//
// =============================================================================

use super::{SECRET_SIZE, HASH_SIZE};

// =============================================================================
// HTLC Script Parameters
// =============================================================================

/// Parameters for creating an HTLC script
#[derive(Clone, Debug)]
pub struct HtlcScriptParams {
    /// SHA256 hash of the secret
    pub secret_hash: [u8; HASH_SIZE],
    
    /// Public key of the recipient (can claim with secret)
    pub recipient_pubkey: [u8; 33],
    
    /// Public key for refund (can claim after timeout)
    pub refund_pubkey: [u8; 33],
    
    /// Absolute timeout (block height)
    pub timeout: u32,
}

impl HtlcScriptParams {
    pub fn new(
        secret_hash: [u8; HASH_SIZE],
        recipient_pubkey: [u8; 33],
        refund_pubkey: [u8; 33],
        timeout: u32,
    ) -> Self {
        HtlcScriptParams {
            secret_hash,
            recipient_pubkey,
            refund_pubkey,
            timeout,
        }
    }
}

// =============================================================================
// Script Opcodes
// =============================================================================

mod opcodes {
    pub const OP_FALSE: u8 = 0x00;
    pub const OP_TRUE: u8 = 0x51;
    pub const OP_IF: u8 = 0x63;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_SHA256: u8 = 0xa8;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
}

// =============================================================================
// Script Creation
// =============================================================================

/// Create an HTLC script for atomic swaps
pub fn create_htlc_script(params: &HtlcScriptParams) -> Vec<u8> {
    use opcodes::*;
    
    let mut script = Vec::new();

    // OP_IF (claim path with secret)
    script.push(OP_IF);

    // OP_SHA256 <hash> OP_EQUALVERIFY
    script.push(OP_SHA256);
    script.push(32); // Push 32 bytes
    script.extend_from_slice(&params.secret_hash);
    script.push(OP_EQUALVERIFY);

    // <recipient_pubkey> OP_CHECKSIG
    script.push(33); // Push 33 bytes (compressed pubkey)
    script.extend_from_slice(&params.recipient_pubkey);
    script.push(OP_CHECKSIG);

    // OP_ELSE (refund path after timeout)
    script.push(OP_ELSE);

    // <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
    let timeout_bytes = encode_locktime(params.timeout);
    script.push(timeout_bytes.len() as u8);
    script.extend_from_slice(&timeout_bytes);
    script.push(OP_CHECKLOCKTIMEVERIFY);
    script.push(OP_DROP);

    // <refund_pubkey> OP_CHECKSIG
    script.push(33);
    script.extend_from_slice(&params.refund_pubkey);
    script.push(OP_CHECKSIG);

    // OP_ENDIF
    script.push(OP_ENDIF);

    script
}

/// Create a script to claim an HTLC with the secret
pub fn create_claim_script(
    signature: &[u8],
    preimage: &[u8; SECRET_SIZE],
) -> Vec<u8> {
    use opcodes::*;
    
    let mut script = Vec::new();

    // <signature>
    script.push(signature.len() as u8);
    script.extend_from_slice(signature);

    // <preimage>
    script.push(SECRET_SIZE as u8);
    script.extend_from_slice(preimage);

    // OP_TRUE (select IF branch)
    script.push(OP_TRUE);

    script
}

/// Create a script to refund an HTLC after timeout
pub fn create_refund_script(signature: &[u8]) -> Vec<u8> {
    use opcodes::*;
    
    let mut script = Vec::new();

    // <signature>
    script.push(signature.len() as u8);
    script.extend_from_slice(signature);

    // OP_FALSE (select ELSE branch)
    script.push(OP_FALSE);

    script
}

// =============================================================================
// Script Address
// =============================================================================

/// Create P2SH address from HTLC script
pub fn htlc_to_p2sh_address(htlc_script: &[u8], prefix: &str) -> String {
    use sha2::{Sha256, Digest};
    use ripemd::Ripemd160;

    // SHA256
    let sha256_hash = Sha256::digest(htlc_script);
    
    // RIPEMD160
    let hash160 = Ripemd160::digest(&sha256_hash);
    
    // Version byte + hash
    let mut address_bytes = vec![0x05]; // P2SH version
    address_bytes.extend_from_slice(&hash160);
    
    // Checksum
    let checksum = &Sha256::digest(&Sha256::digest(&address_bytes))[..4];
    address_bytes.extend_from_slice(checksum);
    
    // Base58 encode
    format!("{}:{}", prefix, bs58::encode(address_bytes).into_string())
}

/// Create script hash (for P2SH)
pub fn script_hash(script: &[u8]) -> [u8; 20] {
    use sha2::{Sha256, Digest};
    use ripemd::Ripemd160;

    let sha256_hash = Sha256::digest(script);
    let hash160 = Ripemd160::digest(&sha256_hash);
    
    let mut result = [0u8; 20];
    result.copy_from_slice(&hash160);
    result
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Encode locktime for Script
fn encode_locktime(locktime: u32) -> Vec<u8> {
    if locktime == 0 {
        return vec![];
    }

    let mut bytes = locktime.to_le_bytes().to_vec();
    
    // Remove trailing zeros
    while bytes.len() > 1 && bytes.last() == Some(&0) {
        bytes.pop();
    }
    
    // If high bit is set, add 0x00 to keep positive
    if bytes.last().map(|b| b & 0x80 != 0).unwrap_or(false) {
        bytes.push(0x00);
    }
    
    bytes
}

/// Decode locktime from Script bytes
pub fn decode_locktime(bytes: &[u8]) -> u32 {
    if bytes.is_empty() {
        return 0;
    }
    
    let mut value: u32 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        if i < 4 {
            value |= (byte as u32) << (i * 8);
        }
    }
    
    // Handle sign bit
    if bytes.len() <= 4 && bytes.last().map(|b| b & 0x80 != 0).unwrap_or(false) {
        let sign_bit = 1u32 << (bytes.len() * 8 - 1);
        value &= !sign_bit;
    }
    
    value
}

/// Disassemble HTLC script for debugging
pub fn disassemble_htlc(script: &[u8]) -> String {
    use opcodes::*;
    
    let mut result = String::new();
    let mut i = 0;
    
    while i < script.len() {
        let op = script[i];
        
        let op_name = match op {
            OP_FALSE => "OP_FALSE",
            OP_TRUE => "OP_TRUE",
            OP_IF => "OP_IF",
            OP_ELSE => "OP_ELSE",
            OP_ENDIF => "OP_ENDIF",
            OP_DROP => "OP_DROP",
            OP_DUP => "OP_DUP",
            OP_EQUALVERIFY => "OP_EQUALVERIFY",
            OP_SHA256 => "OP_SHA256",
            OP_HASH160 => "OP_HASH160",
            OP_CHECKSIG => "OP_CHECKSIG",
            OP_CHECKLOCKTIMEVERIFY => "OP_CLTV",
            OP_CHECKSEQUENCEVERIFY => "OP_CSV",
            1..=75 => {
                // Push data
                let len = op as usize;
                if i + 1 + len <= script.len() {
                    let data = &script[i + 1..i + 1 + len];
                    let hex = hex::encode(data);
                    i += len;
                    result.push_str(&format!("<{}> ", hex));
                    i += 1;
                    continue;
                }
                "PUSH?"
            }
            _ => "?",
        };
        
        result.push_str(op_name);
        result.push(' ');
        i += 1;
    }
    
    result.trim().to_string()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_params() -> HtlcScriptParams {
        HtlcScriptParams {
            secret_hash: [0xAB; 32],
            recipient_pubkey: [0x02; 33],
            refund_pubkey: [0x03; 33],
            timeout: 500_000,
        }
    }

    #[test]
    fn test_create_htlc_script() {
        let params = sample_params();
        let script = create_htlc_script(&params);
        
        // Should contain OP_IF, OP_ELSE, OP_ENDIF
        assert!(script.contains(&opcodes::OP_IF));
        assert!(script.contains(&opcodes::OP_ELSE));
        assert!(script.contains(&opcodes::OP_ENDIF));
        
        // Should contain OP_SHA256 and OP_CLTV
        assert!(script.contains(&opcodes::OP_SHA256));
        assert!(script.contains(&opcodes::OP_CHECKLOCKTIMEVERIFY));
    }

    #[test]
    fn test_create_claim_script() {
        let signature = vec![0x30; 71]; // Mock DER signature
        let preimage = [0xCD; 32];
        
        let script = create_claim_script(&signature, &preimage);
        
        // Should end with OP_TRUE
        assert_eq!(script.last(), Some(&opcodes::OP_TRUE));
    }

    #[test]
    fn test_create_refund_script() {
        let signature = vec![0x30; 71];
        
        let script = create_refund_script(&signature);
        
        // Should end with OP_FALSE
        assert_eq!(script.last(), Some(&opcodes::OP_FALSE));
    }

    #[test]
    fn test_encode_decode_locktime() {
        let tests = vec![
            0u32,
            100,
            500_000,
            2_016_000,
            0x7FFFFFFF,
        ];
        
        for locktime in tests {
            let encoded = encode_locktime(locktime);
            let decoded = decode_locktime(&encoded);
            assert_eq!(decoded, locktime, "Failed for {}", locktime);
        }
    }

    #[test]
    fn test_script_hash() {
        let params = sample_params();
        let script = create_htlc_script(&params);
        let hash = script_hash(&script);
        
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_disassemble() {
        let params = sample_params();
        let script = create_htlc_script(&params);
        let disasm = disassemble_htlc(&script);
        
        assert!(disasm.contains("OP_IF"));
        assert!(disasm.contains("OP_SHA256"));
        assert!(disasm.contains("OP_CLTV"));
        assert!(disasm.contains("OP_CHECKSIG"));
        assert!(disasm.contains("OP_ENDIF"));
    }
}
