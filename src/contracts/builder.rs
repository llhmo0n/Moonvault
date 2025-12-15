// =============================================================================
// MOONCOIN v2.32 - Smart Contracts: Script Builder & Templates
// =============================================================================
//
// High-level API for creating common script types:
// - P2PKH (Pay to Public Key Hash)
// - P2SH (Pay to Script Hash)
// - P2WPKH (Pay to Witness Public Key Hash)
// - Multisig (M-of-N)
// - Timelock (CLTV, CSV)
// - Hash Lock (HTLC)
// - Custom scripts
//
// =============================================================================

use crate::contracts::opcodes::{Opcode, ScriptElement};
use crate::contracts::engine::{hash160, hash256, ScriptError};

// =============================================================================
// Script Type
// =============================================================================

/// Standard script types
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptType {
    /// Pay to Public Key Hash
    P2PKH,
    /// Pay to Script Hash
    P2SH,
    /// Pay to Witness Public Key Hash
    P2WPKH,
    /// Pay to Witness Script Hash
    P2WSH,
    /// Multisig (m-of-n)
    Multisig { m: u8, n: u8 },
    /// Timelock (absolute)
    TimeLock,
    /// Relative timelock
    RelativeTimeLock,
    /// Hash Time Lock Contract
    HTLC,
    /// OP_RETURN data
    NullData,
    /// Non-standard / custom
    NonStandard,
}

// =============================================================================
// Script (compiled)
// =============================================================================

/// A compiled script
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Script {
    /// Raw bytes
    bytes: Vec<u8>,
    /// Detected type
    script_type: ScriptType,
}

impl Script {
    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let script_type = Self::detect_type(&bytes);
        Script { bytes, script_type }
    }
    
    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Get script type
    pub fn script_type(&self) -> &ScriptType {
        &self.script_type
    }
    
    /// Get script length
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    
    /// Get HASH160 of script (for P2SH)
    pub fn hash160(&self) -> [u8; 20] {
        hash160(&self.bytes)
    }
    
    /// Get SHA256 of script (for P2WSH)
    pub fn sha256(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Detect script type from bytes
    fn detect_type(bytes: &[u8]) -> ScriptType {
        let len = bytes.len();
        
        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        if len == 25 
            && bytes[0] == Opcode::OP_DUP.to_byte()
            && bytes[1] == Opcode::OP_HASH160.to_byte()
            && bytes[2] == 0x14 // Push 20 bytes
            && bytes[23] == Opcode::OP_EQUALVERIFY.to_byte()
            && bytes[24] == Opcode::OP_CHECKSIG.to_byte()
        {
            return ScriptType::P2PKH;
        }
        
        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        if len == 23
            && bytes[0] == Opcode::OP_HASH160.to_byte()
            && bytes[1] == 0x14 // Push 20 bytes
            && bytes[22] == Opcode::OP_EQUAL.to_byte()
        {
            return ScriptType::P2SH;
        }
        
        // P2WPKH: OP_0 <20 bytes>
        if len == 22
            && bytes[0] == Opcode::OP_0.to_byte()
            && bytes[1] == 0x14 // Push 20 bytes
        {
            return ScriptType::P2WPKH;
        }
        
        // P2WSH: OP_0 <32 bytes>
        if len == 34
            && bytes[0] == Opcode::OP_0.to_byte()
            && bytes[1] == 0x20 // Push 32 bytes
        {
            return ScriptType::P2WSH;
        }
        
        // OP_RETURN (null data)
        if len > 0 && bytes[0] == Opcode::OP_RETURN.to_byte() {
            return ScriptType::NullData;
        }
        
        // Multisig: OP_m <pubkeys> OP_n OP_CHECKMULTISIG
        if len >= 37 { // Minimum: OP_1 <33-byte pubkey> OP_1 OP_CHECKMULTISIG
            let last = bytes[len - 1];
            if last == Opcode::OP_CHECKMULTISIG.to_byte() {
                let first = bytes[0];
                if first >= 0x51 && first <= 0x60 { // OP_1 to OP_16
                    // This is likely a multisig
                    let m = first - 0x50;
                    // Find n (second-to-last is OP_n)
                    let second_last = bytes[len - 2];
                    if second_last >= 0x51 && second_last <= 0x60 {
                        let n = second_last - 0x50;
                        return ScriptType::Multisig { m, n };
                    }
                }
            }
        }
        
        // Check for timelock
        if len > 0 {
            for i in 0..len {
                if bytes[i] == Opcode::OP_CHECKLOCKTIMEVERIFY.to_byte() {
                    return ScriptType::TimeLock;
                }
                if bytes[i] == Opcode::OP_CHECKSEQUENCEVERIFY.to_byte() {
                    return ScriptType::RelativeTimeLock;
                }
            }
        }
        
        ScriptType::NonStandard
    }
    
    /// Disassemble to human-readable format
    pub fn disassemble(&self) -> String {
        let mut result = String::new();
        let mut i = 0;
        
        while i < self.bytes.len() {
            if i > 0 {
                result.push(' ');
            }
            
            let byte = self.bytes[i];
            
            // Handle push opcodes
            if byte >= 0x01 && byte <= 0x4B {
                let len = byte as usize;
                if i + 1 + len <= self.bytes.len() {
                    let data = &self.bytes[i + 1..i + 1 + len];
                    result.push_str(&format!("<{}>", hex::encode(data)));
                    i += 1 + len;
                    continue;
                }
            }
            
            // Handle PUSHDATA1
            if byte == Opcode::OP_PUSHDATA1.to_byte() {
                if i + 1 < self.bytes.len() {
                    let len = self.bytes[i + 1] as usize;
                    if i + 2 + len <= self.bytes.len() {
                        let data = &self.bytes[i + 2..i + 2 + len];
                        result.push_str(&format!("<{}>", hex::encode(data)));
                        i += 2 + len;
                        continue;
                    }
                }
            }
            
            // Regular opcode
            if let Some(op) = Opcode::from_byte(byte) {
                result.push_str(op.name());
            } else {
                result.push_str(&format!("0x{:02x}", byte));
            }
            
            i += 1;
        }
        
        result
    }
}

impl std::fmt::Display for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.disassemble())
    }
}

// =============================================================================
// Script Builder
// =============================================================================

/// Builder for creating scripts fluently
#[derive(Clone, Debug, Default)]
pub struct ScriptBuilder {
    elements: Vec<ScriptElement>,
}

impl ScriptBuilder {
    /// Create new builder
    pub fn new() -> Self {
        ScriptBuilder { elements: Vec::new() }
    }
    
    /// Add an opcode
    pub fn op(mut self, opcode: Opcode) -> Self {
        self.elements.push(ScriptElement::Op(opcode));
        self
    }
    
    /// Push data
    pub fn push_data(mut self, data: impl AsRef<[u8]>) -> Self {
        self.elements.push(ScriptElement::Data(data.as_ref().to_vec()));
        self
    }
    
    /// Push a number
    pub fn push_num(self, num: i64) -> Self {
        if num == 0 {
            return self.op(Opcode::OP_0);
        }
        if num >= 1 && num <= 16 {
            let opcode = Opcode::from_byte(0x50 + num as u8).unwrap();
            return self.op(opcode);
        }
        if num == -1 {
            return self.op(Opcode::OP_1NEGATE);
        }
        
        // Encode as bytes
        let bytes = encode_num(num);
        self.push_data(bytes)
    }
    
    /// Push a hash160
    pub fn push_hash160(self, hash: &[u8; 20]) -> Self {
        self.push_data(hash)
    }
    
    /// Push a hash256
    pub fn push_hash256(self, hash: &[u8; 32]) -> Self {
        self.push_data(hash)
    }
    
    /// Push a public key
    pub fn push_pubkey(self, pubkey: &[u8]) -> Self {
        self.push_data(pubkey)
    }
    
    /// Push a signature
    pub fn push_sig(self, sig: &[u8]) -> Self {
        self.push_data(sig)
    }
    
    /// Build the script
    pub fn build(self) -> Script {
        let mut bytes = Vec::new();
        for element in self.elements {
            bytes.extend(element.serialize());
        }
        Script::from_bytes(bytes)
    }
    
    // =========================================================================
    // Standard Script Templates
    // =========================================================================
    
    /// Create P2PKH scriptPubKey
    /// OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    pub fn p2pkh(pubkey_hash: &[u8; 20]) -> Script {
        ScriptBuilder::new()
            .op(Opcode::OP_DUP)
            .op(Opcode::OP_HASH160)
            .push_hash160(pubkey_hash)
            .op(Opcode::OP_EQUALVERIFY)
            .op(Opcode::OP_CHECKSIG)
            .build()
    }
    
    /// Create P2PKH scriptSig (unlock script)
    /// <signature> <pubkey>
    pub fn p2pkh_unlock(sig: &[u8], pubkey: &[u8]) -> Script {
        ScriptBuilder::new()
            .push_sig(sig)
            .push_pubkey(pubkey)
            .build()
    }
    
    /// Create P2SH scriptPubKey
    /// OP_HASH160 <script_hash> OP_EQUAL
    pub fn p2sh(script_hash: &[u8; 20]) -> Script {
        ScriptBuilder::new()
            .op(Opcode::OP_HASH160)
            .push_hash160(script_hash)
            .op(Opcode::OP_EQUAL)
            .build()
    }
    
    /// Create P2SH from a redeem script
    pub fn p2sh_from_script(redeem_script: &Script) -> Script {
        Self::p2sh(&redeem_script.hash160())
    }
    
    /// Create P2WPKH scriptPubKey
    /// OP_0 <pubkey_hash>
    pub fn p2wpkh(pubkey_hash: &[u8; 20]) -> Script {
        ScriptBuilder::new()
            .op(Opcode::OP_0)
            .push_hash160(pubkey_hash)
            .build()
    }
    
    /// Create P2WSH scriptPubKey
    /// OP_0 <script_hash>
    pub fn p2wsh(script_hash: &[u8; 32]) -> Script {
        ScriptBuilder::new()
            .op(Opcode::OP_0)
            .push_hash256(script_hash)
            .build()
    }
    
    /// Create multisig script (m-of-n)
    /// OP_m <pubkey1> <pubkey2> ... <pubkeyn> OP_n OP_CHECKMULTISIG
    pub fn multisig(m: u8, pubkeys: &[Vec<u8>]) -> Result<Script, ScriptError> {
        let n = pubkeys.len() as u8;
        
        if m == 0 || m > n {
            return Err(ScriptError::InvalidMultisig);
        }
        if n > 20 {
            return Err(ScriptError::TooManyPubKeys);
        }
        
        let mut builder = ScriptBuilder::new().push_num(m as i64);
        
        for pubkey in pubkeys {
            builder = builder.push_pubkey(pubkey);
        }
        
        Ok(builder
            .push_num(n as i64)
            .op(Opcode::OP_CHECKMULTISIG)
            .build())
    }
    
    /// Create timelock script (CLTV)
    /// <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <inner_script>
    pub fn timelock(locktime: u32, inner_script: &Script) -> Script {
        let builder = ScriptBuilder::new()
            .push_num(locktime as i64)
            .op(Opcode::OP_CHECKLOCKTIMEVERIFY)
            .op(Opcode::OP_DROP);
        
        // Append inner script bytes
        let mut bytes = builder.build().bytes;
        bytes.extend_from_slice(inner_script.as_bytes());
        Script::from_bytes(bytes)
    }
    
    /// Create relative timelock script (CSV)
    /// <sequence> OP_CHECKSEQUENCEVERIFY OP_DROP <inner_script>
    pub fn relative_timelock(sequence: u32, inner_script: &Script) -> Script {
        let builder = ScriptBuilder::new()
            .push_num(sequence as i64)
            .op(Opcode::OP_CHECKSEQUENCEVERIFY)
            .op(Opcode::OP_DROP);
        
        let mut bytes = builder.build().bytes;
        bytes.extend_from_slice(inner_script.as_bytes());
        Script::from_bytes(bytes)
    }
    
    /// Create Hash Time Lock Contract (HTLC)
    /// IF
    ///   OP_SHA256 <hash> OP_EQUALVERIFY <receiver_pubkey> OP_CHECKSIG
    /// ELSE
    ///   <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <sender_pubkey> OP_CHECKSIG
    /// ENDIF
    pub fn htlc(
        hash: &[u8; 32],
        receiver_pubkey: &[u8],
        sender_pubkey: &[u8],
        locktime: u32,
    ) -> Script {
        ScriptBuilder::new()
            .op(Opcode::OP_IF)
                // Hash path (receiver can claim with preimage)
                .op(Opcode::OP_SHA256)
                .push_hash256(hash)
                .op(Opcode::OP_EQUALVERIFY)
                .push_pubkey(receiver_pubkey)
                .op(Opcode::OP_CHECKSIG)
            .op(Opcode::OP_ELSE)
                // Timeout path (sender can reclaim after locktime)
                .push_num(locktime as i64)
                .op(Opcode::OP_CHECKLOCKTIMEVERIFY)
                .op(Opcode::OP_DROP)
                .push_pubkey(sender_pubkey)
                .op(Opcode::OP_CHECKSIG)
            .op(Opcode::OP_ENDIF)
            .build()
    }
    
    /// Create OP_RETURN data output (provably unspendable)
    pub fn null_data(data: &[u8]) -> Script {
        ScriptBuilder::new()
            .op(Opcode::OP_RETURN)
            .push_data(data)
            .build()
    }
    
    /// Create escrow script (2-of-3 with timeout)
    /// Either 2-of-3 multisig, or after timeout, 1-of-1 arbiter
    pub fn escrow(
        buyer_pubkey: &[u8],
        seller_pubkey: &[u8],
        arbiter_pubkey: &[u8],
        timeout: u32,
    ) -> Script {
        ScriptBuilder::new()
            .op(Opcode::OP_IF)
                // Normal 2-of-3 multisig
                .push_num(2)
                .push_pubkey(buyer_pubkey)
                .push_pubkey(seller_pubkey)
                .push_pubkey(arbiter_pubkey)
                .push_num(3)
                .op(Opcode::OP_CHECKMULTISIG)
            .op(Opcode::OP_ELSE)
                // Timeout: arbiter can release unilaterally
                .push_num(timeout as i64)
                .op(Opcode::OP_CHECKLOCKTIMEVERIFY)
                .op(Opcode::OP_DROP)
                .push_pubkey(arbiter_pubkey)
                .op(Opcode::OP_CHECKSIG)
            .op(Opcode::OP_ENDIF)
            .build()
    }
}

// =============================================================================
// Address
// =============================================================================

/// A Mooncoin address
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// Address type
    pub address_type: AddressType,
    /// Hash (20 or 32 bytes)
    pub hash: Vec<u8>,
}

/// Address types
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressType {
    /// Pay to Public Key Hash (legacy)
    P2PKH,
    /// Pay to Script Hash
    P2SH,
    /// Pay to Witness Public Key Hash (native SegWit)
    P2WPKH,
    /// Pay to Witness Script Hash
    P2WSH,
}

impl Address {
    /// Create P2PKH address from public key
    pub fn p2pkh_from_pubkey(pubkey: &[u8]) -> Self {
        Address {
            address_type: AddressType::P2PKH,
            hash: hash160(pubkey).to_vec(),
        }
    }
    
    /// Create P2SH address from script
    pub fn p2sh_from_script(script: &Script) -> Self {
        Address {
            address_type: AddressType::P2SH,
            hash: script.hash160().to_vec(),
        }
    }
    
    /// Create P2WPKH address from public key
    pub fn p2wpkh_from_pubkey(pubkey: &[u8]) -> Self {
        Address {
            address_type: AddressType::P2WPKH,
            hash: hash160(pubkey).to_vec(),
        }
    }
    
    /// Get the scriptPubKey for this address
    pub fn to_script(&self) -> Script {
        match self.address_type {
            AddressType::P2PKH => {
                let hash: [u8; 20] = self.hash.clone().try_into().unwrap();
                ScriptBuilder::p2pkh(&hash)
            }
            AddressType::P2SH => {
                let hash: [u8; 20] = self.hash.clone().try_into().unwrap();
                ScriptBuilder::p2sh(&hash)
            }
            AddressType::P2WPKH => {
                let hash: [u8; 20] = self.hash.clone().try_into().unwrap();
                ScriptBuilder::p2wpkh(&hash)
            }
            AddressType::P2WSH => {
                let hash: [u8; 32] = self.hash.clone().try_into().unwrap();
                ScriptBuilder::p2wsh(&hash)
            }
        }
    }
    
    /// Encode to string (Base58Check for legacy, Bech32 for SegWit)
    pub fn encode(&self) -> String {
        match self.address_type {
            AddressType::P2PKH => {
                // Mainnet P2PKH: version 0x00
                encode_base58check(0x00, &self.hash)
            }
            AddressType::P2SH => {
                // Mainnet P2SH: version 0x05
                encode_base58check(0x05, &self.hash)
            }
            AddressType::P2WPKH | AddressType::P2WSH => {
                // Bech32 encoding (simplified)
                format!("moon1{}", hex::encode(&self.hash))
            }
        }
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Encode number to script format
fn encode_num(num: i64) -> Vec<u8> {
    if num == 0 {
        return vec![];
    }
    
    let negative = num < 0;
    let mut abs_val = num.abs() as u64;
    let mut result = Vec::new();
    
    while abs_val > 0 {
        result.push((abs_val & 0xFF) as u8);
        abs_val >>= 8;
    }
    
    if result[result.len() - 1] & 0x80 != 0 {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let len = result.len();
        result[len - 1] |= 0x80;
    }
    
    result
}

/// Base58 alphabet
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode to Base58Check
fn encode_base58check(version: u8, data: &[u8]) -> String {
    let mut payload = vec![version];
    payload.extend_from_slice(data);
    
    // Add checksum (first 4 bytes of double SHA256)
    let checksum = hash256(&payload);
    payload.extend_from_slice(&checksum[0..4]);
    
    // Convert to Base58
    let mut result = String::new();
    
    // Count leading zeros
    let mut leading_zeros = 0;
    for &byte in &payload {
        if byte == 0 {
            leading_zeros += 1;
        } else {
            break;
        }
    }
    
    // Convert bytes to big integer and then to base58
    let mut num = payload.iter().fold(num_bigint::BigUint::from(0u32), |acc, &b| {
        acc * 256u32 + b as u32
    });
    
    let fifty_eight = num_bigint::BigUint::from(58u32);
    let zero = num_bigint::BigUint::from(0u32);
    
    while num > zero {
        let remainder = (&num % &fifty_eight).to_u32_digits();
        let idx = if remainder.is_empty() { 0 } else { remainder[0] as usize };
        result.push(BASE58_ALPHABET[idx] as char);
        num = num / &fifty_eight;
    }
    
    // Add leading '1's for each leading zero byte
    for _ in 0..leading_zeros {
        result.push('1');
    }
    
    result.chars().rev().collect()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_p2pkh_script() {
        let pubkey_hash = [0u8; 20];
        let script = ScriptBuilder::p2pkh(&pubkey_hash);
        
        assert_eq!(script.script_type(), &ScriptType::P2PKH);
        assert_eq!(script.len(), 25);
    }
    
    #[test]
    fn test_p2sh_script() {
        let script_hash = [0u8; 20];
        let script = ScriptBuilder::p2sh(&script_hash);
        
        assert_eq!(script.script_type(), &ScriptType::P2SH);
        assert_eq!(script.len(), 23);
    }
    
    #[test]
    fn test_multisig() {
        let pubkeys = vec![
            vec![0x02; 33],
            vec![0x03; 33],
            vec![0x04; 33],
        ];
        
        let script = ScriptBuilder::multisig(2, &pubkeys).unwrap();
        
        match script.script_type() {
            ScriptType::Multisig { m, n } => {
                assert_eq!(*m, 2);
                assert_eq!(*n, 3);
            }
            _ => panic!("Expected multisig type"),
        }
    }
    
    #[test]
    fn test_htlc() {
        let hash = [0u8; 32];
        let receiver = vec![0x02; 33];
        let sender = vec![0x03; 33];
        
        let script = ScriptBuilder::htlc(&hash, &receiver, &sender, 500000);
        
        // Should contain both CLTV and hash check
        let disasm = script.disassemble();
        assert!(disasm.contains("OP_IF"));
        assert!(disasm.contains("OP_SHA256"));
        assert!(disasm.contains("OP_CHECKLOCKTIMEVERIFY"));
        assert!(disasm.contains("OP_ENDIF"));
    }
    
    #[test]
    fn test_disassemble() {
        let script = ScriptBuilder::new()
            .op(Opcode::OP_DUP)
            .op(Opcode::OP_HASH160)
            .push_data(vec![0x01, 0x02, 0x03])
            .op(Opcode::OP_EQUALVERIFY)
            .build();
        
        let disasm = script.disassemble();
        assert!(disasm.contains("OP_DUP"));
        assert!(disasm.contains("OP_HASH160"));
        assert!(disasm.contains("010203"));
        assert!(disasm.contains("OP_EQUALVERIFY"));
    }
    
    #[test]
    fn test_address_encoding() {
        let pubkey = [0x02; 33];
        let addr = Address::p2pkh_from_pubkey(&pubkey);
        
        let encoded = addr.encode();
        assert!(encoded.starts_with('1') || encoded.starts_with('m'));
    }
}
