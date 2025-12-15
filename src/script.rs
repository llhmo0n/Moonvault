// =============================================================================
// MOONCOIN v2.0 - Script System (Bitcoin-style)
// =============================================================================
//
// Implementa un lenguaje de scripts stack-based como Bitcoin.
// Soporta P2PKH (Pay to Public Key Hash) y P2SH (Pay to Script Hash)
//
// Ejemplo P2PKH:
//   scriptPubKey: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
//   scriptSig:    <signature> <pubKey>
//
// =============================================================================

use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use secp256k1::{Secp256k1, Message, PublicKey, ecdsa::Signature};

// =============================================================================
// Opcodes
// =============================================================================

#[derive(Clone, Debug, PartialEq)]
pub enum OpCode {
    // Constants
    Op0,                    // Push empty byte array
    OpPushData(Vec<u8>),    // Push data onto stack
    Op1,                    // Push 1
    Op2,                    // Push 2
    Op3,                    // Push 3
    OpTrue,                 // Push 1 (alias)
    OpFalse,                // Push 0 (alias)
    
    // Flow control
    OpIf,
    OpNotIf,
    OpElse,
    OpEndIf,
    OpVerify,               // Fail if top is false
    OpReturn,               // Mark as unspendable
    
    // Stack operations
    OpDup,                  // Duplicate top item
    OpDrop,                 // Remove top item
    OpSwap,                 // Swap top two items
    Op2Dup,                 // Duplicate top two items
    OpOver,                 // Copy second item to top
    OpRot,                  // Rotate top three items
    OpPick,                 // Copy nth item to top
    OpRoll,                 // Move nth item to top
    
    // Bitwise logic
    OpEqual,                // Check if top two are equal
    OpEqualVerify,          // Equal + Verify
    
    // Arithmetic
    OpAdd,                  // Add top two
    OpSub,                  // Subtract
    Op1Add,                 // Add 1
    Op1Sub,                 // Subtract 1
    OpNegate,               // Negate
    OpAbs,                  // Absolute value
    OpNot,                  // Logical not
    Op0NotEqual,            // True if not 0
    OpNumEqual,             // Numeric equal
    OpNumEqualVerify,       // NumEqual + Verify
    OpNumNotEqual,          // Numeric not equal
    OpLessThan,             // Less than
    OpGreaterThan,          // Greater than
    OpLessThanOrEqual,      // Less than or equal
    OpGreaterThanOrEqual,   // Greater than or equal
    OpMin,                  // Minimum of two
    OpMax,                  // Maximum of two
    OpWithin,               // Check if value within range
    
    // Crypto
    OpRipemd160,            // RIPEMD-160 hash
    OpSha256,               // SHA-256 hash
    OpHash160,              // SHA-256 then RIPEMD-160
    OpHash256,              // Double SHA-256
    OpCheckSig,             // Verify signature
    OpCheckSigVerify,       // CheckSig + Verify
    OpCheckMultiSig,        // Verify m-of-n signatures
    OpCheckMultiSigVerify,  // CheckMultiSig + Verify
    
    // Locktime
    OpCheckLockTimeVerify,  // CLTV (BIP65)
    OpCheckSequenceVerify,  // CSV (BIP112)
    
    // Reserved/NOP
    OpNop,
    OpNop1,
    OpNop4,
    OpNop5,
    OpNop6,
    OpNop7,
    OpNop8,
    OpNop9,
    OpNop10,
}

impl OpCode {
    /// Convierte un byte a OpCode
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(OpCode::Op0),
            0x01..=0x4b => None, // Push data directamente (manejado por parser)
            0x4c => None, // OP_PUSHDATA1
            0x4d => None, // OP_PUSHDATA2
            0x4e => None, // OP_PUSHDATA4
            0x4f => Some(OpCode::Op1), // OP_1NEGATE en Bitcoin, usamos como Op1
            0x51 => Some(OpCode::Op1),
            0x52 => Some(OpCode::Op2),
            0x53 => Some(OpCode::Op3),
            0x61 => Some(OpCode::OpNop),
            0x63 => Some(OpCode::OpIf),
            0x64 => Some(OpCode::OpNotIf),
            0x67 => Some(OpCode::OpElse),
            0x68 => Some(OpCode::OpEndIf),
            0x69 => Some(OpCode::OpVerify),
            0x6a => Some(OpCode::OpReturn),
            0x76 => Some(OpCode::OpDup),
            0x75 => Some(OpCode::OpDrop),
            0x7c => Some(OpCode::OpSwap),
            0x6e => Some(OpCode::Op2Dup),
            0x78 => Some(OpCode::OpOver),
            0x7b => Some(OpCode::OpRot),
            0x79 => Some(OpCode::OpPick),
            0x7a => Some(OpCode::OpRoll),
            0x87 => Some(OpCode::OpEqual),
            0x88 => Some(OpCode::OpEqualVerify),
            0x93 => Some(OpCode::OpAdd),
            0x94 => Some(OpCode::OpSub),
            0x8b => Some(OpCode::Op1Add),
            0x8c => Some(OpCode::Op1Sub),
            0x8f => Some(OpCode::OpNegate),
            0x90 => Some(OpCode::OpAbs),
            0x91 => Some(OpCode::OpNot),
            0x92 => Some(OpCode::Op0NotEqual),
            0x9c => Some(OpCode::OpNumEqual),
            0x9d => Some(OpCode::OpNumEqualVerify),
            0x9e => Some(OpCode::OpNumNotEqual),
            0x9f => Some(OpCode::OpLessThan),
            0xa0 => Some(OpCode::OpGreaterThan),
            0xa1 => Some(OpCode::OpLessThanOrEqual),
            0xa2 => Some(OpCode::OpGreaterThanOrEqual),
            0xa3 => Some(OpCode::OpMin),
            0xa4 => Some(OpCode::OpMax),
            0xa5 => Some(OpCode::OpWithin),
            0xa6 => Some(OpCode::OpRipemd160),
            0xa8 => Some(OpCode::OpSha256),
            0xa9 => Some(OpCode::OpHash160),
            0xaa => Some(OpCode::OpHash256),
            0xac => Some(OpCode::OpCheckSig),
            0xad => Some(OpCode::OpCheckSigVerify),
            0xae => Some(OpCode::OpCheckMultiSig),
            0xaf => Some(OpCode::OpCheckMultiSigVerify),
            0xb1 => Some(OpCode::OpCheckLockTimeVerify),
            0xb2 => Some(OpCode::OpCheckSequenceVerify),
            _ => None,
        }
    }
    
    /// Convierte OpCode a byte
    pub fn to_byte(&self) -> u8 {
        match self {
            OpCode::Op0 => 0x00,
            OpCode::OpPushData(_) => 0x00, // Handled specially
            OpCode::Op1 | OpCode::OpTrue => 0x51,
            OpCode::Op2 => 0x52,
            OpCode::Op3 => 0x53,
            OpCode::OpFalse => 0x00,
            OpCode::OpNop => 0x61,
            OpCode::OpIf => 0x63,
            OpCode::OpNotIf => 0x64,
            OpCode::OpElse => 0x67,
            OpCode::OpEndIf => 0x68,
            OpCode::OpVerify => 0x69,
            OpCode::OpReturn => 0x6a,
            OpCode::OpDup => 0x76,
            OpCode::OpDrop => 0x75,
            OpCode::OpSwap => 0x7c,
            OpCode::Op2Dup => 0x6e,
            OpCode::OpOver => 0x78,
            OpCode::OpRot => 0x7b,
            OpCode::OpPick => 0x79,
            OpCode::OpRoll => 0x7a,
            OpCode::OpEqual => 0x87,
            OpCode::OpEqualVerify => 0x88,
            OpCode::OpAdd => 0x93,
            OpCode::OpSub => 0x94,
            OpCode::Op1Add => 0x8b,
            OpCode::Op1Sub => 0x8c,
            OpCode::OpNegate => 0x8f,
            OpCode::OpAbs => 0x90,
            OpCode::OpNot => 0x91,
            OpCode::Op0NotEqual => 0x92,
            OpCode::OpNumEqual => 0x9c,
            OpCode::OpNumEqualVerify => 0x9d,
            OpCode::OpNumNotEqual => 0x9e,
            OpCode::OpLessThan => 0x9f,
            OpCode::OpGreaterThan => 0xa0,
            OpCode::OpLessThanOrEqual => 0xa1,
            OpCode::OpGreaterThanOrEqual => 0xa2,
            OpCode::OpMin => 0xa3,
            OpCode::OpMax => 0xa4,
            OpCode::OpWithin => 0xa5,
            OpCode::OpRipemd160 => 0xa6,
            OpCode::OpSha256 => 0xa8,
            OpCode::OpHash160 => 0xa9,
            OpCode::OpHash256 => 0xaa,
            OpCode::OpCheckSig => 0xac,
            OpCode::OpCheckSigVerify => 0xad,
            OpCode::OpCheckMultiSig => 0xae,
            OpCode::OpCheckMultiSigVerify => 0xaf,
            OpCode::OpCheckLockTimeVerify => 0xb1,
            OpCode::OpCheckSequenceVerify => 0xb2,
            OpCode::OpNop1 => 0xb0,
            OpCode::OpNop4 => 0xb3,
            OpCode::OpNop5 => 0xb4,
            OpCode::OpNop6 => 0xb5,
            OpCode::OpNop7 => 0xb6,
            OpCode::OpNop8 => 0xb7,
            OpCode::OpNop9 => 0xb8,
            OpCode::OpNop10 => 0xb9,
        }
    }
}

// =============================================================================
// Script
// =============================================================================

/// Un script es una secuencia de opcodes
#[derive(Clone, Debug, Default)]
pub struct Script {
    pub ops: Vec<OpCode>,
}

impl Script {
    pub fn new() -> Self {
        Script { ops: Vec::new() }
    }
    
    /// Crea un script desde bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut script = Script::new();
        let mut i = 0;
        
        while i < bytes.len() {
            let b = bytes[i];
            
            if b == 0x00 {
                script.ops.push(OpCode::Op0);
                i += 1;
            } else if b >= 0x01 && b <= 0x4b {
                // Push data directly (1-75 bytes)
                let len = b as usize;
                if i + 1 + len > bytes.len() {
                    return Err("Invalid push data length".to_string());
                }
                let data = bytes[i + 1..i + 1 + len].to_vec();
                script.ops.push(OpCode::OpPushData(data));
                i += 1 + len;
            } else if b == 0x4c {
                // OP_PUSHDATA1: next byte is length
                if i + 1 >= bytes.len() {
                    return Err("Missing PUSHDATA1 length".to_string());
                }
                let len = bytes[i + 1] as usize;
                if i + 2 + len > bytes.len() {
                    return Err("Invalid PUSHDATA1 length".to_string());
                }
                let data = bytes[i + 2..i + 2 + len].to_vec();
                script.ops.push(OpCode::OpPushData(data));
                i += 2 + len;
            } else if b == 0x4d {
                // OP_PUSHDATA2: next 2 bytes are length (little endian)
                if i + 2 >= bytes.len() {
                    return Err("Missing PUSHDATA2 length".to_string());
                }
                let len = u16::from_le_bytes([bytes[i + 1], bytes[i + 2]]) as usize;
                if i + 3 + len > bytes.len() {
                    return Err("Invalid PUSHDATA2 length".to_string());
                }
                let data = bytes[i + 3..i + 3 + len].to_vec();
                script.ops.push(OpCode::OpPushData(data));
                i += 3 + len;
            } else if let Some(op) = OpCode::from_byte(b) {
                script.ops.push(op);
                i += 1;
            } else {
                // Unknown opcode, skip
                i += 1;
            }
        }
        
        Ok(script)
    }
    
    /// Serializa el script a bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        for op in &self.ops {
            match op {
                OpCode::OpPushData(data) => {
                    let len = data.len();
                    if len <= 75 {
                        bytes.push(len as u8);
                        bytes.extend(data);
                    } else if len <= 255 {
                        bytes.push(0x4c);
                        bytes.push(len as u8);
                        bytes.extend(data);
                    } else {
                        bytes.push(0x4d);
                        bytes.extend(&(len as u16).to_le_bytes());
                        bytes.extend(data);
                    }
                }
                _ => bytes.push(op.to_byte()),
            }
        }
        
        bytes
    }
    
    /// Crea un script P2PKH (Pay to Public Key Hash)
    /// OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    pub fn p2pkh(pubkey_hash: &[u8]) -> Self {
        Script {
            ops: vec![
                OpCode::OpDup,
                OpCode::OpHash160,
                OpCode::OpPushData(pubkey_hash.to_vec()),
                OpCode::OpEqualVerify,
                OpCode::OpCheckSig,
            ],
        }
    }
    
    /// Crea un scriptSig para P2PKH
    /// <signature> <pubKey>
    pub fn p2pkh_sig(signature: &[u8], pubkey: &[u8]) -> Self {
        Script {
            ops: vec![
                OpCode::OpPushData(signature.to_vec()),
                OpCode::OpPushData(pubkey.to_vec()),
            ],
        }
    }
    
    /// Crea un script P2SH (Pay to Script Hash)
    /// OP_HASH160 <scriptHash> OP_EQUAL
    pub fn p2sh(script_hash: &[u8]) -> Self {
        Script {
            ops: vec![
                OpCode::OpHash160,
                OpCode::OpPushData(script_hash.to_vec()),
                OpCode::OpEqual,
            ],
        }
    }
    
    /// Crea un script multisig (m-of-n)
    /// OP_m <pubKey1> <pubKey2> ... <pubKeyN> OP_n OP_CHECKMULTISIG
    pub fn multisig(required: u8, pubkeys: &[Vec<u8>]) -> Self {
        let mut ops = vec![Self::num_to_op(required as i64)];
        
        for pk in pubkeys {
            ops.push(OpCode::OpPushData(pk.clone()));
        }
        
        ops.push(Self::num_to_op(pubkeys.len() as i64));
        ops.push(OpCode::OpCheckMultiSig);
        
        Script { ops }
    }
    
    /// Crea un script con timelock (CLTV)
    /// <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <normal_script>
    pub fn with_cltv(locktime: u32, inner_script: Script) -> Self {
        let mut ops = vec![
            OpCode::OpPushData(locktime.to_le_bytes().to_vec()),
            OpCode::OpCheckLockTimeVerify,
            OpCode::OpDrop,
        ];
        ops.extend(inner_script.ops);
        Script { ops }
    }
    
    /// Convierte un número a opcode
    fn num_to_op(n: i64) -> OpCode {
        match n {
            0 => OpCode::Op0,
            1 => OpCode::Op1,
            2 => OpCode::Op2,
            3 => OpCode::Op3,
            _ => OpCode::OpPushData(Self::encode_num(n)),
        }
    }
    
    /// Codifica un número como bytes (formato Bitcoin)
    fn encode_num(n: i64) -> Vec<u8> {
        if n == 0 {
            return vec![];
        }
        
        let negative = n < 0;
        let mut abs_n = n.abs() as u64;
        let mut result = Vec::new();
        
        while abs_n > 0 {
            result.push((abs_n & 0xff) as u8);
            abs_n >>= 8;
        }
        
        // Handle sign
        if result.last().map_or(false, |&b| b & 0x80 != 0) {
            result.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            let last = result.len() - 1;
            result[last] |= 0x80;
        }
        
        result
    }
    
    /// Verifica si es un script P2PKH
    pub fn is_p2pkh(&self) -> bool {
        self.ops.len() == 5
            && self.ops[0] == OpCode::OpDup
            && self.ops[1] == OpCode::OpHash160
            && matches!(&self.ops[2], OpCode::OpPushData(d) if d.len() == 20)
            && self.ops[3] == OpCode::OpEqualVerify
            && self.ops[4] == OpCode::OpCheckSig
    }
    
    /// Verifica si es un script P2SH
    pub fn is_p2sh(&self) -> bool {
        self.ops.len() == 3
            && self.ops[0] == OpCode::OpHash160
            && matches!(&self.ops[1], OpCode::OpPushData(d) if d.len() == 20)
            && self.ops[2] == OpCode::OpEqual
    }
    
    /// Extrae el hash del pubkey de un script P2PKH
    pub fn get_p2pkh_hash(&self) -> Option<Vec<u8>> {
        if self.is_p2pkh() {
            if let OpCode::OpPushData(hash) = &self.ops[2] {
                return Some(hash.clone());
            }
        }
        None
    }
}

// =============================================================================
// Script Execution Engine
// =============================================================================

/// Contexto de ejecución de script
pub struct ScriptContext {
    /// Hash de la transacción para verificar firmas
    pub tx_hash: [u8; 32],
    /// Locktime de la transacción
    pub locktime: u32,
    /// Sequence del input
    pub sequence: u32,
    /// Altura actual del bloque
    pub block_height: u64,
}

/// Motor de ejecución de scripts
pub struct ScriptEngine {
    stack: Vec<Vec<u8>>,
    alt_stack: Vec<Vec<u8>>,
    context: ScriptContext,
}

impl ScriptEngine {
    pub fn new(context: ScriptContext) -> Self {
        ScriptEngine {
            stack: Vec::new(),
            alt_stack: Vec::new(),
            context,
        }
    }
    
    /// Ejecuta un script completo (scriptSig + scriptPubKey)
    pub fn verify(&mut self, script_sig: &Script, script_pubkey: &Script) -> Result<bool, String> {
        // Primero ejecutar scriptSig
        self.execute(script_sig)?;
        
        // Guardar el stack para P2SH
        let stack_copy = self.stack.clone();
        
        // Ejecutar scriptPubKey
        self.execute(script_pubkey)?;
        
        // Verificar resultado
        if self.stack.is_empty() {
            return Ok(false);
        }
        
        let result = self.stack.pop().unwrap();
        if !Self::is_true(&result) {
            return Ok(false);
        }
        
        // P2SH: si el scriptPubKey es P2SH, deserializar y ejecutar el script real
        if script_pubkey.is_p2sh() && !stack_copy.is_empty() {
            // El último elemento del stack original es el serialized script
            let serialized_script = &stack_copy[stack_copy.len() - 1];
            let redeem_script = Script::from_bytes(serialized_script)?;
            
            // Restaurar stack (sin el serialized script)
            self.stack = stack_copy[..stack_copy.len() - 1].to_vec();
            
            // Ejecutar redeem script
            self.execute(&redeem_script)?;
            
            if self.stack.is_empty() {
                return Ok(false);
            }
            
            let p2sh_result = self.stack.pop().unwrap();
            return Ok(Self::is_true(&p2sh_result));
        }
        
        Ok(true)
    }
    
    /// Ejecuta un script
    pub fn execute(&mut self, script: &Script) -> Result<(), String> {
        let mut if_stack: Vec<bool> = Vec::new();
        
        for op in &script.ops {
            // Check if we're in a false branch
            let executing = if_stack.iter().all(|&b| b);
            
            match op {
                // Control flow (always process)
                OpCode::OpIf => {
                    if executing {
                        let val = self.pop()?;
                        if_stack.push(Self::is_true(&val));
                    } else {
                        if_stack.push(false);
                    }
                }
                OpCode::OpNotIf => {
                    if executing {
                        let val = self.pop()?;
                        if_stack.push(!Self::is_true(&val));
                    } else {
                        if_stack.push(false);
                    }
                }
                OpCode::OpElse => {
                    if let Some(last) = if_stack.last_mut() {
                        *last = !*last;
                    }
                }
                OpCode::OpEndIf => {
                    if_stack.pop();
                }
                
                // Skip if not executing
                _ if !executing => continue,
                
                // Constants
                OpCode::Op0 | OpCode::OpFalse => self.stack.push(vec![]),
                OpCode::Op1 | OpCode::OpTrue => self.stack.push(vec![1]),
                OpCode::Op2 => self.stack.push(vec![2]),
                OpCode::Op3 => self.stack.push(vec![3]),
                OpCode::OpPushData(data) => self.stack.push(data.clone()),
                
                // Stack ops
                OpCode::OpDup => {
                    let top = self.peek()?;
                    self.stack.push(top);
                }
                OpCode::OpDrop => { self.pop()?; }
                OpCode::OpSwap => {
                    let a = self.pop()?;
                    let b = self.pop()?;
                    self.stack.push(a);
                    self.stack.push(b);
                }
                OpCode::Op2Dup => {
                    if self.stack.len() < 2 {
                        return Err("Stack underflow".to_string());
                    }
                    let a = self.stack[self.stack.len() - 2].clone();
                    let b = self.stack[self.stack.len() - 1].clone();
                    self.stack.push(a);
                    self.stack.push(b);
                }
                OpCode::OpOver => {
                    if self.stack.len() < 2 {
                        return Err("Stack underflow".to_string());
                    }
                    let val = self.stack[self.stack.len() - 2].clone();
                    self.stack.push(val);
                }
                OpCode::OpRot => {
                    if self.stack.len() < 3 {
                        return Err("Stack underflow".to_string());
                    }
                    let len = self.stack.len();
                    let val = self.stack.remove(len - 3);
                    self.stack.push(val);
                }
                
                // Verification
                OpCode::OpVerify => {
                    let val = self.pop()?;
                    if !Self::is_true(&val) {
                        return Err("OP_VERIFY failed".to_string());
                    }
                }
                OpCode::OpReturn => {
                    return Err("OP_RETURN: script is unspendable".to_string());
                }
                
                // Equality
                OpCode::OpEqual => {
                    let a = self.pop()?;
                    let b = self.pop()?;
                    self.stack.push(if a == b { vec![1] } else { vec![] });
                }
                OpCode::OpEqualVerify => {
                    let a = self.pop()?;
                    let b = self.pop()?;
                    if a != b {
                        return Err("OP_EQUALVERIFY failed".to_string());
                    }
                }
                
                // Arithmetic
                OpCode::OpAdd => {
                    let a = self.pop_num()?;
                    let b = self.pop_num()?;
                    self.push_num(a + b);
                }
                OpCode::OpSub => {
                    let a = self.pop_num()?;
                    let b = self.pop_num()?;
                    self.push_num(b - a);
                }
                OpCode::Op1Add => {
                    let a = self.pop_num()?;
                    self.push_num(a + 1);
                }
                OpCode::Op1Sub => {
                    let a = self.pop_num()?;
                    self.push_num(a - 1);
                }
                OpCode::OpNegate => {
                    let a = self.pop_num()?;
                    self.push_num(-a);
                }
                OpCode::OpAbs => {
                    let a = self.pop_num()?;
                    self.push_num(a.abs());
                }
                OpCode::OpNot => {
                    let a = self.pop_num()?;
                    self.push_num(if a == 0 { 1 } else { 0 });
                }
                OpCode::Op0NotEqual => {
                    let a = self.pop_num()?;
                    self.push_num(if a != 0 { 1 } else { 0 });
                }
                OpCode::OpNumEqual => {
                    let a = self.pop_num()?;
                    let b = self.pop_num()?;
                    self.push_num(if a == b { 1 } else { 0 });
                }
                OpCode::OpNumEqualVerify => {
                    let a = self.pop_num()?;
                    let b = self.pop_num()?;
                    if a != b {
                        return Err("OP_NUMEQUALVERIFY failed".to_string());
                    }
                }
                OpCode::OpNumNotEqual => {
                    let a = self.pop_num()?;
                    let b = self.pop_num()?;
                    self.push_num(if a != b { 1 } else { 0 });
                }
                OpCode::OpLessThan => {
                    let a = self.pop_num()?;
                    let b = self.pop_num()?;
                    self.push_num(if b < a { 1 } else { 0 });
                }
                OpCode::OpGreaterThan => {
                    let a = self.pop_num()?;
                    let b = self.pop_num()?;
                    self.push_num(if b > a { 1 } else { 0 });
                }
                OpCode::OpLessThanOrEqual => {
                    let a = self.pop_num()?;
                    let b = self.pop_num()?;
                    self.push_num(if b <= a { 1 } else { 0 });
                }
                OpCode::OpGreaterThanOrEqual => {
                    let a = self.pop_num()?;
                    let b = self.pop_num()?;
                    self.push_num(if b >= a { 1 } else { 0 });
                }
                OpCode::OpMin => {
                    let a = self.pop_num()?;
                    let b = self.pop_num()?;
                    self.push_num(a.min(b));
                }
                OpCode::OpMax => {
                    let a = self.pop_num()?;
                    let b = self.pop_num()?;
                    self.push_num(a.max(b));
                }
                OpCode::OpWithin => {
                    let max = self.pop_num()?;
                    let min = self.pop_num()?;
                    let x = self.pop_num()?;
                    self.push_num(if x >= min && x < max { 1 } else { 0 });
                }
                
                // Crypto
                OpCode::OpRipemd160 => {
                    let data = self.pop()?;
                    let hash = Ripemd160::digest(&data);
                    self.stack.push(hash.to_vec());
                }
                OpCode::OpSha256 => {
                    let data = self.pop()?;
                    let hash = Sha256::digest(&data);
                    self.stack.push(hash.to_vec());
                }
                OpCode::OpHash160 => {
                    let data = self.pop()?;
                    let sha = Sha256::digest(&data);
                    let hash = Ripemd160::digest(&sha);
                    self.stack.push(hash.to_vec());
                }
                OpCode::OpHash256 => {
                    let data = self.pop()?;
                    let hash1 = Sha256::digest(&data);
                    let hash2 = Sha256::digest(&hash1);
                    self.stack.push(hash2.to_vec());
                }
                OpCode::OpCheckSig => {
                    let pubkey = self.pop()?;
                    let sig = self.pop()?;
                    let valid = self.verify_signature(&sig, &pubkey)?;
                    self.stack.push(if valid { vec![1] } else { vec![] });
                }
                OpCode::OpCheckSigVerify => {
                    let pubkey = self.pop()?;
                    let sig = self.pop()?;
                    let valid = self.verify_signature(&sig, &pubkey)?;
                    if !valid {
                        return Err("OP_CHECKSIGVERIFY failed".to_string());
                    }
                }
                OpCode::OpCheckMultiSig => {
                    // Pop n pubkeys
                    let n = self.pop_num()? as usize;
                    let mut pubkeys = Vec::new();
                    for _ in 0..n {
                        pubkeys.push(self.pop()?);
                    }
                    
                    // Pop m signatures
                    let m = self.pop_num()? as usize;
                    let mut sigs = Vec::new();
                    for _ in 0..m {
                        sigs.push(self.pop()?);
                    }
                    
                    // Pop dummy element (Bitcoin bug)
                    let _ = self.pop();
                    
                    // Verify m-of-n
                    let valid = self.verify_multisig(&sigs, &pubkeys)?;
                    self.stack.push(if valid { vec![1] } else { vec![] });
                }
                OpCode::OpCheckMultiSigVerify => {
                    // Same as CheckMultiSig but verify
                    let n = self.pop_num()? as usize;
                    let mut pubkeys = Vec::new();
                    for _ in 0..n {
                        pubkeys.push(self.pop()?);
                    }
                    
                    let m = self.pop_num()? as usize;
                    let mut sigs = Vec::new();
                    for _ in 0..m {
                        sigs.push(self.pop()?);
                    }
                    
                    let _ = self.pop();
                    
                    let valid = self.verify_multisig(&sigs, &pubkeys)?;
                    if !valid {
                        return Err("OP_CHECKMULTISIGVERIFY failed".to_string());
                    }
                }
                
                // Locktime
                OpCode::OpCheckLockTimeVerify => {
                    let locktime = self.peek_num()?;
                    
                    // Verify locktime
                    if locktime < 0 {
                        return Err("Negative locktime".to_string());
                    }
                    
                    let locktime = locktime as u64;
                    
                    // Compare with transaction locktime
                    if locktime > self.context.locktime as u64 {
                        return Err("Locktime not reached".to_string());
                    }
                    
                    // Check if it's block height or timestamp
                    if locktime < 500_000_000 {
                        // Block height
                        if self.context.block_height < locktime {
                            return Err("Block height not reached".to_string());
                        }
                    }
                    
                    // Check sequence (must not be final)
                    if self.context.sequence == 0xffffffff {
                        return Err("Sequence is final, CLTV disabled".to_string());
                    }
                }
                OpCode::OpCheckSequenceVerify => {
                    let sequence = self.peek_num()?;
                    
                    if sequence < 0 {
                        return Err("Negative sequence".to_string());
                    }
                    
                    // Simplified CSV check
                    let required = sequence as u32;
                    if (required & 0x80000000) == 0 {
                        // CSV is enabled
                        if (self.context.sequence & 0x80000000) != 0 {
                            return Err("CSV disabled in input".to_string());
                        }
                        
                        let masked_required = required & 0x0000ffff;
                        let masked_input = self.context.sequence & 0x0000ffff;
                        
                        if masked_input < masked_required {
                            return Err("Sequence not reached".to_string());
                        }
                    }
                }
                
                // NOPs
                OpCode::OpNop | OpCode::OpNop1 | OpCode::OpNop4 | 
                OpCode::OpNop5 | OpCode::OpNop6 | OpCode::OpNop7 |
                OpCode::OpNop8 | OpCode::OpNop9 | OpCode::OpNop10 => {}
                
                OpCode::OpPick => {
                    let n = self.pop_num()? as usize;
                    if n >= self.stack.len() {
                        return Err("Stack underflow in OP_PICK".to_string());
                    }
                    let val = self.stack[self.stack.len() - 1 - n].clone();
                    self.stack.push(val);
                }
                OpCode::OpRoll => {
                    let n = self.pop_num()? as usize;
                    if n >= self.stack.len() {
                        return Err("Stack underflow in OP_ROLL".to_string());
                    }
                    let idx = self.stack.len() - 1 - n;
                    let val = self.stack.remove(idx);
                    self.stack.push(val);
                }
            }
        }
        
        Ok(())
    }
    
    // Helper functions
    fn pop(&mut self) -> Result<Vec<u8>, String> {
        self.stack.pop().ok_or_else(|| "Stack underflow".to_string())
    }
    
    fn peek(&self) -> Result<Vec<u8>, String> {
        self.stack.last().cloned().ok_or_else(|| "Stack underflow".to_string())
    }
    
    fn pop_num(&mut self) -> Result<i64, String> {
        let data = self.pop()?;
        Ok(Self::decode_num(&data))
    }
    
    fn peek_num(&self) -> Result<i64, String> {
        let data = self.peek()?;
        Ok(Self::decode_num(&data))
    }
    
    fn push_num(&mut self, n: i64) {
        self.stack.push(Script::encode_num(n));
    }
    
    fn is_true(data: &[u8]) -> bool {
        for (i, &byte) in data.iter().enumerate() {
            if byte != 0 {
                // Negative zero check
                if i == data.len() - 1 && byte == 0x80 {
                    return false;
                }
                return true;
            }
        }
        false
    }
    
    fn decode_num(data: &[u8]) -> i64 {
        if data.is_empty() {
            return 0;
        }
        
        let negative = data[data.len() - 1] & 0x80 != 0;
        let mut result: i64 = 0;
        
        for (i, &byte) in data.iter().enumerate() {
            let b = if i == data.len() - 1 {
                byte & 0x7f
            } else {
                byte
            };
            result |= (b as i64) << (8 * i);
        }
        
        if negative {
            -result
        } else {
            result
        }
    }
    
    fn verify_signature(&self, sig: &[u8], pubkey: &[u8]) -> Result<bool, String> {
        let secp = Secp256k1::verification_only();
        
        // Parse public key
        let pk = PublicKey::from_slice(pubkey)
            .map_err(|e| format!("Invalid pubkey: {}", e))?;
        
        // Parse signature (DER format, possibly with sighash byte)
        let sig_bytes = if sig.is_empty() {
            return Ok(false);
        } else if sig.len() > 1 {
            &sig[..sig.len() - 1]  // Remove sighash byte
        } else {
            sig
        };
        
        let signature = Signature::from_der(sig_bytes)
            .map_err(|e| format!("Invalid signature: {}", e))?;
        
        // Create message from tx hash
        let message = Message::from_digest(self.context.tx_hash);
        
        // Verify
        Ok(secp.verify_ecdsa(&message, &signature, &pk).is_ok())
    }
    
    fn verify_multisig(&self, sigs: &[Vec<u8>], pubkeys: &[Vec<u8>]) -> Result<bool, String> {
        let mut sig_idx = 0;
        let mut pk_idx = 0;
        
        while sig_idx < sigs.len() && pk_idx < pubkeys.len() {
            if self.verify_signature(&sigs[sig_idx], &pubkeys[pk_idx])? {
                sig_idx += 1;
            }
            pk_idx += 1;
        }
        
        Ok(sig_idx == sigs.len())
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Calcula HASH160 de datos (SHA256 + RIPEMD160)
pub fn hash160(data: &[u8]) -> Vec<u8> {
    let sha = Sha256::digest(data);
    Ripemd160::digest(&sha).to_vec()
}

/// Calcula HASH256 de datos (double SHA256)
pub fn hash256(data: &[u8]) -> Vec<u8> {
    let first = Sha256::digest(data);
    Sha256::digest(&first).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simple_script() {
        let context = ScriptContext {
            tx_hash: [0u8; 32],
            locktime: 0,
            sequence: 0,
            block_height: 100,
        };
        
        let mut engine = ScriptEngine::new(context);
        
        // Test: 2 + 3 = 5
        let script = Script {
            ops: vec![
                OpCode::Op2,
                OpCode::Op3,
                OpCode::OpAdd,
                OpCode::OpPushData(vec![5]),
                OpCode::OpEqual,
            ],
        };
        
        engine.execute(&script).unwrap();
        assert!(ScriptEngine::is_true(&engine.stack.pop().unwrap()));
    }
    
    #[test]
    fn test_p2pkh_structure() {
        let pubkey_hash = vec![0u8; 20];
        let script = Script::p2pkh(&pubkey_hash);
        
        assert!(script.is_p2pkh());
        assert_eq!(script.get_p2pkh_hash(), Some(pubkey_hash));
    }
}
