// =============================================================================
// MOONCOIN v2.32 - Smart Contracts: Script Engine
// =============================================================================
//
// Stack-based virtual machine for executing Mooncoin scripts.
// Implements Bitcoin Script semantics with security enhancements.
//
// Features:
// - Dual stack (main + alt)
// - Flow control (IF/ELSE/ENDIF)
// - Cryptographic operations
// - Timelock verification
// - Configurable limits
// - Detailed error reporting
//
// =============================================================================

use crate::contracts::opcodes::Opcode;
use sha2::{Sha256, Digest as Sha2Digest};
use ripemd::Ripemd160;



// =============================================================================
// Configuration
// =============================================================================

/// Script execution configuration
#[derive(Clone, Debug)]
pub struct ScriptConfig {
    /// Maximum script size in bytes
    pub max_script_size: usize,
    /// Maximum stack size (elements)
    pub max_stack_size: usize,
    /// Maximum element size in bytes
    pub max_element_size: usize,
    /// Maximum number of operations
    pub max_ops_count: usize,
    /// Maximum number of public keys in multisig
    pub max_pubkeys_per_multisig: usize,
    /// Require minimal push encodings
    pub require_minimal_push: bool,
    /// Allow disabled opcodes (for testing)
    pub allow_disabled_opcodes: bool,
}

impl Default for ScriptConfig {
    fn default() -> Self {
        ScriptConfig {
            max_script_size: 10_000,
            max_stack_size: 1_000,
            max_element_size: 520,
            max_ops_count: 201,
            max_pubkeys_per_multisig: 20,
            require_minimal_push: true,
            allow_disabled_opcodes: false,
        }
    }
}

// =============================================================================
// Script Error
// =============================================================================

/// Errors that can occur during script execution
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptError {
    /// Script exceeds maximum size
    ScriptTooLarge,
    /// Stack overflow
    StackOverflow,
    /// Stack underflow (not enough elements)
    StackUnderflow,
    /// Element exceeds maximum size
    ElementTooLarge,
    /// Too many operations
    TooManyOps,
    /// Invalid opcode
    InvalidOpcode(u8),
    /// Disabled opcode executed
    DisabledOpcode(Opcode),
    /// Reserved opcode executed
    ReservedOpcode(Opcode),
    /// Verification failed
    VerifyFailed,
    /// Script returned false
    EvalFalse,
    /// OP_RETURN executed
    OpReturn,
    /// Unbalanced IF/ELSE/ENDIF
    UnbalancedConditional,
    /// Invalid number encoding
    InvalidNumber,
    /// Invalid public key
    InvalidPubKey,
    /// Invalid signature
    InvalidSignature,
    /// Signature check failed
    SigCheckFailed,
    /// Multisig failed
    MultisigFailed,
    /// Too many pubkeys in multisig
    TooManyPubKeys,
    /// Invalid multisig format
    InvalidMultisig,
    /// Locktime not satisfied
    LocktimeNotSatisfied,
    /// Sequence not satisfied
    SequenceNotSatisfied,
    /// Negative locktime
    NegativeLocktime,
    /// Non-minimal push encoding
    NonMinimalPush,
    /// Empty script
    EmptyScript,
    /// Invalid script encoding
    InvalidEncoding,
    /// Unknown error
    Unknown(String),
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptError::ScriptTooLarge => write!(f, "Script exceeds maximum size"),
            ScriptError::StackOverflow => write!(f, "Stack overflow"),
            ScriptError::StackUnderflow => write!(f, "Stack underflow"),
            ScriptError::ElementTooLarge => write!(f, "Element exceeds maximum size"),
            ScriptError::TooManyOps => write!(f, "Too many operations"),
            ScriptError::InvalidOpcode(b) => write!(f, "Invalid opcode: 0x{:02X}", b),
            ScriptError::DisabledOpcode(op) => write!(f, "Disabled opcode: {}", op),
            ScriptError::ReservedOpcode(op) => write!(f, "Reserved opcode: {}", op),
            ScriptError::VerifyFailed => write!(f, "Verification failed"),
            ScriptError::EvalFalse => write!(f, "Script evaluated to false"),
            ScriptError::OpReturn => write!(f, "OP_RETURN executed"),
            ScriptError::UnbalancedConditional => write!(f, "Unbalanced IF/ELSE/ENDIF"),
            ScriptError::InvalidNumber => write!(f, "Invalid number encoding"),
            ScriptError::InvalidPubKey => write!(f, "Invalid public key"),
            ScriptError::InvalidSignature => write!(f, "Invalid signature"),
            ScriptError::SigCheckFailed => write!(f, "Signature check failed"),
            ScriptError::MultisigFailed => write!(f, "Multisig verification failed"),
            ScriptError::TooManyPubKeys => write!(f, "Too many public keys"),
            ScriptError::InvalidMultisig => write!(f, "Invalid multisig format"),
            ScriptError::LocktimeNotSatisfied => write!(f, "Locktime not satisfied"),
            ScriptError::SequenceNotSatisfied => write!(f, "Sequence not satisfied"),
            ScriptError::NegativeLocktime => write!(f, "Negative locktime"),
            ScriptError::NonMinimalPush => write!(f, "Non-minimal push encoding"),
            ScriptError::EmptyScript => write!(f, "Empty script"),
            ScriptError::InvalidEncoding => write!(f, "Invalid script encoding"),
            ScriptError::Unknown(s) => write!(f, "Unknown error: {}", s),
        }
    }
}

impl std::error::Error for ScriptError {}

// =============================================================================
// Execution Context
// =============================================================================

/// Context for script execution (transaction data)
#[derive(Clone, Debug)]
pub struct ExecutionContext {
    /// Transaction hash being signed
    pub tx_hash: [u8; 32],
    /// Current input index
    pub input_index: usize,
    /// Transaction locktime
    pub locktime: u32,
    /// Input sequence number
    pub sequence: u32,
    /// Signature checker function
    pub sig_checker: Option<SigChecker>,
}

/// Signature verification function type
pub type SigChecker = fn(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> bool;

impl Default for ExecutionContext {
    fn default() -> Self {
        ExecutionContext {
            tx_hash: [0u8; 32],
            input_index: 0,
            locktime: 0,
            sequence: 0xFFFFFFFF,
            sig_checker: None,
        }
    }
}

// =============================================================================
// Script Engine
// =============================================================================

/// Stack-based script execution engine
pub struct ScriptEngine {
    /// Configuration
    config: ScriptConfig,
    /// Main stack
    stack: Vec<Vec<u8>>,
    /// Alternate stack
    alt_stack: Vec<Vec<u8>>,
    /// Conditional execution stack (for IF/ELSE)
    exec_stack: Vec<bool>,
    /// Operation counter
    ops_count: usize,
    /// Execution context
    context: ExecutionContext,
}

impl ScriptEngine {
    /// Create new engine with default config
    pub fn new() -> Self {
        ScriptEngine {
            config: ScriptConfig::default(),
            stack: Vec::new(),
            alt_stack: Vec::new(),
            exec_stack: Vec::new(),
            ops_count: 0,
            context: ExecutionContext::default(),
        }
    }
    
    /// Create with custom config
    pub fn with_config(config: ScriptConfig) -> Self {
        ScriptEngine {
            config,
            stack: Vec::new(),
            alt_stack: Vec::new(),
            exec_stack: Vec::new(),
            ops_count: 0,
            context: ExecutionContext::default(),
        }
    }
    
    /// Set execution context
    pub fn set_context(&mut self, context: ExecutionContext) {
        self.context = context;
    }
    
    /// Reset engine state
    pub fn reset(&mut self) {
        self.stack.clear();
        self.alt_stack.clear();
        self.exec_stack.clear();
        self.ops_count = 0;
    }
    
    /// Execute a script without verifying stack result (for scriptSig)
    /// This allows the stack to be empty after execution
    pub fn execute_no_verify(&mut self, script: &[u8]) -> Result<(), ScriptError> {
        self.execute_internal(script, false)?;
        Ok(())
    }
    
    /// Execute a script and verify the result
    pub fn execute(&mut self, script: &[u8]) -> Result<bool, ScriptError> {
        self.execute_internal(script, true)
    }
    
    /// Internal execution with optional verification
    fn execute_internal(&mut self, script: &[u8], verify_result: bool) -> Result<bool, ScriptError> {
        // Check script size
        if script.len() > self.config.max_script_size {
            return Err(ScriptError::ScriptTooLarge);
        }
        
        // Parse and execute
        let mut pc = 0; // Program counter
        
        while pc < script.len() {
            let opcode_byte = script[pc];
            pc += 1;
            
            // Check if we're in an executing branch
            let executing = self.exec_stack.iter().all(|&b| b);
            
            // Parse opcode
            let opcode = Opcode::from_byte(opcode_byte)
                .ok_or(ScriptError::InvalidOpcode(opcode_byte))?;
            
            // Handle push opcodes
            if opcode_byte >= 0x01 && opcode_byte <= 0x4B {
                // Direct push (1-75 bytes)
                let len = opcode_byte as usize;
                if pc + len > script.len() {
                    return Err(ScriptError::InvalidEncoding);
                }
                if executing {
                    let data = script[pc..pc + len].to_vec();
                    self.push(data)?;
                }
                pc += len;
                continue;
            }
            
            // Handle PUSHDATA opcodes
            match opcode {
                Opcode::OP_PUSHDATA1 => {
                    if pc >= script.len() {
                        return Err(ScriptError::InvalidEncoding);
                    }
                    let len = script[pc] as usize;
                    pc += 1;
                    if pc + len > script.len() {
                        return Err(ScriptError::InvalidEncoding);
                    }
                    if executing {
                        let data = script[pc..pc + len].to_vec();
                        self.push(data)?;
                    }
                    pc += len;
                    continue;
                }
                Opcode::OP_PUSHDATA2 => {
                    if pc + 2 > script.len() {
                        return Err(ScriptError::InvalidEncoding);
                    }
                    let len = u16::from_le_bytes([script[pc], script[pc + 1]]) as usize;
                    pc += 2;
                    if pc + len > script.len() {
                        return Err(ScriptError::InvalidEncoding);
                    }
                    if executing {
                        let data = script[pc..pc + len].to_vec();
                        self.push(data)?;
                    }
                    pc += len;
                    continue;
                }
                Opcode::OP_PUSHDATA4 => {
                    if pc + 4 > script.len() {
                        return Err(ScriptError::InvalidEncoding);
                    }
                    let len = u32::from_le_bytes([
                        script[pc], script[pc + 1], script[pc + 2], script[pc + 3]
                    ]) as usize;
                    pc += 4;
                    if pc + len > script.len() {
                        return Err(ScriptError::InvalidEncoding);
                    }
                    if executing {
                        let data = script[pc..pc + len].to_vec();
                        self.push(data)?;
                    }
                    pc += len;
                    continue;
                }
                _ => {}
            }
            
            // Count non-push operations
            if !opcode.is_push() {
                self.ops_count += 1;
                if self.ops_count > self.config.max_ops_count {
                    return Err(ScriptError::TooManyOps);
                }
            }
            
            // Handle conditionals specially
            match opcode {
                Opcode::OP_IF | Opcode::OP_NOTIF => {
                    let mut value = false;
                    if executing {
                        let top = self.pop()?;
                        value = self.cast_to_bool(&top);
                        if opcode == Opcode::OP_NOTIF {
                            value = !value;
                        }
                    }
                    self.exec_stack.push(value);
                    continue;
                }
                Opcode::OP_ELSE => {
                    if self.exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    let top = self.exec_stack.pop().unwrap();
                    // Only flip if parent is executing
                    let parent_executing = self.exec_stack.iter().all(|&b| b);
                    self.exec_stack.push(if parent_executing { !top } else { false });
                    continue;
                }
                Opcode::OP_ENDIF => {
                    if self.exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    self.exec_stack.pop();
                    continue;
                }
                _ => {}
            }
            
            // Skip non-executing branches
            if !executing {
                continue;
            }
            
            // Check for disabled/reserved opcodes
            if opcode.is_disabled() && !self.config.allow_disabled_opcodes {
                return Err(ScriptError::DisabledOpcode(opcode));
            }
            if opcode.is_reserved() {
                return Err(ScriptError::ReservedOpcode(opcode));
            }
            
            // Execute opcode
            self.execute_opcode(opcode)?;
        }
        
        // Check for unbalanced conditionals
        if !self.exec_stack.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }
        
        // Only verify result if requested
        if verify_result {
            // Script succeeds if stack is non-empty and top is true
            if self.stack.is_empty() {
                return Err(ScriptError::EvalFalse);
            }
            
            let top = &self.stack[self.stack.len() - 1];
            Ok(self.cast_to_bool(top))
        } else {
            // For no-verify mode, just return true if no errors
            Ok(true)
        }
    }
    
    /// Execute a single opcode
    fn execute_opcode(&mut self, opcode: Opcode) -> Result<(), ScriptError> {
        match opcode {
            // =================================================================
            // Constants
            // =================================================================
            Opcode::OP_0 => {
                self.push(vec![])?;
            }
            Opcode::OP_1NEGATE => {
                self.push(self.encode_num(-1))?;
            }
            Opcode::OP_1 | Opcode::OP_2 | Opcode::OP_3 | Opcode::OP_4 |
            Opcode::OP_5 | Opcode::OP_6 | Opcode::OP_7 | Opcode::OP_8 |
            Opcode::OP_9 | Opcode::OP_10 | Opcode::OP_11 | Opcode::OP_12 |
            Opcode::OP_13 | Opcode::OP_14 | Opcode::OP_15 | Opcode::OP_16 => {
                let num = (opcode.to_byte() - 0x50) as i64;
                self.push(self.encode_num(num))?;
            }
            
            // =================================================================
            // Flow Control
            // =================================================================
            Opcode::OP_NOP => {}
            
            Opcode::OP_VERIFY => {
                let top = self.pop()?;
                if !self.cast_to_bool(&top) {
                    return Err(ScriptError::VerifyFailed);
                }
            }
            
            Opcode::OP_RETURN => {
                return Err(ScriptError::OpReturn);
            }
            
            // =================================================================
            // Stack Operations
            // =================================================================
            Opcode::OP_TOALTSTACK => {
                let val = self.pop()?;
                self.alt_stack.push(val);
            }
            
            Opcode::OP_FROMALTSTACK => {
                let val = self.alt_stack.pop()
                    .ok_or(ScriptError::StackUnderflow)?;
                self.push(val)?;
            }
            
            Opcode::OP_2DROP => {
                self.pop()?;
                self.pop()?;
            }
            
            Opcode::OP_2DUP => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(a.clone())?;
                self.push(b.clone())?;
                self.push(a)?;
                self.push(b)?;
            }
            
            Opcode::OP_3DUP => {
                let c = self.pop()?;
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(a.clone())?;
                self.push(b.clone())?;
                self.push(c.clone())?;
                self.push(a)?;
                self.push(b)?;
                self.push(c)?;
            }
            
            Opcode::OP_IFDUP => {
                let top = self.peek(0)?;
                if self.cast_to_bool(&top) {
                    self.push(top)?;
                }
            }
            
            Opcode::OP_DEPTH => {
                let depth = self.stack.len() as i64;
                self.push(self.encode_num(depth))?;
            }
            
            Opcode::OP_DROP => {
                self.pop()?;
            }
            
            Opcode::OP_DUP => {
                let top = self.peek(0)?;
                self.push(top)?;
            }
            
            Opcode::OP_NIP => {
                let top = self.pop()?;
                self.pop()?;
                self.push(top)?;
            }
            
            Opcode::OP_OVER => {
                let second = self.peek(1)?;
                self.push(second)?;
            }
            
            Opcode::OP_PICK => {
                let n = self.pop_num()? as usize;
                let val = self.peek(n)?;
                self.push(val)?;
            }
            
            Opcode::OP_ROLL => {
                let n = self.pop_num()? as usize;
                if n >= self.stack.len() {
                    return Err(ScriptError::StackUnderflow);
                }
                let idx = self.stack.len() - n - 1;
                let val = self.stack.remove(idx);
                self.push(val)?;
            }
            
            Opcode::OP_ROT => {
                let c = self.pop()?;
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(b)?;
                self.push(c)?;
                self.push(a)?;
            }
            
            Opcode::OP_SWAP => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(b)?;
                self.push(a)?;
            }
            
            Opcode::OP_TUCK => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(b.clone())?;
                self.push(a)?;
                self.push(b)?;
            }
            
            Opcode::OP_SIZE => {
                let top = self.peek(0)?;
                let size = top.len() as i64;
                self.push(self.encode_num(size))?;
            }
            
            // =================================================================
            // Bitwise Logic
            // =================================================================
            Opcode::OP_EQUAL => {
                let b = self.pop()?;
                let a = self.pop()?;
                self.push(if a == b { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_EQUALVERIFY => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a != b {
                    return Err(ScriptError::VerifyFailed);
                }
            }
            
            // =================================================================
            // Arithmetic
            // =================================================================
            Opcode::OP_1ADD => {
                let n = self.pop_num()?;
                self.push(self.encode_num(n + 1))?;
            }
            
            Opcode::OP_1SUB => {
                let n = self.pop_num()?;
                self.push(self.encode_num(n - 1))?;
            }
            
            Opcode::OP_NEGATE => {
                let n = self.pop_num()?;
                self.push(self.encode_num(-n))?;
            }
            
            Opcode::OP_ABS => {
                let n = self.pop_num()?;
                self.push(self.encode_num(n.abs()))?;
            }
            
            Opcode::OP_NOT => {
                let n = self.pop_num()?;
                self.push(if n == 0 { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_0NOTEQUAL => {
                let n = self.pop_num()?;
                self.push(if n != 0 { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_ADD => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(self.encode_num(a + b))?;
            }
            
            Opcode::OP_SUB => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(self.encode_num(a - b))?;
            }
            
            Opcode::OP_BOOLAND => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(if a != 0 && b != 0 { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_BOOLOR => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(if a != 0 || b != 0 { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_NUMEQUAL => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(if a == b { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_NUMEQUALVERIFY => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                if a != b {
                    return Err(ScriptError::VerifyFailed);
                }
            }
            
            Opcode::OP_NUMNOTEQUAL => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(if a != b { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_LESSTHAN => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(if a < b { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_GREATERTHAN => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(if a > b { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_LESSTHANOREQUAL => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(if a <= b { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_GREATERTHANOREQUAL => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(if a >= b { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_MIN => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(self.encode_num(a.min(b)))?;
            }
            
            Opcode::OP_MAX => {
                let b = self.pop_num()?;
                let a = self.pop_num()?;
                self.push(self.encode_num(a.max(b)))?;
            }
            
            Opcode::OP_WITHIN => {
                let max = self.pop_num()?;
                let min = self.pop_num()?;
                let x = self.pop_num()?;
                self.push(if x >= min && x < max { vec![1] } else { vec![] })?;
            }
            
            // =================================================================
            // Cryptographic
            // =================================================================
            Opcode::OP_RIPEMD160 => {
                let data = self.pop()?;
                let mut hasher = Ripemd160::new();
                hasher.update(&data);
                self.push(hasher.finalize().to_vec())?;
            }
            
            Opcode::OP_SHA1 => {
                let data = self.pop()?;
                let hash = sha1_hash(&data);
                self.push(hash.to_vec())?;
            }
            
            Opcode::OP_SHA256 => {
                let data = self.pop()?;
                let mut hasher = Sha256::new();
                hasher.update(&data);
                self.push(hasher.finalize().to_vec())?;
            }
            
            Opcode::OP_HASH160 => {
                let data = self.pop()?;
                let hash = hash160(&data);
                self.push(hash.to_vec())?;
            }
            
            Opcode::OP_HASH256 => {
                let data = self.pop()?;
                let hash = hash256(&data);
                self.push(hash.to_vec())?;
            }
            
            Opcode::OP_CODESEPARATOR => {
                // Mark position for signature hashing
                // Implementation depends on transaction context
            }
            
            Opcode::OP_CHECKSIG => {
                let pubkey = self.pop()?;
                let sig = self.pop()?;
                let result = self.check_sig(&pubkey, &sig)?;
                self.push(if result { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_CHECKSIGVERIFY => {
                let pubkey = self.pop()?;
                let sig = self.pop()?;
                if !self.check_sig(&pubkey, &sig)? {
                    return Err(ScriptError::SigCheckFailed);
                }
            }
            
            Opcode::OP_CHECKMULTISIG => {
                let result = self.check_multisig()?;
                self.push(if result { vec![1] } else { vec![] })?;
            }
            
            Opcode::OP_CHECKMULTISIGVERIFY => {
                if !self.check_multisig()? {
                    return Err(ScriptError::MultisigFailed);
                }
            }
            
            // =================================================================
            // Locktime
            // =================================================================
            Opcode::OP_CHECKLOCKTIMEVERIFY => {
                let locktime = self.peek_num(0)?;
                
                if locktime < 0 {
                    return Err(ScriptError::NegativeLocktime);
                }
                
                let locktime = locktime as u64;
                let tx_locktime = self.context.locktime as u64;
                
                // Check threshold (500_000_000 separates block height from timestamp)
                let threshold = 500_000_000u64;
                if (locktime < threshold && tx_locktime >= threshold) ||
                   (locktime >= threshold && tx_locktime < threshold) {
                    return Err(ScriptError::LocktimeNotSatisfied);
                }
                
                if locktime > tx_locktime {
                    return Err(ScriptError::LocktimeNotSatisfied);
                }
                
                if self.context.sequence == 0xFFFFFFFF {
                    return Err(ScriptError::SequenceNotSatisfied);
                }
            }
            
            Opcode::OP_CHECKSEQUENCEVERIFY => {
                let sequence = self.peek_num(0)?;
                
                if sequence < 0 {
                    return Err(ScriptError::NegativeLocktime);
                }
                
                let sequence = sequence as u32;
                
                // Check disable flag
                if sequence & (1 << 31) != 0 {
                    // Disabled, NOP behavior
                    return Ok(());
                }
                
                // Type must match
                let type_mask = 1 << 22;
                if (sequence & type_mask) != (self.context.sequence & type_mask) {
                    return Err(ScriptError::SequenceNotSatisfied);
                }
                
                // Check value
                let mask = 0x0000FFFF;
                if (sequence & mask) > (self.context.sequence & mask) {
                    return Err(ScriptError::SequenceNotSatisfied);
                }
            }
            
            // =================================================================
            // NOP (expansion)
            // =================================================================
            Opcode::OP_NOP1 | Opcode::OP_NOP4 | Opcode::OP_NOP5 |
            Opcode::OP_NOP6 | Opcode::OP_NOP7 | Opcode::OP_NOP8 |
            Opcode::OP_NOP9 | Opcode::OP_NOP10 => {
                // Do nothing (forward compatible)
            }
            
            _ => {
                return Err(ScriptError::InvalidOpcode(opcode.to_byte()));
            }
        }
        
        Ok(())
    }
    
    // =========================================================================
    // Stack Helpers
    // =========================================================================
    
    fn push(&mut self, data: Vec<u8>) -> Result<(), ScriptError> {
        if data.len() > self.config.max_element_size {
            return Err(ScriptError::ElementTooLarge);
        }
        if self.stack.len() >= self.config.max_stack_size {
            return Err(ScriptError::StackOverflow);
        }
        self.stack.push(data);
        Ok(())
    }
    
    fn pop(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.stack.pop().ok_or(ScriptError::StackUnderflow)
    }
    
    fn peek(&self, n: usize) -> Result<Vec<u8>, ScriptError> {
        if n >= self.stack.len() {
            return Err(ScriptError::StackUnderflow);
        }
        Ok(self.stack[self.stack.len() - n - 1].clone())
    }
    
    fn pop_num(&mut self) -> Result<i64, ScriptError> {
        let data = self.pop()?;
        self.decode_num(&data)
    }
    
    fn peek_num(&self, n: usize) -> Result<i64, ScriptError> {
        let data = self.peek(n)?;
        self.decode_num(&data)
    }
    
    fn cast_to_bool(&self, data: &[u8]) -> bool {
        for (i, &byte) in data.iter().enumerate() {
            if byte != 0 {
                // Negative zero is still false
                if i == data.len() - 1 && byte == 0x80 {
                    return false;
                }
                return true;
            }
        }
        false
    }
    
    fn decode_num(&self, data: &[u8]) -> Result<i64, ScriptError> {
        if data.is_empty() {
            return Ok(0);
        }
        if data.len() > 4 {
            return Err(ScriptError::InvalidNumber);
        }
        
        let mut result = 0i64;
        for (i, &byte) in data.iter().enumerate() {
            result |= (byte as i64) << (8 * i);
        }
        
        // Handle sign bit
        if data[data.len() - 1] & 0x80 != 0 {
            result &= !((0x80i64) << (8 * (data.len() - 1)));
            result = -result;
        }
        
        Ok(result)
    }
    
    fn encode_num(&self, num: i64) -> Vec<u8> {
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
        
        // Add sign bit if needed
        if result[result.len() - 1] & 0x80 != 0 {
            result.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            let len = result.len();
            result[len - 1] |= 0x80;
        }
        
        result
    }
    
    // =========================================================================
    // Signature Verification
    // =========================================================================
    
    fn check_sig(&self, pubkey: &[u8], sig: &[u8]) -> Result<bool, ScriptError> {
        if sig.is_empty() {
            return Ok(false);
        }
        
        // Use provided signature checker if available
        if let Some(checker) = self.context.sig_checker {
            return Ok(checker(pubkey, sig, &self.context.tx_hash));
        }
        
        // Default: simplified signature check for testing
        // In production, this would verify actual ECDSA signatures
        Ok(!pubkey.is_empty() && !sig.is_empty())
    }
    
    fn check_multisig(&mut self) -> Result<bool, ScriptError> {
        // Pop n (number of public keys)
        let n = self.pop_num()? as usize;
        if n > self.config.max_pubkeys_per_multisig {
            return Err(ScriptError::TooManyPubKeys);
        }
        
        // Pop public keys
        let mut pubkeys = Vec::with_capacity(n);
        for _ in 0..n {
            pubkeys.push(self.pop()?);
        }
        
        // Pop m (required signatures)
        let m = self.pop_num()? as usize;
        if m > n {
            return Err(ScriptError::InvalidMultisig);
        }
        
        // Pop signatures
        let mut sigs = Vec::with_capacity(m);
        for _ in 0..m {
            sigs.push(self.pop()?);
        }
        
        // Pop dummy element (Bitcoin bug compatibility)
        self.pop()?;
        
        // Verify m-of-n
        let mut sig_idx = 0;
        let mut key_idx = 0;
        
        while sig_idx < m && key_idx < n {
            if self.check_sig(&pubkeys[key_idx], &sigs[sig_idx])? {
                sig_idx += 1;
            }
            key_idx += 1;
            
            // Not enough keys left
            if n - key_idx < m - sig_idx {
                return Ok(false);
            }
        }
        
        Ok(sig_idx == m)
    }
    
    /// Get current stack (for debugging)
    pub fn get_stack(&self) -> &[Vec<u8>] {
        &self.stack
    }
    
    /// Get alt stack (for debugging)
    pub fn get_alt_stack(&self) -> &[Vec<u8>] {
        &self.alt_stack
    }
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Hash Functions
// =============================================================================

/// SHA-1 hash
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    use sha1::{Sha1, Digest};
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&result);
    hash
}

/// HASH160 = RIPEMD160(SHA256(data))
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let mut sha = Sha256::new();
    sha.update(data);
    let sha_result = sha.finalize();
    
    let mut ripemd = Ripemd160::new();
    ripemd.update(&sha_result);
    let result = ripemd.finalize();
    
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&result);
    hash
}

/// HASH256 = SHA256(SHA256(data))
pub fn hash256(data: &[u8]) -> [u8; 32] {
    let mut sha1 = Sha256::new();
    sha1.update(data);
    let first = sha1.finalize();
    
    let mut sha2 = Sha256::new();
    sha2.update(&first);
    let result = sha2.finalize();
    
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simple_true() {
        let mut engine = ScriptEngine::new();
        let script = vec![Opcode::OP_1.to_byte()];
        assert_eq!(engine.execute(&script), Ok(true));
    }
    
    #[test]
    fn test_simple_false() {
        let mut engine = ScriptEngine::new();
        let script = vec![Opcode::OP_0.to_byte()];
        assert_eq!(engine.execute(&script), Ok(false));
    }
    
    #[test]
    fn test_add() {
        let mut engine = ScriptEngine::new();
        let script = vec![
            Opcode::OP_2.to_byte(),
            Opcode::OP_3.to_byte(),
            Opcode::OP_ADD.to_byte(),
            Opcode::OP_5.to_byte(),
            Opcode::OP_EQUAL.to_byte(),
        ];
        assert_eq!(engine.execute(&script), Ok(true));
    }
    
    #[test]
    fn test_if_true() {
        let mut engine = ScriptEngine::new();
        let script = vec![
            Opcode::OP_1.to_byte(),
            Opcode::OP_IF.to_byte(),
            Opcode::OP_2.to_byte(),
            Opcode::OP_ELSE.to_byte(),
            Opcode::OP_3.to_byte(),
            Opcode::OP_ENDIF.to_byte(),
        ];
        assert_eq!(engine.execute(&script), Ok(true));
        assert_eq!(engine.stack[0], vec![0x02]); // OP_2 result
    }
    
    #[test]
    fn test_hash160() {
        let data = b"hello";
        let hash = hash160(data);
        assert_eq!(hash.len(), 20);
    }
    
    #[test]
    fn test_verify_fail() {
        let mut engine = ScriptEngine::new();
        let script = vec![
            Opcode::OP_0.to_byte(),
            Opcode::OP_VERIFY.to_byte(),
        ];
        assert_eq!(engine.execute(&script), Err(ScriptError::VerifyFailed));
    }
    
    #[test]
    fn test_dup_hash_equalverify() {
        let mut engine = ScriptEngine::new();
        // Simulate P2PKH: <sig> <pubkey> DUP HASH160 <hash> EQUALVERIFY CHECKSIG
        // Simplified version: <data> DUP HASH160 <hash> EQUALVERIFY
        let data = vec![0x01, 0x02, 0x03];
        let hash = hash160(&data);
        
        let mut script = vec![
            0x03, 0x01, 0x02, 0x03, // Push data
            Opcode::OP_DUP.to_byte(),
            Opcode::OP_HASH160.to_byte(),
            0x14, // Push 20 bytes
        ];
        script.extend_from_slice(&hash);
        script.push(Opcode::OP_EQUALVERIFY.to_byte());
        script.push(Opcode::OP_1.to_byte()); // Simulate successful CHECKSIG
        
        assert_eq!(engine.execute(&script), Ok(true));
    }
}
