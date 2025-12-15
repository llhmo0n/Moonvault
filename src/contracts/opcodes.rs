// =============================================================================
// MOONCOIN v2.32 - Smart Contracts: Opcodes
// =============================================================================
//
// Complete opcode definitions for the Mooncoin scripting language.
// Based on Bitcoin Script with enhancements for better usability.
//
// Categories:
// - Constants (0x00-0x60)
// - Flow Control (0x61-0x6A)
// - Stack Operations (0x6B-0x7E)
// - Bitwise Logic (0x80-0x88)
// - Arithmetic (0x8B-0xA0)
// - Cryptographic (0xA6-0xAF)
// - Locktime (0xB0-0xB2)
// - Reserved/NOP (0xB3-0xFF)
//
// =============================================================================

use std::fmt;

/// All supported opcodes
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    // =========================================================================
    // Constants (0x00 - 0x60)
    // =========================================================================
    
    /// Push empty byte array (false)
    OP_0 = 0x00,
    
    /// Push the next N bytes (1-75)
    OP_PUSHBYTES_1 = 0x01,
    OP_PUSHBYTES_2 = 0x02,
    OP_PUSHBYTES_3 = 0x03,
    OP_PUSHBYTES_4 = 0x04,
    OP_PUSHBYTES_5 = 0x05,
    OP_PUSHBYTES_6 = 0x06,
    OP_PUSHBYTES_7 = 0x07,
    OP_PUSHBYTES_8 = 0x08,
    OP_PUSHBYTES_9 = 0x09,
    OP_PUSHBYTES_10 = 0x0A,
    OP_PUSHBYTES_11 = 0x0B,
    OP_PUSHBYTES_12 = 0x0C,
    OP_PUSHBYTES_13 = 0x0D,
    OP_PUSHBYTES_14 = 0x0E,
    OP_PUSHBYTES_15 = 0x0F,
    OP_PUSHBYTES_16 = 0x10,
    OP_PUSHBYTES_17 = 0x11,
    OP_PUSHBYTES_18 = 0x12,
    OP_PUSHBYTES_19 = 0x13,
    OP_PUSHBYTES_20 = 0x14,
    OP_PUSHBYTES_21 = 0x15,
    OP_PUSHBYTES_22 = 0x16,
    OP_PUSHBYTES_23 = 0x17,
    OP_PUSHBYTES_24 = 0x18,
    OP_PUSHBYTES_25 = 0x19,
    OP_PUSHBYTES_26 = 0x1A,
    OP_PUSHBYTES_27 = 0x1B,
    OP_PUSHBYTES_28 = 0x1C,
    OP_PUSHBYTES_29 = 0x1D,
    OP_PUSHBYTES_30 = 0x1E,
    OP_PUSHBYTES_31 = 0x1F,
    OP_PUSHBYTES_32 = 0x20,
    OP_PUSHBYTES_33 = 0x21,
    OP_PUSHBYTES_34 = 0x22,
    OP_PUSHBYTES_35 = 0x23,
    OP_PUSHBYTES_36 = 0x24,
    OP_PUSHBYTES_37 = 0x25,
    OP_PUSHBYTES_38 = 0x26,
    OP_PUSHBYTES_39 = 0x27,
    OP_PUSHBYTES_40 = 0x28,
    OP_PUSHBYTES_41 = 0x29,
    OP_PUSHBYTES_42 = 0x2A,
    OP_PUSHBYTES_43 = 0x2B,
    OP_PUSHBYTES_44 = 0x2C,
    OP_PUSHBYTES_45 = 0x2D,
    OP_PUSHBYTES_46 = 0x2E,
    OP_PUSHBYTES_47 = 0x2F,
    OP_PUSHBYTES_48 = 0x30,
    OP_PUSHBYTES_49 = 0x31,
    OP_PUSHBYTES_50 = 0x32,
    OP_PUSHBYTES_51 = 0x33,
    OP_PUSHBYTES_52 = 0x34,
    OP_PUSHBYTES_53 = 0x35,
    OP_PUSHBYTES_54 = 0x36,
    OP_PUSHBYTES_55 = 0x37,
    OP_PUSHBYTES_56 = 0x38,
    OP_PUSHBYTES_57 = 0x39,
    OP_PUSHBYTES_58 = 0x3A,
    OP_PUSHBYTES_59 = 0x3B,
    OP_PUSHBYTES_60 = 0x3C,
    OP_PUSHBYTES_61 = 0x3D,
    OP_PUSHBYTES_62 = 0x3E,
    OP_PUSHBYTES_63 = 0x3F,
    OP_PUSHBYTES_64 = 0x40,
    OP_PUSHBYTES_65 = 0x41,
    OP_PUSHBYTES_66 = 0x42,
    OP_PUSHBYTES_67 = 0x43,
    OP_PUSHBYTES_68 = 0x44,
    OP_PUSHBYTES_69 = 0x45,
    OP_PUSHBYTES_70 = 0x46,
    OP_PUSHBYTES_71 = 0x47,
    OP_PUSHBYTES_72 = 0x48,
    OP_PUSHBYTES_73 = 0x49,
    OP_PUSHBYTES_74 = 0x4A,
    OP_PUSHBYTES_75 = 0x4B,
    
    /// Next byte is length, then push that many bytes
    OP_PUSHDATA1 = 0x4C,
    /// Next 2 bytes are length (LE), then push that many bytes
    OP_PUSHDATA2 = 0x4D,
    /// Next 4 bytes are length (LE), then push that many bytes
    OP_PUSHDATA4 = 0x4E,
    
    /// Push -1
    OP_1NEGATE = 0x4F,
    
    /// Reserved (transaction invalid if executed)
    OP_RESERVED = 0x50,
    
    /// Push 1 (true)
    OP_1 = 0x51,
    
    /// Push numbers 2-16
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5A,
    OP_11 = 0x5B,
    OP_12 = 0x5C,
    OP_13 = 0x5D,
    OP_14 = 0x5E,
    OP_15 = 0x5F,
    OP_16 = 0x60,
    
    // =========================================================================
    // Flow Control (0x61 - 0x6A)
    // =========================================================================
    
    /// Do nothing
    OP_NOP = 0x61,
    
    /// Reserved (transaction invalid)
    OP_VER = 0x62,
    
    /// If top stack is true, execute statements
    OP_IF = 0x63,
    
    /// If top stack is false, execute statements
    OP_NOTIF = 0x64,
    
    /// Reserved (transaction invalid)
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    
    /// Else branch of IF
    OP_ELSE = 0x67,
    
    /// End of IF block
    OP_ENDIF = 0x68,
    
    /// Marks transaction invalid if top is false
    OP_VERIFY = 0x69,
    
    /// Marks transaction invalid
    OP_RETURN = 0x6A,
    
    // =========================================================================
    // Stack Operations (0x6B - 0x7E)
    // =========================================================================
    
    /// Move top item to alt stack
    OP_TOALTSTACK = 0x6B,
    
    /// Move top alt stack item to main stack
    OP_FROMALTSTACK = 0x6C,
    
    /// Remove top two items
    OP_2DROP = 0x6D,
    
    /// Duplicate top two items
    OP_2DUP = 0x6E,
    
    /// Duplicate top three items
    OP_3DUP = 0x6F,
    
    /// Copy items 3&4 to top
    OP_2OVER = 0x70,
    
    /// Move items 5&6 to top
    OP_2ROT = 0x71,
    
    /// Swap top two pairs
    OP_2SWAP = 0x72,
    
    /// Duplicate top if nonzero
    OP_IFDUP = 0x73,
    
    /// Push stack size
    OP_DEPTH = 0x74,
    
    /// Remove top item
    OP_DROP = 0x75,
    
    /// Duplicate top item
    OP_DUP = 0x76,
    
    /// Remove second item
    OP_NIP = 0x77,
    
    /// Copy second item to top
    OP_OVER = 0x78,
    
    /// Copy nth item to top
    OP_PICK = 0x79,
    
    /// Move nth item to top
    OP_ROLL = 0x7A,
    
    /// Rotate top 3: (a b c → b c a)
    OP_ROT = 0x7B,
    
    /// Swap top two items
    OP_SWAP = 0x7C,
    
    /// Copy top to second position
    OP_TUCK = 0x7D,
    
    // =========================================================================
    // Splice Operations (0x7E - 0x82) - Disabled in Bitcoin
    // =========================================================================
    
    /// Concatenate (disabled)
    OP_CAT = 0x7E,
    
    /// Split at position (disabled)
    OP_SUBSTR = 0x7F,
    
    /// Keep left n bytes (disabled)
    OP_LEFT = 0x80,
    
    /// Keep right n bytes (disabled)
    OP_RIGHT = 0x81,
    
    /// Push string length
    OP_SIZE = 0x82,
    
    // =========================================================================
    // Bitwise Logic (0x83 - 0x8A)
    // =========================================================================
    
    /// Bitwise invert (disabled)
    OP_INVERT = 0x83,
    
    /// Bitwise AND (disabled)
    OP_AND = 0x84,
    
    /// Bitwise OR (disabled)
    OP_OR = 0x85,
    
    /// Bitwise XOR (disabled)
    OP_XOR = 0x86,
    
    /// True if inputs are equal byte-by-byte
    OP_EQUAL = 0x87,
    
    /// OP_EQUAL then OP_VERIFY
    OP_EQUALVERIFY = 0x88,
    
    /// Reserved
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8A,
    
    // =========================================================================
    // Arithmetic (0x8B - 0xA5)
    // =========================================================================
    
    /// Add 1 to top
    OP_1ADD = 0x8B,
    
    /// Subtract 1 from top
    OP_1SUB = 0x8C,
    
    /// Multiply by 2 (disabled)
    OP_2MUL = 0x8D,
    
    /// Divide by 2 (disabled)
    OP_2DIV = 0x8E,
    
    /// Negate top
    OP_NEGATE = 0x8F,
    
    /// Absolute value
    OP_ABS = 0x90,
    
    /// Boolean NOT
    OP_NOT = 0x91,
    
    /// True if not 0
    OP_0NOTEQUAL = 0x92,
    
    /// a + b
    OP_ADD = 0x93,
    
    /// a - b
    OP_SUB = 0x94,
    
    /// a * b (disabled)
    OP_MUL = 0x95,
    
    /// a / b (disabled)
    OP_DIV = 0x96,
    
    /// a % b (disabled)
    OP_MOD = 0x97,
    
    /// Left shift (disabled)
    OP_LSHIFT = 0x98,
    
    /// Right shift (disabled)
    OP_RSHIFT = 0x99,
    
    /// Boolean AND
    OP_BOOLAND = 0x9A,
    
    /// Boolean OR
    OP_BOOLOR = 0x9B,
    
    /// Numeric equality
    OP_NUMEQUAL = 0x9C,
    
    /// OP_NUMEQUAL then OP_VERIFY
    OP_NUMEQUALVERIFY = 0x9D,
    
    /// Numeric inequality
    OP_NUMNOTEQUAL = 0x9E,
    
    /// a < b
    OP_LESSTHAN = 0x9F,
    
    /// a > b
    OP_GREATERTHAN = 0xA0,
    
    /// a <= b
    OP_LESSTHANOREQUAL = 0xA1,
    
    /// a >= b
    OP_GREATERTHANOREQUAL = 0xA2,
    
    /// min(a, b)
    OP_MIN = 0xA3,
    
    /// max(a, b)
    OP_MAX = 0xA4,
    
    /// True if x in [min, max]
    OP_WITHIN = 0xA5,
    
    // =========================================================================
    // Cryptographic (0xA6 - 0xAF)
    // =========================================================================
    
    /// RIPEMD-160 hash
    OP_RIPEMD160 = 0xA6,
    
    /// SHA-1 hash
    OP_SHA1 = 0xA7,
    
    /// SHA-256 hash
    OP_SHA256 = 0xA8,
    
    /// SHA-256 then RIPEMD-160
    OP_HASH160 = 0xA9,
    
    /// Double SHA-256
    OP_HASH256 = 0xAA,
    
    /// Mark for signature checking
    OP_CODESEPARATOR = 0xAB,
    
    /// Check signature
    OP_CHECKSIG = 0xAC,
    
    /// OP_CHECKSIG then OP_VERIFY
    OP_CHECKSIGVERIFY = 0xAD,
    
    /// Check multisig (m-of-n)
    OP_CHECKMULTISIG = 0xAE,
    
    /// OP_CHECKMULTISIG then OP_VERIFY
    OP_CHECKMULTISIGVERIFY = 0xAF,
    
    // =========================================================================
    // Expansion / NOP (0xB0 - 0xB9)
    // =========================================================================
    
    /// No operation (can be redefined)
    OP_NOP1 = 0xB0,
    
    /// Check lock time (absolute)
    OP_CHECKLOCKTIMEVERIFY = 0xB1,
    
    /// Check sequence (relative)
    OP_CHECKSEQUENCEVERIFY = 0xB2,
    
    /// Reserved for future expansion
    OP_NOP4 = 0xB3,
    OP_NOP5 = 0xB4,
    OP_NOP6 = 0xB5,
    OP_NOP7 = 0xB6,
    OP_NOP8 = 0xB7,
    OP_NOP9 = 0xB8,
    OP_NOP10 = 0xB9,
    
    // =========================================================================
    // Invalid / Undefined (0xBA - 0xFF)
    // =========================================================================
    
    /// Invalid opcode
    OP_INVALIDOPCODE = 0xFF,
}

impl Opcode {
    /// Create opcode from byte
    pub fn from_byte(byte: u8) -> Option<Self> {
        // Handle special cases and ranges
        Some(match byte {
            0x00 => Opcode::OP_0,
            0x01..=0x4B => unsafe { std::mem::transmute(byte) }, // PUSHBYTES
            0x4C => Opcode::OP_PUSHDATA1,
            0x4D => Opcode::OP_PUSHDATA2,
            0x4E => Opcode::OP_PUSHDATA4,
            0x4F => Opcode::OP_1NEGATE,
            0x50 => Opcode::OP_RESERVED,
            0x51..=0x60 => unsafe { std::mem::transmute(byte) }, // OP_1 to OP_16
            0x61 => Opcode::OP_NOP,
            0x62 => Opcode::OP_VER,
            0x63 => Opcode::OP_IF,
            0x64 => Opcode::OP_NOTIF,
            0x65 => Opcode::OP_VERIF,
            0x66 => Opcode::OP_VERNOTIF,
            0x67 => Opcode::OP_ELSE,
            0x68 => Opcode::OP_ENDIF,
            0x69 => Opcode::OP_VERIFY,
            0x6A => Opcode::OP_RETURN,
            0x6B => Opcode::OP_TOALTSTACK,
            0x6C => Opcode::OP_FROMALTSTACK,
            0x6D => Opcode::OP_2DROP,
            0x6E => Opcode::OP_2DUP,
            0x6F => Opcode::OP_3DUP,
            0x70 => Opcode::OP_2OVER,
            0x71 => Opcode::OP_2ROT,
            0x72 => Opcode::OP_2SWAP,
            0x73 => Opcode::OP_IFDUP,
            0x74 => Opcode::OP_DEPTH,
            0x75 => Opcode::OP_DROP,
            0x76 => Opcode::OP_DUP,
            0x77 => Opcode::OP_NIP,
            0x78 => Opcode::OP_OVER,
            0x79 => Opcode::OP_PICK,
            0x7A => Opcode::OP_ROLL,
            0x7B => Opcode::OP_ROT,
            0x7C => Opcode::OP_SWAP,
            0x7D => Opcode::OP_TUCK,
            0x7E => Opcode::OP_CAT,
            0x7F => Opcode::OP_SUBSTR,
            0x80 => Opcode::OP_LEFT,
            0x81 => Opcode::OP_RIGHT,
            0x82 => Opcode::OP_SIZE,
            0x83 => Opcode::OP_INVERT,
            0x84 => Opcode::OP_AND,
            0x85 => Opcode::OP_OR,
            0x86 => Opcode::OP_XOR,
            0x87 => Opcode::OP_EQUAL,
            0x88 => Opcode::OP_EQUALVERIFY,
            0x89 => Opcode::OP_RESERVED1,
            0x8A => Opcode::OP_RESERVED2,
            0x8B => Opcode::OP_1ADD,
            0x8C => Opcode::OP_1SUB,
            0x8D => Opcode::OP_2MUL,
            0x8E => Opcode::OP_2DIV,
            0x8F => Opcode::OP_NEGATE,
            0x90 => Opcode::OP_ABS,
            0x91 => Opcode::OP_NOT,
            0x92 => Opcode::OP_0NOTEQUAL,
            0x93 => Opcode::OP_ADD,
            0x94 => Opcode::OP_SUB,
            0x95 => Opcode::OP_MUL,
            0x96 => Opcode::OP_DIV,
            0x97 => Opcode::OP_MOD,
            0x98 => Opcode::OP_LSHIFT,
            0x99 => Opcode::OP_RSHIFT,
            0x9A => Opcode::OP_BOOLAND,
            0x9B => Opcode::OP_BOOLOR,
            0x9C => Opcode::OP_NUMEQUAL,
            0x9D => Opcode::OP_NUMEQUALVERIFY,
            0x9E => Opcode::OP_NUMNOTEQUAL,
            0x9F => Opcode::OP_LESSTHAN,
            0xA0 => Opcode::OP_GREATERTHAN,
            0xA1 => Opcode::OP_LESSTHANOREQUAL,
            0xA2 => Opcode::OP_GREATERTHANOREQUAL,
            0xA3 => Opcode::OP_MIN,
            0xA4 => Opcode::OP_MAX,
            0xA5 => Opcode::OP_WITHIN,
            0xA6 => Opcode::OP_RIPEMD160,
            0xA7 => Opcode::OP_SHA1,
            0xA8 => Opcode::OP_SHA256,
            0xA9 => Opcode::OP_HASH160,
            0xAA => Opcode::OP_HASH256,
            0xAB => Opcode::OP_CODESEPARATOR,
            0xAC => Opcode::OP_CHECKSIG,
            0xAD => Opcode::OP_CHECKSIGVERIFY,
            0xAE => Opcode::OP_CHECKMULTISIG,
            0xAF => Opcode::OP_CHECKMULTISIGVERIFY,
            0xB0 => Opcode::OP_NOP1,
            0xB1 => Opcode::OP_CHECKLOCKTIMEVERIFY,
            0xB2 => Opcode::OP_CHECKSEQUENCEVERIFY,
            0xB3 => Opcode::OP_NOP4,
            0xB4 => Opcode::OP_NOP5,
            0xB5 => Opcode::OP_NOP6,
            0xB6 => Opcode::OP_NOP7,
            0xB7 => Opcode::OP_NOP8,
            0xB8 => Opcode::OP_NOP9,
            0xB9 => Opcode::OP_NOP10,
            0xFF => Opcode::OP_INVALIDOPCODE,
            _ => return None,
        })
    }
    
    /// Convert to byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }
    
    /// Check if this is a push opcode
    pub fn is_push(&self) -> bool {
        let byte = self.to_byte();
        byte <= 0x60 && byte != 0x50 // OP_0 through OP_16, excluding OP_RESERVED
    }
    
    /// Check if disabled (makes TX invalid if executed)
    pub fn is_disabled(&self) -> bool {
        matches!(self,
            Opcode::OP_CAT |
            Opcode::OP_SUBSTR |
            Opcode::OP_LEFT |
            Opcode::OP_RIGHT |
            Opcode::OP_INVERT |
            Opcode::OP_AND |
            Opcode::OP_OR |
            Opcode::OP_XOR |
            Opcode::OP_2MUL |
            Opcode::OP_2DIV |
            Opcode::OP_MUL |
            Opcode::OP_DIV |
            Opcode::OP_MOD |
            Opcode::OP_LSHIFT |
            Opcode::OP_RSHIFT
        )
    }
    
    /// Check if reserved (makes TX invalid)
    pub fn is_reserved(&self) -> bool {
        matches!(self,
            Opcode::OP_RESERVED |
            Opcode::OP_VER |
            Opcode::OP_VERIF |
            Opcode::OP_VERNOTIF |
            Opcode::OP_RESERVED1 |
            Opcode::OP_RESERVED2
        )
    }
    
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Opcode::OP_0 => "OP_0",
            Opcode::OP_PUSHDATA1 => "OP_PUSHDATA1",
            Opcode::OP_PUSHDATA2 => "OP_PUSHDATA2",
            Opcode::OP_PUSHDATA4 => "OP_PUSHDATA4",
            Opcode::OP_1NEGATE => "OP_1NEGATE",
            Opcode::OP_RESERVED => "OP_RESERVED",
            Opcode::OP_1 => "OP_1",
            Opcode::OP_2 => "OP_2",
            Opcode::OP_3 => "OP_3",
            Opcode::OP_4 => "OP_4",
            Opcode::OP_5 => "OP_5",
            Opcode::OP_6 => "OP_6",
            Opcode::OP_7 => "OP_7",
            Opcode::OP_8 => "OP_8",
            Opcode::OP_9 => "OP_9",
            Opcode::OP_10 => "OP_10",
            Opcode::OP_11 => "OP_11",
            Opcode::OP_12 => "OP_12",
            Opcode::OP_13 => "OP_13",
            Opcode::OP_14 => "OP_14",
            Opcode::OP_15 => "OP_15",
            Opcode::OP_16 => "OP_16",
            Opcode::OP_NOP => "OP_NOP",
            Opcode::OP_VER => "OP_VER",
            Opcode::OP_IF => "OP_IF",
            Opcode::OP_NOTIF => "OP_NOTIF",
            Opcode::OP_VERIF => "OP_VERIF",
            Opcode::OP_VERNOTIF => "OP_VERNOTIF",
            Opcode::OP_ELSE => "OP_ELSE",
            Opcode::OP_ENDIF => "OP_ENDIF",
            Opcode::OP_VERIFY => "OP_VERIFY",
            Opcode::OP_RETURN => "OP_RETURN",
            Opcode::OP_TOALTSTACK => "OP_TOALTSTACK",
            Opcode::OP_FROMALTSTACK => "OP_FROMALTSTACK",
            Opcode::OP_2DROP => "OP_2DROP",
            Opcode::OP_2DUP => "OP_2DUP",
            Opcode::OP_3DUP => "OP_3DUP",
            Opcode::OP_2OVER => "OP_2OVER",
            Opcode::OP_2ROT => "OP_2ROT",
            Opcode::OP_2SWAP => "OP_2SWAP",
            Opcode::OP_IFDUP => "OP_IFDUP",
            Opcode::OP_DEPTH => "OP_DEPTH",
            Opcode::OP_DROP => "OP_DROP",
            Opcode::OP_DUP => "OP_DUP",
            Opcode::OP_NIP => "OP_NIP",
            Opcode::OP_OVER => "OP_OVER",
            Opcode::OP_PICK => "OP_PICK",
            Opcode::OP_ROLL => "OP_ROLL",
            Opcode::OP_ROT => "OP_ROT",
            Opcode::OP_SWAP => "OP_SWAP",
            Opcode::OP_TUCK => "OP_TUCK",
            Opcode::OP_SIZE => "OP_SIZE",
            Opcode::OP_EQUAL => "OP_EQUAL",
            Opcode::OP_EQUALVERIFY => "OP_EQUALVERIFY",
            Opcode::OP_1ADD => "OP_1ADD",
            Opcode::OP_1SUB => "OP_1SUB",
            Opcode::OP_NEGATE => "OP_NEGATE",
            Opcode::OP_ABS => "OP_ABS",
            Opcode::OP_NOT => "OP_NOT",
            Opcode::OP_0NOTEQUAL => "OP_0NOTEQUAL",
            Opcode::OP_ADD => "OP_ADD",
            Opcode::OP_SUB => "OP_SUB",
            Opcode::OP_BOOLAND => "OP_BOOLAND",
            Opcode::OP_BOOLOR => "OP_BOOLOR",
            Opcode::OP_NUMEQUAL => "OP_NUMEQUAL",
            Opcode::OP_NUMEQUALVERIFY => "OP_NUMEQUALVERIFY",
            Opcode::OP_NUMNOTEQUAL => "OP_NUMNOTEQUAL",
            Opcode::OP_LESSTHAN => "OP_LESSTHAN",
            Opcode::OP_GREATERTHAN => "OP_GREATERTHAN",
            Opcode::OP_LESSTHANOREQUAL => "OP_LESSTHANOREQUAL",
            Opcode::OP_GREATERTHANOREQUAL => "OP_GREATERTHANOREQUAL",
            Opcode::OP_MIN => "OP_MIN",
            Opcode::OP_MAX => "OP_MAX",
            Opcode::OP_WITHIN => "OP_WITHIN",
            Opcode::OP_RIPEMD160 => "OP_RIPEMD160",
            Opcode::OP_SHA1 => "OP_SHA1",
            Opcode::OP_SHA256 => "OP_SHA256",
            Opcode::OP_HASH160 => "OP_HASH160",
            Opcode::OP_HASH256 => "OP_HASH256",
            Opcode::OP_CODESEPARATOR => "OP_CODESEPARATOR",
            Opcode::OP_CHECKSIG => "OP_CHECKSIG",
            Opcode::OP_CHECKSIGVERIFY => "OP_CHECKSIGVERIFY",
            Opcode::OP_CHECKMULTISIG => "OP_CHECKMULTISIG",
            Opcode::OP_CHECKMULTISIGVERIFY => "OP_CHECKMULTISIGVERIFY",
            Opcode::OP_NOP1 => "OP_NOP1",
            Opcode::OP_CHECKLOCKTIMEVERIFY => "OP_CHECKLOCKTIMEVERIFY",
            Opcode::OP_CHECKSEQUENCEVERIFY => "OP_CHECKSEQUENCEVERIFY",
            Opcode::OP_NOP4 => "OP_NOP4",
            Opcode::OP_NOP5 => "OP_NOP5",
            Opcode::OP_NOP6 => "OP_NOP6",
            Opcode::OP_NOP7 => "OP_NOP7",
            Opcode::OP_NOP8 => "OP_NOP8",
            Opcode::OP_NOP9 => "OP_NOP9",
            Opcode::OP_NOP10 => "OP_NOP10",
            Opcode::OP_INVALIDOPCODE => "OP_INVALIDOPCODE",
            _ => {
                let byte = self.to_byte();
                if byte >= 0x01 && byte <= 0x4B {
                    "OP_PUSHBYTES"
                } else {
                    "OP_UNKNOWN"
                }
            }
        }
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// =============================================================================
// Script Element
// =============================================================================

/// Element in a script (opcode or data)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptElement {
    /// An opcode
    Op(Opcode),
    /// Raw data to push
    Data(Vec<u8>),
}

impl ScriptElement {
    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            ScriptElement::Op(op) => vec![op.to_byte()],
            ScriptElement::Data(data) => {
                let len = data.len();
                if len == 0 {
                    vec![Opcode::OP_0.to_byte()]
                } else if len <= 75 {
                    let mut result = vec![len as u8];
                    result.extend_from_slice(data);
                    result
                } else if len <= 255 {
                    let mut result = vec![Opcode::OP_PUSHDATA1.to_byte(), len as u8];
                    result.extend_from_slice(data);
                    result
                } else if len <= 65535 {
                    let mut result = vec![Opcode::OP_PUSHDATA2.to_byte()];
                    result.extend_from_slice(&(len as u16).to_le_bytes());
                    result.extend_from_slice(data);
                    result
                } else {
                    let mut result = vec![Opcode::OP_PUSHDATA4.to_byte()];
                    result.extend_from_slice(&(len as u32).to_le_bytes());
                    result.extend_from_slice(data);
                    result
                }
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_opcode_from_byte() {
        assert_eq!(Opcode::from_byte(0x00), Some(Opcode::OP_0));
        assert_eq!(Opcode::from_byte(0x51), Some(Opcode::OP_1));
        assert_eq!(Opcode::from_byte(0x76), Some(Opcode::OP_DUP));
        assert_eq!(Opcode::from_byte(0xAC), Some(Opcode::OP_CHECKSIG));
    }
    
    #[test]
    fn test_opcode_to_byte() {
        assert_eq!(Opcode::OP_0.to_byte(), 0x00);
        assert_eq!(Opcode::OP_1.to_byte(), 0x51);
        assert_eq!(Opcode::OP_DUP.to_byte(), 0x76);
    }
    
    #[test]
    fn test_is_disabled() {
        assert!(Opcode::OP_MUL.is_disabled());
        assert!(Opcode::OP_DIV.is_disabled());
        assert!(!Opcode::OP_ADD.is_disabled());
        assert!(!Opcode::OP_SUB.is_disabled());
    }
    
    #[test]
    fn test_serialize_data() {
        // Small data (direct push)
        let elem = ScriptElement::Data(vec![0x01, 0x02, 0x03]);
        let serialized = elem.serialize();
        assert_eq!(serialized, vec![0x03, 0x01, 0x02, 0x03]);
        
        // Empty data
        let elem = ScriptElement::Data(vec![]);
        let serialized = elem.serialize();
        assert_eq!(serialized, vec![0x00]); // OP_0
    }
}

// =============================================================================
// Opcode Aliases (for convenience)
// =============================================================================

impl Opcode {
    pub const OP_FALSE: Opcode = Opcode::OP_0;
    pub const OP_TRUE: Opcode = Opcode::OP_1;
    pub const OP_CLTV: Opcode = Opcode::OP_CHECKLOCKTIMEVERIFY;
    pub const OP_CSV: Opcode = Opcode::OP_CHECKSEQUENCEVERIFY;
}
