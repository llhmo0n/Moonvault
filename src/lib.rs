// =============================================================================
// MOONCOIN v2.0 - Constantes del Protocolo
// Bitcoin 2009 style - Híbrido (5 min blocks, dificultad ajustable)
// =============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

// --- Archivos de datos ---
pub const DATA_FILE: &str = "mooncoin.chain";
pub const DATA_FILE_BACKUP: &str = "mooncoin.chain.bak";
pub const WALLET_FILE: &str = "wallet.key";
pub const PENDING_TX_FILE: &str = "mempool.bin";

// --- Parámetros de tiempo ---
pub const BLOCK_TIME_TARGET: u64 = 300;          // 5 minutos (300 segundos)
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;  // Cada 2016 bloques (como Bitcoin)
pub const EXPECTED_TIMESPAN: u64 = BLOCK_TIME_TARGET * DIFFICULTY_ADJUSTMENT_INTERVAL; // ~7 días

// --- Parámetros económicos ---
pub const INITIAL_REWARD: u64 = 50 * 100_000_000;  // 50 MOON en satoshis (10^8)
pub const HALVING_INTERVAL: u64 = 210_000;          // Halving cada 210,000 bloques
pub const MAX_SUPPLY: u64 = 21_000_000 * 100_000_000; // 21 millones de MOON
pub const COINBASE_MATURITY: u64 = 100;            // Coinbase gastable después de 100 bloques
pub const MIN_FEE_PER_BYTE: u64 = 1;               // Fee mínimo: 1 satoshi por byte
pub const MIN_RELAY_FEE: u64 = 1000;               // Fee mínimo para relay: 1000 satoshis

// --- Parámetros de red ---
pub const P2P_PORT: u16 = 38333;
pub const RPC_PORT: u16 = 38332;
pub const MAX_PEERS: usize = 8;
pub const PROTOCOL_VERSION: u32 = 70001;
pub const NETWORK_MAGIC: [u8; 4] = [0x4D, 0x4F, 0x4F, 0x4E]; // "MOON"

// --- Parámetros de minería ---
pub const INITIAL_DIFFICULTY_BITS: u32 = 20;  // Dificultad inicial (20 bits de ceros)
pub const MIN_DIFFICULTY_BITS: u32 = 16;      // Dificultad mínima
pub const MAX_DIFFICULTY_BITS: u32 = 32;      // Dificultad máxima

// --- Parámetros de bloque ---
pub const MAX_BLOCK_SIZE: usize = 1_000_000;  // 1 MB máximo por bloque
pub const MAX_TXS_PER_BLOCK: usize = 1000;    // Máximo de transacciones por bloque

// --- Genesis block ---
pub const GENESIS_TIMESTAMP: u64 = 1734120000; // Fecha de génesis (ajustar)
pub const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const GENESIS_MESSAGE: &str = "Mooncoin Genesis - La plata digital - KNKI 2025";

// --- Address ---
pub const ADDRESS_PREFIX: &str = "MC";
pub const ADDRESS_VERSION: u8 = 0x32;  // Version byte para addresses (produce "M" en base58)

// --- Utilidades ---
pub fn get_reward(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 {
        0
    } else {
        INITIAL_REWARD >> halvings
    }
}

pub fn format_coins(satoshis: u64) -> String {
    let whole = satoshis / 100_000_000;
    let frac = satoshis % 100_000_000;
    if frac == 0 {
        format!("{} MOON", whole)
    } else {
        format!("{}.{:08} MOON", whole, frac)
    }
}
