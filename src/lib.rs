// =============================================================================
// MOONVAULT v4.0 - Bitcoin Security Infrastructure
// "Protecting your Bitcoin, not replacing it"
// =============================================================================
//
// IMPORTANT: MoonVault is NOT money. It is infrastructure software.
// - Gas units have NO monetary value
// - Gas is NOT transferable (burn-only)
// - BTC is the ONLY economic asset
// - Fees are paid in BTC on Bitcoin L1
//
// =============================================================================

#![allow(dead_code, unused_imports, unused_variables)]

// --- Protocol Identity ---
pub const PROTOCOL_NAME: &str = "MoonVault";
pub const PROTOCOL_VERSION_STR: &str = "4.0.0";
pub const PROTOCOL_DESCRIPTION: &str = "Bitcoin Security Infrastructure";
pub const SOFTWARE_LEGACY_NAME: &str = "Mooncoin";  // Historical reference only

// --- Gas System (NOT money) ---
pub const GAS_UNIT_NAME: &str = "gas";              // NOT "MOON", NOT "coin"
pub const GAS_TRANSFERABLE: bool = false;           // Gas CANNOT be sent to others
pub const GAS_BURNABLE: bool = true;                // Gas can ONLY be burned
pub const HALVING_ENABLED: bool = false;            // No artificial scarcity

// --- Archivos de datos ---
pub const DATA_FILE: &str = "moonvault.chain";
pub const DATA_FILE_BACKUP: &str = "moonvault.chain.bak";
pub const WALLET_FILE: &str = "vault.key";
pub const PENDING_TX_FILE: &str = "mempool.bin";
pub const VAULTS_FILE: &str = "vaults.json";
pub const FEE_RECORDS_FILE: &str = "fee_records.json";

// --- Parámetros de tiempo ---
pub const BLOCK_TIME_TARGET: u64 = 300;          // 5 minutos (300 segundos)
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;  // Cada 2016 bloques
pub const EXPECTED_TIMESPAN: u64 = BLOCK_TIME_TARGET * DIFFICULTY_ADJUSTMENT_INTERVAL;

// --- Parámetros de Gas (NO económicos - solo anti-spam) ---
pub const INITIAL_REWARD: u64 = 50 * 100_000_000;  // 50 gas units per block (constant, no halving)
pub const HALVING_INTERVAL: u64 = u64::MAX;        // Effectively disabled
pub const MAX_SUPPLY: u64 = u64::MAX;              // No artificial cap
pub const COINBASE_MATURITY: u64 = 100;            // Gas usable after 100 blocks
pub const MIN_FEE_PER_BYTE: u64 = 1;               // Internal gas fee
pub const MIN_RELAY_FEE: u64 = 1000;               // Internal gas fee

// --- Service Fees (in BTC satoshis, paid on Bitcoin L1) ---
pub const FEE_VAULT_CREATE: u64 = 10_000;          // 10,000 sats to create vault
pub const FEE_VAULT_MODIFY: u64 = 5_000;           // 5,000 sats to modify vault
pub const FEE_MONITORING_MONTHLY: u64 = 1_000;     // 1,000 sats/month for monitoring

// --- Gas Burn Costs (anti-spam) ---
pub const GAS_BURN_VAULT_CREATE: u64 = 1 * 100_000_000;   // 1 gas unit
pub const GAS_BURN_VAULT_MODIFY: u64 = 1 * 100_000_000;   // 1 gas unit
pub const GAS_BURN_SERVICE_REQUEST: u64 = 1 * 100_000_000; // 1 gas unit

// --- Fee Distribution (percentages) ---
pub const FEE_DIST_NODES: u8 = 70;                 // 70% to node operators
pub const FEE_DIST_MAINTENANCE: u8 = 20;           // 20% to maintenance
pub const FEE_DIST_RESERVE: u8 = 10;               // 10% to security reserve

// --- Fee Pool (Bitcoin L1) ---
// IMPORTANT: This will be set to actual address before mainnet launch
pub const FEE_POOL_ADDRESS_MAINNET: &str = "bc1q3nwy5deczus3uaz99snahq4xrmgwlc6d9dv7xk";
pub const FEE_POOL_ADDRESS_TESTNET: &str = "tb1q_FEE_POOL_ADDRESS_HERE";

// --- Parámetros de red ---
pub const P2P_PORT: u16 = 38333;
pub const RPC_PORT: u16 = 38332;
pub const MAX_PEERS: usize = 8;
pub const PROTOCOL_VERSION: u32 = 70002;           // Bumped for v4.0
pub const NETWORK_MAGIC: [u8; 4] = [0x4D, 0x56, 0x4C, 0x54]; // "MVLT" (MoonVault)

// --- Parámetros de minería/coordinación ---
pub const INITIAL_DIFFICULTY_BITS: u32 = 20;
pub const MIN_DIFFICULTY_BITS: u32 = 16;
pub const MAX_DIFFICULTY_BITS: u32 = 32;

// --- Parámetros de bloque ---
pub const MAX_BLOCK_SIZE: usize = 1_000_000;
pub const MAX_TXS_PER_BLOCK: usize = 1000;

// --- Genesis block ---
pub const GENESIS_TIMESTAMP: u64 = 1734120000;
pub const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const GENESIS_MESSAGE: &str = "MoonVault Genesis - Bitcoin Security Infrastructure - KNKI 2025";

// --- Address ---
pub const ADDRESS_PREFIX: &str = "MV";             // MoonVault
pub const ADDRESS_VERSION: u8 = 0x32;

// --- Utilidades ---

/// Get block reward (constant, no halving in v4.0)
pub fn get_reward(height: u64) -> u64 {
    // No halving - constant emission
    // Gas has no monetary value, only anti-spam function
    if HALVING_ENABLED {
        let halvings = height / HALVING_INTERVAL;
        if halvings >= 64 { 0 } else { INITIAL_REWARD >> halvings }
    } else {
        INITIAL_REWARD  // Constant 50 gas units per block
    }
}

/// Format gas units (NOT money)
pub fn format_gas(units: u64) -> String {
    let whole = units / 100_000_000;
    let frac = units % 100_000_000;
    if frac == 0 {
        format!("{} {}", whole, GAS_UNIT_NAME)
    } else {
        format!("{}.{:08} {}", whole, frac, GAS_UNIT_NAME)
    }
}

/// Legacy format function (deprecated, use format_gas)
pub fn format_coins(satoshis: u64) -> String {
    format_gas(satoshis)
}

/// Print startup warning
pub fn print_startup_warning() {
    eprintln!("╔═══════════════════════════════════════════════════════════════════════════╗");
    eprintln!("║                         MOONVAULT v4.0                                    ║");
    eprintln!("║                  Bitcoin Security Infrastructure                          ║");
    eprintln!("╠═══════════════════════════════════════════════════════════════════════════╣");
    eprintln!("║                                                                           ║");
    eprintln!("║  IMPORTANT: MoonVault is NOT money.                                       ║");
    eprintln!("║                                                                           ║");
    eprintln!("║  • 'Gas units' have NO monetary value                                     ║");
    eprintln!("║  • Gas is NOT transferable - burn only                                    ║");
    eprintln!("║  • BTC is the ONLY economic asset                                         ║");
    eprintln!("║  • Service fees are paid in BTC on Bitcoin L1                             ║");
    eprintln!("║                                                                           ║");
    eprintln!("║  If anyone tries to sell you gas units, they are scamming you.            ║");
    eprintln!("║                                                                           ║");
    eprintln!("╚═══════════════════════════════════════════════════════════════════════════╝");
    eprintln!();
}
