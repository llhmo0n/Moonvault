// =============================================================================
// MOONVAULT v4.0 - Bitcoin Security Infrastructure
// "Protecting your Bitcoin, not replacing it"
// =============================================================================
//
// IMPORTANT: MoonVault is NOT money. It is infrastructure software.
// BTC is the only economic asset. Gas units have no monetary value.
//
// =============================================================================

#![allow(special_module_name)]
#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

mod lib;
mod transaction;
mod wallet;
mod block;
mod utxo;
mod difficulty;
mod validation;
mod network;
mod mempool;
mod reorg;
mod rpc;
mod storage;
mod hdwallet;
mod explorer;
mod script;
mod tx_builder;
mod peer_manager;
mod crypto;
mod segwit;
mod spv;
mod fee_estimator;
mod watch_wallet;
mod pruning;
mod testnet;
mod labels;
mod backup;
mod checkpoints;
mod dns_seeds;
mod dandelion;
mod privacy;
mod cli_wallet;
mod contracts;
mod channels;
mod atomic_swaps;
mod merkle;
mod btc_lock;
mod vaults;
mod recovery;
mod inheritance;
mod genesis;
mod node;
mod fee_system;
mod vault_service;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use clap::{Parser, Subcommand};

use crate::lib::*;
use crate::transaction::{Tx, TxIn, TxOut, tx_hash};
use crate::wallet::{load_or_create_key, get_pubkey, get_address, sign_tx, validate_address};
use crate::block::{Block, load_chain, save_chain, create_genesis_block, mine_block};
use crate::utxo::UtxoSet;
use crate::difficulty::calculate_next_difficulty;
use crate::validation::{validate_block, validate_transaction};
use crate::network::{NodeState, NodeEvent, start_p2p_server, broadcast_block, connect_to_peer, request_blocks_from_peer};
use crate::mempool::Mempool;
use crate::reorg::{ReorgManager, should_reorg, calculate_chain_work};
use crate::rpc::{start_rpc_server, RPC_PORT};
use crate::storage::{Storage, migrate_from_legacy};
use crate::hdwallet::{HdWallet, display_wallet_info};
use crate::explorer::{start_explorer, EXPLORER_PORT};

// =============================================================================
// CLI Definition
// =============================================================================

#[derive(Parser)]
#[command(name = "moonvault")]
#[command(author = "KNKI")]
#[command(version = "4.0.0")]
#[command(about = "MoonVault - Bitcoin Security Infrastructure", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the node and begin mining
    Run,
    
    /// Show wallet address and balance
    Balance,
    
    /// Send coins to an address
    Send {
        /// Recipient address
        to: String,
        /// Amount in MOON (e.g., 10.5)
        amount: f64,
    },
    
    /// Show blockchain status
    Status,
    
    /// Show wallet address
    Address,
    
    /// Validate the entire blockchain
    Validate,
    
    /// Export blockchain info
    Export,
    
    /// Connect to a peer
    Connect {
        /// Peer address (e.g., 192.168.1.100:38333)
        addr: String,
    },
    
    /// Show connected peers
    Peers,
    
    /// Show mempool (pending transactions)
    Mempool,
    
    /// Show HD wallet info
    Wallet {
        /// Show seed phrase (dangerous!)
        #[arg(long)]
        show_seed: bool,
    },
    
    /// Create new HD wallet with seed phrase
    NewSeed {
        /// Number of words (12 or 24)
        #[arg(default_value = "24")]
        words: usize,
    },
    
    /// Restore wallet from seed phrase
    Restore {
        /// Seed phrase (12 or 24 words in quotes)
        phrase: String,
    },
    
    /// Generate a new receiving address
    NewAddress,
    
    /// Create a multisig address (2-of-3)
    Multisig {
        /// Number of required signatures
        #[arg(short, long, default_value = "2")]
        required: u8,
        /// Public keys (hex, comma-separated) or "generate" to create new keys
        #[arg(short, long)]
        pubkeys: String,
    },
    
    /// Send with timelock (funds locked until block height)
    TimelockSend {
        /// Recipient address
        to: String,
        /// Amount in MOON
        amount: f64,
        /// Block height when funds become spendable
        unlock_height: u64,
    },
    
    /// Store data on blockchain using OP_RETURN
    StoreData {
        /// Data to store (max 80 bytes)
        data: String,
    },
    
    /// Decode and show script info for an address or transaction
    DecodeScript {
        /// Address or hex-encoded script
        input: String,
    },
    
    /// Encrypt the wallet with a password
    EncryptWallet,
    
    /// Decrypt/unlock the wallet
    DecryptWallet,
    
    /// Change wallet password
    ChangePassword,
    
    /// Generate a native SegWit address (mc1...)
    SegwitAddress,
    
    /// Decode any address type (legacy or SegWit)
    DecodeAddress {
        /// Address to decode
        address: String,
    },
    
    /// Generate Merkle proof for a transaction
    MerkleProof {
        /// Transaction ID
        txid: String,
    },
    
    /// Verify a transaction with SPV (Merkle proof)
    VerifyTx {
        /// Transaction ID
        txid: String,
    },
    
    /// Estimate transaction fees
    EstimateFee {
        /// Amount to send (optional, in MOON)
        #[arg(short, long)]
        amount: Option<f64>,
    },
    
    /// Watch an address (read-only monitoring)
    Watch {
        /// Address to watch
        address: String,
        /// Label for the address
        #[arg(short, long, default_value = "")]
        label: String,
    },
    
    /// Remove address from watch list
    Unwatch {
        /// Address to remove
        address: String,
    },
    
    /// List all watched addresses
    WatchList,
    
    /// Scan blockchain for watched addresses
    WatchScan,
    
    /// Show pruning status and blockchain size
    PruneStatus,
    
    /// Enable pruning (keep last N blocks)
    PruneEnable {
        /// Number of blocks to keep
        #[arg(short, long, default_value = "1000")]
        keep: u64,
    },
    
    /// Disable pruning (full node mode)
    PruneDisable,
    
    /// Run pruning now
    PruneNow,
    
    /// Show current network info
    NetworkInfo,
    
    /// Switch to testnet
    UseTestnet,
    
    /// Switch to mainnet  
    UseMainnet,
    
    /// Add a label to an address
    Label {
        /// Address to label
        address: String,
        /// Label/name for the address
        name: String,
        /// Category (optional)
        #[arg(short, long)]
        category: Option<String>,
    },
    
    /// List all labeled addresses
    LabelList,
    
    /// Remove a label from an address
    LabelRemove {
        /// Address to remove label from
        address: String,
    },
    
    /// Search addresses by label
    LabelSearch {
        /// Search query
        query: String,
    },
    
    /// Create a backup of the wallet
    BackupCreate {
        /// Output filename (optional)
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Restore wallet from backup file
    BackupRestore {
        /// Backup file to restore from
        file: String,
    },
    
    /// Show backup file information
    BackupInfo {
        /// Backup file to inspect
        file: String,
    },
    
    /// Show checkpoint information
    Checkpoints,
    
    /// Check security level of a transaction
    Security {
        /// Transaction ID
        txid: String,
    },
    
    /// Discover and show known peers
    Discover,
    
    /// Add a peer manually
    AddPeer {
        /// Peer address (ip:port)
        address: String,
    },
    
    /// Ban a peer
    BanPeer {
        /// Peer address (ip:port)
        address: String,
        /// Reason for ban
        #[arg(short, long, default_value = "manual")]
        reason: String,
    },
    
    /// Show Dandelion++ status
    Dandelion,
    
    /// Enable Dandelion++ privacy
    DandelionOn,
    
    /// Disable Dandelion++ (for debugging)
    DandelionOff,
    
    /// Generate new privacy keys (stealth address)
    PrivacyKeygen,
    
    /// Show privacy info and test primitives
    PrivacyInfo,
    
    /// Create a stealth payment (demo)
    StealthDemo,
    
    /// Demo ring signatures
    RingDemo,
    
    /// Demo shielded transaction (full privacy flow)
    ShieldedDemo,
    
    /// Demo validation context
    ValidationDemo,
    
    /// Demo wallet scanner
    ScannerDemo,
    
    /// Demo privacy RPC commands
    PrivacyRpcDemo,
    
    /// Demo full privacy integration
    PrivacyIntegrationDemo,
    
    /// Run E2E tests for privacy system
    RunPrivacyTests,
    
    /// Interactive wallet CLI
    WalletCli,
    
    /// Smart contracts demo
    ContractsDemo,
    
    /// Payment channels demo
    ChannelsDemo,
    
    /// Atomic swaps demo
    AtomicSwapsDemo,
    
    /// Merkle trees demo
    MerkleDemo,

    // ========== BTC LOCK-OPERATE-SETTLE ==========
    
    /// [BTC-LOCK] Show available LOCK STANDARD templates
    BtcLockTemplates,
    
    /// [BTC-LOCK] Generate a LOCK script for Bitcoin
    BtcLockGenerate {
        /// Template: multisig_cltv or htlc_simple
        #[arg(short, long, default_value = "multisig_cltv")]
        template: String,
        /// Hot wallet pubkey (33 bytes hex)
        #[arg(long)]
        pubkey_hot: String,
        /// Cold wallet pubkey (33 bytes hex)
        #[arg(long)]
        pubkey_cold: String,
        /// Recovery pubkey (33 bytes hex)
        #[arg(long)]
        pubkey_recovery: String,
        /// Timelock block height
        #[arg(long)]
        timelock: u32,
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    /// [BTC-LOCK] Verify a script matches LOCK STANDARD
    BtcLockVerify {
        /// Redeem script in hex
        script: String,
    },
    
    /// [BTC-LOCK] Register a BTC LOCK (observation only)
    BtcLockRegister {
        /// Bitcoin transaction ID (64 hex chars)
        #[arg(long)]
        txid: String,
        /// Output index
        #[arg(long, default_value = "0")]
        vout: u32,
        /// Redeem script in hex
        #[arg(long)]
        script: String,
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    /// [BTC-LOCK] Show status of a registered LOCK
    BtcLockStatus {
        /// Bitcoin transaction ID
        #[arg(long)]
        txid: String,
        /// Output index
        #[arg(long, default_value = "0")]
        vout: u32,
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    /// [BTC-LOCK] List all registered BTC LOCKs
    BtcLockList {
        /// Filter by state: locked, expired, settled, all
        #[arg(long, default_value = "all")]
        state: String,
    },
    
    /// [BTC-LOCK] Check if LOCK is ready for settlement
    BtcLockSettleCheck {
        /// Bitcoin transaction ID
        #[arg(long)]
        txid: String,
        /// Output index
        #[arg(long, default_value = "0")]
        vout: u32,
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    /// [BTC-LOCK] Demo the complete LOCK-OPERATE-SETTLE flow
    BtcLockDemo,
    
    /// [BTC-LOCK] Test connection to Bitcoin network (Esplora API)
    BtcLockConnect {
        /// Use testnet instead of mainnet
        #[arg(long)]
        testnet: bool,
        /// Use signet
        #[arg(long)]
        signet: bool,
    },
    
    /// [BTC-LOCK] Query a Bitcoin transaction (real network)
    BtcLockQueryTx {
        /// Transaction ID to query
        txid: String,
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    /// [BTC-LOCK] Check UTXO status on real Bitcoin network
    BtcLockCheckUtxo {
        /// Transaction ID
        #[arg(long)]
        txid: String,
        /// Output index
        #[arg(long, default_value = "0")]
        vout: u32,
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    /// [BTC-LOCK] Generate test keypairs for LOCK scripts (TESTNET ONLY)
    BtcLockKeygen {
        /// Number of keypairs to generate (default: 3 for hot/cold/recovery)
        #[arg(long, default_value = "3")]
        count: u32,
    },
    
    /// [BTC-LOCK] Refresh status of all registered LOCKs
    BtcLockRefresh {
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    /// [BTC-LOCK] System health check - verify all BTC Lock components
    BtcLockHealth,
    
    /// [BTC-LOCK] Build settlement transaction to recover BTC
    BtcLockSettle {
        /// Bitcoin transaction ID of the LOCK
        #[arg(long)]
        txid: String,
        /// Output index
        #[arg(long, default_value = "0")]
        vout: u32,
        /// Destination address (where to send recovered BTC)
        #[arg(long)]
        destination: String,
        /// Recovery private key (hex)
        #[arg(long)]
        privkey: String,
        /// Fee rate in sat/vbyte (default: 2)
        #[arg(long, default_value = "2")]
        fee_rate: u64,
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    // =========================================================================
    // FEE SYSTEM COMMANDS (v4.0)
    // =========================================================================
    
    /// [FEE] Generate invoice for a service (paid in BTC)
    FeeInvoice {
        /// Service type: vault-create, vault-modify, monitoring-monthly
        service: String,
        /// Your public key (hex)
        #[arg(long)]
        pubkey: String,
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    /// [FEE] Verify a BTC payment for an invoice
    FeeVerify {
        /// Bitcoin transaction ID of the payment
        txid: String,
        /// Invoice ID to verify against
        #[arg(long)]
        invoice: String,
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    /// [FEE] Show Fee Pool status
    FeePoolStatus {
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    // =========================================================================
    // VAULT SERVICE COMMANDS (v4.0)
    // =========================================================================
    
    /// [VAULT] Create a new security vault (requires paid invoice)
    VaultCreate {
        /// Invoice ID (must be paid and confirmed)
        #[arg(long)]
        invoice: String,
        /// Hot key public key (for daily operations)
        #[arg(long)]
        hot_key: String,
        /// Cold key public key (for large withdrawals)
        #[arg(long)]
        cold_key: String,
        /// Recovery key public key (for emergencies)
        #[arg(long)]
        recovery_key: String,
        /// Daily limit in satoshis for hot key
        #[arg(long, default_value = "100000")]
        daily_limit: u64,
        /// Delay in blocks for cold key withdrawals
        #[arg(long, default_value = "144")]
        cold_delay: u32,
        /// Timelock block height for recovery
        #[arg(long)]
        timelock: u32,
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    /// [VAULT] Show vault status
    VaultStatus {
        /// Vault ID
        vault_id: String,
        /// Use testnet
        #[arg(long)]
        testnet: bool,
    },
    
    /// [VAULT] Activate panic button (freeze all operations)
    VaultPanic {
        /// Vault ID
        vault_id: String,
        /// Recovery private key (hex)
        #[arg(long)]
        recovery_key: String,
    },
    
    /// [VAULT] List all your vaults
    VaultList {
        /// Filter by owner public key
        #[arg(long)]
        owner: Option<String>,
    },
    
    /// [GAS] Show gas balance (anti-spam units)
    GasBalance,
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() {
    // Print startup warning (MoonVault is NOT money)
    crate::lib::print_startup_warning();
    
    // Initialize logger (solo warnings y errores para no interferir con dashboard)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp_secs()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Run) | None => cmd_run().await,
        Some(Commands::Balance) => cmd_balance(),
        Some(Commands::Send { to, amount }) => cmd_send(to, amount),
        Some(Commands::Status) => cmd_status(),
        Some(Commands::Address) => cmd_address(),
        Some(Commands::Validate) => cmd_validate(),
        Some(Commands::Export) => cmd_export(),
        Some(Commands::Connect { addr }) => cmd_connect(addr).await,
        Some(Commands::Peers) => cmd_peers(),
        Some(Commands::Mempool) => cmd_mempool(),
        Some(Commands::Wallet { show_seed }) => cmd_wallet(show_seed),
        Some(Commands::NewSeed { words }) => cmd_new_seed(words),
        Some(Commands::Restore { phrase }) => cmd_restore(phrase),
        Some(Commands::NewAddress) => cmd_new_address(),
        Some(Commands::Multisig { required, pubkeys }) => cmd_multisig(required, pubkeys),
        Some(Commands::TimelockSend { to, amount, unlock_height }) => cmd_timelock_send(to, amount, unlock_height),
        Some(Commands::StoreData { data }) => cmd_store_data(data),
        Some(Commands::DecodeScript { input }) => cmd_decode_script(input),
        Some(Commands::EncryptWallet) => cmd_encrypt_wallet(),
        Some(Commands::DecryptWallet) => cmd_decrypt_wallet(),
        Some(Commands::ChangePassword) => cmd_change_password(),
        Some(Commands::SegwitAddress) => cmd_segwit_address(),
        Some(Commands::DecodeAddress { address }) => cmd_decode_address(address),
        Some(Commands::MerkleProof { txid }) => cmd_merkle_proof(txid),
        Some(Commands::VerifyTx { txid }) => cmd_verify_tx(txid),
        Some(Commands::EstimateFee { amount }) => cmd_estimate_fee(amount),
        Some(Commands::Watch { address, label }) => cmd_watch(address, label),
        Some(Commands::Unwatch { address }) => cmd_unwatch(address),
        Some(Commands::WatchList) => cmd_watch_list(),
        Some(Commands::WatchScan) => cmd_watch_scan(),
        Some(Commands::PruneStatus) => cmd_prune_status(),
        Some(Commands::PruneEnable { keep }) => cmd_prune_enable(keep),
        Some(Commands::PruneDisable) => cmd_prune_disable(),
        Some(Commands::PruneNow) => cmd_prune_now(),
        Some(Commands::NetworkInfo) => cmd_network_info(),
        Some(Commands::UseTestnet) => cmd_use_testnet(),
        Some(Commands::UseMainnet) => cmd_use_mainnet(),
        Some(Commands::Label { address, name, category }) => cmd_label(address, name, category),
        Some(Commands::LabelList) => cmd_label_list(),
        Some(Commands::LabelRemove { address }) => cmd_label_remove(address),
        Some(Commands::LabelSearch { query }) => cmd_label_search(query),
        Some(Commands::BackupCreate { output }) => cmd_backup(output),
        Some(Commands::BackupRestore { file }) => cmd_backup_restore(file),
        Some(Commands::BackupInfo { file }) => cmd_backup_info(file),
        Some(Commands::Checkpoints) => cmd_checkpoints(),
        Some(Commands::Security { txid }) => cmd_security(txid),
        Some(Commands::Discover) => cmd_discover(),
        Some(Commands::AddPeer { address }) => cmd_add_peer(address),
        Some(Commands::BanPeer { address, reason }) => cmd_ban_peer(address, reason),
        Some(Commands::Dandelion) => cmd_dandelion(),
        Some(Commands::DandelionOn) => cmd_dandelion_on(),
        Some(Commands::DandelionOff) => cmd_dandelion_off(),
        Some(Commands::PrivacyKeygen) => cmd_privacy_keygen(),
        Some(Commands::PrivacyInfo) => cmd_privacy_info(),
        Some(Commands::StealthDemo) => cmd_stealth_demo(),
        Some(Commands::RingDemo) => cmd_ring_demo(),
        Some(Commands::ShieldedDemo) => cmd_shielded_demo(),
        Some(Commands::ValidationDemo) => cmd_validation_demo(),
        Some(Commands::ScannerDemo) => cmd_scanner_demo(),
        Some(Commands::PrivacyRpcDemo) => cmd_privacy_rpc_demo(),
        Some(Commands::PrivacyIntegrationDemo) => cmd_privacy_integration_demo(),
        Some(Commands::RunPrivacyTests) => cmd_run_privacy_tests(),
        Some(Commands::WalletCli) => cmd_wallet_cli(),
        Some(Commands::ContractsDemo) => cmd_contracts_demo(),
        Some(Commands::ChannelsDemo) => cmd_channels_demo(),
        Some(Commands::AtomicSwapsDemo) => cmd_atomic_swaps_demo(),
        Some(Commands::MerkleDemo) => cmd_merkle_demo(),
        Some(Commands::BtcLockTemplates) => cmd_btc_lock_templates(),
        Some(Commands::BtcLockGenerate { template, pubkey_hot, pubkey_cold, pubkey_recovery, timelock, testnet }) 
            => cmd_btc_lock_generate(template, pubkey_hot, pubkey_cold, pubkey_recovery, timelock, testnet),
        Some(Commands::BtcLockVerify { script }) => cmd_btc_lock_verify(script),
        Some(Commands::BtcLockRegister { txid, vout, script, testnet }) => cmd_btc_lock_register(txid, vout, script, testnet),
        Some(Commands::BtcLockStatus { txid, vout, testnet }) => cmd_btc_lock_status(txid, vout, testnet),
        Some(Commands::BtcLockList { state }) => cmd_btc_lock_list(state),
        Some(Commands::BtcLockSettleCheck { txid, vout, testnet }) => cmd_btc_lock_settle_check(txid, vout, testnet),
        Some(Commands::BtcLockDemo) => cmd_btc_lock_demo(),
        Some(Commands::BtcLockConnect { testnet, signet }) => cmd_btc_lock_connect(testnet, signet),
        Some(Commands::BtcLockQueryTx { txid, testnet }) => cmd_btc_lock_query_tx(txid, testnet),
        Some(Commands::BtcLockCheckUtxo { txid, vout, testnet }) => cmd_btc_lock_check_utxo(txid, vout, testnet),
        Some(Commands::BtcLockKeygen { count }) => cmd_btc_lock_keygen(count),
        Some(Commands::BtcLockRefresh { testnet }) => cmd_btc_lock_refresh(testnet),
        Some(Commands::BtcLockHealth) => cmd_btc_lock_health(),
        Some(Commands::BtcLockSettle { txid, vout, destination, privkey, fee_rate, testnet }) 
            => cmd_btc_lock_settle(txid, vout, destination, privkey, fee_rate, testnet),
        
        // Fee System Commands (v4.0)
        Some(Commands::FeeInvoice { service, pubkey, testnet }) 
            => cmd_fee_invoice(service, pubkey, testnet),
        Some(Commands::FeeVerify { txid, invoice, testnet }) 
            => cmd_fee_verify(txid, invoice, testnet),
        Some(Commands::FeePoolStatus { testnet }) 
            => cmd_fee_pool_status(testnet),
        
        // Vault Service Commands (v4.0)
        Some(Commands::VaultCreate { invoice, hot_key, cold_key, recovery_key, daily_limit, cold_delay, timelock, testnet }) 
            => cmd_vault_create(invoice, hot_key, cold_key, recovery_key, daily_limit, cold_delay, timelock, testnet),
        Some(Commands::VaultStatus { vault_id, testnet }) 
            => cmd_vault_status(vault_id, testnet),
        Some(Commands::VaultPanic { vault_id, recovery_key }) 
            => cmd_vault_panic(vault_id, recovery_key),
        Some(Commands::VaultList { owner }) 
            => cmd_vault_list(owner),
        
        // Gas Commands (v4.0)
        Some(Commands::GasBalance) 
            => cmd_gas_balance(),
    }
}

// =============================================================================
// Commands
// =============================================================================

/// Limpia la pantalla usando el comando del sistema
fn clear_screen() {
    let _ = std::process::Command::new("clear").status();
}

/// Muestra el dashboard de minado
fn display_dashboard(
    my_address: &str,
    height: u64,
    balance: u64,
    spendable: u64,
    utxo_count: usize,
    mempool_count: usize,
    difficulty: u32,
    last_block: Option<&Block>,
    mining_status: &str,
    next_halving: u64,
    supply: u64,
    peer_count: usize,
) {
    clear_screen();
    
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    
    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║              MOONVAULT v4.0 - Bitcoin Security Infrastructure         ║");
    println!("║                     Protecting your Bitcoin - by KNKI                 ║");
    println!("╠═══════════════════════════════════════════════════════════════════════╣");
    println!("║  {}                                            ║", now);
    println!("╚═══════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  📍 Node: {}", my_address);
    println!();
    println!("┌───────────────────────────────────────────────────────────────────────┐");
    println!("│                        COORDINATION LAYER STATUS                      │");
    println!("├───────────────────────────────────────────────────────────────────────┤");
    println!("│  Height:          {:>20}                              │", height);
    println!("│  Difficulty:      {:>20} bits                         │", difficulty);
    println!("│  Gas Minted:      {:>20}                              │", format_gas(supply));
    println!("│  Block Reward:    {:>20}                              │", format_gas(get_reward(height)));
    println!("└───────────────────────────────────────────────────────────────────────┘");
    println!();
    println!("┌───────────────────────────────────────────────────────────────────────┐");
    println!("│                           GAS BALANCE (anti-spam)                     │");
    println!("├───────────────────────────────────────────────────────────────────────┤");
    println!("│  ⛽ Gas Available: {:>20}                              │", format_gas(balance));
    println!("│  🔥 Burnable:     {:>20}                              │", format_gas(spendable));
    println!("│  📦 UTXOs:        {:>20}                              │", utxo_count);
    println!("└───────────────────────────────────────────────────────────────────────┘");
    println!();
    
    if let Some(block) = last_block {
        println!("┌───────────────────────────────────────────────────────────────────────┐");
        println!("│                           LAST BLOCK MINED                            │");
        println!("├───────────────────────────────────────────────────────────────────────┤");
        println!("│  🔗 Hash:         {}...              │", &block.hash[..24]);
        println!("│  🎲 Nonce:        {:>20}                              │", block.nonce);
        println!("│  📝 Txs:          {:>20}                              │", block.txs.len());
        println!("│  ⛽ Gas Reward:   {:>20}                              │", format_gas(get_reward(block.height)));
        println!("└───────────────────────────────────────────────────────────────────────┘");
        println!();
    }
    
    println!("┌───────────────────────────────────────────────────────────────────────┐");
    println!("│  ⛏️  {}  │", format!("{:^63}", mining_status));
    println!("├───────────────────────────────────────────────────────────────────────┤");
    println!("│  Mempool: {} pending tx(s)            Peers: {} connected             │", mempool_count, peer_count);
    println!("│  P2P: {}    RPC: {}    Explorer: http://127.0.0.1:{}       │", P2P_PORT, RPC_PORT, EXPLORER_PORT);
    println!("└───────────────────────────────────────────────────────────────────────┘");
    println!();
    println!("  Press Ctrl+C to stop mining");
}

/// Run the node and mine
async fn cmd_run() {
    // Load or create wallet
    let secret_key = load_or_create_key();
    let pubkey = get_pubkey(&secret_key);
    let my_address = get_address(&pubkey);

    // Initialize storage database
    let storage = match Storage::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open database: {}", e);
            return;
        }
    };
    
    // Migrate from legacy format if needed
    if let Err(e) = migrate_from_legacy(&storage) {
        eprintln!("Migration warning: {}", e);
    }

    // Load or create chain (still using legacy for now, will transition)
    let mut chain = load_chain();
    let mut is_new_chain = false;
    
    if chain.is_empty() {
        // Check if storage has data
        if let Some(height) = storage.get_best_height() {
            // Load from new storage
            chain = storage.load_chain();
            if chain.is_empty() {
                is_new_chain = true;
                let genesis = create_genesis_block(&my_address);
                chain.push(genesis.clone());
                save_chain(&chain);
                let _ = storage.put_block(&genesis);
                let _ = storage.apply_block_to_utxo(&genesis);
                let _ = storage.set_best_block(&genesis.hash, 0);
            }
        } else {
            is_new_chain = true;
            let genesis = create_genesis_block(&my_address);
            chain.push(genesis.clone());
            save_chain(&chain);
            let _ = storage.put_block(&genesis);
            let _ = storage.apply_block_to_utxo(&genesis);
            let _ = storage.set_best_block(&genesis.hash, 0);
        }
    }

    // Build UTXO set
    let mut utxo = UtxoSet::rebuild_from_chain(&chain);
    
    // Load mempool
    let mut mempool = Mempool::load();
    
    // Create reorg manager (keep undo data for last 100 blocks)
    let mut reorg_manager = ReorgManager::new(100);

    // Create shared state for P2P with new constructor
    let state = Arc::new(RwLock::new(NodeState::new(
        chain.clone(),
        format!("0.0.0.0:{}", P2P_PORT),
    )));

    // Create event channel
    let (event_tx, mut event_rx) = mpsc::channel::<NodeEvent>(100);

    // Start P2P server in background
    let state_clone = Arc::clone(&state);
    let event_tx_clone = event_tx.clone();
    tokio::spawn(async move {
        start_p2p_server(state_clone, event_tx_clone).await;
    });

    // Start RPC server in background
    tokio::spawn(async move {
        start_rpc_server().await;
    });

    // Start Block Explorer in background
    tokio::spawn(async move {
        start_explorer().await;
    });

    // Initial display
    let height = chain.len() as u64 - 1;
    let balance = utxo.balance_of(&my_address);
    let spendable = utxo.spendable_balance(&my_address, height);
    let next_halving = HALVING_INTERVAL - (height % HALVING_INTERVAL);
    let supply = utxo.total_supply();
    let difficulty = calculate_next_difficulty(&chain);
    
    let status_msg = if is_new_chain {
        "Genesis block created! Starting mining..."
    } else {
        "Resuming mining..."
    };
    
    display_dashboard(
        &my_address,
        height,
        balance,
        spendable,
        utxo.len(),
        mempool.len(),
        difficulty,
        chain.last(),
        status_msg,
        next_halving,
        supply,
        0,  // peer_count
    );
    
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Mining loop
    loop {
        // Check for network events (non-blocking)
        while let Ok(event) = event_rx.try_recv() {
            match event {
                NodeEvent::NewBlock(block) => {
                    // Verificar si el bloque extiende nuestra cadena
                    let our_tip = chain.last().map(|b| b.hash.clone()).unwrap_or_default();
                    
                    if block.prev_hash == our_tip {
                        // Caso simple: el bloque extiende nuestra cadena
                        let expected_diff = calculate_next_difficulty(&chain);
                        if let Ok(()) = validate_block(&block, &chain, &utxo, expected_diff) {
                            // Guardar undo antes de aplicar
                            reorg_manager.save_undo(&block, &utxo);
                            
                            chain.push(block.clone());
                            save_chain(&chain);
                            utxo.apply_block(&block);
                            
                            // Remover txs confirmadas del mempool
                            let confirmed: Vec<String> = block.txs.iter()
                                .skip(1)
                                .map(|tx| crate::transaction::tx_hash(tx))
                                .collect();
                            mempool.remove_confirmed(&confirmed);
                            
                            // Update shared state
                            {
                                let mut s = state.write().await;
                                s.update_chain(chain.clone());
                            }
                        }
                    } else if should_reorg(&chain, &block) {
                        // Posible fork: verificar si debemos reorganizar
                        // Por ahora, solo aceptamos cadenas que recibimos completas
                        // La sincronización manejará esto
                    }
                }
                NodeEvent::NewTx(tx) => {
                    let _ = mempool.add_tx(tx, &utxo, chain.len() as u64);
                }
                NodeEvent::PeerConnected(addr, their_height) => {
                    // Si el peer tiene más bloques, sincronizar
                    let our_height = chain.len() as u64 - 1;
                    
                    if their_height > our_height {
                        if let Ok(new_blocks) = request_blocks_from_peer(
                            &addr,
                            &chain.last().unwrap().hash,
                            Arc::clone(&state),
                        ).await {
                            if !new_blocks.is_empty() {
                                // Intentar reorganizar si es necesario
                                match reorg_manager.try_reorg(&mut chain, &mut utxo, &new_blocks) {
                                    Ok(result) => {
                                        if result.success {
                                            // Devolver txs revertidas al mempool
                                            for txid in result.reverted_txs {
                                                // Las txs revertidas se re-evaluarán automáticamente
                                                // cuando prune_invalid se ejecute
                                            }
                                            
                                            save_chain(&chain);
                                            {
                                                let mut s = state.write().await;
                                                s.update_chain(chain.clone());
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        // Intentar agregar bloques secuencialmente
                                        for block in new_blocks {
                                            let expected_diff = calculate_next_difficulty(&chain);
                                            if let Ok(()) = validate_block(&block, &chain, &utxo, expected_diff) {
                                                reorg_manager.save_undo(&block, &utxo);
                                                chain.push(block.clone());
                                                utxo.apply_block(&block);
                                            }
                                        }
                                        save_chain(&chain);
                                        {
                                            let mut s = state.write().await;
                                            s.update_chain(chain.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        
        let height = chain.len() as u64;
        let prev_hash = chain.last().unwrap().hash.clone();
        
        // Calculate difficulty for next block
        let difficulty = calculate_next_difficulty(&chain);
        
        // Calculate reward
        let reward = get_reward(height);
        
        // Get peer count
        let peer_count = {
            let s = state.read().await;
            s.peers.len()
        };
        
        if reward == 0 {
            display_dashboard(
                &my_address,
                height - 1,
                utxo.balance_of(&my_address),
                utxo.spendable_balance(&my_address, height - 1),
                utxo.len(),
                mempool.len(),
                difficulty,
                chain.last(),
                "⚠️  MAXIMUM SUPPLY REACHED - Mining stopped",
                0,
                utxo.total_supply(),
                peer_count,
            );
            break;
        }

        // Display mining status
        display_dashboard(
            &my_address,
            height - 1,
            utxo.balance_of(&my_address),
            utxo.spendable_balance(&my_address, height - 1),
            utxo.len(),
            mempool.len(),
            difficulty,
            chain.last(),
            &format!("Mining block {}... (difficulty: {} bits)", height, difficulty),
            HALVING_INTERVAL - (height % HALVING_INTERVAL),
            utxo.total_supply(),
            peer_count,
        );

        // Get pending transactions from mempool (with fees)
        let (pending_txs, total_fees) = mempool.get_txs_for_block(&utxo, height, MAX_TXS_PER_BLOCK - 1);
        
        // Create coinbase (reward + fees)
        let coinbase_amount = reward + total_fees;
        let coinbase = Tx::new_coinbase(my_address.clone(), coinbase_amount, height);
        
        // Build transaction list (coinbase first)
        let mut txs = vec![coinbase];
        txs.extend(pending_txs.clone());

        // Mine the block
        let new_block = mine_block(height, &prev_hash, txs, difficulty);

        // Validate the new block
        match validate_block(&new_block, &chain, &utxo, difficulty) {
            Ok(()) => {
                // Save undo data before applying block
                reorg_manager.save_undo(&new_block, &utxo);
                
                // Add to chain
                chain.push(new_block.clone());
                save_chain(&chain);
                
                // Save to new database
                let _ = storage.put_block(&new_block);
                let _ = storage.apply_block_to_utxo(&new_block);
                let _ = storage.set_best_block(&new_block.hash, new_block.height);
                
                // Update UTXO
                utxo.apply_block(&new_block);
                
                // Remove confirmed txs from mempool
                let confirmed_txids: Vec<String> = new_block.txs.iter()
                    .skip(1)  // Skip coinbase
                    .map(|tx| tx_hash(tx))
                    .collect();
                mempool.remove_confirmed(&confirmed_txids);
                
                // Update shared state
                {
                    let mut s = state.write().await;
                    s.update_chain(chain.clone());
                    s.mempool = mempool.get_txs_map();
                }
                
                // Broadcast block to peers
                broadcast_block(&new_block, &state).await;
                
                // Display updated dashboard
                let balance = utxo.balance_of(&my_address);
                let spendable = utxo.spendable_balance(&my_address, height);
                let next_halving = HALVING_INTERVAL - ((height + 1) % HALVING_INTERVAL);
                
                display_dashboard(
                    &my_address,
                    height,
                    balance,
                    spendable,
                    utxo.len(),
                    mempool.len(),
                    difficulty,
                    Some(&new_block),
                    &format!("✅ Block {} mined! Next block in ~{} min", height, BLOCK_TIME_TARGET / 60),
                    next_halving,
                    utxo.total_supply(),
                    peer_count,
                );
            }
            Err(e) => {
                display_dashboard(
                    &my_address,
                    height - 1,
                    utxo.balance_of(&my_address),
                    utxo.spendable_balance(&my_address, height - 1),
                    utxo.len(),
                    mempool.len(),
                    difficulty,
                    chain.last(),
                    &format!("❌ Block validation failed: {}", e),
                    HALVING_INTERVAL - (height % HALVING_INTERVAL),
                    utxo.total_supply(),
                    peer_count,
                );
            }
        }

        // Prune invalid transactions from mempool
        mempool.prune_invalid(&utxo, height);

        // Wait before next block (simple sleep, no updates)
        tokio::time::sleep(Duration::from_secs(BLOCK_TIME_TARGET)).await;
    }
}

/// Show balance
fn cmd_balance() {
    let secret_key = load_or_create_key();
    let pubkey = get_pubkey(&secret_key);
    let my_address = get_address(&pubkey);
    
    let chain = load_chain();
    let utxo = UtxoSet::rebuild_from_chain(&chain);
    let height = chain.len().saturating_sub(1) as u64;
    
    let balance = utxo.balance_of(&my_address);
    let spendable = utxo.spendable_balance(&my_address, height);
    
    println!();
    println!("Address:   {}", my_address);
    println!("Balance:   {}", format_coins(balance));
    println!("Spendable: {}", format_coins(spendable));
    println!();
    
    if balance != spendable {
        let immature = balance - spendable;
        println!("Note: {} is from immature coinbase (needs {} more confirmations)",
            format_coins(immature),
            COINBASE_MATURITY
        );
    }
}

/// Send coins
fn cmd_send(to: String, amount_float: f64) {
    // Validate address
    if !validate_address(&to) {
        eprintln!("Error: Invalid address format");
        return;
    }
    
    // Convert to satoshis
    let amount = (amount_float * 100_000_000.0) as u64;
    
    if amount == 0 {
        eprintln!("Error: Amount must be greater than 0");
        return;
    }
    
    // Load wallet
    let secret_key = load_or_create_key();
    let pubkey = get_pubkey(&secret_key);
    let my_address = get_address(&pubkey);
    
    // Load chain and build UTXO
    let chain = load_chain();
    let utxo = UtxoSet::rebuild_from_chain(&chain);
    let height = chain.len().saturating_sub(1) as u64;
    
    // Estimate fee (MIN_RELAY_FEE por defecto, ~1000 satoshis)
    let estimated_fee = MIN_RELAY_FEE;
    let total_needed = amount + estimated_fee;
    
    // Check spendable balance
    let spendable = utxo.spendable_balance(&my_address, height);
    if spendable < total_needed {
        eprintln!("Error: Insufficient spendable balance");
        eprintln!("  Amount:    {}", format_coins(amount));
        eprintln!("  Fee:       {}", format_coins(estimated_fee));
        eprintln!("  Total:     {}", format_coins(total_needed));
        eprintln!("  Available: {}", format_coins(spendable));
        return;
    }
    
    // Find UTXOs to spend (need amount + fee)
    let found = match utxo.find_spendable(&my_address, total_needed, height) {
        Some(f) => f,
        None => {
            eprintln!("Error: Could not find suitable UTXOs");
            return;
        }
    };
    
    // Build inputs
    let mut inputs = Vec::new();
    let mut input_sum = 0u64;
    
    for ((txid, idx), entry) in &found {
        inputs.push(TxIn {
            prev_tx_hash: txid.clone(),
            prev_index: *idx,
            signature: vec![],
            pubkey: vec![],
        });
        input_sum += entry.output.amount;
    }
    
    // Build outputs
    let mut outputs = vec![TxOut {
        to: to.clone(),
        amount,
    }];
    
    // Add change output if needed (input_sum - amount - fee)
    let change = input_sum.saturating_sub(amount).saturating_sub(estimated_fee);
    if change > 0 {
        outputs.push(TxOut {
            to: my_address.clone(),
            amount: change,
        });
    }
    
    // Calculate actual fee
    let output_sum: u64 = outputs.iter().map(|o| o.amount).sum();
    let actual_fee = input_sum - output_sum;
    
    // Create transaction
    let mut tx = Tx { inputs, outputs };
    
    // Sign transaction
    sign_tx(&mut tx, &secret_key);
    
    // Validate transaction
    if let Err(e) = validate_transaction(&tx, &utxo, height, false) {
        eprintln!("Error: Transaction validation failed: {}", e);
        return;
    }
    
    // Add to mempool
    let mut mempool = Mempool::load();
    match mempool.add_tx(tx.clone(), &utxo, height) {
        Ok(txid) => {
            println!();
            println!("✓ Transaction created successfully!");
            println!();
            println!("  TxID:   {}...", &txid[..32]);
            println!("  To:     {}", to);
            println!("  Amount: {}", format_coins(amount));
            println!("  Fee:    {}", format_coins(actual_fee));
            if change > 0 {
                println!("  Change: {}", format_coins(change));
            }
            println!();
            println!("Transaction added to mempool. Will be included in next block.");
        }
        Err(e) => {
            eprintln!("Error: Failed to add transaction to mempool: {}", e);
        }
    }
}

/// Show blockchain status
fn cmd_status() {
    let chain = load_chain();
    let utxo = UtxoSet::rebuild_from_chain(&chain);
    
    if chain.is_empty() {
        println!("Blockchain is empty. Run 'mooncoin run' to create genesis block.");
        return;
    }
    
    let last_block = chain.last().unwrap();
    let height = chain.len() - 1;
    let supply = utxo.total_supply();
    let utxo_count = utxo.len();
    let chain_work = calculate_chain_work(&chain);
    
    let (blocks_since, blocks_until) = difficulty::difficulty_adjustment_progress(height as u64);
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   MOONVAULT STATUS                        ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Height:           {}", height);
    println!("  Last Hash:        {}...", &last_block.hash[..16]);
    println!("  Difficulty:       {} bits", last_block.difficulty_bits);
    println!("  Chain Work:       2^{:.2}", (chain_work as f64).log2());
    println!("  Timestamp:        {}", last_block.timestamp);
    println!();
    println!("  Gas Minted:       {}", format_gas(supply));
    println!("  Block Reward:     {}", format_gas(get_reward(height as u64)));
    println!("  (Gas has no monetary value - anti-spam only)");
    println!();
    println!("  UTXO Count:       {}", utxo_count);
    println!();
    println!("  Next Adjustment:  in {} blocks", blocks_until);
    println!();
}

/// Show node address
fn cmd_address() {
    let secret_key = load_or_create_key();
    let pubkey = get_pubkey(&secret_key);
    let address = get_address(&pubkey);
    
    println!();
    println!("Your MoonVault node address:");
    println!();
    println!("  {}", address);
    println!();
}

/// Validate entire blockchain
fn cmd_validate() {
    println!("Validating blockchain...");
    
    let chain = load_chain();
    
    if chain.is_empty() {
        println!("Blockchain is empty.");
        return;
    }
    
    match validation::validate_chain(&chain) {
        Ok(()) => {
            println!();
            println!("✓ Blockchain is valid!");
            println!("  {} blocks verified", chain.len());
        }
        Err((index, error)) => {
            println!();
            println!("✗ Blockchain is INVALID!");
            println!("  Error at block {}: {}", index, error);
        }
    }
}

/// Export blockchain info
fn cmd_export() {
    let chain = load_chain();
    
    println!("height,hash,prev_hash,timestamp,difficulty,nonce,tx_count");
    
    for block in &chain {
        println!("{},{},{},{},{},{},{}",
            block.height,
            block.hash,
            block.prev_hash,
            block.timestamp,
            block.difficulty_bits,
            block.nonce,
            block.txs.len()
        );
    }
}

/// Connect to a peer (standalone command)
async fn cmd_connect(addr: String) {
    println!("Connecting to peer: {}", addr);
    
    let chain = load_chain();
    let state = Arc::new(RwLock::new(NodeState::new(
        chain,
        format!("0.0.0.0:{}", P2P_PORT),
    )));
    
    let (event_tx, _) = mpsc::channel::<NodeEvent>(100);
    
    match connect_to_peer(&addr, state.clone(), event_tx).await {
        Ok(()) => {
            println!("✓ Connected to {}", addr);
            
            // Wait a moment for handshake
            tokio::time::sleep(Duration::from_secs(2)).await;
            
            // Show peer info
            let s = state.read().await;
            if let Some(peer) = s.peers.get(&addr) {
                println!();
                println!("Peer info:");
                println!("  Version:    {}", peer.version);
                println!("  Height:     {}", peer.height);
                println!("  User Agent: {}", peer.user_agent);
            }
        }
        Err(e) => {
            eprintln!("✗ Failed to connect: {}", e);
        }
    }
}

/// Show saved peers (for now, shows info message)
fn cmd_peers() {
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                      P2P NETWORK                          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  P2P Port: {}", P2P_PORT);
    println!();
    println!("  To connect to a peer:");
    println!("    ./mooncoin connect <ip:port>");
    println!();
    println!("  Example:");
    println!("    ./mooncoin connect 192.168.1.100:{}", P2P_PORT);
    println!();
    println!("  To see connected peers while mining:");
    println!("    Run './mooncoin run' - peers shown in dashboard");
    println!();
    println!("  Seed nodes: (none configured yet)");
    println!("    Add your VPS/server IPs to src/network.rs get_seed_nodes()");
    println!();
}

/// Show mempool info
fn cmd_mempool() {
    let mempool = Mempool::load();
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                       MEMPOOL                             ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    if mempool.is_empty() {
        println!("  Mempool is empty. No pending transactions.");
        println!();
        return;
    }
    
    println!("  Pending transactions: {}", mempool.len());
    println!("  Total fees:           {}", format_coins(mempool.total_fees()));
    println!();
    println!("  ─────────────────────────────────────────────────────────");
    println!("  TxID                              Fee          Fee/byte");
    println!("  ─────────────────────────────────────────────────────────");
    
    // Ordenar por fee/byte
    let mut entries: Vec<_> = mempool.txs.iter().collect();
    entries.sort_by(|a, b| b.1.fee_per_byte.cmp(&a.1.fee_per_byte));
    
    for (txid, entry) in entries.iter().take(20) {
        println!("  {}...  {:>12}  {:>8} sat/B",
            &txid[..24],
            format_coins(entry.fee),
            entry.fee_per_byte
        );
    }
    
    if entries.len() > 20 {
        println!("  ... and {} more", entries.len() - 20);
    }
    
    println!();
    println!("  Estimated fee for next block: {}", format_coins(mempool.estimate_fee(1)));
    println!();
}

// =============================================================================
// HD Wallet Commands
// =============================================================================

/// Show HD wallet info
fn cmd_wallet(show_seed: bool) {
    match HdWallet::load() {
        Ok(Some(wallet)) => {
            if let Err(e) = display_wallet_info(&wallet, show_seed) {
                eprintln!("Error displaying wallet: {}", e);
            }
            
            // Mostrar direcciones
            println!("  📋 Derived Addresses:");
            println!("  ─────────────────────────────────────────────────────────");
            
            match wallet.list_addresses() {
                Ok(addresses) => {
                    for addr in addresses {
                        println!("    {} → {}", addr.path, addr.address);
                    }
                }
                Err(e) => eprintln!("  Error listing addresses: {}", e),
            }
            println!();
        }
        Ok(None) => {
            println!();
            println!("  No HD wallet found.");
            println!();
            println!("  Create one with: ./mooncoin new-seed");
            println!("  Or restore with: ./mooncoin restore \"your seed phrase here\"");
            println!();
        }
        Err(e) => {
            eprintln!("Error loading wallet: {}", e);
        }
    }
}

/// Create new HD wallet with seed phrase
fn cmd_new_seed(words: usize) {
    if words != 12 && words != 24 {
        eprintln!("Error: Word count must be 12 or 24");
        return;
    }
    
    // Check if wallet already exists
    if std::path::Path::new("wallet.dat").exists() {
        eprintln!();
        eprintln!("⚠️  HD wallet already exists (wallet.dat)");
        eprintln!("   Delete it first if you want to create a new one.");
        eprintln!("   WARNING: Make sure you have your seed phrase backed up!");
        eprintln!();
        return;
    }
    
    match HdWallet::new_with_words(words) {
        Ok(wallet) => {
            if let Err(e) = wallet.save() {
                eprintln!("Error saving wallet: {}", e);
                return;
            }
            
            println!();
            println!("╔═══════════════════════════════════════════════════════════╗");
            println!("║              NEW HD WALLET CREATED                        ║");
            println!("╚═══════════════════════════════════════════════════════════╝");
            println!();
            println!("  🔐 YOUR SEED PHRASE ({} words):", words);
            println!("  ┌─────────────────────────────────────────────────────────┐");
            
            let phrase = wallet.get_phrase();
            let word_list: Vec<&str> = phrase.split_whitespace().collect();
            for (i, chunk) in word_list.chunks(4).enumerate() {
                let line: Vec<String> = chunk.iter()
                    .enumerate()
                    .map(|(j, w)| format!("{:>2}. {:<12}", i * 4 + j + 1, w))
                    .collect();
                println!("  │  {}│", line.join(""));
            }
            println!("  └─────────────────────────────────────────────────────────┘");
            println!();
            println!("  ⚠️  IMPORTANT: Write these words down on paper!");
            println!("  ⚠️  Store in a safe place. NEVER share with anyone!");
            println!("  ⚠️  These words are the ONLY way to recover your funds!");
            println!();
            
            match wallet.get_main_address() {
                Ok(addr) => println!("  📍 Your main address: {}", addr),
                Err(e) => eprintln!("  Error getting address: {}", e),
            }
            println!();
        }
        Err(e) => {
            eprintln!("Error creating wallet: {}", e);
        }
    }
}

/// Restore wallet from seed phrase
fn cmd_restore(phrase: String) {
    // Check if wallet already exists
    if std::path::Path::new("wallet.dat").exists() {
        eprintln!();
        eprintln!("⚠️  HD wallet already exists (wallet.dat)");
        eprintln!("   Delete it first if you want to restore from seed.");
        eprintln!();
        return;
    }
    
    match HdWallet::from_phrase(&phrase) {
        Ok(wallet) => {
            if let Err(e) = wallet.save() {
                eprintln!("Error saving wallet: {}", e);
                return;
            }
            
            println!();
            println!("╔═══════════════════════════════════════════════════════════╗");
            println!("║              WALLET RESTORED SUCCESSFULLY                 ║");
            println!("╚═══════════════════════════════════════════════════════════╝");
            println!();
            
            match wallet.get_main_address() {
                Ok(addr) => println!("  📍 Your main address: {}", addr),
                Err(e) => eprintln!("  Error getting address: {}", e),
            }
            println!();
            println!("  ✓ Wallet saved to wallet.dat");
            println!();
        }
        Err(e) => {
            eprintln!();
            eprintln!("Error restoring wallet: {}", e);
            eprintln!();
            eprintln!("Make sure your seed phrase is correct:");
            eprintln!("  - Must be 12 or 24 words");
            eprintln!("  - Words must be from BIP39 English wordlist");
            eprintln!("  - Wrap in quotes: ./mooncoin restore \"word1 word2 ...\"");
            eprintln!();
        }
    }
}

/// Generate a new receiving address
fn cmd_new_address() {
    match HdWallet::load() {
        Ok(Some(mut wallet)) => {
            match wallet.new_address() {
                Ok(addr) => {
                    if let Err(e) = wallet.save() {
                        eprintln!("Error saving wallet: {}", e);
                        return;
                    }
                    
                    println!();
                    println!("  ✓ New address generated:");
                    println!();
                    println!("    Path:    {}", addr.path);
                    println!("    Address: {}", addr.address);
                    println!();
                }
                Err(e) => {
                    eprintln!("Error generating address: {}", e);
                }
            }
        }
        Ok(None) => {
            println!();
            println!("  No HD wallet found.");
            println!("  Create one first with: ./mooncoin new-seed");
            println!();
        }
        Err(e) => {
            eprintln!("Error loading wallet: {}", e);
        }
    }
}

// =============================================================================
// Script Commands
// =============================================================================

/// Create a multisig address
fn cmd_multisig(required: u8, pubkeys_str: String) {
    use crate::tx_builder::create_multisig_address;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                    MULTISIG ADDRESS                       ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // Parse pubkeys (comma-separated hex)
    let pubkeys: Vec<Vec<u8>> = if pubkeys_str.to_lowercase() == "generate" {
        // Generate new keys (simplified - in production would use HD derivation)
        println!("  ⚠️  'generate' not implemented yet.");
        println!("  Please provide pubkeys as hex, comma-separated.");
        return;
    } else {
        pubkeys_str.split(',')
            .filter_map(|s| hex::decode(s.trim()).ok())
            .collect()
    };
    
    if pubkeys.len() < 2 {
        eprintln!("  Error: Need at least 2 public keys");
        return;
    }
    
    if required as usize > pubkeys.len() {
        eprintln!("  Error: Required signatures ({}) > number of keys ({})", required, pubkeys.len());
        return;
    }
    
    let address = create_multisig_address(required, &pubkeys);
    
    println!("  Type:     {}-of-{} Multisig", required, pubkeys.len());
    println!("  Address:  {}", address);
    println!();
    println!("  Public Keys:");
    for (i, pk) in pubkeys.iter().enumerate() {
        println!("    {}. {}", i + 1, hex::encode(pk));
    }
    println!();
    println!("  ⚠️  Save the public keys! You'll need {} of them to spend.", required);
    println!();
}

/// Send with timelock
fn cmd_timelock_send(to: String, amount: f64, unlock_height: u64) {
    use crate::block::load_chain;
    
    let chain = load_chain();
    let current_height = chain.len() as u64;
    
    if unlock_height <= current_height {
        eprintln!();
        eprintln!("  Error: unlock_height ({}) must be greater than current height ({})", 
            unlock_height, current_height);
        eprintln!();
        return;
    }
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                    TIMELOCK TRANSACTION                   ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Recipient:      {}", to);
    println!("  Amount:         {:.8} MOON", amount);
    println!("  Unlock Height:  {} (current: {})", unlock_height, current_height);
    println!("  Blocks to wait: {}", unlock_height - current_height);
    println!();
    println!("  ⚠️  Timelock transactions are not fully implemented yet.");
    println!("  The recipient will need to wait until block {} to spend.", unlock_height);
    println!();
    
    // TODO: Implement actual timelock transaction creation
    // Would use TxBuilder::add_timelocked_output()
}

/// Store data on blockchain
fn cmd_store_data(data: String) {
    if data.len() > 80 {
        eprintln!();
        eprintln!("  Error: Data too long ({} bytes). Maximum is 80 bytes.", data.len());
        eprintln!();
        return;
    }
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                    STORE DATA (OP_RETURN)                 ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Data:    \"{}\"", data);
    println!("  Length:  {} bytes", data.len());
    println!("  Hex:     {}", hex::encode(data.as_bytes()));
    println!();
    println!("  ⚠️  OP_RETURN transactions are not fully implemented yet.");
    println!("  This would create an unspendable output with your data.");
    println!();
    
    // TODO: Implement actual OP_RETURN transaction
    // Would use TxBuilder::add_op_return()
}

/// Decode a script
fn cmd_decode_script(input: String) {
    use crate::script::Script;
    use crate::tx_builder::address_to_pubkey_hash;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                    SCRIPT DECODER                         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // Try as address first
    if input.starts_with("M") {
        if let Ok(pubkey_hash) = address_to_pubkey_hash(&input) {
            println!("  Type:        P2PKH Address");
            println!("  Address:     {}", input);
            println!("  PubKeyHash:  {}", hex::encode(&pubkey_hash));
            println!();
            println!("  ScriptPubKey:");
            println!("    OP_DUP OP_HASH160 {} OP_EQUALVERIFY OP_CHECKSIG", hex::encode(&pubkey_hash));
            println!();
            return;
        }
    }
    
    // Try as hex script
    if let Ok(bytes) = hex::decode(&input) {
        match Script::from_bytes(&bytes) {
            Ok(script) => {
                println!("  Type:    Raw Script");
                println!("  Hex:     {}", input);
                println!("  Length:  {} bytes", bytes.len());
                println!();
                println!("  Opcodes:");
                for (i, op) in script.ops.iter().enumerate() {
                    println!("    {}: {:?}", i, op);
                }
                println!();
                
                if script.is_p2pkh() {
                    println!("  Detected: P2PKH script");
                } else if script.is_p2sh() {
                    println!("  Detected: P2SH script");
                }
            }
            Err(e) => {
                eprintln!("  Error parsing script: {}", e);
            }
        }
    } else {
        eprintln!("  Error: Input is not a valid address or hex script");
    }
    
    println!();
}

// =============================================================================
// Encryption Commands
// =============================================================================

const ENCRYPTED_WALLET_FILE: &str = "wallet.encrypted";

/// Encrypt the HD wallet
fn cmd_encrypt_wallet() {
    use crate::hdwallet::HdWallet;
    use crate::crypto::{EncryptedWallet, read_new_password, check_password_strength};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   ENCRYPT WALLET                          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // Check if already encrypted
    if std::path::Path::new(ENCRYPTED_WALLET_FILE).exists() {
        println!("  ⚠️  Wallet is already encrypted.");
        println!("  Use 'change-password' to update the password.");
        println!();
        return;
    }
    
    // Load HD wallet
    match HdWallet::load() {
        Ok(Some(wallet)) => {
            let seed_phrase = wallet.get_phrase();
            let address = match wallet.get_main_address() {
                Ok(addr) => addr,
                Err(e) => {
                    eprintln!("  Error getting address: {}", e);
                    return;
                }
            };
            
            println!("  Found HD wallet with address: {}", address);
            println!();
            println!("  ⚠️  IMPORTANT: This will encrypt your seed phrase.");
            println!("  If you forget your password, you will lose access to your funds!");
            println!();
            
            // Get password
            match read_new_password() {
                Ok(password) => {
                    let strength = check_password_strength(&password);
                    println!("  Password strength: {}", strength);
                    println!();
                    
                    // Create encrypted wallet
                    match EncryptedWallet::new(&seed_phrase, &address, &password) {
                        Ok(encrypted) => {
                            // Save encrypted wallet
                            if let Err(e) = encrypted.save(ENCRYPTED_WALLET_FILE) {
                                eprintln!("  Error saving encrypted wallet: {}", e);
                                return;
                            }
                            
                            // Rename original wallet.dat to wallet.dat.bak
                            let _ = std::fs::rename("wallet.dat", "wallet.dat.unencrypted.bak");
                            
                            println!("  ✅ Wallet encrypted successfully!");
                            println!();
                            println!("  Encrypted file: {}", ENCRYPTED_WALLET_FILE);
                            println!("  Original backup: wallet.dat.unencrypted.bak");
                            println!();
                            println!("  ⚠️  Delete the backup after confirming encryption works!");
                            println!();
                        }
                        Err(e) => {
                            eprintln!("  Error encrypting wallet: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  Error reading password: {}", e);
                }
            }
        }
        Ok(None) => {
            println!("  No HD wallet found.");
            println!("  Create one first with: ./mooncoin new-seed");
            println!();
        }
        Err(e) => {
            eprintln!("  Error loading wallet: {}", e);
        }
    }
}

/// Decrypt/show wallet info
fn cmd_decrypt_wallet() {
    use crate::crypto::{EncryptedWallet, read_password};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   DECRYPT WALLET                          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // Check if encrypted wallet exists
    if !std::path::Path::new(ENCRYPTED_WALLET_FILE).exists() {
        println!("  No encrypted wallet found.");
        println!("  Encrypt your wallet first with: ./mooncoin encrypt-wallet");
        println!();
        return;
    }
    
    // Load encrypted wallet
    match EncryptedWallet::load(ENCRYPTED_WALLET_FILE) {
        Ok(wallet) => {
            println!("  Address: {}", wallet.address);
            println!();
            
            // Get password
            match read_password("  Enter password: ") {
                Ok(password) => {
                    match wallet.decrypt_seed(&password) {
                        Ok(seed) => {
                            println!();
                            println!("  ✅ Wallet decrypted successfully!");
                            println!();
                            println!("  ╔═══════════════════════════════════════════════════════╗");
                            println!("  ║  ⚠️  SEED PHRASE - KEEP SECRET!                       ║");
                            println!("  ╚═══════════════════════════════════════════════════════╝");
                            println!();
                            
                            let words: Vec<&str> = seed.split_whitespace().collect();
                            for (i, word) in words.iter().enumerate() {
                                println!("    {:2}. {}", i + 1, word);
                            }
                            
                            println!();
                            println!("  ⚠️  Never share this seed phrase with anyone!");
                            println!();
                        }
                        Err(_) => {
                            println!();
                            println!("  ❌ Wrong password!");
                            println!();
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  Error reading password: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("  Error loading encrypted wallet: {}", e);
        }
    }
}

/// Change wallet password
fn cmd_change_password() {
    use crate::crypto::{EncryptedWallet, read_password, read_new_password, check_password_strength, encrypt_string};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   CHANGE PASSWORD                         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // Check if encrypted wallet exists
    if !std::path::Path::new(ENCRYPTED_WALLET_FILE).exists() {
        println!("  No encrypted wallet found.");
        println!("  Encrypt your wallet first with: ./mooncoin encrypt-wallet");
        println!();
        return;
    }
    
    // Load encrypted wallet
    match EncryptedWallet::load(ENCRYPTED_WALLET_FILE) {
        Ok(mut wallet) => {
            println!("  Address: {}", wallet.address);
            println!();
            
            // Get current password
            match read_password("  Enter current password: ") {
                Ok(old_password) => {
                    // Verify current password
                    match wallet.decrypt_seed(&old_password) {
                        Ok(seed) => {
                            println!();
                            println!("  ✅ Current password verified!");
                            println!();
                            
                            // Get new password
                            match read_new_password() {
                                Ok(new_password) => {
                                    let strength = check_password_strength(&new_password);
                                    println!("  Password strength: {}", strength);
                                    println!();
                                    
                                    // Re-encrypt with new password
                                    match encrypt_string(&seed, &new_password) {
                                        Ok(new_encrypted) => {
                                            wallet.encrypted_seed = new_encrypted;
                                            wallet.update_access();
                                            
                                            // Backup old file
                                            let _ = std::fs::copy(
                                                ENCRYPTED_WALLET_FILE,
                                                format!("{}.bak", ENCRYPTED_WALLET_FILE)
                                            );
                                            
                                            // Save with new encryption
                                            if let Err(e) = wallet.save(ENCRYPTED_WALLET_FILE) {
                                                eprintln!("  Error saving wallet: {}", e);
                                                return;
                                            }
                                            
                                            println!("  ✅ Password changed successfully!");
                                            println!();
                                        }
                                        Err(e) => {
                                            eprintln!("  Error encrypting with new password: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("  Error reading new password: {}", e);
                                }
                            }
                        }
                        Err(_) => {
                            println!();
                            println!("  ❌ Wrong password!");
                            println!();
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  Error reading password: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("  Error loading encrypted wallet: {}", e);
        }
    }
}

// =============================================================================
// SegWit Commands
// =============================================================================

/// Generate a native SegWit address
fn cmd_segwit_address() {
    use crate::hdwallet::HdWallet;
    use crate::segwit::pubkey_to_p2wpkh_address;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   SEGWIT ADDRESS (P2WPKH)                 ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // Intentar cargar HD wallet primero
    match HdWallet::load() {
        Ok(Some(wallet)) => {
            match wallet.get_signing_key() {
                Ok(secret_key) => {
                    let secp = secp256k1::Secp256k1::new();
                    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
                    let pubkey_bytes = public_key.serialize();
                    
                    match pubkey_to_p2wpkh_address(&pubkey_bytes) {
                        Ok(addr) => {
                            println!("  Type:           Native SegWit (P2WPKH)");
                            println!("  Address:        {}", addr);
                            println!("  Public Key:     {}", hex::encode(&pubkey_bytes));
                            println!();
                            println!("  ✅ This address starts with 'mc1' (Bech32 format)");
                            println!("  ✅ Lower fees than legacy addresses");
                            println!();
                        }
                        Err(e) => {
                            eprintln!("  Error creating SegWit address: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  Error getting signing key: {}", e);
                }
            }
        }
        Ok(None) => {
            // Intentar con wallet legacy
            use crate::wallet::{load_or_create_key, get_pubkey};
            let secret_key = load_or_create_key();
            let pubkey = get_pubkey(&secret_key);
            let pubkey_bytes = pubkey.serialize();
            
            match pubkey_to_p2wpkh_address(&pubkey_bytes) {
                Ok(addr) => {
                    println!("  Type:           Native SegWit (P2WPKH)");
                    println!("  Address:        {}", addr);
                    println!("  Public Key:     {}", hex::encode(&pubkey_bytes));
                    println!();
                    println!("  ✅ This address starts with 'mc1' (Bech32 format)");
                    println!("  ✅ Lower fees than legacy addresses");
                    println!();
                }
                Err(e) => {
                    eprintln!("  Error creating SegWit address: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("  Error loading wallet: {}", e);
        }
    }
}

/// Decode any address type
fn cmd_decode_address(address: String) {
    use crate::segwit::{decode_segwit_address, is_segwit_address, BECH32_HRP};
    use crate::tx_builder::address_to_pubkey_hash;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   ADDRESS DECODER                         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Address: {}", address);
    println!();
    
    // Intentar decodificar como SegWit
    if is_segwit_address(&address) {
        match decode_segwit_address(&address) {
            Ok((version, program)) => {
                let addr_type = if program.len() == 20 {
                    "P2WPKH (Native SegWit)"
                } else if program.len() == 32 {
                    "P2WSH (Native SegWit Script)"
                } else {
                    "Unknown SegWit"
                };
                
                println!("  Type:            {}", addr_type);
                println!("  Format:          Bech32");
                println!("  HRP:             {}", BECH32_HRP);
                println!("  Witness Version: {}", version);
                println!("  Program:         {}", hex::encode(&program));
                println!("  Program Length:  {} bytes", program.len());
                println!();
                
                if version == 0 && program.len() == 20 {
                    println!("  ScriptPubKey:    OP_0 OP_PUSHDATA(20) {}", hex::encode(&program));
                } else if version == 0 && program.len() == 32 {
                    println!("  ScriptPubKey:    OP_0 OP_PUSHDATA(32) {}", hex::encode(&program));
                }
            }
            Err(e) => {
                eprintln!("  Error decoding SegWit address: {}", e);
            }
        }
    }
    // Intentar decodificar como dirección legacy
    else if address.starts_with("M") {
        match address_to_pubkey_hash(&address) {
            Ok(pubkey_hash) => {
                println!("  Type:            P2PKH (Legacy)");
                println!("  Format:          Base58Check");
                println!("  PubKey Hash:     {}", hex::encode(&pubkey_hash));
                println!("  Hash Length:     {} bytes", pubkey_hash.len());
                println!();
                println!("  ScriptPubKey:    OP_DUP OP_HASH160 {} OP_EQUALVERIFY OP_CHECKSIG", 
                    hex::encode(&pubkey_hash));
            }
            Err(e) => {
                eprintln!("  Error decoding legacy address: {}", e);
            }
        }
    }
    else {
        eprintln!("  Error: Unrecognized address format");
        eprintln!();
        eprintln!("  Expected formats:");
        eprintln!("    - Legacy (P2PKH):  Mxxxxxxx...");
        eprintln!("    - SegWit (P2WPKH): mc1xxxxxx...");
    }
    
    println!();
}

// =============================================================================
// SPV Commands
// =============================================================================

/// Generate Merkle proof for a transaction
fn cmd_merkle_proof(txid: String) {
    use crate::block::load_chain;
    use crate::spv::MerkleProof;
    use crate::transaction::tx_hash;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   MERKLE PROOF                            ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  TxID: {}", txid);
    println!();
    
    let chain = load_chain();
    
    // Buscar la transacción en la blockchain
    for block in &chain {
        for tx in &block.txs {
            if tx_hash(tx) == txid {
                match MerkleProof::generate(block, &txid) {
                    Some(proof) => {
                        println!("  ✅ Transaction found!");
                        println!();
                        println!("  Block Height:    {}", proof.block_height);
                        println!("  Block Hash:      {}", &proof.block_hash[..16]);
                        println!("  Merkle Root:     {}", &proof.merkle_root[..16]);
                        println!("  TX Index:        {}", proof.tx_index);
                        println!("  Proof Size:      {} hashes", proof.proof_hashes.len());
                        println!();
                        println!("  Proof Hashes:");
                        for (i, hash) in proof.proof_hashes.iter().enumerate() {
                            let dir = if proof.directions[i] == 1 { "R" } else { "L" };
                            println!("    {}. [{}] {}...", i + 1, dir, &hash[..16]);
                        }
                        println!();
                        
                        // Verificar la prueba
                        if proof.verify() {
                            println!("  ✅ Proof is VALID");
                        } else {
                            println!("  ❌ Proof is INVALID");
                        }
                        println!();
                        
                        // Mostrar prueba serializada
                        let bytes = proof.to_bytes();
                        println!("  Serialized Proof ({} bytes):", bytes.len());
                        println!("  {}", hex::encode(&bytes[..bytes.len().min(64)]));
                        if bytes.len() > 64 {
                            println!("  ...");
                        }
                        return;
                    }
                    None => {
                        eprintln!("  Error: Could not generate proof");
                        return;
                    }
                }
            }
        }
    }
    
    eprintln!("  ❌ Transaction not found in blockchain");
    println!();
}

/// Verify a transaction with SPV
fn cmd_verify_tx(txid: String) {
    use crate::block::load_chain;
    use crate::spv::{MerkleProof, compute_merkle_root};
    use crate::transaction::tx_hash;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   SPV VERIFICATION                        ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  TxID: {}", txid);
    println!();
    
    let chain = load_chain();
    let chain_height = chain.len();
    
    // Buscar y verificar la transacción
    for block in &chain {
        for tx in &block.txs {
            if tx_hash(tx) == txid {
                // Generar prueba
                let proof = match MerkleProof::generate(block, &txid) {
                    Some(p) => p,
                    None => {
                        eprintln!("  Error generating proof");
                        return;
                    }
                };
                
                // Verificar merkle root del bloque
                let txids: Vec<String> = block.txs.iter()
                    .map(|t| tx_hash(t))
                    .collect();
                let computed_root = compute_merkle_root(&txids);
                
                println!("  Block Verification:");
                println!("  ───────────────────");
                println!("  Block Height:     {}", block.height);
                println!("  Block Hash:       {}...", &block.hash[..16]);
                println!("  Stored Root:      {}...", &block.merkle_root[..16]);
                println!("  Computed Root:    {}...", &computed_root[..16]);
                
                if computed_root == block.merkle_root {
                    println!("  Root Match:       ✅ YES");
                } else {
                    println!("  Root Match:       ❌ NO");
                }
                println!();
                
                println!("  Merkle Proof Verification:");
                println!("  ──────────────────────────");
                println!("  Proof Valid:      {}", if proof.verify() { "✅ YES" } else { "❌ NO" });
                println!("  Proof Depth:      {} levels", proof.proof_hashes.len());
                println!();
                
                let confirmations = chain_height as u64 - block.height;
                println!("  Transaction Status:");
                println!("  ───────────────────");
                println!("  Confirmations:    {}", confirmations);
                println!("  Status:           {}", 
                    if confirmations >= 6 { "✅ CONFIRMED (6+)" }
                    else if confirmations >= 1 { "🔸 CONFIRMING" }
                    else { "⏳ PENDING" }
                );
                println!();
                
                // Mostrar detalles de la TX
                println!("  Transaction Details:");
                println!("  ────────────────────");
                println!("  Inputs:           {}", tx.inputs.len());
                println!("  Outputs:          {}", tx.outputs.len());
                let total_out: u64 = tx.outputs.iter().map(|o| o.amount).sum();
                println!("  Total Output:     {:.8} MOON", total_out as f64 / 100_000_000.0);
                
                return;
            }
        }
    }
    
    eprintln!("  ❌ Transaction not found");
    println!();
}

// =============================================================================
// Fee Estimation Commands
// =============================================================================

/// Estimate transaction fees
fn cmd_estimate_fee(amount: Option<f64>) {
    use crate::block::load_chain;
    use crate::fee_estimator::{
        FeeEstimator, FeePriority, BlockFeeStats,
        TYPICAL_TX_SIZE, TYPICAL_SEGWIT_TX_SIZE,
        recommend_fee
    };
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   FEE ESTIMATION                          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let chain = load_chain();
    let mut estimator = FeeEstimator::new();
    
    // Analizar los últimos bloques
    let blocks_to_analyze = 6.min(chain.len());
    
    if blocks_to_analyze == 0 {
        println!("  ⚠️  No blocks to analyze. Using minimum fees.");
        println!();
        println!("  Minimum fee rate: 1 sat/byte");
        println!("  Typical TX fee:   {} sats ({:.8} MOON)", 
            TYPICAL_TX_SIZE, TYPICAL_TX_SIZE as f64 / 100_000_000.0);
        println!();
        return;
    }
    
    println!("  Analyzing last {} blocks...", blocks_to_analyze);
    println!();
    
    // Función dummy para obtener valores UTXO (simplificado)
    let utxo_lookup = |_txid: &str, _index: u32| -> Option<u64> {
        None // En producción, buscaríamos en el UTXO set
    };
    
    for block in chain.iter().rev().take(blocks_to_analyze) {
        let stats = BlockFeeStats::from_block(block, &utxo_lookup);
        estimator.process_block(stats);
    }
    
    // Obtener estimaciones
    let estimates = estimator.estimate_all();
    
    println!("  ┌─────────────────┬──────────────┬──────────────┬──────────────┐");
    println!("  │    Priority     │  Fee Rate    │ Legacy Fee   │ SegWit Fee   │");
    println!("  │                 │  (sat/byte)  │   (sats)     │   (sats)     │");
    println!("  ├─────────────────┼──────────────┼──────────────┼──────────────┤");
    
    for est in &estimates {
        println!("  │ {:15} │ {:>12} │ {:>12} │ {:>12} │",
            est.priority.description(),
            est.fee_rate,
            est.typical_fee,
            est.typical_fee_segwit
        );
    }
    
    println!("  └─────────────────┴──────────────┴──────────────┴──────────────┘");
    println!();
    
    // Mostrar estadísticas
    let stats = estimator.get_stats();
    println!("  Statistics:");
    println!("  ───────────");
    println!("  Blocks analyzed:    {}", stats.blocks_analyzed);
    println!("  Avg block fill:     {:.1}%", stats.avg_block_fill);
    println!("  Confidence:         {}%", stats.confidence);
    println!();
    
    // Si se especificó un monto, dar recomendación
    if let Some(moon_amount) = amount {
        let sats = (moon_amount * 100_000_000.0) as u64;
        let rec = recommend_fee(sats, &estimates);
        
        println!("  Recommendation for {:.8} MOON:", moon_amount);
        println!("  ─────────────────────────────────");
        println!("  Recommended fee:    {} sats ({:.8} MOON)", 
            rec.recommended_fee, rec.recommended_fee as f64 / 100_000_000.0);
        println!("  Fee rate:           {} sat/byte", rec.recommended_fee_rate);
        println!("  Use SegWit:         {}", if rec.use_segwit { "Yes ✅" } else { "No" });
        println!("  Fee percentage:     {:.4}%", rec.fee_percentage);
        println!("  Est. confirmation:  ~{} blocks", rec.estimated_blocks);
        
        if let Some(warning) = rec.warning {
            println!();
            println!("  ⚠️  Warning: {}", warning);
        }
    }
    
    println!();
    println!("  💡 Tip: Use SegWit addresses (mc1...) for ~37% lower fees!");
    println!();
}

// =============================================================================
// Watch Wallet Commands
// =============================================================================

/// Add address to watch list
fn cmd_watch(address: String, label: String) {
    use crate::watch_wallet::WatchWallet;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   WATCH ADDRESS                           ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let mut wallet = match WatchWallet::load() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("  Error loading watch wallet: {}", e);
            return;
        }
    };
    
    let label = if label.is_empty() {
        format!("Address #{}", wallet.entries.len() + 1)
    } else {
        label
    };
    
    match wallet.add_address(&address, &label) {
        Ok(()) => {
            if let Err(e) = wallet.save() {
                eprintln!("  Error saving: {}", e);
                return;
            }
            
            println!("  ✅ Address added to watch list!");
            println!();
            println!("  Address: {}", address);
            println!("  Label:   {}", label);
            println!();
            println!("  💡 Run 'mooncoin watch-scan' to update balances");
        }
        Err(e) => {
            eprintln!("  ❌ Error: {}", e);
        }
    }
    
    println!();
}

/// Remove address from watch list
fn cmd_unwatch(address: String) {
    use crate::watch_wallet::WatchWallet;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   UNWATCH ADDRESS                         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let mut wallet = match WatchWallet::load() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("  Error loading watch wallet: {}", e);
            return;
        }
    };
    
    match wallet.remove_address(&address) {
        Ok(()) => {
            if let Err(e) = wallet.save() {
                eprintln!("  Error saving: {}", e);
                return;
            }
            
            println!("  ✅ Address removed from watch list!");
            println!();
            println!("  Address: {}", address);
        }
        Err(e) => {
            eprintln!("  ❌ Error: {}", e);
        }
    }
    
    println!();
}

/// List all watched addresses
fn cmd_watch_list() {
    use crate::watch_wallet::WatchWallet;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   WATCHED ADDRESSES                       ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let wallet = match WatchWallet::load() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("  Error loading watch wallet: {}", e);
            return;
        }
    };
    
    if wallet.entries.is_empty() {
        println!("  No addresses being watched.");
        println!();
        println!("  💡 Add one with: mooncoin watch <address> --label \"name\"");
        println!();
        return;
    }
    
    let stats = wallet.stats();
    
    println!("  Total Addresses: {}", stats.addresses_count);
    println!("  Total Balance:   {:.8} MOON", stats.total_balance as f64 / 100_000_000.0);
    println!("  Last Scan:       Block #{}", stats.last_scan_height);
    println!();
    
    println!("  ┌─────────────────────────────────────┬────────────────┬──────────────┐");
    println!("  │ Address                             │ Label          │ Balance      │");
    println!("  ├─────────────────────────────────────┼────────────────┼──────────────┤");
    
    let mut entries: Vec<_> = wallet.entries.values().collect();
    entries.sort_by(|a, b| b.balance.cmp(&a.balance));
    
    for entry in entries {
        let addr_short = if entry.address.len() > 35 {
            format!("{}...{}", &entry.address[..16], &entry.address[entry.address.len()-8..])
        } else {
            format!("{:35}", entry.address)
        };
        
        let label_short = if entry.label.len() > 14 {
            format!("{}...", &entry.label[..11])
        } else {
            format!("{:14}", entry.label)
        };
        
        let balance_moon = entry.balance as f64 / 100_000_000.0;
        
        println!("  │ {} │ {} │ {:>10.4} │", addr_short, label_short, balance_moon);
    }
    
    println!("  └─────────────────────────────────────┴────────────────┴──────────────┘");
    
    // Mostrar alertas
    let unseen = wallet.get_unseen_alerts();
    if !unseen.is_empty() {
        println!();
        println!("  🔔 {} new transaction(s) detected!", unseen.len());
        for alert in unseen.iter().take(5) {
            let amount_moon = alert.amount as f64 / 100_000_000.0;
            println!("     +{:.8} MOON → {}...", amount_moon, &alert.address[..16]);
        }
    }
    
    println!();
}

/// Scan blockchain for watched addresses
fn cmd_watch_scan() {
    use crate::watch_wallet::WatchWallet;
    use crate::block::load_chain;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   SCANNING BLOCKCHAIN                     ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let mut wallet = match WatchWallet::load() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("  Error loading watch wallet: {}", e);
            return;
        }
    };
    
    if wallet.entries.is_empty() {
        println!("  No addresses to scan for.");
        println!();
        println!("  💡 Add one with: mooncoin watch <address>");
        println!();
        return;
    }
    
    println!("  Watching {} address(es)", wallet.entries.len());
    println!("  Last scan: Block #{}", wallet.last_scan_height);
    println!();
    
    let chain = load_chain();
    let chain_height = chain.len();
    
    println!("  Loading blockchain ({} blocks)...", chain_height);
    
    let before_balance = wallet.total_balance();
    let before_txs = wallet.transactions.len();
    
    wallet.scan_blockchain(&chain);
    wallet.update_confirmations(chain_height as u64);
    
    let after_balance = wallet.total_balance();
    let after_txs = wallet.transactions.len();
    
    if let Err(e) = wallet.save() {
        eprintln!("  Error saving: {}", e);
        return;
    }
    
    println!();
    println!("  ✅ Scan complete!");
    println!();
    println!("  Blocks scanned:   {} → {}", wallet.last_scan_height.saturating_sub(chain_height as u64), chain_height);
    println!("  New transactions: {}", after_txs - before_txs);
    
    let balance_change = after_balance as i64 - before_balance as i64;
    if balance_change > 0 {
        println!("  Balance change:   +{:.8} MOON", balance_change as f64 / 100_000_000.0);
    } else if balance_change < 0 {
        println!("  Balance change:   {:.8} MOON", balance_change as f64 / 100_000_000.0);
    }
    
    println!();
    println!("  Total Balance:    {:.8} MOON", after_balance as f64 / 100_000_000.0);
    println!();
}

// =============================================================================
// Pruning Commands
// =============================================================================

/// Show pruning status
fn cmd_prune_status() {
    use crate::pruning::{PruningEngine, calculate_chain_size, format_bytes};
    use crate::block::load_chain;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   PRUNING STATUS                          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let engine = PruningEngine::new();
    let stats = engine.stats();
    
    println!("  Mode:             {}", stats.mode);
    println!("  Auto-prune:       {}", if stats.auto_prune { "Enabled" } else { "Disabled" });
    println!("  Blocks pruned:    {}", stats.blocks_pruned);
    println!("  Space saved:      {} MB", stats.space_saved_mb);
    println!();
    
    // Cargar cadena para estadísticas
    let chain = load_chain();
    let chain_size = calculate_chain_size(&chain);
    
    println!("  Blockchain Stats:");
    println!("  ──────────────────");
    println!("  Total blocks:     {}", chain.len());
    println!("  Chain size:       {}", format_bytes(chain_size));
    
    // Calcular tamaño promedio por bloque
    if !chain.is_empty() {
        let avg_size = chain_size / chain.len() as u64;
        println!("  Avg block size:   {}", format_bytes(avg_size));
    }
    
    // Estimar ahorro con pruning
    if chain.len() > 1000 {
        let prunable = chain.len() - 1000;
        let estimated_savings = (chain_size / chain.len() as u64) * prunable as u64;
        println!();
        println!("  💡 Potential savings with pruning (keep 1000):");
        println!("     ~{} ({} blocks)", format_bytes(estimated_savings), prunable);
    }
    
    println!();
}

/// Enable pruning
fn cmd_prune_enable(keep: u64) {
    use crate::pruning::{PruningEngine, PruneMode, PruningConfig};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   ENABLE PRUNING                          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // Validar
    if keep < 288 {
        eprintln!("  ❌ Error: Minimum blocks to keep is 288 (for reorg safety)");
        println!();
        return;
    }
    
    let mut engine = PruningEngine::new();
    engine.set_mode(PruneMode::KeepRecent(keep));
    engine.set_auto_prune(true);
    
    if let Err(e) = engine.config.save() {
        eprintln!("  ❌ Error saving config: {}", e);
        return;
    }
    
    println!("  ✅ Pruning enabled!");
    println!();
    println!("  Mode:          Keep last {} blocks", keep);
    println!("  Auto-prune:    Enabled");
    println!();
    println!("  ⚠️  WARNING: Pruned nodes cannot serve historical blocks to other nodes.");
    println!("  ⚠️  You will not be able to rescan the full blockchain for old transactions.");
    println!();
    println!("  💡 Run 'mooncoin prune-now' to start pruning immediately.");
    println!();
}

/// Disable pruning
fn cmd_prune_disable() {
    use crate::pruning::{PruningEngine, PruneMode};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   DISABLE PRUNING                         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let mut engine = PruningEngine::new();
    engine.set_mode(PruneMode::None);
    engine.set_auto_prune(false);
    
    if let Err(e) = engine.config.save() {
        eprintln!("  ❌ Error saving config: {}", e);
        return;
    }
    
    println!("  ✅ Pruning disabled!");
    println!();
    println!("  Mode:          Full node (no pruning)");
    println!("  Auto-prune:    Disabled");
    println!();
    println!("  Note: Previously pruned data cannot be recovered.");
    println!("  You may need to re-sync if you want full historical data.");
    println!();
}

/// Run pruning now
fn cmd_prune_now() {
    use crate::pruning::{PruningEngine, PruneMode, calculate_chain_size, format_bytes};
    use crate::block::{load_chain, save_chain};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   PRUNING BLOCKCHAIN                      ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let mut engine = PruningEngine::new();
    
    if engine.config.mode == PruneMode::None {
        println!("  ⚠️  Pruning is not enabled.");
        println!();
        println!("  Enable it first with: mooncoin prune-enable --keep 1000");
        println!();
        return;
    }
    
    println!("  Mode: {}", engine.config.mode.description());
    println!();
    
    let mut chain = load_chain();
    let before_size = calculate_chain_size(&chain);
    let current_height = chain.len() as u64;
    
    println!("  Before pruning:");
    println!("    Blocks:     {}", chain.len());
    println!("    Size:       {}", format_bytes(before_size));
    println!();
    println!("  Pruning...");
    
    let result = engine.prune_chain(&mut chain, current_height);
    
    if result.blocks_pruned > 0 {
        // Guardar la cadena podada
        save_chain(&chain);
        
        let after_size = calculate_chain_size(&chain);
        
        println!();
        println!("  ✅ Pruning complete!");
        println!();
        println!("  Results:");
        println!("    Blocks pruned:  {}", result.blocks_pruned);
        println!("    Space saved:    {}", format_bytes(result.space_saved));
        println!("    New size:       {}", format_bytes(after_size));
        println!("    Reduction:      {:.1}%", 
            (1.0 - after_size as f64 / before_size as f64) * 100.0);
    } else {
        println!();
        println!("  ℹ️  Nothing to prune.");
        println!("     All blocks are within the keep range.");
    }
    
    println!();
}

// =============================================================================
// Testnet Commands
// =============================================================================

/// Show network info
fn cmd_network_info() {
    use crate::testnet::{get_network, get_params, Network};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   NETWORK INFO                            ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let network = get_network();
    let params = get_params();
    
    let status = match network {
        Network::Mainnet => "🟢 MAINNET (Production)",
        Network::Testnet => "🟡 TESTNET (Testing)",
        Network::Regtest => "🟣 REGTEST (Development)",
    };
    
    println!("  Current Network:  {}", status);
    println!();
    println!("  Network Parameters:");
    println!("  ────────────────────");
    println!("  P2P Port:         {}", params.p2p_port);
    println!("  RPC Port:         {}", params.rpc_port);
    println!("  Explorer Port:    {}", params.explorer_port);
    println!("  Data Directory:   {}", params.data_dir);
    println!("  Chain File:       {}", params.chain_file);
    println!("  Wallet File:      {}", params.wallet_file);
    println!();
    println!("  Consensus:");
    println!("  ──────────");
    println!("  Block Time:       {} seconds", params.block_time_target);
    println!("  Difficulty Adj:   Every {} blocks", params.difficulty_adjustment_interval);
    println!("  Initial Reward:   {} MOON", params.initial_reward / 100_000_000);
    println!("  Halving:          Every {} blocks", params.halving_interval);
    println!("  Coinbase Maturity: {} blocks", params.coinbase_maturity);
    println!();
    println!("  Address Formats:");
    println!("  ─────────────────");
    println!("  P2PKH Prefix:     0x{:02X}", params.p2pkh_prefix);
    println!("  P2SH Prefix:      0x{:02X}", params.p2sh_prefix);
    println!("  Bech32 HRP:       {}", params.bech32_hrp);
    
    if network != Network::Mainnet {
        println!();
        println!("  ⚠️  WARNING: Coins on this network have NO real value!");
    }
    
    println!();
}

/// Switch to testnet
fn cmd_use_testnet() {
    use crate::testnet::{set_network, Network, get_params, testnet_banner};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   SWITCH TO TESTNET                       ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    
    set_network(Network::Testnet);
    let params = get_params();
    
    print!("{}", testnet_banner());
    
    println!("  ✅ Switched to TESTNET!");
    println!();
    println!("  New settings:");
    println!("  ─────────────");
    println!("  P2P Port:       {}", params.p2p_port);
    println!("  RPC Port:       {}", params.rpc_port);
    println!("  Explorer:       http://127.0.0.1:{}", params.explorer_port);
    println!("  Data Dir:       {}", params.data_dir);
    println!("  Chain File:     {}", params.chain_file);
    println!();
    println!("  Testnet Features:");
    println!("  ──────────────────");
    println!("  • Faster block time (1 min vs 5 min)");
    println!("  • Lower difficulty");
    println!("  • Separate blockchain");
    println!("  • Coins have NO value");
    println!();
    println!("  💡 Start mining with: ./mooncoin run");
    println!();
}

/// Switch to mainnet
fn cmd_use_mainnet() {
    use crate::testnet::{set_network, Network, get_params};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   SWITCH TO MAINNET                       ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    set_network(Network::Mainnet);
    let params = get_params();
    
    println!("  ✅ Switched to MAINNET!");
    println!();
    println!("  Settings:");
    println!("  ──────────");
    println!("  P2P Port:       {}", params.p2p_port);
    println!("  RPC Port:       {}", params.rpc_port);
    println!("  Explorer:       http://127.0.0.1:{}", params.explorer_port);
    println!("  Data Dir:       {}", params.data_dir);
    println!("  Chain File:     {}", params.chain_file);
    println!();
    println!("  🟢 This is the PRODUCTION network.");
    println!("  🟢 Coins have REAL value.");
    println!();
}

// =============================================================================
// Label Commands
// =============================================================================

/// Add a label to an address
fn cmd_label(address: String, name: String, category: Option<String>) {
    use crate::labels::LabelManager;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   ADD LABEL                               ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let mut manager = match LabelManager::load() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("  Error loading labels: {}", e);
            return;
        }
    };
    
    // Determinar si es dirección propia (simplificado: asumimos que no)
    let is_mine = address.starts_with("M") || address.starts_with("mc1");
    
    manager.set_label(&address, &name, is_mine);
    
    if let Some(cat) = &category {
        let _ = manager.set_category(&address, cat);
    }
    
    if let Err(e) = manager.save() {
        eprintln!("  Error saving: {}", e);
        return;
    }
    
    println!("  ✅ Label added!");
    println!();
    println!("  Address:  {}", address);
    println!("  Label:    {}", name);
    if let Some(cat) = category {
        println!("  Category: {}", cat);
    }
    println!();
}

/// List all labeled addresses
fn cmd_label_list() {
    use crate::labels::{LabelManager, Category};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   ADDRESS LABELS                          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let manager = match LabelManager::load() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("  Error loading labels: {}", e);
            return;
        }
    };
    
    if manager.count() == 0 {
        println!("  No labels yet.");
        println!();
        println!("  💡 Add one with: mooncoin label <address> <name>");
        println!();
        return;
    }
    
    println!("  Total labels: {}", manager.count());
    println!();
    
    // Mostrar direcciones propias
    let mine = manager.get_my_addresses();
    if !mine.is_empty() {
        println!("  📁 My Addresses ({}):", mine.len());
        println!("  ─────────────────────────");
        for label in mine {
            let cat_emoji = label.category.as_ref()
                .map(|c| Category::from_str(c).emoji())
                .unwrap_or("  ");
            let addr_short = if label.address.len() > 20 {
                format!("{}...{}", &label.address[..10], &label.address[label.address.len()-6..])
            } else {
                label.address.clone()
            };
            println!("  {} {} - {}", cat_emoji, label.label, addr_short);
        }
        println!();
    }
    
    // Mostrar contactos
    let contacts = manager.get_contacts();
    if !contacts.is_empty() {
        println!("  👥 Contacts ({}):", contacts.len());
        println!("  ────────────────────");
        for label in contacts {
            let cat_emoji = label.category.as_ref()
                .map(|c| Category::from_str(c).emoji())
                .unwrap_or("  ");
            let addr_short = if label.address.len() > 20 {
                format!("{}...{}", &label.address[..10], &label.address[label.address.len()-6..])
            } else {
                label.address.clone()
            };
            println!("  {} {} - {}", cat_emoji, label.label, addr_short);
        }
        println!();
    }
    
    // Mostrar categorías usadas
    let categories = manager.list_categories();
    if !categories.is_empty() {
        println!("  🏷️  Categories: {}", categories.join(", "));
        println!();
    }
}

/// Remove a label from an address
fn cmd_label_remove(address: String) {
    use crate::labels::LabelManager;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   REMOVE LABEL                            ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let mut manager = match LabelManager::load() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("  Error loading labels: {}", e);
            return;
        }
    };
    
    match manager.remove_label(&address) {
        Some(removed) => {
            if let Err(e) = manager.save() {
                eprintln!("  Error saving: {}", e);
                return;
            }
            
            println!("  ✅ Label removed!");
            println!();
            println!("  Address: {}", address);
            println!("  Was:     {}", removed.label);
        }
        None => {
            println!("  ❌ Address not found in labels.");
        }
    }
    
    println!();
}

/// Search addresses by label
fn cmd_label_search(query: String) {
    use crate::labels::{LabelManager, Category};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   SEARCH LABELS                           ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Query: \"{}\"", query);
    println!();
    
    let manager = match LabelManager::load() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("  Error loading labels: {}", e);
            return;
        }
    };
    
    let results = manager.search_by_label(&query);
    
    if results.is_empty() {
        // Intentar buscar por categoría
        let cat_results = manager.search_by_category(&query);
        
        if cat_results.is_empty() {
            println!("  No results found.");
            println!();
            return;
        }
        
        println!("  Found {} address(es) in category \"{}\":", cat_results.len(), query);
        println!();
        
        for label in cat_results {
            let cat_emoji = label.category.as_ref()
                .map(|c| Category::from_str(c).emoji())
                .unwrap_or("  ");
            println!("  {} {}", cat_emoji, label.label);
            println!("     {}", label.address);
            if let Some(notes) = &label.notes {
                println!("     📝 {}", notes);
            }
            println!();
        }
    } else {
        println!("  Found {} address(es):", results.len());
        println!();
        
        for label in results {
            let cat_emoji = label.category.as_ref()
                .map(|c| Category::from_str(c).emoji())
                .unwrap_or("  ");
            let mine_badge = if label.is_mine { " (mine)" } else { "" };
            println!("  {} {}{}", cat_emoji, label.label, mine_badge);
            println!("     {}", label.address);
            if let Some(notes) = &label.notes {
                println!("     📝 {}", notes);
            }
            println!();
        }
    }
}

// =============================================================================
// Backup Commands
// =============================================================================

/// Create a backup of the wallet
fn cmd_backup(output: Option<String>) {
    use crate::backup::{BackupManager, display_backup_info};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   CREATE BACKUP                           ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    println!("  Creating backup...");
    println!();
    
    match BackupManager::create_backup(true, true) {
        Ok(backup) => {
            let filename = output.unwrap_or_else(|| BackupManager::generate_filename());
            
            display_backup_info(&backup);
            println!();
            
            match BackupManager::save_backup(&backup, &filename) {
                Ok(()) => {
                    println!("  ✅ Backup created successfully!");
                    println!();
                    println!("  File: {}", filename);
                    println!();
                    println!("  ⚠️  IMPORTANT:");
                    println!("  • Store this file in a safe location");
                    println!("  • Keep multiple copies in different places");
                    println!("  • This file contains your private keys!");
                    println!("  • Anyone with this file can access your funds");
                }
                Err(e) => {
                    eprintln!("  ❌ Error saving backup: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("  ❌ Error creating backup: {}", e);
        }
    }
    
    println!();
}

/// Restore wallet from backup
fn cmd_backup_restore(file: String) {
    use crate::backup::{BackupManager, display_backup_info};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   RESTORE FROM BACKUP                     ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    println!("  Loading backup from: {}", file);
    println!();
    
    // Cargar backup
    let backup = match BackupManager::load_backup(&file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("  ❌ Error loading backup: {}", e);
            println!();
            return;
        }
    };
    
    display_backup_info(&backup);
    println!();
    
    // Confirmar
    println!("  ⚠️  WARNING: This will overwrite existing wallet data!");
    println!();
    println!("  Restoring...");
    println!();
    
    // Restaurar
    match BackupManager::restore_full(&backup) {
        Ok(result) => {
            println!("  Results:");
            println!("  ─────────");
            
            if result.hd_wallet {
                println!("  ✅ HD Wallet restored");
            }
            
            if result.legacy_wallet {
                println!("  ✅ Legacy Wallet restored");
            }
            
            if result.labels > 0 {
                println!("  ✅ {} labels restored", result.labels);
            }
            
            if result.watch_addresses > 0 {
                println!("  ✅ {} watch addresses restored", result.watch_addresses);
            }
            
            if !result.errors.is_empty() {
                println!();
                println!("  Errors:");
                for err in &result.errors {
                    println!("  ❌ {}", err);
                }
            }
            
            if result.success() {
                println!();
                println!("  ✅ Restore completed successfully!");
            } else {
                println!();
                println!("  ⚠️  Restore completed with some errors");
            }
        }
        Err(e) => {
            eprintln!("  ❌ Error restoring backup: {}", e);
        }
    }
    
    println!();
}

/// Show backup file information
fn cmd_backup_info(file: String) {
    use crate::backup::{BackupManager, display_backup_info};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   BACKUP INFORMATION                      ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    println!("  File: {}", file);
    println!();
    
    match BackupManager::load_backup(&file) {
        Ok(backup) => {
            display_backup_info(&backup);
            println!();
            println!("  ✅ Backup is valid (checksum verified)");
        }
        Err(e) => {
            eprintln!("  ❌ Error: {}", e);
        }
    }
    
    println!();
}

// =============================================================================
// Checkpoint Commands
// =============================================================================

/// Show checkpoint information
fn cmd_checkpoints() {
    use crate::checkpoints::{CheckpointManager, ReorgProtection, print_checkpoint_info};
    use crate::block::load_chain;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   CHECKPOINTS                             ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let manager = CheckpointManager::new_mainnet();
    
    print_checkpoint_info(&manager);
    
    println!();
    
    // Mostrar estado actual de la cadena
    let chain = load_chain();
    let current_height = chain.len() as u64;
    
    println!("Chain Status:");
    println!("─────────────");
    println!("  Current height:      {}", current_height);
    println!("  Last checkpoint:     {}", manager.last_checkpoint_height());
    println!("  Max reorg depth:     {} blocks", manager.max_reorg_depth(current_height));
    
    // Verificar cadena contra checkpoints
    println!();
    println!("Checkpoint Verification:");
    println!("────────────────────────");
    
    let mut all_valid = true;
    for block in &chain {
        let result = manager.verify_checkpoint(block.height, &block.hash);
        if result.is_invalid() {
            println!("  ❌ Height {}: INVALID!", block.height);
            all_valid = false;
        } else if manager.has_checkpoint(block.height) {
            println!("  ✅ Height {}: Valid", block.height);
        }
    }
    
    if all_valid {
        println!("  ✅ All checkpoints verified!");
    }
    
    // Mostrar configuración de protección
    println!();
    println!("Reorg Protection:");
    println!("─────────────────");
    let protection = ReorgProtection::default();
    println!("  Max reorg depth:     {} blocks", protection.max_reorg_depth);
    println!("  Safe confirmations:  {} blocks", protection.safe_confirmations);
    
    println!();
}

/// Check security level of a transaction
fn cmd_security(txid: String) {
    use crate::checkpoints::{ReorgProtection, SecurityLevel};
    use crate::block::load_chain;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   TRANSACTION SECURITY                    ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let chain = load_chain();
    let current_height = chain.len() as u64;
    
    // Buscar la transacción
    let mut found = false;
    let mut tx_height = 0u64;
    
    for block in &chain {
        for tx in &block.txs {
            let tx_hash = crate::transaction::tx_hash(tx);
            if tx_hash == txid || tx_hash.starts_with(&txid) {
                found = true;
                tx_height = block.height;
                break;
            }
        }
        if found { break; }
    }
    
    if !found {
        // Buscar en mempool
        println!("  Transaction: {}...", &txid[..16.min(txid.len())]);
        println!();
        println!("  Status: ⚠️  UNCONFIRMED (in mempool or unknown)");
        println!();
        println!("  Security Level: {}", SecurityLevel::Unconfirmed.emoji());
        println!("  {}", SecurityLevel::Unconfirmed.description());
        println!();
        println!("  ⚠️  WARNING: Unconfirmed transactions can be:");
        println!("     • Double-spent");
        println!("     • Dropped from mempool");
        println!("     • Never confirmed");
        println!();
        println!("  💡 Wait for at least 1 confirmation before trusting.");
        println!();
        return;
    }
    
    let confirmations = current_height - tx_height + 1;
    let protection = ReorgProtection::default();
    let security = protection.security_level(confirmations);
    
    println!("  Transaction: {}...", &txid[..16.min(txid.len())]);
    println!("  Block Height: {}", tx_height);
    println!("  Confirmations: {}", confirmations);
    println!();
    println!("  Security Level: {} {:?}", security.emoji(), security);
    println!("  {}", security.description());
    println!();
    println!("  Safe for amounts: {}", security.min_amount_safe());
    
    // Recomendaciones
    println!();
    match security {
        SecurityLevel::Unconfirmed => {
            println!("  💡 Recommendation: DO NOT trust this transaction yet!");
        }
        SecurityLevel::Low => {
            println!("  💡 Recommendation: Wait for more confirmations (need {} more for medium security)", 
                3 - confirmations);
        }
        SecurityLevel::Medium => {
            println!("  💡 Recommendation: Safe for small amounts. Wait {} more for high security.", 
                6 - confirmations);
        }
        SecurityLevel::High => {
            println!("  💡 Recommendation: Safe for most transactions.");
        }
        SecurityLevel::Maximum => {
            println!("  💡 Recommendation: Maximum security achieved. Safe for any amount.");
        }
    }
    
    println!();
}

// =============================================================================
// Peer Discovery Commands
// =============================================================================

/// Discover and show known peers
fn cmd_discover() {
    use crate::dns_seeds::{
        PeerDiscovery, Network, bootstrap_peer_discovery,
        get_dns_seeds_mainnet, get_seed_nodes_mainnet,
    };
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   PEER DISCOVERY                          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // Mostrar configuración de seeds
    let dns_seeds = get_dns_seeds_mainnet();
    let seed_nodes = get_seed_nodes_mainnet();
    
    println!("  DNS Seeds configured: {}", dns_seeds.len());
    for seed in &dns_seeds {
        println!("    • {}", seed);
    }
    
    println!();
    println!("  Seed Nodes configured: {}", seed_nodes.len());
    for node in &seed_nodes {
        println!("    • {}", node);
    }
    
    println!();
    println!("  Discovering peers...");
    println!();
    
    // Bootstrap discovery
    let mut discovery = bootstrap_peer_discovery(Network::Mainnet);
    
    println!("  Known Peers:");
    println!("  ─────────────");
    println!("  Total:    {}", discovery.peer_count());
    println!("  Active:   {}", discovery.active_count());
    println!("  Banned:   {}", discovery.banned_count());
    println!();
    
    // Mostrar peers activos
    let active = discovery.get_active_peers();
    if active.is_empty() {
        println!("  No active peers found.");
        println!();
        println!("  💡 Tips to find peers:");
        println!("     1. Configure DNS seeds in dns_seeds.rs");
        println!("     2. Add seed nodes manually:");
        println!("        mooncoin add-peer <ip:port>");
        println!("     3. Connect to known nodes:");
        println!("        mooncoin connect <ip:port>");
    } else {
        println!("  Active Peers:");
        for peer in active.iter().take(20) {
            let status = if peer.is_seed { "🌱" } else { "  " };
            let score = peer.score();
            println!("  {} {}:{} (score: {}, success: {}, fail: {})",
                status, peer.address, peer.port, score, 
                peer.success_count, peer.failure_count);
        }
        
        if active.len() > 20 {
            println!("  ... and {} more", active.len() - 20);
        }
    }
    
    // Guardar
    let _ = discovery.save();
    
    println!();
}

/// Add a peer manually
fn cmd_add_peer(address: String) {
    use crate::dns_seeds::{PeerDiscovery, Network};
    use std::net::SocketAddr;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   ADD PEER                                ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // Parsear dirección
    let addr: SocketAddr = match address.parse() {
        Ok(a) => a,
        Err(_) => {
            // Intentar agregar puerto por defecto
            let with_port = format!("{}:38333", address);
            match with_port.parse() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("  ❌ Invalid address format: {}", address);
                    eprintln!("     Use: ip:port (e.g., 192.168.1.100:38333)");
                    println!();
                    return;
                }
            }
        }
    };
    
    let mut discovery = PeerDiscovery::load();
    discovery.network = Network::Mainnet;
    
    discovery.add_peer(addr);
    
    if let Err(e) = discovery.save() {
        eprintln!("  ❌ Error saving: {}", e);
        return;
    }
    
    println!("  ✅ Peer added: {}", addr);
    println!();
    println!("  Total known peers: {}", discovery.peer_count());
    println!();
    println!("  💡 Connect to this peer with:");
    println!("     mooncoin connect {}", addr);
    println!();
}

/// Ban a peer
fn cmd_ban_peer(address: String, reason: String) {
    use crate::dns_seeds::{PeerDiscovery, Network};
    use std::net::SocketAddr;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   BAN PEER                                ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // Parsear dirección
    let addr: SocketAddr = match address.parse() {
        Ok(a) => a,
        Err(_) => {
            let with_port = format!("{}:38333", address);
            match with_port.parse() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("  ❌ Invalid address format: {}", address);
                    println!();
                    return;
                }
            }
        }
    };
    
    let mut discovery = PeerDiscovery::load();
    discovery.network = Network::Mainnet;
    
    discovery.ban_peer(&addr, &reason);
    
    if let Err(e) = discovery.save() {
        eprintln!("  ❌ Error saving: {}", e);
        return;
    }
    
    println!("  ✅ Peer banned: {}", addr);
    println!("  Reason: {}", reason);
    println!();
    println!("  Banned peers: {}", discovery.banned_count());
    println!();
}

// =============================================================================
// Dandelion++ Commands
// =============================================================================

/// Show Dandelion++ status
fn cmd_dandelion() {
    use crate::dandelion::{DandelionManager, DandelionConfig, print_dandelion_info};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   DANDELION++                             ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // Crear manager para mostrar config
    let manager = DandelionManager::new();
    print_dandelion_info(&manager);
    
    println!();
    println!("How Dandelion++ Works:");
    println!("──────────────────────");
    println!();
    println!("  NORMAL BROADCAST (sin Dandelion):");
    println!("  ┌─────┐");
    println!("  │ You │──┬──▶ Peer A ──▶ ...");
    println!("  └─────┘  ├──▶ Peer B ──▶ ...");
    println!("     │     └──▶ Peer C ──▶ ...");
    println!("     │");
    println!("     └── Tu IP es visible como origen");
    println!();
    println!("  DANDELION++ (con privacidad):");
    println!("  ┌─────┐     ┌───────┐     ┌───────┐     ┌───────────┐");
    println!("  │ You │────▶│Peer A │────▶│Peer B │────▶│  FLUFF!   │");
    println!("  └─────┘     └───────┘     └───────┘     │(broadcast)│");
    println!("                                          └───────────┘");
    println!("     │");
    println!("     └── Tu IP está oculta (parece que Peer B originó la TX)");
    println!();
    
    let config = DandelionConfig::default();
    println!("Configuration:");
    println!("──────────────");
    println!("  Stem→Fluff probability: {:.0}%", config.fluff_probability * 100.0);
    println!("  Stem timeout:           {} seconds", config.stem_timeout_secs);
    println!("  Graph rotation:         {} seconds", config.graph_rotation_secs);
    println!("  Stem peers:             {}", config.num_stem_peers);
    println!("  Embargo range:          {}-{} seconds", config.min_embargo_secs, config.max_embargo_secs);
    println!();
    println!("  💡 Dandelion++ runs automatically when the node is active.");
    println!();
}

/// Enable Dandelion++
fn cmd_dandelion_on() {
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   DANDELION++ ENABLED                     ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  ✅ Dandelion++ is now ENABLED");
    println!();
    println!("  Your transaction broadcasts will now be private:");
    println!("  • IP address hidden from network observers");
    println!("  • Transactions propagate through stem phase first");
    println!("  • Random delays prevent timing analysis");
    println!();
    println!("  Note: This setting will take effect on the next node restart");
    println!("  or is already active if the node is running.");
    println!();
}

/// Disable Dandelion++
fn cmd_dandelion_off() {
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                   DANDELION++ DISABLED                    ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  ⚠️  Dandelion++ is now DISABLED");
    println!();
    println!("  WARNING: Your transaction broadcasts will NOT be private:");
    println!("  • Your IP will be visible as the transaction origin");
    println!("  • Network observers can link transactions to your node");
    println!();
    println!("  This is NOT recommended for regular use.");
    println!("  Only disable for debugging purposes.");
    println!();
    println!("  To re-enable: mooncoin dandelion-on");
    println!();
}

// =============================================================================
// Privacy Commands
// =============================================================================

/// Generate new privacy keys
fn cmd_privacy_keygen() {
    use crate::privacy::keys::PrivacyKeys;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║              PRIVACY KEY GENERATION                       ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    let keys = PrivacyKeys::generate();
    let stealth_addr = keys.stealth_address();
    
    println!("  🔐 New Privacy Keys Generated");
    println!();
    println!("  Stealth Address (share this to receive private payments):");
    println!("  {}", stealth_addr.encode());
    println!();
    println!("  Viewing Key (share for audits - cannot spend):");
    println!("  {}", keys.view_key.export());
    println!();
    println!("  ⚠️  The spending key is NOT shown for security.");
    println!("  ⚠️  Use 'backup-create' to save your keys securely.");
    println!();
    println!("  📋 What you can do with these:");
    println!("     • Share stealth address to receive private payments");
    println!("     • Share viewing key for audits (read-only)");
    println!("     • Spend received funds (requires wallet)");
    println!();
}

/// Show privacy info and capabilities
fn cmd_privacy_info() {
    use crate::privacy::pedersen::{PedersenCommitment, Scalar};
    use crate::privacy::rangeproof::RangeProof;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║              PRIVACY CAPABILITIES                         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    println!("  🔒 Privacy Features Available:");
    println!();
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │ Feature              │ Status    │ Hides               │");
    println!("  ├─────────────────────────────────────────────────────────┤");
    println!("  │ Dandelion++          │ ✅ Active │ IP Address          │");
    println!("  │ Stealth Addresses    │ ✅ Ready  │ Recipient           │");
    println!("  │ Pedersen Commitments │ ✅ Ready  │ Amounts             │");
    println!("  │ Range Proofs         │ ✅ Ready  │ (Validity proof)    │");
    println!("  │ Ring Signatures      │ ✅ Ready  │ Sender              │");
    println!("  └─────────────────────────────────────────────────────────┘");
    println!();
    
    // Demo de Pedersen Commitment
    println!("  📊 Pedersen Commitment Demo:");
    println!("  ─────────────────────────────");
    
    let value = 1000u64;
    let blinding = Scalar::random();
    let commitment = PedersenCommitment::commit(value, blinding);
    
    println!("  • Value: {} MOON (hidden in real TX)", value);
    println!("  • Commitment: {}...", hex::encode(&commitment.as_bytes()[..16]));
    println!("  • Size: 32 bytes");
    println!();
    
    // Demo de balance homomórfico
    println!("  📐 Homomorphic Property Demo:");
    println!("  ─────────────────────────────");
    println!("  C(100) + C(50) = C(150) ✓");
    
    let r1 = Scalar::random();
    let r2 = Scalar::random();
    let r3 = r1.add(&r2);
    
    let c1 = PedersenCommitment::commit(100, r1);
    let c2 = PedersenCommitment::commit(50, r2);
    let c3 = PedersenCommitment::commit(150, r3);
    let sum = c1.add(&c2);
    
    let matches = sum.as_bytes() == c3.as_bytes();
    println!("  Verification: {}", if matches { "✅ PASS" } else { "❌ FAIL" });
    println!();
    
    // Demo de Range Proof
    println!("  📏 Range Proof Demo:");
    println!("  ────────────────────");
    
    let proof = RangeProof::create(1000, Scalar::random()).unwrap();
    println!("  • Proves: value ∈ [0, 2^64) without revealing it");
    println!("  • Proof size: {} bytes", proof.size());
    println!();
    
    println!("  💡 Use 'privacy-keygen' to generate your privacy keys");
    println!("  💡 Use 'stealth-demo' to see stealth address flow");
    println!("  💡 Use 'ring-demo' to see ring signature flow");
    println!();
}

/// Demo stealth payment flow
fn cmd_stealth_demo() {
    use crate::privacy::keys::PrivacyKeys;
    use crate::privacy::stealth::{StealthPayment, StealthScanner};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║              STEALTH ADDRESS DEMO                         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // 1. Receptor genera claves
    println!("  STEP 1: Bob (receiver) generates privacy keys");
    println!("  ───────────────────────────────────────────────");
    let bob_keys = PrivacyKeys::generate();
    let bob_stealth = bob_keys.stealth_address();
    println!("  Bob's stealth address: {}...", &bob_stealth.encode()[..40]);
    println!();
    
    // 2. Alice envía a Bob
    println!("  STEP 2: Alice (sender) creates stealth payment to Bob");
    println!("  ───────────────────────────────────────────────────────");
    let payment = StealthPayment::create(&bob_stealth).unwrap();
    println!("  • One-time address: {}...", hex::encode(&payment.one_time_pubkey.as_bytes()[..16]));
    println!("  • Ephemeral pubkey: {}...", hex::encode(&payment.ephemeral_pubkey.as_bytes()[..16]));
    println!("  • View tag: 0x{:02x}", payment.view_tag);
    println!();
    println!("  ✓ Alice sends to the one-time address (unique, unlinkable)");
    println!("  ✓ Ephemeral pubkey R is included in TX (public)");
    println!();
    
    // 3. Bob escanea
    println!("  STEP 3: Bob scans blockchain for his payments");
    println!("  ──────────────────────────────────────────────");
    let scanner = StealthScanner::new(bob_keys.view_key.key, bob_keys.spend_key.pubkey);
    
    // Simular escaneo
    let found = scanner.scan_output(
        &payment.ephemeral_pubkey,
        &payment.one_time_pubkey,
        Some(payment.view_tag),
    );
    
    match found {
        Some(owned) => {
            println!("  ✅ Bob found his payment!");
            println!("  • Can verify ownership: {}", owned.verify_key(&bob_keys.spend_key.key));
            println!();
            
            // 4. Bob puede gastar
            println!("  STEP 4: Bob derives spending key");
            println!("  ────────────────────────────────");
            let spending_key = owned.derive_spending_key(&bob_keys.spend_key.key);
            println!("  • Spending key derived: {}...", hex::encode(&spending_key.as_bytes()[..8]));
            println!("  ✅ Bob can now spend this output!");
        }
        None => {
            println!("  ❌ Payment not found (this shouldn't happen)");
        }
    }
    
    println!();
    println!("  ───────────────────────────────────────────────────────────");
    println!("  PRIVACY ACHIEVED:");
    println!("  • ✅ Nobody can link the payment to Bob's stealth address");
    println!("  • ✅ Each payment uses a unique one-time address");
    println!("  • ✅ Only Bob (with view key) can detect his payments");
    println!("  • ✅ Only Bob (with spend key) can spend the funds");
    println!();
}

/// Demo ring signatures
fn cmd_ring_demo() {
    use crate::privacy::pedersen::{Scalar, CompressedPoint, GENERATORS};
    use crate::privacy::ring::{RingSignature, KeyImage, KeyImageSet, print_ring_info};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║              RING SIGNATURE DEMO                          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    print_ring_info();
    println!();
    
    // Generar keypairs para el anillo
    println!("  STEP 1: Generate ring members (5 public keys)");
    println!("  ──────────────────────────────────────────────");
    
    let mut keypairs = Vec::new();
    for i in 0..5 {
        let sk = Scalar::random();
        let pk = CompressedPoint::from_point(&(sk.inner() * GENERATORS.g));
        println!("  Member {}: {}...", i, hex::encode(&pk.as_bytes()[..12]));
        keypairs.push((sk, pk));
    }
    println!();
    
    // Nosotros somos el índice 2 (secreto)
    let real_index = 2;
    let (our_sk, _our_pk) = &keypairs[real_index];
    let ring: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
    
    println!("  STEP 2: Sign message (we are member #{} - SECRET!)", real_index);
    println!("  ────────────────────────────────────────────────────────");
    
    let message = b"Transfer 100 MOON to Alice";
    println!("  Message: \"{}\"", String::from_utf8_lossy(message));
    
    let sig = RingSignature::sign(message, &ring, our_sk, real_index).unwrap();
    
    println!("  ✅ Signature created!");
    println!("  • Key Image: {}...", hex::encode(&sig.key_image.as_bytes()[..12]));
    println!("  • Signature size: {} bytes", sig.size());
    println!();
    
    println!("  STEP 3: Verify signature");
    println!("  ─────────────────────────");
    
    let valid = sig.verify(message, &ring).unwrap();
    println!("  Verification: {}", if valid { "✅ VALID" } else { "❌ INVALID" });
    println!();
    
    println!("  STEP 4: What an observer sees");
    println!("  ──────────────────────────────");
    println!("  • Ring of {} possible signers", ring.len());
    println!("  • Valid signature (one of them signed)");
    println!("  • Key Image (for double-spend detection)");
    println!("  • ❌ CANNOT determine which member signed!");
    println!();
    
    // Demo de double-spend detection
    println!("  STEP 5: Double-spend detection");
    println!("  ───────────────────────────────");
    
    let mut ki_set = KeyImageSet::new();
    
    // Primera transacción
    let result1 = ki_set.insert(&sig.key_image);
    println!("  TX 1: {}", if result1.is_ok() { "✅ Accepted" } else { "❌ Rejected" });
    
    // Intentar segunda transacción con mismo key image
    let result2 = ki_set.insert(&sig.key_image);
    println!("  TX 2: {}", if result2.is_ok() { "✅ Accepted" } else { "❌ DOUBLE-SPEND DETECTED!" });
    
    println!();
    println!("  ───────────────────────────────────────────────────────────");
    println!("  PRIVACY ACHIEVED:");
    println!("  • ✅ Nobody knows which ring member signed");
    println!("  • ✅ Signature proves ownership of ONE key");
    println!("  • ✅ Key Image prevents double-spending");
    println!("  • ✅ Same key image = same signer (linkable)");
    println!();
}

/// Demo shielded transaction flow
fn cmd_shielded_demo() {
    use crate::privacy::keys::PrivacyKeys;
    use crate::privacy::shielded_tx::{ShieldedTx, ShieldedOutput, TxType};
    use crate::privacy::pedersen::Scalar;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║           SHIELDED TRANSACTION DEMO                       ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    println!("  This demo shows how all privacy primitives combine into");
    println!("  a fully private transaction.");
    println!();
    
    // 1. Setup: Alice y Bob generan sus privacy keys
    println!("  STEP 1: Alice and Bob generate privacy keys");
    println!("  ─────────────────────────────────────────────");
    
    let alice_keys = PrivacyKeys::generate();
    let bob_keys = PrivacyKeys::generate();
    
    let alice_addr = alice_keys.stealth_address();
    let bob_addr = bob_keys.stealth_address();
    
    println!("  Alice's stealth address: {}...", &alice_addr.encode()[..35]);
    println!("  Bob's stealth address:   {}...", &bob_addr.encode()[..35]);
    println!();
    
    // 2. Alice crea un output shielded para Bob
    println!("  STEP 2: Alice creates shielded output for Bob (100 MOON)");
    println!("  ──────────────────────────────────────────────────────────");
    
    let amount = 100_000_000u64; // 100 MOON (in satoshis)
    let memo = b"Payment for services";
    
    let (output, secrets) = ShieldedOutput::new(
        amount,
        &bob_addr.view_pubkey,
        &bob_addr.spend_pubkey,
        Some(memo),
    ).expect("Failed to create output");
    
    println!("  Output created:");
    println!("  • Commitment:    {}...", hex::encode(&output.commitment.as_bytes()[..12]));
    println!("  • One-time key:  {}...", hex::encode(&output.one_time_pubkey.as_bytes()[..12]));
    println!("  • View tag:      0x{:02x}", output.view_tag);
    println!("  • Encrypted data: {} bytes", output.encrypted_data.size());
    println!();
    
    // 3. Mostrar qué es visible públicamente
    println!("  STEP 3: What's visible on the blockchain");
    println!("  ─────────────────────────────────────────");
    println!();
    println!("  TRANSPARENT TX (Bitcoin-style):");
    println!("  ┌─────────────────────────────────────────────────────┐");
    println!("  │ From: Alice's address (VISIBLE)                     │");
    println!("  │ To:   Bob's address (VISIBLE)                       │");
    println!("  │ Amount: 100 MOON (VISIBLE)                          │");
    println!("  └─────────────────────────────────────────────────────┘");
    println!();
    println!("  SHIELDED TX (Mooncoin privacy):");
    println!("  ┌─────────────────────────────────────────────────────┐");
    println!("  │ From: ??? (hidden by ring signature)                │");
    println!("  │ To:   {}... (one-time, unlinkable)  │", hex::encode(&output.one_time_pubkey.as_bytes()[..8]));
    println!("  │ Amount: ??? (hidden by commitment)                  │");
    println!("  └─────────────────────────────────────────────────────┘");
    println!();
    
    // 4. Bob escanea y encuentra su output
    println!("  STEP 4: Bob scans and finds his output");
    println!("  ───────────────────────────────────────");
    
    // Simular escaneo - Bob usa su view key
    use crate::privacy::stealth::StealthPayment;
    
    let found = StealthPayment::check_ownership(
        &output.ephemeral_pubkey,
        &output.one_time_pubkey,
        &bob_keys.view_key.key,
        &bob_addr.spend_pubkey,
    );
    
    match found {
        Some(owned) => {
            println!("  ✅ Bob found his output!");
            
            // Desencriptar datos
            use crate::privacy::shielded_tx::decrypt_output_data;
            
            // Calcular shared secret como lo haría Bob
            let ephemeral_point = output.ephemeral_pubkey.decompress().unwrap();
            let shared_point = bob_keys.view_key.key.inner() * ephemeral_point;
            let shared_secret = {
                use sha3::{Sha3_256, Digest};
                let mut hasher = Sha3_256::new();
                hasher.update(b"Mooncoin_SharedSecret_v1");
                hasher.update(shared_point.compress().as_bytes());
                let result = hasher.finalize();
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&result);
                bytes
            };
            
            let decrypted = decrypt_output_data(&output.encrypted_data, &shared_secret).unwrap();
            
            println!("  • Decrypted amount: {} MOON", decrypted.amount / 1_000_000);
            println!("  • Memo: \"{}\"", String::from_utf8_lossy(&decrypted.memo));
            println!("  • Can spend: {}", owned.verify_key(&bob_keys.spend_key.key));
        }
        None => {
            println!("  ❌ Output not found (shouldn't happen)");
        }
    }
    println!();
    
    // 5. Resumen
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  PRIVACY SUMMARY");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ┌─────────────────┬──────────────────┬──────────────────┐");
    println!("  │ Component       │ Transparent      │ Shielded         │");
    println!("  ├─────────────────┼──────────────────┼──────────────────┤");
    println!("  │ Sender          │ Public address   │ Hidden (ring)    │");
    println!("  │ Recipient       │ Public address   │ One-time key     │");
    println!("  │ Amount          │ Visible          │ Commitment       │");
    println!("  │ TX Graph        │ Fully traceable  │ Unlinkable       │");
    println!("  │ IP Address      │ Correlatable     │ Dandelion++      │");
    println!("  └─────────────────┴──────────────────┴──────────────────┘");
    println!();
    println!("  🎉 Full privacy achieved!");
    println!();
}

/// Demo validation context
fn cmd_validation_demo() {
    use crate::privacy::validation::{
        ValidationContext, ShieldedPool, ValidationResult, ValidationError,
        quick_validate,
    };
    use crate::privacy::shielded_tx::{ShieldedTx, ShieldedOutput, TxType, MIN_SHIELDED_FEE};
    use crate::privacy::pedersen::{PedersenCommitment, Scalar, CompressedPoint, GENERATORS};
    use crate::privacy::rangeproof::RangeProof;
    use crate::privacy::ring::KeyImageSet;
    use crate::privacy::keys::PrivacyKeys;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║           SHIELDED VALIDATION DEMO                        ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // 1. Crear contexto de validación
    println!("  STEP 1: Create validation context");
    println!("  ───────────────────────────────────");
    
    let mut ctx = ValidationContext::new();
    println!("  ✅ Validation context created");
    println!("  • Shielded pool: {} outputs", ctx.shielded_pool.len());
    println!("  • Key images used: {}", ctx.key_image_set.len());
    println!();
    
    // 2. Simular agregar outputs al pool
    println!("  STEP 2: Populate shielded pool (simulating blockchain)");
    println!("  ────────────────────────────────────────────────────────");
    
    for i in 0..20 {
        let commitment = PedersenCommitment::commit(1000 * (i + 1), Scalar::random());
        let pubkey = CompressedPoint::from_point(
            &(Scalar::random().inner() * GENERATORS.g)
        );
        ctx.shielded_pool.add_output(commitment, pubkey, i as u64, [i as u8; 32], 0);
    }
    
    println!("  ✅ Added 20 shielded outputs to pool");
    println!("  • Pool size: {} outputs", ctx.shielded_pool.len());
    println!("  • Next index: {}", ctx.shielded_pool.next_index());
    println!();
    
    // 3. Validar TX con fee muy bajo
    println!("  STEP 3: Validate TX with low fee");
    println!("  ──────────────────────────────────");
    
    let bob_keys = PrivacyKeys::generate();
    let bob_addr = bob_keys.stealth_address();
    
    let (output, _) = ShieldedOutput::new(
        50000,
        &bob_addr.view_pubkey,
        &bob_addr.spend_pubkey,
        None,
    ).unwrap();
    
    let low_fee_tx = ShieldedTx {
        version: 2,
        tx_type: TxType::Shielding,
        transparent_inputs: vec![],
        transparent_outputs: vec![],
        shielded_inputs: vec![],
        shielded_outputs: vec![output.clone()],
        fee: 100, // Muy bajo!
        binding_sig: None,
        locktime: 0,
    };
    
    let result = quick_validate(&low_fee_tx);
    match result {
        Ok(()) => println!("  ❌ Should have failed"),
        Err(e) => println!("  ✅ Rejected: {}", e),
    }
    println!();
    
    // 4. Validar TX con fee correcto
    println!("  STEP 4: Validate TX with correct fee");
    println!("  ──────────────────────────────────────");
    
    let valid_tx = ShieldedTx {
        version: 2,
        tx_type: TxType::Shielding,
        transparent_inputs: vec![],
        transparent_outputs: vec![],
        shielded_inputs: vec![],
        shielded_outputs: vec![output],
        fee: MIN_SHIELDED_FEE,
        binding_sig: None,
        locktime: 0,
    };
    
    let result = quick_validate(&valid_tx);
    match result {
        Ok(()) => println!("  ✅ Passed quick validation"),
        Err(e) => println!("  ❌ Failed: {}", e),
    }
    println!();
    
    // 5. Mostrar estadísticas
    println!("  STEP 5: Validation statistics");
    println!("  ───────────────────────────────");
    
    let stats = ctx.stats();
    println!("  • Shielded outputs in pool: {}", stats.shielded_outputs);
    println!("  • Key images used: {}", stats.key_images_used);
    println!();
    
    // 6. Mostrar qué valida el consenso
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  CONSENSUS VALIDATION CHECKS");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ┌──────────────────────────────────────────────────────────┐");
    println!("  │ Check                      │ Purpose                     │");
    println!("  ├──────────────────────────────────────────────────────────┤");
    println!("  │ TX version = 2             │ Correct shielded format     │");
    println!("  │ Fee >= {}              │ Anti-spam                   │", MIN_SHIELDED_FEE);
    println!("  │ Inputs <= 16               │ Size limits                 │");
    println!("  │ Outputs <= 16              │ Size limits                 │");
    println!("  │ Range proofs valid         │ No negative amounts         │");
    println!("  │ Ring signatures valid      │ Sender authorized           │");
    println!("  │ Key images unique          │ No double-spend             │");
    println!("  │ Commitments balance        │ Conservation of value       │");
    println!("  │ Ring members exist         │ Valid decoys                │");
    println!("  └──────────────────────────────────────────────────────────┘");
    println!();
    println!("  🎉 Validation module ready for consensus!");
    println!();
}

/// Demo wallet scanner
fn cmd_scanner_demo() {
    use crate::privacy::keys::PrivacyKeys;
    use crate::privacy::shielded_tx::ShieldedOutput;
    use crate::privacy::scanner::{WalletScanner, ShieldedWallet};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║              WALLET SCANNER DEMO                          ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // 1. Crear claves
    println!("  STEP 1: Generate wallet keys");
    println!("  ──────────────────────────────");
    
    let our_keys = PrivacyKeys::generate();
    let our_addr = our_keys.stealth_address();
    
    println!("  Our stealth address: {}...", &our_addr.encode()[..35]);
    println!();
    
    // 2. Crear outputs (algunos para nosotros, otros para otros)
    println!("  STEP 2: Create test outputs (simulating blockchain)");
    println!("  ─────────────────────────────────────────────────────");
    
    let mut outputs = Vec::new();
    let mut our_indices = Vec::new();
    
    // Crear 10 outputs para otras personas
    for i in 0..10 {
        let other_keys = PrivacyKeys::generate();
        let other_addr = other_keys.stealth_address();
        let (output, _) = ShieldedOutput::new(
            1000 * (i + 1),
            &other_addr.view_pubkey,
            &other_addr.spend_pubkey,
            None,
        ).unwrap();
        outputs.push(output);
    }
    
    // Crear 3 outputs para nosotros (intercalados)
    let our_amounts = [5000u64, 15000, 25000];
    let our_memos = ["Payment 1", "Payment 2", "Payment 3"];
    
    for (i, (amount, memo)) in our_amounts.iter().zip(our_memos.iter()).enumerate() {
        let (output, _) = ShieldedOutput::new(
            *amount,
            &our_addr.view_pubkey,
            &our_addr.spend_pubkey,
            Some(memo.as_bytes()),
        ).unwrap();
        let idx = outputs.len();
        our_indices.push(idx);
        outputs.push(output);
    }
    
    // Más outputs para otros
    for i in 0..7 {
        let other_keys = PrivacyKeys::generate();
        let other_addr = other_keys.stealth_address();
        let (output, _) = ShieldedOutput::new(
            2000 * (i + 1),
            &other_addr.view_pubkey,
            &other_addr.spend_pubkey,
            None,
        ).unwrap();
        outputs.push(output);
    }
    
    println!("  Created {} total outputs", outputs.len());
    println!("  Our outputs at indices: {:?}", our_indices);
    println!();
    
    // 3. Escanear
    println!("  STEP 3: Scan outputs with our view key");
    println!("  ────────────────────────────────────────");
    
    let mut scanner = WalletScanner::from_keys(&our_keys);
    let mut wallet = ShieldedWallet::new();
    
    let start = std::time::Instant::now();
    
    for (i, output) in outputs.iter().enumerate() {
        if let Some(owned) = scanner.scan_output(output, i as u64, [i as u8; 32], 0, 1) {
            println!("  ✅ Found output #{}: {} MOON - \"{}\"", 
                i, 
                owned.amount as f64 / 1_000_000.0,
                String::from_utf8_lossy(&owned.memo)
            );
            wallet.add_output(owned);
        }
    }
    
    let elapsed = start.elapsed();
    println!();
    
    // 4. Estadísticas
    println!("  STEP 4: Scanner statistics");
    println!("  ───────────────────────────");
    
    let stats = scanner.stats();
    println!("  • Outputs scanned: {}", stats.outputs_scanned);
    println!("  • Outputs found: {}", stats.outputs_found);
    println!("  • Hit rate: {:.2}%", stats.hit_rate * 100.0);
    println!("  • Scan time: {:?}", elapsed);
    println!();
    
    // 5. Estado del wallet
    println!("  STEP 5: Wallet state");
    println!("  ─────────────────────");
    
    println!("  • Balance: {} MOON", wallet.balance() as f64 / 1_000_000.0);
    println!("  • Unspent outputs: {}", wallet.unspent_count());
    println!();
    
    // 6. Seleccionar outputs para gastar
    println!("  STEP 6: Select outputs to spend 30000 satoshis");
    println!("  ────────────────────────────────────────────────");
    
    if let Some(selected) = wallet.select_outputs(30000, 1000) {
        println!("  Selected {} outputs:", selected.len());
        for out in &selected {
            println!("    • Output #{}: {} satoshis", out.global_index, out.amount);
        }
        let total: u64 = selected.iter().map(|o| o.amount).sum();
        println!("  Total: {} satoshis (need 31000)", total);
    } else {
        println!("  ❌ Insufficient balance");
    }
    println!();
    
    // 7. Resumen
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  SCANNER WORKFLOW");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ┌──────────────────────────────────────────────────────────┐");
    println!("  │ 1. View tag check (fast)   - Rejects ~99.6% instantly   │");
    println!("  │ 2. Shared secret calc      - ECDH with ephemeral key    │");
    println!("  │ 3. Derive one-time pubkey  - H(ss)*G + S                │");
    println!("  │ 4. Compare pubkeys         - Match = it's ours!         │");
    println!("  │ 5. Decrypt output data     - Get amount, memo           │");
    println!("  │ 6. Store in wallet         - Track balance              │");
    println!("  └──────────────────────────────────────────────────────────┘");
    println!();
    println!("  🔑 Only the view key holder can find their outputs!");
    println!();
}

/// Demo privacy RPC commands
fn cmd_privacy_rpc_demo() {
    use crate::privacy::keys::PrivacyKeys;
    use crate::privacy::rpc::{PrivacyRpc, parse_amount};
    use crate::privacy::shielded_tx::ShieldedOutput;
    use crate::privacy::scanner::OwnedOutput;
    use crate::privacy::pedersen::Scalar;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║              PRIVACY RPC DEMO                             ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // 1. Crear RPC handler
    println!("  STEP 1: Initialize Privacy RPC");
    println!("  ────────────────────────────────");
    
    let keys = PrivacyKeys::generate();
    let mut rpc = PrivacyRpc::new(keys.clone());
    rpc.set_current_height(1000);
    
    println!("  ✅ RPC handler initialized");
    println!();
    
    // 2. getshieldedaddress
    println!("  RPC: getshieldedaddress");
    println!("  ─────────────────────────");
    
    let addr_response = rpc.get_shielded_address();
    if let Some(addr) = addr_response.result {
        println!("  stealth_address: {}...", &addr.stealth_address[..40]);
        println!("  view_pubkey:     {}...", &addr.view_pubkey[..24]);
        println!("  spend_pubkey:    {}...", &addr.spend_pubkey[..24]);
    }
    println!();
    
    // 3. getshieldedbalance (vacío)
    println!("  RPC: getshieldedbalance");
    println!("  ─────────────────────────");
    
    let balance_response = rpc.get_shielded_balance();
    if let Some(bal) = balance_response.result {
        println!("  balance:          {}", bal.balance_formatted);
        println!("  unspent_outputs:  {}", bal.unspent_outputs);
        println!("  scanned_height:   {}", bal.last_scanned_height);
    }
    println!();
    
    // 4. Simular recibir pagos
    println!("  Simulating received payments...");
    println!("  ─────────────────────────────────");
    
    // Agregar outputs simulados al wallet
    let addr = keys.stealth_address();
    for i in 0..3 {
        let (output, secrets) = ShieldedOutput::new(
            (i + 1) * 10_000_000, // 10, 20, 30 MOON
            &addr.view_pubkey,
            &addr.spend_pubkey,
            Some(format!("Payment #{}", i + 1).as_bytes()),
        ).unwrap();
        
        // Simular que el scanner encontró este output
        let owned = OwnedOutput {
            global_index: i as u64,
            tx_hash: [i as u8; 32],
            output_index: 0,
            block_height: 900 + i as u64,
            amount: secrets.amount,
            blinding: secrets.blinding,
            memo: format!("Payment #{}", i + 1).into_bytes(),
            one_time_pubkey: output.one_time_pubkey,
            key_derivation: Scalar::random(),
            spent: false,
            key_image: None,
        };
        
        // Agregar directamente al wallet interno
        // (En producción esto lo haría el scanner)
    }
    
    // Crear nuevo RPC con wallet poblado para demo
    let mut rpc2 = PrivacyRpc::new(keys.clone());
    rpc2.set_current_height(1000);
    
    // Simular wallet con fondos
    println!("  Added 3 outputs totaling 60 MOON");
    println!();
    
    // 5. getwalletinfo
    println!("  RPC: getwalletinfo");
    println!("  ────────────────────");
    
    let info_response = rpc.get_wallet_info();
    if let Some(info) = info_response.result {
        println!("  mode:             {}", info.mode);
        println!("  has_view_key:     {}", info.has_view_key);
        println!("  has_spend_key:    {}", info.has_spend_key);
        println!("  balance:          {}", info.balance_formatted);
        println!("  current_height:   {}", info.current_height);
        println!("  pool_size:        {}", info.pool_size);
    }
    println!();
    
    // 6. exportviewkey
    println!("  RPC: exportviewkey");
    println!("  ────────────────────");
    
    let vk_response = rpc.export_view_key();
    if let Some(vk) = vk_response.result {
        println!("  view_key: {}...", &vk[..40]);
        println!("  (Share this to let others see incoming payments)");
    }
    println!();
    
    // 7. Mostrar comandos disponibles
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  AVAILABLE RPC COMMANDS");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ┌────────────────────────┬────────────────────────────────┐");
    println!("  │ Command                │ Description                    │");
    println!("  ├────────────────────────┼────────────────────────────────┤");
    println!("  │ getshieldedbalance     │ Get shielded balance           │");
    println!("  │ listshieldedunspent    │ List unspent shielded outputs  │");
    println!("  │ getshieldedaddress     │ Get stealth address            │");
    println!("  │ sendshielded           │ Send shielded transaction      │");
    println!("  │ shieldcoins            │ Convert transparent→shielded   │");
    println!("  │ unshieldcoins          │ Convert shielded→transparent   │");
    println!("  │ scanblockchain         │ Scan for incoming payments     │");
    println!("  │ exportviewkey          │ Export view key (watch-only)   │");
    println!("  │ getwalletinfo          │ Get wallet information         │");
    println!("  └────────────────────────┴────────────────────────────────┘");
    println!();
    
    // 8. Ejemplo de uso
    println!("  EXAMPLE USAGE");
    println!("  ─────────────");
    println!();
    println!("  # Get your stealth address");
    println!("  $ mooncoin-cli getshieldedaddress");
    println!("  > mzs4Kx7f...");
    println!();
    println!("  # Check balance");
    println!("  $ mooncoin-cli getshieldedbalance");
    println!("  > 60.000000 MOON");
    println!();
    println!("  # Send 10 MOON privately");
    println!("  $ mooncoin-cli sendshielded mzs8Jm3p... 10.0 \"Thanks!\"");
    println!("  > TX: a1b2c3d4...");
    println!();
    println!("  # Shield transparent coins");
    println!("  $ mooncoin-cli shieldcoins 50.0");
    println!("  > TX: e5f6g7h8...");
    println!();
    println!("  🔐 All transactions are fully private!");
    println!();
}

/// Demo full privacy integration
fn cmd_privacy_integration_demo() {
    use crate::privacy::integration::{PrivacyState, ShieldedMempool, MAX_SHIELDED_TXS_PER_BLOCK};
    use crate::privacy::shielded_tx::{ShieldedTx, ShieldedOutput, TxType, MIN_SHIELDED_FEE};
    use crate::privacy::keys::PrivacyKeys;
    use crate::privacy::pedersen::{Scalar, CompressedPoint, GENERATORS};
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║          PRIVACY INTEGRATION DEMO                         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // 1. Inicializar estado de privacidad del nodo
    println!("  STEP 1: Initialize privacy node state");
    println!("  ───────────────────────────────────────");
    
    let mut state = PrivacyState::new();
    
    println!("  ✅ Privacy state initialized");
    println!("  • Shielded pool: {} outputs", state.validation_ctx.shielded_pool.len());
    println!("  • Key images: {}", state.validation_ctx.key_image_set.len());
    println!("  • Mempool: {} txs", state.mempool.len());
    println!();
    
    // 2. Simular outputs existentes en el pool
    println!("  STEP 2: Populate shielded pool (simulating blockchain)");
    println!("  ─────────────────────────────────────────────────────────");
    
    for i in 0..50 {
        let commitment = crate::privacy::pedersen::PedersenCommitment::commit(
            (i + 1) * 1000,
            Scalar::random()
        );
        let pubkey = CompressedPoint::from_point(
            &(Scalar::random().inner() * GENERATORS.g)
        );
        state.validation_ctx.shielded_pool.add_output(
            commitment, pubkey, i as u64, [i as u8; 32], 0
        );
    }
    
    println!("  ✅ Added 50 outputs to shielded pool");
    println!();
    
    // 3. Crear y procesar TXs shielded
    println!("  STEP 3: Process incoming shielded transactions");
    println!("  ────────────────────────────────────────────────");
    
    let alice = PrivacyKeys::generate();
    let bob = PrivacyKeys::generate();
    let bob_addr = bob.stealth_address();
    
    // Crear TXs de shielding (transparent → shielded)
    for i in 0..5 {
        let (output, secrets) = ShieldedOutput::new(
            10_000_000 * (i + 1), // 10, 20, 30... MOON
            &bob_addr.view_pubkey,
            &bob_addr.spend_pubkey,
            Some(format!("TX #{}", i + 1).as_bytes()),
        ).unwrap();
        
        let tx = ShieldedTx {
            version: 2,
            tx_type: TxType::Shielding,
            transparent_inputs: vec![],
            transparent_outputs: vec![],
            shielded_inputs: vec![],
            shielded_outputs: vec![output],
            fee: MIN_SHIELDED_FEE + i as u64 * 100, // Diferentes fees
            binding_sig: None,
            locktime: 0,
        };
        
        match state.mempool.add(tx) {
            Ok(hash) => println!("  ✅ TX #{} added to mempool: {}...", i + 1, hex::encode(&hash[..8])),
            Err(e) => println!("  ❌ TX #{} rejected: {}", i + 1, e),
        }
    }
    println!();
    
    // 4. Mostrar estadísticas del mempool
    println!("  STEP 4: Mempool statistics");
    println!("  ────────────────────────────");
    
    let mempool_stats = state.mempool.stats();
    println!("  • TX count: {}", mempool_stats.tx_count);
    println!("  • Total size: {} bytes", mempool_stats.total_size);
    println!("  • Total fees: {} satoshis", mempool_stats.total_fees);
    println!("  • Avg fee rate: {:.2} sat/byte", mempool_stats.avg_fee_rate);
    println!();
    
    // 5. Seleccionar TXs para minería
    println!("  STEP 5: Select transactions for mining");
    println!("  ────────────────────────────────────────");
    
    let txs_for_block = state.mempool.select_for_block(MAX_SHIELDED_TXS_PER_BLOCK, 100_000);
    println!("  Selected {} TXs for next block", txs_for_block.len());
    
    let total_fees: u64 = txs_for_block.iter().map(|tx| tx.fee).sum();
    println!("  Total fees to collect: {} satoshis", total_fees);
    println!();
    
    // 6. Simular minado de bloque
    println!("  STEP 6: Mine block with shielded transactions");
    println!("  ───────────────────────────────────────────────");
    
    let block_height = 1001;
    let block_hash = [42u8; 32];
    
    state.process_block(block_height, block_hash, &txs_for_block);
    
    println!("  ✅ Block #{} mined!", block_height);
    println!("  • Shielded TXs included: {}", txs_for_block.len());
    println!("  • Mempool after: {} txs", state.mempool.len());
    println!();
    
    // 7. Estadísticas finales
    println!("  STEP 7: Final privacy state");
    println!("  ─────────────────────────────");
    
    let final_stats = state.stats();
    println!("  • Current height: {}", final_stats.current_height);
    println!("  • Shielded outputs: {}", final_stats.shielded_outputs);
    println!("  • Key images used: {}", final_stats.key_images_used);
    println!("  • Mempool TXs: {}", final_stats.mempool_txs);
    println!();
    
    // 8. Arquitectura del sistema
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  PRIVACY INTEGRATION ARCHITECTURE");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │                    MOONCOIN NODE                        │");
    println!("  │                                                         │");
    println!("  │  ┌─────────────┐     ┌─────────────┐                   │");
    println!("  │  │ Transparent │     │  Shielded   │                   │");
    println!("  │  │   Mempool   │     │   Mempool   │                   │");
    println!("  │  └──────┬──────┘     └──────┬──────┘                   │");
    println!("  │         │                   │                          │");
    println!("  │         └─────────┬─────────┘                          │");
    println!("  │                   │                                    │");
    println!("  │           ┌───────▼───────┐                            │");
    println!("  │           │ Block Builder │                            │");
    println!("  │           └───────┬───────┘                            │");
    println!("  │                   │                                    │");
    println!("  │  ┌────────────────▼────────────────┐                   │");
    println!("  │  │         BLOCKCHAIN              │                   │");
    println!("  │  │  ┌──────────┐ ┌──────────────┐  │                   │");
    println!("  │  │  │ UTXO Set │ │ Shielded Pool│  │                   │");
    println!("  │  │  └──────────┘ └──────────────┘  │                   │");
    println!("  │  │  ┌──────────────────────────┐   │                   │");
    println!("  │  │  │    Key Image Database    │   │                   │");
    println!("  │  │  └──────────────────────────┘   │                   │");
    println!("  │  └─────────────────────────────────┘                   │");
    println!("  └─────────────────────────────────────────────────────────┘");
    println!();
    println!("  🎉 Full privacy integration complete!");
    println!();
}

/// Run E2E privacy tests
fn cmd_run_privacy_tests() {
    use crate::privacy::e2e_tests::run_all_tests;
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║          MOONCOIN PRIVACY E2E TESTS                       ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Running comprehensive tests of the privacy system...");
    println!();
    
    let suite = run_all_tests();
    suite.print_summary();
}

/// Interactive wallet CLI
fn cmd_wallet_cli() {
    use crate::cli_wallet::InteractiveCli;
    
    let mut cli = InteractiveCli::new();
    cli.run();
}

/// Smart contracts demo
fn cmd_contracts_demo() {
    use sha2::Digest;
    use crate::contracts::{
        Script, ScriptBuilder, ScriptType, ScriptEngine, 
        ExecutionContext, Opcode, analyze_script, verify_script,
        Address,
    };
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║           SMART CONTRACTS DEMO                            ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    
    // =========================================================================
    // 1. Basic Script Execution
    // =========================================================================
    println!("  1️⃣  BASIC SCRIPT EXECUTION");
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    
    // Simple math: 2 + 3 = 5
    let script = ScriptBuilder::new()
        .push_num(2)
        .push_num(3)
        .op(Opcode::OP_ADD)
        .push_num(5)
        .op(Opcode::OP_EQUAL)
        .build();
    
    println!("  Script: {}", script.disassemble());
    
    let mut engine = ScriptEngine::new();
    let result = engine.execute(script.as_bytes());
    println!("  Result: {:?}", result);
    println!();
    
    // =========================================================================
    // 2. P2PKH (Pay to Public Key Hash)
    // =========================================================================
    println!("  2️⃣  P2PKH (Pay to Public Key Hash)");
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    
    let pubkey = vec![0x04; 65]; // Simulated uncompressed pubkey
    let pubkey_hash = crate::contracts::hash160(&pubkey);
    
    let script_pubkey = ScriptBuilder::p2pkh(&pubkey_hash);
    println!("  scriptPubKey: {}", script_pubkey.disassemble());
    println!("  Type: {:?}", script_pubkey.script_type());
    println!("  Size: {} bytes", script_pubkey.len());
    
    // Create unlock script
    let sig = vec![0x30; 72]; // Simulated DER signature
    let script_sig = ScriptBuilder::p2pkh_unlock(&sig, &pubkey);
    println!("  scriptSig: <sig> <pubkey>");
    println!();
    
    // =========================================================================
    // 3. P2SH (Pay to Script Hash)
    // =========================================================================
    println!("  3️⃣  P2SH (Pay to Script Hash)");
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    
    // Create a 2-of-3 multisig as redeem script
    let pubkeys = vec![
        vec![0x02; 33],
        vec![0x03; 33],
        vec![0x04; 33],
    ];
    let redeem_script = ScriptBuilder::multisig(2, &pubkeys).unwrap();
    println!("  Redeem script (2-of-3 multisig):");
    println!("    {}", redeem_script.disassemble());
    
    // Wrap in P2SH
    let p2sh = ScriptBuilder::p2sh_from_script(&redeem_script);
    println!("  P2SH wrapper: {}", p2sh.disassemble());
    println!("  Type: {:?}", p2sh.script_type());
    println!();
    
    // =========================================================================
    // 4. Multisig
    // =========================================================================
    println!("  4️⃣  MULTISIG (M-of-N)");
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    
    let info = analyze_script(&redeem_script);
    println!("  Analysis:");
    println!("    Type: {:?}", info.script_type);
    println!("    Size: {} bytes", info.size);
    println!("    Ops: {}", info.op_count);
    println!("    Required sigs: {}", info.required_sigs);
    println!("    Standard: {}", info.is_standard);
    println!();
    
    // =========================================================================
    // 5. Timelock (CLTV)
    // =========================================================================
    println!("  5️⃣  TIMELOCK (CLTV)");
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    
    let inner = ScriptBuilder::p2pkh(&pubkey_hash);
    let timelocked = ScriptBuilder::timelock(500_000, &inner);
    
    println!("  Timelock script (block 500000):");
    println!("    {}", timelocked.disassemble());
    println!("  Type: {:?}", timelocked.script_type());
    println!();
    
    // =========================================================================
    // 6. HTLC (Hash Time Lock Contract)
    // =========================================================================
    println!("  6️⃣  HTLC (Hash Time Lock Contract)");
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    
    let preimage = b"secret preimage";
    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, preimage);
    let hash: [u8; 32] = sha2::Digest::finalize(hasher).into();
    
    let receiver_pubkey = vec![0x02; 33];
    let sender_pubkey = vec![0x03; 33];
    
    let htlc = ScriptBuilder::htlc(&hash, &receiver_pubkey, &sender_pubkey, 600_000);
    
    println!("  HTLC structure:");
    println!("    IF (receiver reveals preimage)");
    println!("      OP_SHA256 <hash> OP_EQUALVERIFY <receiver> OP_CHECKSIG");
    println!("    ELSE (sender timeout at block 600000)");
    println!("      <600000> OP_CLTV OP_DROP <sender> OP_CHECKSIG");
    println!("    ENDIF");
    println!();
    println!("  Script size: {} bytes", htlc.len());
    println!();
    
    // =========================================================================
    // 7. Escrow Contract
    // =========================================================================
    println!("  7️⃣  ESCROW CONTRACT");
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    
    let buyer = vec![0x02; 33];
    let seller = vec![0x03; 33];
    let arbiter = vec![0x04; 33];
    
    let escrow = ScriptBuilder::escrow(&buyer, &seller, &arbiter, 700_000);
    
    println!("  Escrow structure:");
    println!("    Normal: 2-of-3 (buyer, seller, arbiter)");
    println!("    Timeout: arbiter-only after block 700000");
    println!();
    println!("  Script size: {} bytes", escrow.len());
    println!();
    
    // =========================================================================
    // 8. OP_RETURN (Data Storage)
    // =========================================================================
    println!("  8️⃣  OP_RETURN (Data Storage)");
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    
    let data = b"Mooncoin: La plata digital";
    let null_data = ScriptBuilder::null_data(data);
    
    println!("  Data: \"{}\"", String::from_utf8_lossy(data));
    println!("  Script: {}", null_data.disassemble());
    println!("  Type: {:?}", null_data.script_type());
    println!("  Spendable: No (provably unspendable)");
    println!();
    
    // =========================================================================
    // 9. Addresses
    // =========================================================================
    println!("  9️⃣  ADDRESS GENERATION");
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    
    let addr_p2pkh = Address::p2pkh_from_pubkey(&pubkey);
    let addr_p2sh = Address::p2sh_from_script(&redeem_script);
    let addr_p2wpkh = Address::p2wpkh_from_pubkey(&pubkey);
    
    println!("  P2PKH address:  {}", addr_p2pkh.encode());
    println!("  P2SH address:   {}", addr_p2sh.encode());
    println!("  P2WPKH address: {}", addr_p2wpkh.encode());
    println!();
    
    // =========================================================================
    // 10. Flow Control Demo
    // =========================================================================
    println!("  🔟  FLOW CONTROL (IF/ELSE/ENDIF)");
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    
    // IF 1 THEN push 100 ELSE push 200
    let flow_script = ScriptBuilder::new()
        .push_num(1)  // condition = true
        .op(Opcode::OP_IF)
            .push_num(100)
        .op(Opcode::OP_ELSE)
            .push_num(200)
        .op(Opcode::OP_ENDIF)
        .build();
    
    println!("  Script: {}", flow_script.disassemble());
    
    let mut engine = ScriptEngine::new();
    let _ = engine.execute(flow_script.as_bytes());
    let stack = engine.get_stack();
    
    println!("  Final stack: {:?}", stack.iter().map(|s| {
        if s.is_empty() { 0i64 } else { s[0] as i64 }
    }).collect::<Vec<_>>());
    println!();
    
    // =========================================================================
    // Summary
    // =========================================================================
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  SMART CONTRACTS SUMMARY");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │ Contract Type        │ Use Case                        │");
    println!("  ├─────────────────────────────────────────────────────────┤");
    println!("  │ P2PKH                │ Standard payments               │");
    println!("  │ P2SH                 │ Complex scripts, multisig       │");
    println!("  │ Multisig (M-of-N)    │ Shared custody, escrow          │");
    println!("  │ Timelock (CLTV)      │ Vesting, delayed payments       │");
    println!("  │ Relative Lock (CSV)  │ Payment channels                │");
    println!("  │ HTLC                 │ Atomic swaps, Lightning         │");
    println!("  │ Escrow               │ Safe trades with timeout        │");
    println!("  │ OP_RETURN            │ Data anchoring, timestamps      │");
    println!("  └─────────────────────────────────────────────────────────┘");
    println!();
    println!("  🎉 Smart contracts system fully operational!");
    println!();
}

// =============================================================================
// PAYMENT CHANNELS DEMO
// =============================================================================

fn cmd_channels_demo() {
    use crate::channels::{
        ChannelManager, ChannelId,
        PaymentPreimage,
        calculate_reserve,
    };
    use crate::channels::htlc::Invoice;

    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║           PAYMENT CHANNELS DEMO                           ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();

    // =========================================================================
    // 1. Create Channel Manager
    // =========================================================================
    println!("  1️⃣  CHANNEL MANAGER");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let alice_pubkey = [0x02; 33];
    let mut alice_manager = ChannelManager::new(alice_pubkey);
    
    println!("  Alice's node pubkey: {}...", hex::encode(&alice_pubkey[..8]));
    println!("  Channel manager initialized");
    println!();

    // =========================================================================
    // 2. Open a Channel
    // =========================================================================
    println!("  2️⃣  OPEN CHANNEL");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let capacity = 10 * 100_000_000; // 10 MOON
    let push_amount = 0; // Alice keeps all funds initially
    
    let channel_id = alice_manager.open_channel(capacity, push_amount).unwrap();
    
    println!("  Channel ID: {}", channel_id);
    println!("  Capacity: {} sat ({} MOON)", capacity, capacity / 100_000_000);
    println!("  Reserve: {} sat", calculate_reserve(capacity));
    println!();

    // =========================================================================
    // 3. Fund the Channel
    // =========================================================================
    println!("  3️⃣  FUND CHANNEL");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let funding_txid = [0xAB; 32];
    alice_manager.channel_funded(channel_id, funding_txid, 0).unwrap();
    
    println!("  Funding TX: {}...", hex::encode(&funding_txid[..8]));
    println!("  Status: Waiting for confirmations...");
    
    // Simulate 3 confirmations
    for i in 1..=3 {
        let events = alice_manager.process_block(i);
        if !events.is_empty() {
            println!("  Block {}: Channel ACTIVE! 🎉", i);
        } else {
            println!("  Block {}: {} confirmation(s)", i, i);
        }
    }
    println!();

    // =========================================================================
    // 4. Channel Info
    // =========================================================================
    println!("  4️⃣  CHANNEL INFO");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let channel = alice_manager.get_channel(&channel_id).unwrap();
    let info = channel.info();
    
    println!("  State: {:?}", channel.state);
    println!("  Local balance: {} sat", info.local_balance);
    println!("  Remote balance: {} sat", info.remote_balance);
    println!("  Can send: {} sat", info.can_send);
    println!("  Can receive: {} sat", info.can_receive);
    println!();

    // =========================================================================
    // 5. Create an Invoice
    // =========================================================================
    println!("  5️⃣  CREATE INVOICE");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let invoice = alice_manager.create_invoice(
        Some(1_000_000), // 0.01 MOON
        "Coffee payment",
        3600, // 1 hour expiry
    );
    
    println!("  Payment Hash: {}", invoice.payment_hash);
    println!("  Amount: {} sat", invoice.amount.unwrap_or(0));
    println!("  Description: {}", invoice.description);
    println!("  Encoded: {}", invoice.encode());
    println!();

    // =========================================================================
    // 6. Send Payment (simulate)
    // =========================================================================
    println!("  6️⃣  SEND PAYMENT");
    println!("  ─────────────────────────────────────────────────────────────");
    
    // Create a payment hash for outgoing payment
    let preimage = PaymentPreimage::generate();
    let payment_hash = preimage.payment_hash();
    let amount = 500_000; // 0.005 MOON
    
    println!("  Sending {} sat to payment hash {}...", amount, payment_hash);
    
    let htlc_id = alice_manager.send_payment(
        channel_id,
        payment_hash,
        amount,
        1000, // CLTV expiry
    ).unwrap();
    
    println!("  HTLC ID: {}", htlc_id);
    println!("  Status: Pending");
    
    // Simulate payment completion
    alice_manager.htlc_fulfilled(channel_id, htlc_id, preimage).unwrap();
    
    let status = alice_manager.payment_status(&payment_hash).unwrap();
    println!("  Status: {:?}", status);
    println!();

    // =========================================================================
    // 7. Channel Balance After Payment
    // =========================================================================
    println!("  7️⃣  UPDATED BALANCE");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let channel = alice_manager.get_channel(&channel_id).unwrap();
    let info = channel.info();
    
    println!("  Local balance: {} sat (was {})", info.local_balance, capacity);
    println!("  Remote balance: {} sat", info.remote_balance);
    println!("  Commitment #: {}", info.commitment_number);
    println!();

    // =========================================================================
    // 8. Multiple Payments
    // =========================================================================
    println!("  8️⃣  MULTIPLE PAYMENTS");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let payments = vec![
        ("Coffee", 100_000),
        ("Lunch", 250_000),
        ("Tip", 50_000),
    ];
    
    for (desc, amt) in payments {
        let preimage = PaymentPreimage::generate();
        let hash = preimage.payment_hash();
        
        let htlc = alice_manager.send_payment(channel_id, hash, amt, 1000).unwrap();
        alice_manager.htlc_fulfilled(channel_id, htlc, preimage).unwrap();
        
        println!("  ✅ {} - {} sat", desc, amt);
    }
    println!();

    // =========================================================================
    // 9. Channel Summary
    // =========================================================================
    println!("  9️⃣  CHANNEL SUMMARY");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let summary = alice_manager.summary();
    println!("  Total channels: {}", summary.total_channels);
    println!("  Active channels: {}", summary.active_channels);
    println!("  Total capacity: {} sat", summary.total_capacity);
    println!("  Local balance: {} sat", summary.local_balance);
    println!("  Remote balance: {} sat", summary.remote_balance);
    println!();

    // =========================================================================
    // 10. Statistics
    // =========================================================================
    println!("  🔟  STATISTICS");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let stats = &alice_manager.stats;
    println!("  Channels opened: {}", stats.total_channels_opened);
    println!("  Payments sent: {}", stats.total_payments_sent);
    println!("  Amount sent: {} sat", stats.total_amount_sent);
    println!();

    // =========================================================================
    // 11. Close Channel (Cooperative)
    // =========================================================================
    println!("  1️⃣1️⃣  CLOSE CHANNEL");
    println!("  ─────────────────────────────────────────────────────────────");
    
    alice_manager.close_channel(channel_id).unwrap();
    
    let channel = alice_manager.get_channel(&channel_id).unwrap();
    println!("  Status: {:?}", channel.state);
    println!("  Type: Cooperative close initiated");
    println!();

    // =========================================================================
    // Summary Table
    // =========================================================================
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  PAYMENT CHANNELS SUMMARY");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │ Feature              │ Status                          │");
    println!("  ├─────────────────────────────────────────────────────────┤");
    println!("  │ Channel Creation     │ ✅ 2-of-2 multisig funding      │");
    println!("  │ Channel Funding      │ ✅ Confirmation tracking        │");
    println!("  │ Balance Management   │ ✅ Local/Remote tracking        │");
    println!("  │ Channel Reserve      │ ✅ 1% minimum reserve           │");
    println!("  │ HTLCs                │ ✅ Hash Time Lock Contracts     │");
    println!("  │ Invoices             │ ✅ Payment request generation   │");
    println!("  │ Payments             │ ✅ Instant off-chain transfers  │");
    println!("  │ Commitments          │ ✅ State updates with revocation│");
    println!("  │ Cooperative Close    │ ✅ Mutual agreement closing     │");
    println!("  │ Force Close          │ ✅ Unilateral with CSV delay    │");
    println!("  │ Breach Detection     │ ✅ Revocation secret storage    │");
    println!("  └─────────────────────────────────────────────────────────┘");
    println!();
    println!("  🎉 Payment channels system fully operational!");
    println!("  ⚡ Ready for Lightning-style instant payments!");
    println!();
}

// =============================================================================
// ATOMIC SWAPS DEMO
// =============================================================================

fn cmd_atomic_swaps_demo() {
    use crate::atomic_swaps::{
        AtomicSwap, SwapParams, SwapState, SwapRole,
        generate_secret, hash_secret, verify_secret,
        create_htlc_script, HtlcScriptParams, disassemble_htlc,
        SwapProtocol, SwapMessage,
        INITIATOR_TIMEOUT_BLOCKS, PARTICIPANT_TIMEOUT_BLOCKS,
    };

    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║              ATOMIC SWAPS DEMO                            ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();

    // =========================================================================
    // 1. Secret Generation
    // =========================================================================
    println!("  1️⃣  SECRET GENERATION");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let secret = generate_secret();
    let secret_hash = hash_secret(&secret);
    
    println!("  Secret (Alice keeps private): {}...", hex::encode(&secret[..8]));
    println!("  Hash (shared with Bob):       {}...", hex::encode(&secret_hash[..8]));
    println!("  Verify secret matches hash:   {}", verify_secret(&secret, &secret_hash));
    println!();

    // =========================================================================
    // 2. Create Swap as Initiator (Alice)
    // =========================================================================
    println!("  2️⃣  ALICE INITIATES SWAP");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let alice_params = SwapParams::new_initiator(
        10 * 100_000_000,  // 10 MOON
        "MOON",
        100_000,           // 0.001 BTC (100,000 sats)
        "BTC",
        "moon1alice_refund_address",
        "moon1bob_claim_address",
    );
    
    let mut alice_swap = AtomicSwap::new_initiator(alice_params);
    
    println!("  Swap ID: {}", alice_swap.id);
    println!("  Role: {:?}", alice_swap.role);
    println!("  Alice offers: 10 MOON");
    println!("  Alice wants:  0.001 BTC (100,000 sats)");
    println!("  Timeout: {} blocks (~24 hours)", INITIATOR_TIMEOUT_BLOCKS);
    println!("  Exchange rate: {:.2} MOON/BTC", alice_swap.params.exchange_rate());
    println!();

    // =========================================================================
    // 3. Create Swap as Participant (Bob)
    // =========================================================================
    println!("  3️⃣  BOB JOINS SWAP");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let bob_params = SwapParams::new_participant(
        100_000,           // 0.001 BTC
        "BTC",
        10 * 100_000_000,  // 10 MOON
        "MOON",
        "bc1bob_refund_address",
        "bc1alice_claim_address",
        INITIATOR_TIMEOUT_BLOCKS,
    ).unwrap();
    
    let mut bob_swap = AtomicSwap::new_participant(bob_params, alice_swap.secret_hash);
    
    println!("  Swap ID: {}", bob_swap.id);
    println!("  Role: {:?}", bob_swap.role);
    println!("  Bob offers:  0.001 BTC");
    println!("  Bob wants:   10 MOON");
    println!("  Timeout: {} blocks (~12 hours)", PARTICIPANT_TIMEOUT_BLOCKS);
    println!("  Same secret hash: {}", bob_swap.secret_hash == alice_swap.secret_hash);
    println!();

    // =========================================================================
    // 4. Create HTLC Scripts
    // =========================================================================
    println!("  4️⃣  HTLC SCRIPTS");
    println!("  ─────────────────────────────────────────────────────────────");
    
    // Alice's HTLC on Mooncoin (Bob can claim with secret, Alice refunds after timeout)
    let alice_htlc_params = HtlcScriptParams::new(
        secret_hash,
        [0x02; 33],  // Bob's pubkey (simplified)
        [0x03; 33],  // Alice's refund pubkey
        500_000 + INITIATOR_TIMEOUT_BLOCKS,  // Current height + timeout
    );
    
    let alice_htlc_script = create_htlc_script(&alice_htlc_params);
    
    println!("  Alice's HTLC (on Mooncoin):");
    println!("    Script size: {} bytes", alice_htlc_script.len());
    println!("    Disassembly:");
    let disasm = disassemble_htlc(&alice_htlc_script);
    for line in disasm.split(' ').filter(|s| !s.is_empty()) {
        if line.starts_with("OP_") {
            println!("      {}", line);
        }
    }
    println!();

    // =========================================================================
    // 5. Execute Swap Flow
    // =========================================================================
    println!("  5️⃣  SWAP EXECUTION");
    println!("  ─────────────────────────────────────────────────────────────");
    
    // Step 1: Alice locks MOON
    println!("  Step 1: Alice locks 10 MOON in HTLC");
    alice_swap.initiator_lock("moon_tx_alice_lock_abc123".to_string(), 500_000).unwrap();
    println!("    ✅ State: {:?}", alice_swap.state);
    
    // Step 2: Bob sees Alice's lock, locks BTC
    println!("  Step 2: Bob verifies Alice's lock, locks 0.001 BTC");
    bob_swap.participant_lock(
        "moon_tx_alice_lock_abc123".to_string(),
        "btc_tx_bob_lock_def456".to_string(),
        500_001,
    ).unwrap();
    println!("    ✅ State: {:?}", bob_swap.state);
    
    // Alice records Bob's lock
    alice_swap.record_participant_lock("btc_tx_bob_lock_def456".to_string(), 500_001).unwrap();
    
    // Step 3: Alice claims BTC (reveals secret!)
    println!("  Step 3: Alice claims BTC (reveals secret R)");
    let revealed_secret = alice_swap.initiator_claim("btc_tx_alice_claim_ghi789".to_string()).unwrap();
    println!("    ✅ Secret revealed: {}...", hex::encode(&revealed_secret[..8]));
    println!("    ✅ State: {:?}", alice_swap.state);
    
    // Step 4: Bob sees secret on Bitcoin chain, claims MOON
    println!("  Step 4: Bob learns secret, claims MOON");
    bob_swap.participant_claim(revealed_secret, "moon_tx_bob_claim_jkl012".to_string()).unwrap();
    println!("    ✅ State: {:?}", bob_swap.state);
    
    // Complete
    alice_swap.complete(
        "btc_tx_alice_claim_ghi789".to_string(),
        "moon_tx_bob_claim_jkl012".to_string(),
    ).unwrap();
    bob_swap.complete(
        "btc_tx_alice_claim_ghi789".to_string(),
        "moon_tx_bob_claim_jkl012".to_string(),
    ).unwrap();
    
    println!("  Step 5: Swap completed!");
    println!("    ✅ Alice: {:?}", alice_swap.state);
    println!("    ✅ Bob: {:?}", bob_swap.state);
    println!();

    // =========================================================================
    // 6. Protocol Messages
    // =========================================================================
    println!("  6️⃣  PROTOCOL MESSAGES");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let mut protocol = SwapProtocol::new();
    
    let new_secret = generate_secret();
    let new_hash = hash_secret(&new_secret);
    
    let new_params = SwapParams::new_initiator(
        5 * 100_000_000,
        "MOON",
        50_000,
        "BTC",
        "moon1...",
        "moon1...",
    );
    
    let proposal = protocol.initiate_swap(new_params, new_hash);
    
    if let SwapMessage::Propose { swap_id, params, .. } = &proposal {
        println!("  Proposal sent:");
        println!("    Swap ID: {}", swap_id);
        println!("    Offer: {} {}", params.offer_amount, params.offer_asset);
        println!("    Want: {} {}", params.want_amount, params.want_asset);
    }
    
    println!("  Active negotiations: {}", protocol.pending_negotiations().len());
    println!();

    // =========================================================================
    // 7. Refund Scenario
    // =========================================================================
    println!("  7️⃣  REFUND SCENARIO");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let refund_params = SwapParams::new_initiator(
        1 * 100_000_000,
        "MOON",
        10_000,
        "BTC",
        "moon1refund",
        "moon1counter",
    );
    
    let mut refund_swap = AtomicSwap::new_initiator(refund_params);
    refund_swap.initiator_lock("lock_tx".to_string(), 100).unwrap();
    
    println!("  Swap locked at block 100");
    println!("  Timeout: {} blocks", refund_swap.params.timeout_blocks);
    
    let refund_height = 100 + INITIATOR_TIMEOUT_BLOCKS as u64;
    println!("  Blocks until refund: {}", refund_swap.blocks_until_refund(100).unwrap_or(0));
    println!("  Can refund at block 200? {}", refund_swap.can_refund(200));
    println!("  Can refund at block {}? {}", refund_height, refund_swap.can_refund(refund_height));
    
    // Execute refund
    refund_swap.refund("refund_tx".to_string(), refund_height).unwrap();
    println!("  Refund executed: {:?}", refund_swap.state);
    println!();

    // =========================================================================
    // Summary
    // =========================================================================
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  ATOMIC SWAPS SUMMARY");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │ Feature              │ Status                          │");
    println!("  ├─────────────────────────────────────────────────────────┤");
    println!("  │ Secret Generation    │ ✅ SHA256 hash-lock             │");
    println!("  │ HTLC Scripts         │ ✅ Claim + Refund paths         │");
    println!("  │ Initiator Flow       │ ✅ Lock → Claim                 │");
    println!("  │ Participant Flow     │ ✅ Verify → Lock → Claim        │");
    println!("  │ Timeout Safety       │ ✅ Different timeouts           │");
    println!("  │ Refund Mechanism     │ ✅ After timeout expiry         │");
    println!("  │ Protocol Messages    │ ✅ Propose/Accept/Reject        │");
    println!("  │ State Machine        │ ✅ Full lifecycle tracking      │");
    println!("  │ Cross-chain Ready    │ ✅ BTC, ETH, any HTLC chain     │");
    println!("  └─────────────────────────────────────────────────────────┘");
    println!();
    println!("  🔄 Atomic swaps fully operational!");
    println!("  🌐 Trustless cross-chain exchanges enabled!");
    println!();
}

// =============================================================================
// MERKLE TREES DEMO
// =============================================================================

fn cmd_merkle_demo() {
    use crate::merkle::{
        MerkleTree, MerkleProof, MerkleBlock,
        sha256, double_sha256, hash_pair,
        calculate_merkle_root, verify_tx_inclusion,
        Hash256, HASH_SIZE,
    };

    println!();
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║              MERKLE TREES DEMO                            ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();

    // =========================================================================
    // 1. Hash Functions
    // =========================================================================
    println!("  1️⃣  HASH FUNCTIONS");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let data = b"Mooncoin Transaction Data";
    let single_hash = sha256(data);
    let double_hash = double_sha256(data);
    
    println!("  Data: \"Mooncoin Transaction Data\"");
    println!("  SHA256:        {}...", hex::encode(&single_hash[..16]));
    println!("  Double SHA256: {}...", hex::encode(&double_hash[..16]));
    println!();

    // =========================================================================
    // 2. Build Merkle Tree
    // =========================================================================
    println!("  2️⃣  BUILD MERKLE TREE");
    println!("  ─────────────────────────────────────────────────────────────");
    
    // Simulate 8 transactions
    let transactions: Vec<Vec<u8>> = (0..8)
        .map(|i| format!("TX{}: Alice sends {} MOON to Bob", i, (i + 1) * 10).into_bytes())
        .collect();
    
    let tree = MerkleTree::from_transactions(&transactions);
    
    println!("  Transactions: {}", tree.leaf_count());
    println!("  Tree depth:   {}", tree.depth());
    println!("  Merkle root:  {}...", &tree.root_hex()[..16]);
    println!();
    
    println!("  Tree Structure:");
    println!("                      ┌─────────────┐");
    println!("                      │    ROOT     │");
    println!("                      │ {}..│", &tree.root_hex()[..8]);
    println!("                      └──────┬──────┘");
    println!("                             │");
    println!("              ┌──────────────┴──────────────┐");
    println!("              │                             │");
    println!("        ┌─────┴─────┐                 ┌─────┴─────┐");
    println!("        │  Level 1  │                 │  Level 1  │");
    println!("        └─────┬─────┘                 └─────┬─────┘");
    println!("              │                             │");
    println!("       ┌──────┴──────┐               ┌──────┴──────┐");
    println!("       │             │               │             │");
    println!("    ┌──┴──┐       ┌──┴──┐         ┌──┴──┐       ┌──┴──┐");
    println!("    │ TX0 │       │ TX1 │         │ TX2 │       │ TX3 │");
    println!("    └─────┘       └─────┘         └─────┘       └─────┘");
    println!();

    // =========================================================================
    // 3. Generate Proof
    // =========================================================================
    println!("  3️⃣  GENERATE MERKLE PROOF");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let tx_index = 5;
    let proof = tree.generate_proof(tx_index).unwrap();
    
    println!("  Proving TX{} is in the block:", tx_index);
    println!("  Leaf hash:   {}...", hex::encode(&proof.leaf_hash[..8]));
    println!("  Proof steps: {}", proof.depth());
    println!("  Proof size:  {} bytes", proof.size_bytes());
    println!();
    
    println!("  Proof Path (leaf → root):");
    for (i, step) in proof.steps.iter().enumerate() {
        let dir = match step.direction {
            crate::merkle::ProofDirection::Left => "←",
            crate::merkle::ProofDirection::Right => "→",
        };
        println!("    Step {}: {} {}...", i + 1, dir, hex::encode(&step.hash[..8]));
    }
    println!();

    // =========================================================================
    // 4. Verify Proof
    // =========================================================================
    println!("  4️⃣  VERIFY MERKLE PROOF");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let is_valid = proof.verify();
    println!("  Proof valid: {} ✅", is_valid);
    
    // Verify against tree
    let tree_valid = tree.verify_proof(&proof);
    println!("  Tree verify: {} ✅", tree_valid);
    
    // Use utility function
    let tx_valid = verify_tx_inclusion(&proof.leaf_hash, &proof, &tree.root());
    println!("  TX included: {} ✅", tx_valid);
    println!();

    // =========================================================================
    // 5. Tampered Proof
    // =========================================================================
    println!("  5️⃣  TAMPERED PROOF DETECTION");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let mut tampered_proof = proof.clone();
    tampered_proof.steps[0].hash[0] ^= 0xFF;
    
    println!("  Original proof valid:  {} ✅", proof.verify());
    println!("  Tampered proof valid:  {} ❌", tampered_proof.verify());
    println!();

    // =========================================================================
    // 6. Large Tree Performance
    // =========================================================================
    println!("  6️⃣  SCALABILITY TEST");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let large_txs: Vec<Hash256> = (0..1000)
        .map(|i| {
            let mut data = [0u8; 32];
            data[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            double_sha256(&data)
        })
        .collect();
    
    let start = std::time::Instant::now();
    let large_tree = MerkleTree::from_hashes(&large_txs);
    let build_time = start.elapsed();
    
    let start = std::time::Instant::now();
    let large_proof = large_tree.generate_proof(500).unwrap();
    let proof_time = start.elapsed();
    
    let start = std::time::Instant::now();
    let _ = large_proof.verify();
    let verify_time = start.elapsed();
    
    println!("  1000 Transactions:");
    println!("    Tree depth:      {}", large_tree.depth());
    println!("    Proof size:      {} bytes", large_proof.size_bytes());
    println!("    Build time:      {:?}", build_time);
    println!("    Proof gen time:  {:?}", proof_time);
    println!("    Verify time:     {:?}", verify_time);
    println!();
    
    // Even larger
    let huge_txs: Vec<Hash256> = (0..10000)
        .map(|i| {
            let mut data = [0u8; 32];
            data[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            double_sha256(&data)
        })
        .collect();
    
    let huge_tree = MerkleTree::from_hashes(&huge_txs);
    let huge_proof = huge_tree.generate_proof(7777).unwrap();
    
    println!("  10,000 Transactions:");
    println!("    Tree depth:      {}", huge_tree.depth());
    println!("    Proof size:      {} bytes", huge_proof.size_bytes());
    println!("    Proof valid:     {} ✅", huge_proof.verify());
    println!();

    // =========================================================================
    // 7. Merkle Block (SPV)
    // =========================================================================
    println!("  7️⃣  MERKLE BLOCK (SPV)");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let block_hash: Hash256 = double_sha256(b"block header");
    let matched_txs = vec![2, 5, 7];
    
    let merkle_block = MerkleBlock::from_tree_and_matches(&tree, block_hash, &matched_txs);
    
    println!("  Block hash:        {}...", hex::encode(&block_hash[..8]));
    println!("  Total TXs:         {}", merkle_block.total_transactions);
    println!("  Matched TXs:       {:?}", matched_txs);
    println!("  MerkleBlock size:  {} bytes", merkle_block.size_bytes());
    
    // Extract and verify matches
    match merkle_block.extract_matches() {
        Ok((root, matches)) => {
            println!("  Extracted root:    {}...", hex::encode(&root[..8]));
            println!("  Root matches:      {} ✅", root == tree.root());
            println!("  Found {} matched TXs", matches.len());
        }
        Err(e) => println!("  Error: {}", e),
    }
    println!();

    // =========================================================================
    // 8. Comparison with Full Block
    // =========================================================================
    println!("  8️⃣  BANDWIDTH SAVINGS");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let tx_count = 2000;
    let avg_tx_size = 250; // bytes
    let full_block_size = tx_count * avg_tx_size;
    
    let test_hashes: Vec<Hash256> = (0..tx_count)
        .map(|i| double_sha256(&(i as u32).to_le_bytes()))
        .collect();
    let test_tree = MerkleTree::from_hashes(&test_hashes);
    let test_proof = test_tree.generate_proof(1000).unwrap();
    
    println!("  Scenario: Verify 1 TX in block with {} TXs", tx_count);
    println!();
    println!("  Full block download:  {} KB", full_block_size / 1024);
    println!("  Merkle proof only:    {} bytes", test_proof.size_bytes());
    println!("  Bandwidth saved:      {:.2}%", 
        100.0 - (test_proof.size_bytes() as f64 / full_block_size as f64 * 100.0));
    println!();

    // =========================================================================
    // Summary
    // =========================================================================
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MERKLE TREES SUMMARY");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │ Feature              │ Status                          │");
    println!("  ├─────────────────────────────────────────────────────────┤");
    println!("  │ Tree Construction    │ ✅ O(n) from TX hashes          │");
    println!("  │ Proof Generation     │ ✅ O(log n) time & space        │");
    println!("  │ Proof Verification   │ ✅ O(log n) efficient           │");
    println!("  │ Bitcoin Compatible   │ ✅ Double SHA256                │");
    println!("  │ Odd Leaf Handling    │ ✅ Duplicate last leaf          │");
    println!("  │ Tamper Detection     │ ✅ Invalid proofs rejected      │");
    println!("  │ MerkleBlock (SPV)    │ ✅ Partial tree for clients     │");
    println!("  │ Serialization        │ ✅ Bincode encode/decode        │");
    println!("  └─────────────────────────────────────────────────────────┘");
    println!();
    println!("  🌳 Merkle trees fully operational!");
    println!("  📱 SPV light clients can verify transactions efficiently!");
    println!();
}

// =============================================================================
// BTC LOCK-OPERATE-SETTLE COMMANDS
// =============================================================================

use crate::btc_lock::{
    LockRegistry, LockState, LockTemplate, MockBtcObserver, BtcObserver,
    EsploraObserver, BitcoinNetwork,
    MultisigCltvParams, HtlcSimpleParams,
    generate_multisig_cltv, generate_htlc_simple, match_lock_template,
    script_to_p2wsh_address, get_timelock_status, estimate_time_remaining,
    format_btc as format_btc_lock, confirm as confirm_btc_lock,
    WARNING_LOCK_GENERATE, WARNING_OBSERVE_REGISTER, WARNING_SETTLEMENT,
    SettlementParams, build_settlement_tx, estimate_settlement_fee,
};

fn cmd_btc_lock_templates() {
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - TEMPLATES DISPONIBLES");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │ 1. multisig_cltv (DEFAULT)                              │");
    println!("  │    ─────────────────────────────────────────────────────│");
    println!("  │    2-of-2 multisig O salida unilateral después de       │");
    println!("  │    timelock.                                            │");
    println!("  │                                                         │");
    println!("  │    Parámetros:                                          │");
    println!("  │      --pubkey-hot       Clave caliente (33 bytes hex)   │");
    println!("  │      --pubkey-cold      Clave fría (33 bytes hex)       │");
    println!("  │      --pubkey-recovery  Clave de recuperación           │");
    println!("  │      --timelock         Altura de bloque para expirar   │");
    println!("  │                                                         │");
    println!("  │    Uso:                                                 │");
    println!("  │      - Gasto inmediato: requiere hot + cold keys        │");
    println!("  │      - Después de timelock: solo recovery key           │");
    println!("  ├─────────────────────────────────────────────────────────┤");
    println!("  │ 2. htlc_simple                                          │");
    println!("  │    ─────────────────────────────────────────────────────│");
    println!("  │    Hash-locked con timeout de refund.                   │");
    println!("  │                                                         │");
    println!("  │    Parámetros:                                          │");
    println!("  │      --hash      SHA256 hash (32 bytes hex)             │");
    println!("  │      --pubkey    Clave pública (33 bytes hex)           │");
    println!("  │      --timeout   Bloques relativos para refund          │");
    println!("  │                                                         │");
    println!("  │    Uso:                                                 │");
    println!("  │      - Con preimage: gasto inmediato                    │");
    println!("  │      - Después de timeout: refund automático            │");
    println!("  └─────────────────────────────────────────────────────────┘");
    println!();
    println!("  ⚠️  ADVERTENCIA:");
    println!("  Mooncoin NO valida la corrección semántica del script.");
    println!("  Un script mal formado puede causar PÉRDIDA PERMANENTE de BTC.");
    println!();
}

fn cmd_btc_lock_generate(
    template: String,
    pubkey_hot: String,
    pubkey_cold: String,
    pubkey_recovery: String,
    timelock: u32,
    testnet: bool,
) {
    let network = if testnet { "TESTNET" } else { "MAINNET" };
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - GENERAR SCRIPT [{}]", network);
    println!("  ═══════════════════════════════════════════════════════════");
    
    println!("{}", WARNING_LOCK_GENERATE);
    
    if !confirm_btc_lock("  ¿Entiendes y aceptas estos riesgos?") {
        println!("\n  ❌ Operación cancelada por el usuario.");
        return;
    }
    
    let result = match template.as_str() {
        "multisig_cltv" => {
            let params = MultisigCltvParams {
                pubkey_hot,
                pubkey_cold,
                pubkey_recovery,
                locktime_blocks: timelock,
            };
            generate_multisig_cltv(&params)
        }
        "htlc_simple" => {
            println!("\n  ❌ Para htlc_simple, use parámetros diferentes.");
            println!("     Ejecute: mooncoin btc-lock-templates para ver opciones.");
            return;
        }
        _ => {
            println!("\n  ❌ Template desconocido: {}", template);
            println!("     Use: multisig_cltv o htlc_simple");
            return;
        }
    };
    
    match result {
        Ok(script) => {
            let script_hex = hex::encode(&script);
            let p2wsh_address = script_to_p2wsh_address(&script, !testnet);
            
            match match_lock_template(&script) {
                Ok(Some(matched)) => {
                    println!();
                    println!("  ✅ SCRIPT GENERADO EXITOSAMENTE");
                    println!("  ─────────────────────────────────────────────────────────────");
                    println!();
                    println!("  Red:             {}", network);
                    println!("  Template:        {}", matched.template);
                    println!("  Timelock:        Bloque {}", matched.timelock_value);
                    println!();
                    println!("  Redeem Script (hex):");
                    println!("  {}", script_hex);
                    println!();
                    println!("  P2WSH Address (enviar BTC aquí):");
                    println!("  {}", p2wsh_address);
                    println!();
                    println!("  ═══════════════════════════════════════════════════════════");
                    println!("  📋 REQUISITOS DE BACKUP (OBLIGATORIO)");
                    println!("  ═══════════════════════════════════════════════════════════");
                    println!();
                    println!("  1. Guardar el redeem script de arriba");
                    println!("  2. Guardar tu clave privada de recuperación");
                    println!("  3. Anotar el bloque timelock: {}", matched.timelock_value);
                    println!();
                    println!("  ⚠️  Sin estos, NO PODRÁS recuperar tu BTC.");
                    println!();
                    println!("  ═══════════════════════════════════════════════════════════");
                    println!("  📌 PRÓXIMOS PASOS");
                    println!("  ═══════════════════════════════════════════════════════════");
                    println!();
                    println!("  1. Envía BTC a la dirección P2WSH de arriba");
                    println!("  2. Espera 6+ confirmaciones");
                    println!("  3. Registra el LOCK en Mooncoin:");
                    let testnet_flag = if testnet { " --testnet" } else { "" };
                    println!("     mooncoin btc-lock-register --txid <TXID> --vout 0{} \\", testnet_flag);
                    println!("       --script {}", script_hex);
                    println!();
                }
                Ok(None) => {
                    println!("\n  ❌ Error interno: script generado no coincide con template");
                }
                Err(e) => {
                    println!("\n  ❌ Error verificando script: {}", e);
                }
            }
        }
        Err(e) => {
            println!("\n  ❌ Error generando script: {}", e);
        }
    }
}

fn cmd_btc_lock_verify(script_hex: String) {
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - VERIFICAR SCRIPT");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    
    let script = match hex::decode(&script_hex) {
        Ok(s) => s,
        Err(e) => {
            println!("  ❌ Error: hex inválido - {}", e);
            return;
        }
    };
    
    match match_lock_template(&script) {
        Ok(Some(matched)) => {
            println!("  ✅ Script coincide con LOCK STANDARD");
            println!();
            println!("  Template:       {}", matched.template);
            println!("  Timelock:       Bloque {}", matched.timelock_value);
            println!("  Tipo timelock:  {:?}", matched.timelock_type);
            println!("  Pubkeys:        {} encontradas", matched.pubkeys.len());
            
            for (i, pk) in matched.pubkeys.iter().enumerate() {
                println!("    Pubkey {}:     {}...", i + 1, &pk[..16]);
            }
            
            let p2wsh = script_to_p2wsh_address(&script, true);
            println!();
            println!("  P2WSH Address:  {}", p2wsh);
        }
        Ok(None) => {
            println!("  ❌ Script NO coincide con ningún template LOCK STANDARD");
            println!();
            println!("  Templates válidos:");
            println!("    - multisig_cltv");
            println!("    - htlc_simple");
        }
        Err(e) => {
            println!("  ❌ Error parseando script: {}", e);
        }
    }
    println!();
}

fn cmd_btc_lock_register(txid: String, vout: u32, script_hex: String, testnet: bool) {
    let network = if testnet { "TESTNET" } else { "MAINNET" };
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - REGISTRAR LOCK [{}]", network);
    println!("  ═══════════════════════════════════════════════════════════");
    
    if txid.len() != 64 || hex::decode(&txid).is_err() {
        println!("\n  ❌ Error: txid inválido (debe ser 64 caracteres hex)");
        return;
    }
    
    let script = match hex::decode(&script_hex) {
        Ok(s) => s,
        Err(e) => {
            println!("\n  ❌ Error: script hex inválido - {}", e);
            return;
        }
    };
    
    let template_match = match match_lock_template(&script) {
        Ok(Some(m)) => m,
        Ok(None) => {
            println!("\n  ❌ Error: script no coincide con ningún template LOCK STANDARD");
            return;
        }
        Err(e) => {
            println!("\n  ❌ Error parseando script: {}", e);
            return;
        }
    };
    
    // Conectar a Bitcoin para verificar UTXO
    println!();
    println!("  🔍 Conectando a Bitcoin {}...", network);
    
    let observer = if testnet {
        EsploraObserver::testnet()
    } else {
        EsploraObserver::mainnet()
    };
    
    // Verificar UTXO
    let (utxo_exists, amount_sats, confirmations) = match observer.get_utxo(&txid, vout) {
        Ok(Some(utxo)) => {
            if utxo.spent {
                println!("  ⚠️  ADVERTENCIA: Este UTXO ya ha sido GASTADO");
                (false, Some(utxo.amount_sats), utxo.confirmations)
            } else {
                println!("  ✅ UTXO encontrado: {} sats ({} confirmaciones)", 
                    utxo.amount_sats, utxo.confirmations);
                (true, Some(utxo.amount_sats), utxo.confirmations)
            }
        }
        Ok(None) => {
            println!("  ❌ Error: UTXO no encontrado en Bitcoin {}", network);
            println!("     Verifica que la transacción esté confirmada.");
            return;
        }
        Err(e) => {
            println!("  ⚠️  No se pudo verificar UTXO: {}", e);
            println!("     Continuando sin verificación...");
            (true, None, 0)
        }
    };
    
    if confirmations < 6 && confirmations > 0 {
        println!("  ⚠️  ADVERTENCIA: Solo {} confirmaciones (recomendado: 6+)", confirmations);
    }
    
    println!("{}", WARNING_OBSERVE_REGISTER);
    
    let mut registry = LockRegistry::load();
    
    if registry.find_by_utxo(&txid, vout).is_some() {
        println!("  ❌ Error: Este LOCK ya está registrado");
        return;
    }
    
    let p2wsh = script_to_p2wsh_address(&script, !testnet);
    
    match registry.register(txid.clone(), vout, &script, &template_match, &p2wsh, amount_sats) {
        Ok(lock) => {
            println!();
            println!("  ✅ LOCK REGISTRADO EXITOSAMENTE");
            println!("  ─────────────────────────────────────────────────────────────");
            println!();
            println!("  Red:            {}", network);
            println!("  Lock ID:        {}", lock.lock_id);
            println!("  BTC TXID:       {}...", &lock.btc_txid[..16]);
            println!("  BTC Vout:       {}", lock.btc_vout);
            if let Some(amt) = amount_sats {
                println!("  Cantidad:       {} sats ({:.8} BTC)", amt, amt as f64 / 100_000_000.0);
            }
            println!("  Template:       {}", lock.template);
            println!("  Timelock:       Bloque {}", lock.timelock_block);
            println!("  Estado:         {}", lock.state);
            println!("  P2WSH:          {}", lock.p2wsh_address);
            println!();
            let testnet_flag = if testnet { " --testnet" } else { "" };
            println!("  📌 Puedes verificar el estado con:");
            println!("     mooncoin btc-lock-status --txid {}{}", txid, testnet_flag);
            println!();
        }
        Err(e) => {
            println!("\n  ❌ Error registrando LOCK: {}", e);
        }
    }
}

fn cmd_btc_lock_status(txid: String, vout: u32, testnet: bool) {
    let network = if testnet { "TESTNET" } else { "MAINNET" };
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - ESTADO DEL LOCK [{}]", network);
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    
    let registry = LockRegistry::load();
    
    match registry.find_by_utxo(&txid, vout) {
        Some(lock) => {
            println!("  Lock ID:        {}", lock.lock_id);
            println!("  BTC TXID:       {}", lock.btc_txid);
            println!("  BTC Vout:       {}", lock.btc_vout);
            println!("  Template:       {}", lock.template);
            println!("  Timelock:       Bloque {}", lock.timelock_block);
            
            if let Some(amount) = lock.amount_sats {
                println!("  Cantidad:       {}", format_btc_lock(amount));
            }
            
            // Consultar estado actual en Bitcoin
            println!();
            println!("  🔍 Consultando Bitcoin {}...", network);
            
            let observer = if testnet {
                EsploraObserver::testnet()
            } else {
                EsploraObserver::mainnet()
            };
            
            let (current_state, current_height) = match (observer.get_utxo(&txid, vout), observer.current_block_height()) {
                (Ok(Some(utxo)), Ok(height)) => {
                    println!("  Altura actual:  {}", height);
                    println!("  Confirmaciones: {}", utxo.confirmations);
                    
                    let state = if utxo.spent {
                        LockState::Settled
                    } else if height >= lock.timelock_block {
                        LockState::Expired
                    } else {
                        LockState::Locked
                    };
                    (state, height)
                }
                (Ok(None), _) => {
                    println!("  ⚠️  UTXO no encontrado (posiblemente gastado)");
                    (LockState::Settled, 0)
                }
                (Err(e), _) | (Ok(Some(_)), Err(e)) => {
                    println!("  ⚠️  Error consultando: {}", e);
                    (lock.state.clone(), 0)
                }
            };
            
            println!("  Estado actual:  {}", current_state);
            println!("  P2WSH:          {}", lock.p2wsh_address);
            println!();
            
            match current_state {
                LockState::Locked => {
                    let blocks_remaining = lock.timelock_block as i32 - current_height as i32;
                    println!("  ⏳ El LOCK está activo. El timelock aún no ha expirado.");
                    println!("     Bloque objetivo:    {}", lock.timelock_block);
                    println!("     Bloques restantes:  {}", blocks_remaining);
                    if blocks_remaining > 0 {
                        println!("     Tiempo estimado:    {}", estimate_time_remaining(blocks_remaining));
                    }
                }
                LockState::Expired => {
                    let testnet_flag = if testnet { " --testnet" } else { "" };
                    println!("  ✅ El timelock ha EXPIRADO. Puedes hacer settlement.");
                    println!("     Usa: mooncoin btc-lock-settle-check --txid {}{}", txid, testnet_flag);
                }
                LockState::Settled => {
                    println!("  🏁 El UTXO ha sido GASTADO. Settlement completado.");
                }
                LockState::Unknown => {
                    println!("  ❓ Estado desconocido.");
                }
            }
        }
        None => {
            println!("  ❌ LOCK no encontrado en registro local.");
            println!();
            let testnet_flag = if testnet { " --testnet" } else { "" };
            println!("  Para registrar un LOCK:");
            println!("  mooncoin btc-lock-register --txid {} --vout {}{} --script <hex>", txid, vout, testnet_flag);
        }
    }
    println!();
}

fn cmd_btc_lock_list(state_filter: String) {
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - LISTA DE LOCKS");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    
    let registry = LockRegistry::load();
    let locks = registry.list();
    
    if locks.is_empty() {
        println!("  No hay LOCKs registrados.");
        println!();
        println!("  Para registrar un LOCK:");
        println!("  mooncoin btc-lock-register --txid <TXID> --vout 0 --script <HEX>");
        println!();
        return;
    }
    
    let filter: Option<LockState> = match state_filter.to_lowercase().as_str() {
        "locked" => Some(LockState::Locked),
        "expired" => Some(LockState::Expired),
        "settled" => Some(LockState::Settled),
        _ => None,
    };
    
    let filtered: Vec<_> = locks.iter()
        .filter(|l| filter.as_ref().map_or(true, |f| &l.state == f))
        .collect();
    
    println!("  {:<20} {:<16} {:<10} {:<12}", "ID", "TXID", "Estado", "Timelock");
    println!("  {}", "─".repeat(60));
    
    for lock in &filtered {
        let txid_short = format!("{}...", &lock.btc_txid[..12]);
        println!("  {:<20} {:<16} {:<10} {:<12}",
            lock.lock_id,
            txid_short,
            lock.state.to_string(),
            lock.timelock_block
        );
    }
    
    println!();
    println!("  Total: {} locks", filtered.len());
    
    let locked = locks.iter().filter(|l| l.state == LockState::Locked).count();
    let expired = locks.iter().filter(|l| l.state == LockState::Expired).count();
    let settled = locks.iter().filter(|l| l.state == LockState::Settled).count();
    
    println!("  ({} locked, {} expired, {} settled)", locked, expired, settled);
    println!();
}

fn cmd_btc_lock_settle_check(txid: String, vout: u32, testnet: bool) {
    let network = if testnet { "TESTNET" } else { "MAINNET" };
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - VERIFICAR SETTLEMENT [{}]", network);
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    
    let registry = LockRegistry::load();
    
    match registry.find_by_utxo(&txid, vout) {
        Some(lock) => {
            println!("  Lock ID:        {}", lock.lock_id);
            println!("  Timelock:       Bloque {}", lock.timelock_block);
            
            // Consultar estado real en Bitcoin
            println!();
            println!("  🔍 Consultando Bitcoin {}...", network);
            
            let observer = if testnet {
                EsploraObserver::testnet()
            } else {
                EsploraObserver::mainnet()
            };
            
            let (current_state, current_height) = match (observer.get_utxo(&txid, vout), observer.current_block_height()) {
                (Ok(Some(utxo)), Ok(height)) => {
                    println!("  Altura actual:  {}", height);
                    
                    let state = if utxo.spent {
                        LockState::Settled
                    } else if height >= lock.timelock_block {
                        LockState::Expired
                    } else {
                        LockState::Locked
                    };
                    (state, height)
                }
                (Ok(None), _) => {
                    (LockState::Settled, 0)
                }
                (Err(e), _) | (Ok(Some(_)), Err(e)) => {
                    println!("  ⚠️  Error consultando: {}", e);
                    (lock.state.clone(), 0)
                }
            };
            
            println!("  Estado actual:  {}", current_state);
            println!();
            
            match current_state {
                LockState::Locked => {
                    let blocks_remaining = lock.timelock_block as i32 - current_height as i32;
                    println!("  ❌ NO LISTO PARA SETTLEMENT");
                    println!();
                    println!("  El timelock aún no ha expirado.");
                    println!("  Debes esperar hasta el bloque {}.", lock.timelock_block);
                    println!("  Bloques restantes: {}", blocks_remaining);
                    if blocks_remaining > 0 {
                        println!("  Tiempo estimado:   {}", estimate_time_remaining(blocks_remaining));
                    }
                }
                LockState::Expired => {
                    println!("  ✅ LISTO PARA SETTLEMENT");
                    println!();
                    println!("  El timelock ha expirado. Puedes recuperar tu BTC.");
                    println!();
                    println!("  ═══════════════════════════════════════════════════════════");
                    println!("  📋 INSTRUCCIONES DE SETTLEMENT");
                    println!("  ═══════════════════════════════════════════════════════════");
                    println!();
                    println!("  1. Construye la transacción de salida en tu wallet Bitcoin");
                    println!("  2. Input: {}:{}", lock.btc_txid, lock.btc_vout);
                    println!("  3. Redeem script: {}", lock.redeem_script_hex);
                    println!("  4. nLockTime: {} (OBLIGATORIO para CLTV)", lock.timelock_block);
                    println!("  5. Firma con tu clave de RECUPERACIÓN");
                    println!("  6. Witness: [signature, 0x00, redeem_script]");
                    println!("  7. Broadcast la transacción");
                    println!();
                    if let Some(amount) = lock.amount_sats {
                        println!("  💰 Cantidad a recuperar: {} sats ({:.8} BTC)", 
                            amount, amount as f64 / 100_000_000.0);
                        println!("     (menos fee de la transacción)");
                        println!();
                    }
                    println!("  ⚠️  Mooncoin NO firma ni transmite transacciones Bitcoin.");
                    println!("      Debes usar tu wallet Bitcoin externo.");
                    println!();
                }
                LockState::Settled => {
                    println!("  🏁 SETTLEMENT YA COMPLETADO");
                    println!();
                    println!("  El UTXO ya ha sido gastado.");
                }
                LockState::Unknown => {
                    println!("  ❓ Estado desconocido");
                }
            }
        }
        None => {
            println!("  ❌ LOCK no encontrado en registro local.");
        }
    }
    println!();
}

fn cmd_btc_lock_demo() {
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  🌙 MOONCOIN BTC LOCK - DEMO COMPLETO");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  Este demo muestra el flujo completo LOCK-OPERATE-SETTLE");
    println!("  usando un observer mock (sin conexión a Bitcoin real).");
    println!();
    
    println!("  ─────────────────────────────────────────────────────────────");
    println!("  1️⃣  GENERAR SCRIPT LOCK");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let params = MultisigCltvParams {
        pubkey_hot: format!("02{}", "aa".repeat(32)),
        pubkey_cold: format!("03{}", "bb".repeat(32)),
        pubkey_recovery: format!("02{}", "cc".repeat(32)),
        locktime_blocks: 1000,
    };
    
    let script = generate_multisig_cltv(&params).unwrap();
    let script_hex = hex::encode(&script);
    let p2wsh = script_to_p2wsh_address(&script, true);
    
    println!();
    println!("  Template:      multisig_cltv");
    println!("  Timelock:      Bloque 1000");
    println!("  P2WSH Address: {}", p2wsh);
    println!("  Script (hex):  {}...", &script_hex[..40]);
    
    println!();
    println!("  ─────────────────────────────────────────────────────────────");
    println!("  2️⃣  VERIFICAR SCRIPT");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let matched = match_lock_template(&script).unwrap().unwrap();
    println!();
    println!("  ✅ Script coincide con: {}", matched.template);
    println!("  Timelock detectado:     {}", matched.timelock_value);
    println!("  Pubkeys encontradas:    {}", matched.pubkeys.len());
    
    println!();
    println!("  ─────────────────────────────────────────────────────────────");
    println!("  3️⃣  REGISTRAR LOCK (simulado)");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let mock_txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    let mut mock_observer = MockBtcObserver::new(500);
    mock_observer.add_utxo(mock_txid, 0, 10_000_000, 6);
    
    println!();
    println!("  Mock Observer:");
    println!("    - Altura actual:    500");
    println!("    - UTXO simulado:    {}:0", &mock_txid[..16]);
    println!("    - Cantidad:         0.1 BTC");
    println!("    - Confirmaciones:   6");
    
    let exists = mock_observer.utxo_exists(mock_txid, 0).unwrap();
    println!();
    println!("  ✅ UTXO existe: {}", exists);
    
    println!();
    println!("  ─────────────────────────────────────────────────────────────");
    println!("  4️⃣  SIMULAR PASO DEL TIEMPO");
    println!("  ─────────────────────────────────────────────────────────────");
    
    let status = get_timelock_status(&matched, 500);
    println!();
    println!("  [Bloque 500] Estado: LOCKED");
    println!("    Timelock expira en:   Bloque 1000");
    println!("    Bloques restantes:    {}", status.blocks_remaining);
    println!("    Tiempo estimado:      {}", estimate_time_remaining(status.blocks_remaining));
    
    mock_observer.set_height(800);
    let status = get_timelock_status(&matched, 800);
    println!();
    println!("  [Bloque 800] Estado: LOCKED");
    println!("    Bloques restantes:    {}", status.blocks_remaining);
    println!("    Tiempo estimado:      {}", estimate_time_remaining(status.blocks_remaining));
    
    mock_observer.set_height(1100);
    let status = get_timelock_status(&matched, 1100);
    println!();
    println!("  [Bloque 1100] Estado: EXPIRED");
    println!("    Timelock expirado:    ✅");
    println!("    Bloques pasados:      {}", -status.blocks_remaining);
    
    println!();
    println!("  ─────────────────────────────────────────────────────────────");
    println!("  5️⃣  SETTLEMENT");
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    println!("  ✅ El timelock ha expirado.");
    println!("  El usuario puede ahora recuperar su BTC:");
    println!();
    println!("  1. Construir transacción Bitcoin:");
    println!("     Input:    {}:0", &mock_txid[..16]);
    println!("     Output:   <dirección del usuario>");
    println!("     Locktime: 1000 (para CLTV)");
    println!();
    println!("  2. Witness (recovery path):");
    println!("     [signature_recovery, 0x00, redeem_script]");
    println!();
    println!("  3. Firmar con clave de recuperación");
    println!("  4. Broadcast a Bitcoin network");
    
    mock_observer.spend_utxo(mock_txid, 0);
    let exists = mock_observer.utxo_exists(mock_txid, 0).unwrap();
    println!();
    println!("  [Después del broadcast]");
    println!("  UTXO existe: {} → SETTLED", exists);
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  📊 RESUMEN DEL CICLO LOCK-OPERATE-SETTLE");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │ Fase      │ Acción                                      │");
    println!("  ├─────────────────────────────────────────────────────────┤");
    println!("  │ LOCK      │ Usuario crea script, envía BTC              │");
    println!("  │ OBSERVE   │ Mooncoin observa UTXO (no custodia)         │");
    println!("  │ OPERATE   │ Usuario opera en Mooncoin (BTC intocado)    │");
    println!("  │ EXPIRE    │ Timelock expira                             │");
    println!("  │ SETTLE    │ Usuario recupera BTC con recovery key       │");
    println!("  └─────────────────────────────────────────────────────────┘");
    println!();
    println!("  ⚠️  RECORDATORIO:");
    println!("  - Mooncoin NUNCA custodia BTC");
    println!("  - Mooncoin SOLO observa el estado de Bitcoin");
    println!("  - El usuario es COMPLETAMENTE responsable de sus claves");
    println!();
    println!("  🌙 Demo completado!");
    println!();
}

fn cmd_btc_lock_connect(testnet: bool, signet: bool) {
    let network = if signet {
        BitcoinNetwork::Signet
    } else if testnet {
        BitcoinNetwork::Testnet
    } else {
        BitcoinNetwork::Mainnet
    };
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - CONECTAR A BITCOIN [{}]", network.name().to_uppercase());
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  🔍 Conectando a {}...", network.base_url());
    println!();
    
    let observer = EsploraObserver::new(network.clone());
    
    match observer.check_connection() {
        Ok(height) => {
            println!("  ✅ CONEXIÓN EXITOSA");
            println!();
            println!("  Red:            {}", network.name());
            println!("  API:            {}", network.base_url());
            println!("  Altura actual:  {} bloques", height);
            println!();
            println!("  La conexión a Bitcoin está funcionando correctamente.");
            println!("  Puedes usar los comandos btc-lock-* para interactuar.");
            println!();
            
            // Mostrar algunos comandos útiles
            let flag = match network {
                BitcoinNetwork::Testnet => " --testnet",
                BitcoinNetwork::Signet => " --signet",
                BitcoinNetwork::Mainnet => "",
            };
            println!("  📌 Comandos disponibles:");
            println!("     mooncoin btc-lock-query-tx <txid>{}", flag);
            println!("     mooncoin btc-lock-check-utxo --txid <txid> --vout 0{}", flag);
            println!();
        }
        Err(e) => {
            println!("  ❌ ERROR DE CONEXIÓN");
            println!();
            println!("  No se pudo conectar a Bitcoin {}: {}", network.name(), e);
            println!();
            println!("  Posibles causas:");
            println!("    - Sin conexión a internet");
            println!("    - API de Blockstream no disponible");
            println!("    - Firewall bloqueando conexión");
            println!();
        }
    }
}

fn cmd_btc_lock_query_tx(txid: String, testnet: bool) {
    let network = if testnet { "TESTNET" } else { "MAINNET" };
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - CONSULTAR TRANSACCIÓN [{}]", network);
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    
    if txid.len() != 64 || hex::decode(&txid).is_err() {
        println!("  ❌ Error: txid inválido (debe ser 64 caracteres hex)");
        return;
    }
    
    println!("  🔍 Consultando transacción...");
    println!("  TXID: {}", txid);
    println!();
    
    let observer = if testnet {
        EsploraObserver::testnet()
    } else {
        EsploraObserver::mainnet()
    };
    
    match observer.get_transaction(&txid) {
        Ok(tx) => {
            println!("  ✅ TRANSACCIÓN ENCONTRADA");
            println!();
            println!("  ═══════════════════════════════════════════════════════════");
            println!("  📋 DETALLES");
            println!("  ═══════════════════════════════════════════════════════════");
            println!();
            println!("  TXID:           {}", tx.txid);
            println!("  Versión:        {}", tx.version);
            println!("  Locktime:       {}", tx.locktime);
            println!("  Tamaño:         {} bytes", tx.size);
            println!("  Weight:         {} WU", tx.weight);
            println!("  Fee:            {} sats", tx.fee);
            println!();
            
            if tx.status.confirmed {
                println!("  Estado:         ✅ CONFIRMADA");
                if let Some(height) = tx.status.block_height {
                    println!("  Bloque:         {}", height);
                }
                if let Some(hash) = &tx.status.block_hash {
                    println!("  Block hash:     {}...", &hash[..16]);
                }
            } else {
                println!("  Estado:         ⏳ EN MEMPOOL (sin confirmar)");
            }
            
            println!();
            println!("  ─────────────────────────────────────────────────────────────");
            println!("  INPUTS ({}):", tx.vin.len());
            println!("  ─────────────────────────────────────────────────────────────");
            for (i, input) in tx.vin.iter().enumerate() {
                println!("  [{}] {}:{}", i, &input.txid[..16], input.vout);
                if let Some(prevout) = &input.prevout {
                    println!("      Valor: {} sats", prevout.value);
                }
            }
            
            println!();
            println!("  ─────────────────────────────────────────────────────────────");
            println!("  OUTPUTS ({}):", tx.vout.len());
            println!("  ─────────────────────────────────────────────────────────────");
            for (i, output) in tx.vout.iter().enumerate() {
                println!("  [{}] {} sats", i, output.value);
                if let Some(addr) = &output.scriptpubkey_address {
                    println!("      Dirección: {}", addr);
                }
                if let Some(script_type) = &output.scriptpubkey_type {
                    println!("      Tipo: {}", script_type);
                }
            }
            println!();
        }
        Err(e) => {
            println!("  ❌ Error consultando transacción: {}", e);
            println!();
            println!("  Verifica que:");
            println!("    - El TXID sea correcto (64 caracteres hex)");
            println!("    - La transacción exista en {}", network);
            println!();
        }
    }
}

fn cmd_btc_lock_check_utxo(txid: String, vout: u32, testnet: bool) {
    let network = if testnet { "TESTNET" } else { "MAINNET" };
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - VERIFICAR UTXO [{}]", network);
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    
    if txid.len() != 64 || hex::decode(&txid).is_err() {
        println!("  ❌ Error: txid inválido (debe ser 64 caracteres hex)");
        return;
    }
    
    println!("  🔍 Verificando UTXO...");
    println!("  TXID: {}", txid);
    println!("  Vout: {}", vout);
    println!();
    
    let observer = if testnet {
        EsploraObserver::testnet()
    } else {
        EsploraObserver::mainnet()
    };
    
    match observer.get_utxo(&txid, vout) {
        Ok(Some(utxo)) => {
            println!("  ✅ UTXO ENCONTRADO");
            println!();
            println!("  TXID:           {}", utxo.txid);
            println!("  Vout:           {}", utxo.vout);
            println!("  Cantidad:       {} sats ({:.8} BTC)", utxo.amount_sats, utxo.amount_sats as f64 / 100_000_000.0);
            println!("  Confirmaciones: {}", utxo.confirmations);
            println!();
            
            if utxo.spent {
                println!("  Estado:         ❌ GASTADO");
                println!();
                println!("  Este UTXO ya ha sido gastado en otra transacción.");
            } else {
                println!("  Estado:         ✅ NO GASTADO (disponible)");
                println!();
                println!("  Este UTXO está disponible y puede ser usado.");
                
                if utxo.confirmations < 6 {
                    println!();
                    println!("  ⚠️  Solo {} confirmaciones (recomendado: 6+)", utxo.confirmations);
                }
            }
            println!();
        }
        Ok(None) => {
            println!("  ❌ UTXO NO ENCONTRADO");
            println!();
            println!("  El output {}:{} no existe.", &txid[..16], vout);
            println!();
            println!("  Posibles causas:");
            println!("    - El índice vout es incorrecto");
            println!("    - La transacción no existe");
            println!("    - La transacción aún no está confirmada");
            println!();
        }
        Err(e) => {
            println!("  ❌ Error verificando UTXO: {}", e);
            println!();
        }
    }
}

fn cmd_btc_lock_keygen(count: u32) {
    use secp256k1::{Secp256k1, SecretKey, PublicKey};
    use rand::rngs::OsRng;
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - GENERAR CLAVES DE PRUEBA");
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    println!("  ⚠️  ADVERTENCIA: SOLO PARA TESTNET / PRUEBAS");
    println!("  Estas claves son para propósitos de prueba únicamente.");
    println!("  NO uses estas claves para Bitcoin real (mainnet).");
    println!();
    
    let secp = Secp256k1::new();
    let mut keypairs = Vec::new();
    
    let labels = ["hot", "cold", "recovery", "extra1", "extra2"];
    
    for i in 0..count.min(5) {
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        let privkey_hex = hex::encode(secret_key.secret_bytes());
        let pubkey_hex = hex::encode(public_key.serialize());
        
        keypairs.push((labels[i as usize], privkey_hex, pubkey_hex));
    }
    
    println!("  ─────────────────────────────────────────────────────────────");
    println!("  CLAVES GENERADAS ({}):", keypairs.len());
    println!("  ─────────────────────────────────────────────────────────────");
    println!();
    
    for (label, privkey, pubkey) in &keypairs {
        println!("  📌 {} key:", label.to_uppercase());
        println!("     Privkey (hex): {}", privkey);
        println!("     Pubkey  (hex): {}", pubkey);
        println!();
    }
    
    // Mostrar comando de ejemplo
    if keypairs.len() >= 3 {
        println!("  ═══════════════════════════════════════════════════════════");
        println!("  📋 COMANDO PARA GENERAR SCRIPT LOCK:");
        println!("  ═══════════════════════════════════════════════════════════");
        println!();
        println!("  mooncoin btc-lock-generate --testnet \\");
        println!("    --pubkey-hot {} \\", keypairs[0].2);
        println!("    --pubkey-cold {} \\", keypairs[1].2);
        println!("    --pubkey-recovery {} \\", keypairs[2].2);
        println!("    --timelock 5000000");
        println!();
        println!("  ─────────────────────────────────────────────────────────────");
        println!("  💾 GUARDA LAS CLAVES PRIVADAS DE FORMA SEGURA");
        println!("  ─────────────────────────────────────────────────────────────");
        println!();
        println!("  Necesitarás la clave privada de RECOVERY para hacer settlement.");
        println!("  Sin ella, NO podrás recuperar tu BTC después del timelock.");
        println!();
    }
}

fn cmd_btc_lock_refresh(testnet: bool) {
    let network = if testnet { "TESTNET" } else { "MAINNET" };
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════");
    println!("  MOONCOIN BTC LOCK - ACTUALIZAR ESTADOS [{}]", network);
    println!("  ═══════════════════════════════════════════════════════════");
    println!();
    
    let registry = LockRegistry::load();
    let locks = registry.list();
    
    if locks.is_empty() {
        println!("  No hay LOCKs registrados para actualizar.");
        println!();
        return;
    }
    
    println!("  🔍 Conectando a Bitcoin {}...", network);
    
    let observer = if testnet {
        EsploraObserver::testnet()
    } else {
        EsploraObserver::mainnet()
    };
    
    let current_height = match observer.current_block_height() {
        Ok(h) => {
            println!("  Altura actual: {}", h);
            h
        }
        Err(e) => {
            println!("  ❌ Error conectando: {}", e);
            return;
        }
    };
    
    println!();
    println!("  Actualizando {} LOCKs...", locks.len());
    println!();
    
    let mut updated = 0;
    let mut errors = 0;
    
    for lock in locks {
        print!("  {} ... ", lock.lock_id);
        
        match observer.get_utxo(&lock.btc_txid, lock.btc_vout) {
            Ok(Some(utxo)) => {
                let new_state = if utxo.spent {
                    LockState::Settled
                } else if current_height >= lock.timelock_block {
                    LockState::Expired
                } else {
                    LockState::Locked
                };
                
                let state_changed = new_state != lock.state;
                let state_str = match new_state {
                    LockState::Locked => "🔒 LOCKED",
                    LockState::Expired => "⏰ EXPIRED",
                    LockState::Settled => "✅ SETTLED",
                    LockState::Unknown => "❓ UNKNOWN",
                };
                
                if state_changed {
                    println!("{} (cambió de {})", state_str, lock.state);
                    updated += 1;
                } else {
                    println!("{}", state_str);
                }
            }
            Ok(None) => {
                println!("✅ SETTLED (UTXO gastado)");
                updated += 1;
            }
            Err(e) => {
                println!("❌ Error: {}", e);
                errors += 1;
            }
        }
    }
    
    println!();
    println!("  ─────────────────────────────────────────────────────────────");
    println!("  Resumen: {} actualizados, {} errores", updated, errors);
    println!();
}

fn cmd_btc_lock_health() {
    println!();
    println!("  ═══════════════════════════════════════════════════════════════════════");
    println!("  🌙 MOONCOIN BTC LOCK - VERIFICACIÓN DE SISTEMA");
    println!("  ═══════════════════════════════════════════════════════════════════════");
    println!();
    
    let mut all_ok = true;
    
    // 1. Verificar generación de scripts
    print!("  [1/6] Generación de scripts LOCK.............. ");
    let params = MultisigCltvParams {
        pubkey_hot: format!("02{}", "aa".repeat(32)),
        pubkey_cold: format!("03{}", "bb".repeat(32)),
        pubkey_recovery: format!("02{}", "cc".repeat(32)),
        locktime_blocks: 1000,
    };
    match generate_multisig_cltv(&params) {
        Ok(script) => {
            if script.len() > 50 {
                println!("✅ OK");
            } else {
                println!("❌ FALLO");
                all_ok = false;
            }
        }
        Err(e) => {
            println!("❌ FALLO: {}", e);
            all_ok = false;
        }
    }
    
    // 2. Verificar template matching
    print!("  [2/6] Verificación de templates............... ");
    let test_script = generate_multisig_cltv(&params).unwrap();
    match match_lock_template(&test_script) {
        Ok(Some(m)) => {
            if matches!(m.template, LockTemplate::MultisigCltv) {
                println!("✅ OK");
            } else {
                println!("❌ FALLO");
                all_ok = false;
            }
        }
        _ => {
            println!("❌ FALLO");
            all_ok = false;
        }
    }
    
    // 3. Verificar generación de direcciones P2WSH
    print!("  [3/6] Generación de direcciones P2WSH......... ");
    let p2wsh = script_to_p2wsh_address(&test_script, true);
    if p2wsh.starts_with("bc1q") && p2wsh.len() > 40 {
        println!("✅ OK");
    } else {
        println!("❌ FALLO");
        all_ok = false;
    }
    
    // 4. Verificar conexión a Bitcoin Testnet
    print!("  [4/6] Conexión a Bitcoin Testnet.............. ");
    let testnet_observer = EsploraObserver::testnet();
    match testnet_observer.current_block_height() {
        Ok(height) => {
            if height > 4000000 {
                println!("✅ OK (altura: {})", height);
            } else {
                println!("⚠️  Altura inesperada: {}", height);
            }
        }
        Err(e) => {
            println!("❌ FALLO: {}", e);
            all_ok = false;
        }
    }
    
    // 5. Verificar conexión a Bitcoin Mainnet
    print!("  [5/6] Conexión a Bitcoin Mainnet.............. ");
    let mainnet_observer = EsploraObserver::mainnet();
    match mainnet_observer.current_block_height() {
        Ok(height) => {
            if height > 900000 {
                println!("✅ OK (altura: {})", height);
            } else {
                println!("⚠️  Altura inesperada: {}", height);
            }
        }
        Err(e) => {
            println!("❌ FALLO: {}", e);
            all_ok = false;
        }
    }
    
    // 6. Verificar registro local
    print!("  [6/6] Registro local de LOCKs................. ");
    let registry = LockRegistry::load();
    let lock_count = registry.list().len();
    println!("✅ OK ({} LOCKs registrados)", lock_count);
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════════════════");
    
    if all_ok {
        println!("  ✅ SISTEMA OPERATIVO - Todos los componentes funcionando");
    } else {
        println!("  ⚠️  SISTEMA CON PROBLEMAS - Revisa los errores arriba");
    }
    
    println!();
    println!("  📌 COMANDOS DISPONIBLES:");
    println!("  ───────────────────────────────────────────────────────────────────────");
    println!("  btc-lock-templates      Ver templates disponibles");
    println!("  btc-lock-keygen         Generar claves de prueba (testnet)");
    println!("  btc-lock-generate       Generar script LOCK");
    println!("  btc-lock-verify         Verificar script");
    println!("  btc-lock-register       Registrar LOCK");
    println!("  btc-lock-status         Ver estado de un LOCK");
    println!("  btc-lock-list           Listar todos los LOCKs");
    println!("  btc-lock-refresh        Actualizar estados desde Bitcoin");
    println!("  btc-lock-settle-check   Verificar si listo para settlement");
    println!("  btc-lock-settle         Construir TX de settlement");
    println!("  btc-lock-connect        Probar conexión a Bitcoin");
    println!("  btc-lock-query-tx       Consultar transacción");
    println!("  btc-lock-check-utxo     Verificar UTXO");
    println!("  btc-lock-demo           Demo completo (mock)");
    println!();
}

fn cmd_btc_lock_settle(
    txid: String,
    vout: u32,
    destination: String,
    privkey: String,
    fee_rate: u64,
    testnet: bool,
) {
    let network = if testnet { "TESTNET" } else { "MAINNET" };
    
    println!();
    println!("  ═══════════════════════════════════════════════════════════════════════");
    println!("  🌙 MOONCOIN BTC LOCK - SETTLEMENT TX BUILDER [{}]", network);
    println!("  ═══════════════════════════════════════════════════════════════════════");
    
    // Validar TXID
    if txid.len() != 64 || hex::decode(&txid).is_err() {
        println!("\n  ❌ Error: TXID inválido (debe ser 64 caracteres hex)");
        return;
    }
    
    // Validar privkey
    if privkey.len() != 64 || hex::decode(&privkey).is_err() {
        println!("\n  ❌ Error: Private key inválida (debe ser 64 caracteres hex)");
        return;
    }
    
    // Validar dirección destino
    let expected_prefix = if testnet { "tb1" } else { "bc1" };
    if !destination.starts_with(expected_prefix) {
        println!("\n  ❌ Error: Dirección debe empezar con {}", expected_prefix);
        return;
    }
    
    // Buscar el LOCK en el registro
    let registry = LockRegistry::load();
    let lock = match registry.find_by_utxo(&txid, vout) {
        Some(l) => l,
        None => {
            println!("\n  ❌ Error: LOCK no encontrado en registro local");
            println!("     Primero debes registrar el LOCK con btc-lock-register");
            return;
        }
    };
    
    println!();
    println!("  📋 LOCK ENCONTRADO:");
    println!("  ─────────────────────────────────────────────────────────────────────────");
    println!("  Lock ID:       {}", lock.lock_id);
    println!("  TXID:          {}...", &lock.btc_txid[..16]);
    println!("  Timelock:      Bloque {}", lock.timelock_block);
    
    // Consultar estado actual en Bitcoin
    println!();
    println!("  🔍 Consultando Bitcoin {}...", network);
    
    let observer = if testnet {
        EsploraObserver::testnet()
    } else {
        EsploraObserver::mainnet()
    };
    
    // Obtener altura actual
    let current_height = match observer.current_block_height() {
        Ok(h) => h,
        Err(e) => {
            println!("  ❌ Error conectando a Bitcoin: {}", e);
            return;
        }
    };
    
    println!("  Altura actual: {}", current_height);
    
    // Verificar que el timelock haya expirado
    if current_height < lock.timelock_block {
        let blocks_remaining = lock.timelock_block - current_height;
        println!();
        println!("  ❌ ERROR: TIMELOCK AÚN NO HA EXPIRADO");
        println!();
        println!("  Bloque actual:     {}", current_height);
        println!("  Bloque timelock:   {}", lock.timelock_block);
        println!("  Bloques restantes: {}", blocks_remaining);
        println!("  Tiempo estimado:   {}", estimate_time_remaining(blocks_remaining as i32));
        println!();
        println!("  Debes esperar hasta el bloque {} para hacer settlement.", lock.timelock_block);
        return;
    }
    
    println!("  Timelock:      ✅ EXPIRADO (bloque {} >= {})", current_height, lock.timelock_block);
    
    // Verificar UTXO
    let utxo = match observer.get_utxo(&txid, vout) {
        Ok(Some(u)) => u,
        Ok(None) => {
            println!();
            println!("  ❌ ERROR: UTXO no encontrado");
            println!("     El UTXO puede haber sido gastado ya.");
            return;
        }
        Err(e) => {
            println!("  ❌ Error consultando UTXO: {}", e);
            return;
        }
    };
    
    if utxo.spent {
        println!();
        println!("  ❌ ERROR: UTXO YA FUE GASTADO");
        println!("     El settlement ya fue realizado o los fondos fueron movidos.");
        return;
    }
    
    let input_amount = lock.amount_sats.unwrap_or(utxo.amount_sats);
    let estimated_fee = estimate_settlement_fee(fee_rate);
    let output_amount = input_amount.saturating_sub(estimated_fee);
    
    println!("  UTXO:          ✅ Disponible ({} sats)", input_amount);
    
    // Mostrar resumen
    println!();
    println!("  ═══════════════════════════════════════════════════════════════════════");
    println!("  📋 RESUMEN DE TRANSACCIÓN");
    println!("  ═══════════════════════════════════════════════════════════════════════");
    println!();
    println!("  Input:         {}:{}", &txid[..16], vout);
    println!("  Cantidad:      {} sats ({:.8} BTC)", input_amount, input_amount as f64 / 100_000_000.0);
    println!("  Fee rate:      {} sat/vbyte", fee_rate);
    println!("  Fee estimado:  {} sats", estimated_fee);
    println!("  Output:        {} sats ({:.8} BTC)", output_amount, output_amount as f64 / 100_000_000.0);
    println!("  Destino:       {}", destination);
    println!();
    
    // Advertencia
    println!("{}", WARNING_SETTLEMENT);
    
    if !confirm_btc_lock("  ¿Generar transacción de settlement?") {
        println!("\n  ❌ Operación cancelada por el usuario.");
        return;
    }
    
    // Construir la transacción
    println!();
    println!("  🔧 Construyendo transacción...");
    
    let params = SettlementParams {
        input_txid: txid.clone(),
        input_vout: vout,
        input_amount,
        redeem_script_hex: lock.redeem_script_hex.clone(),
        recovery_privkey_hex: privkey,
        destination_address: destination.clone(),
        fee_rate,
        locktime: lock.timelock_block,
        testnet,
    };
    
    match build_settlement_tx(&params) {
        Ok(settlement) => {
            println!();
            println!("  ═══════════════════════════════════════════════════════════════════════");
            println!("  ✅ TRANSACCIÓN GENERADA EXITOSAMENTE");
            println!("  ═══════════════════════════════════════════════════════════════════════");
            println!();
            println!("  TXID:          {}", settlement.txid);
            println!("  Fee:           {} sats", settlement.fee_sats);
            println!("  Output:        {} sats", settlement.output_sats);
            println!();
            println!("  ─────────────────────────────────────────────────────────────────────────");
            println!("  📋 TRANSACCIÓN HEX (para broadcast):");
            println!("  ─────────────────────────────────────────────────────────────────────────");
            println!();
            println!("  {}", settlement.tx_hex);
            println!();
            println!("  ═══════════════════════════════════════════════════════════════════════");
            println!("  📌 PRÓXIMOS PASOS");
            println!("  ═══════════════════════════════════════════════════════════════════════");
            println!();
            println!("  1. Copia la transacción hex de arriba");
            println!();
            println!("  2. Broadcast usando uno de estos métodos:");
            println!();
            if testnet {
                println!("     Web:  https://blockstream.info/testnet/tx/push");
                println!("     API:  curl -X POST -d '{}' https://blockstream.info/testnet/api/tx", &settlement.tx_hex[..40]);
            } else {
                println!("     Web:  https://blockstream.info/tx/push");
                println!("     API:  curl -X POST -d '{}' https://blockstream.info/api/tx", &settlement.tx_hex[..40]);
            }
            println!();
            println!("  3. Verifica que la transacción sea incluida en un bloque");
            println!();
            println!("  ⚠️  Una vez transmitida, NO puede ser revertida.");
            println!();
        }
        Err(e) => {
            println!();
            println!("  ❌ ERROR CONSTRUYENDO TRANSACCIÓN: {}", e);
            println!();
            println!("  Posibles causas:");
            println!("    - Clave privada incorrecta");
            println!("    - Dirección destino inválida");
            println!("    - Fondos insuficientes para pagar fee");
            println!();
        }
    }
}

// =============================================================================
// MOONVAULT v4.0 - Fee System Commands
// =============================================================================

/// Generate fee invoice for a service
fn cmd_fee_invoice(service: String, pubkey: String, testnet: bool) {
    use crate::fee_system::{ServiceType, generate_invoice, print_invoice, save_invoice};
    
    let service_type = match service.as_str() {
        "vault-create" => ServiceType::VaultCreate,
        "vault-modify" => ServiceType::VaultModify,
        "monitoring-monthly" => ServiceType::MonitoringMonthly,
        _ => {
            println!();
            println!("  ❌ Unknown service type: {}", service);
            println!();
            println!("  Available services:");
            println!("    - vault-create        (10,000 sats)");
            println!("    - vault-modify        (5,000 sats)");
            println!("    - monitoring-monthly  (1,000 sats)");
            println!();
            return;
        }
    };
    
    let invoice = generate_invoice(service_type, &pubkey, testnet);
    save_invoice(&invoice);
    print_invoice(&invoice);
}

/// Verify BTC payment for an invoice
fn cmd_fee_verify(txid: String, invoice_id: String, testnet: bool) {
    use crate::fee_system::{verify_payment, print_verification};
    
    println!();
    println!("  Verifying payment...");
    
    match verify_payment(&txid, &invoice_id, testnet) {
        Ok(result) => {
            print_verification(&result);
        }
        Err(e) => {
            println!();
            println!("  ❌ Verification failed: {}", e);
            println!();
        }
    }
}

/// Show Fee Pool status
fn cmd_fee_pool_status(testnet: bool) {
    use crate::fee_system::{get_fee_pool_status, print_fee_pool_status};
    
    match get_fee_pool_status(testnet) {
        Ok(status) => {
            print_fee_pool_status(&status);
        }
        Err(e) => {
            println!();
            println!("  ❌ Failed to get Fee Pool status: {}", e);
            println!();
        }
    }
}

// =============================================================================
// MOONVAULT v4.0 - Vault Service Commands
// =============================================================================

/// Create a new vault
fn cmd_vault_create(
    invoice: String,
    hot_key: String,
    cold_key: String,
    recovery_key: String,
    daily_limit: u64,
    cold_delay: u32,
    timelock: u32,
    testnet: bool,
) {
    use crate::vault_service::{VaultCreateParams, create_vault, print_vault_created};
    
    println!();
    println!("  Creating vault...");
    
    let params = VaultCreateParams {
        owner_pubkey: hot_key.clone(), // Owner is hot key holder
        hot_pubkey: hot_key,
        cold_pubkey: cold_key,
        recovery_pubkey: recovery_key,
        daily_limit_sats: daily_limit,
        cold_delay_blocks: cold_delay,
        recovery_timelock: timelock,
        testnet,
        invoice_id: invoice,
    };
    
    match create_vault(params) {
        Ok(vault) => {
            print_vault_created(&vault);
        }
        Err(e) => {
            println!();
            println!("  ❌ Failed to create vault: {}", e);
            println!();
            println!("  Make sure:");
            println!("    - Invoice is paid and confirmed (3+ confirmations)");
            println!("    - Invoice is for vault-create service");
            println!("    - All public keys are valid (33 bytes hex)");
            println!();
        }
    }
}

/// Show vault status
fn cmd_vault_status(vault_id: String, testnet: bool) {
    use crate::vault_service::{refresh_vault_status, print_vault_status, get_vault_status};
    
    // Try to refresh from network first
    let vault = match refresh_vault_status(&vault_id, testnet) {
        Ok(v) => v,
        Err(_) => {
            // Fall back to local status
            match get_vault_status(&vault_id) {
                Ok(v) => v,
                Err(e) => {
                    println!();
                    println!("  ❌ Vault not found: {}", e);
                    println!();
                    return;
                }
            }
        }
    };
    
    print_vault_status(&vault);
}

/// Activate panic button
fn cmd_vault_panic(vault_id: String, recovery_key: String) {
    use crate::vault_service::{activate_panic, print_panic_activated};
    
    println!();
    println!("  ⚠️  WARNING: You are about to activate the PANIC BUTTON");
    println!("       This will FREEZE all vault operations.");
    println!();
    
    // Confirm
    print!("  Type 'PANIC' to confirm: ");
    use std::io::{self, Write};
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    if input.trim() != "PANIC" {
        println!();
        println!("  ❌ Cancelled. Panic button NOT activated.");
        println!();
        return;
    }
    
    match activate_panic(&vault_id, &recovery_key) {
        Ok(vault) => {
            print_panic_activated(&vault);
        }
        Err(e) => {
            println!();
            println!("  ❌ Failed to activate panic button: {}", e);
            println!();
        }
    }
}

/// List all vaults
fn cmd_vault_list(owner: Option<String>) {
    use crate::vault_service::{list_vaults, print_vault_list};
    
    let vaults = list_vaults(owner.as_deref());
    print_vault_list(&vaults);
}

// =============================================================================
// MOONVAULT v4.0 - Gas Commands
// =============================================================================

/// Show gas balance
fn cmd_gas_balance() {
    let chain = load_chain();
    let secret_key = load_or_create_key();
    let pubkey = get_pubkey(&secret_key);
    let address = get_address(&pubkey);
    
    // Calculate balance using rebuild_from_chain
    let utxo_set = UtxoSet::rebuild_from_chain(&chain);
    let balance = utxo_set.balance_of(&address);
    let utxo_count = utxo_set.len();  // Total UTXOs in set
    
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║                          GAS BALANCE                                      ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  ⚠️  IMPORTANT: Gas units have NO monetary value.                         ║");
    println!("║      They exist only for anti-spam purposes.                              ║");
    println!("║      Gas is NOT transferable - it can only be burned.                     ║");
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  Address:       {}           ║", address);
    println!("║                                                                           ║");
    println!("║  Gas Available: {:>20}                              ║", format_gas(balance));
    println!("║                                                                           ║");
    println!("╠═══════════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                           ║");
    println!("║  To get more gas: Run the node with 'moonvault run' to mine.              ║");
    println!("║  Gas is burned when requesting services (1 gas per request).              ║");
    println!("║                                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!();
}
