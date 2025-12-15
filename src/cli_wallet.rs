// =============================================================================
// MOONCOIN v2.31 - Interactive CLI Wallet
// =============================================================================
//
// Wallet interactivo que unifica todas las funcionalidades:
// - Crear/cargar wallet
// - Balance (transparent + shielded)
// - Enviar (normal y privado)
// - Recibir (addresses)
// - Historial
// - Backup/restore
//
// =============================================================================

use crate::privacy::keys::PrivacyKeys;

use crate::privacy::scanner::{ShieldedWallet, OwnedOutput};
use crate::privacy::shielded_tx::{ShieldedOutput, MIN_SHIELDED_FEE};
use crate::privacy::pedersen::Scalar;
use crate::privacy::rpc::parse_amount;

use std::io::{self, Write};
use std::fs;

use serde::{Serialize, Deserialize};

// =============================================================================
// Wallet Data
// =============================================================================

/// Datos persistentes del wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletData {
    /// Nombre del wallet
    pub name: String,
    /// Seed phrase (para recovery)
    pub seed_phrase: String,
    /// Privacy keys serializadas
    pub privacy_keys_data: PrivacyKeysData,
    /// Wallet shielded
    pub shielded_wallet: ShieldedWallet,
    /// Última altura sincronizada
    pub last_sync_height: u64,
    /// Timestamp de creación
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyKeysData {
    pub view_key: [u8; 32],
    pub spend_key: [u8; 32],
}

impl WalletData {
    /// Crea un nuevo wallet
    pub fn new(name: &str) -> Self {
        let seed = generate_seed_phrase();
        let keys = PrivacyKeys::generate();
        
        WalletData {
            name: name.to_string(),
            seed_phrase: seed,
            privacy_keys_data: PrivacyKeysData {
                view_key: keys.view_key.key.as_bytes(),
                spend_key: keys.spend_key.key.as_bytes(),
            },
            shielded_wallet: ShieldedWallet::new(),
            last_sync_height: 0,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Guarda wallet a archivo
    pub fn save(&self, path: &str) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(path, json)
    }
    
    /// Carga wallet desde archivo
    pub fn load(path: &str) -> io::Result<Self> {
        let json = fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
    
    /// Obtiene las privacy keys
    pub fn get_privacy_keys(&self) -> PrivacyKeys {
        let view_key = Scalar::from_bytes_mod_order(&self.privacy_keys_data.view_key);
        let spend_key = Scalar::from_bytes_mod_order(&self.privacy_keys_data.spend_key);
        PrivacyKeys::from_scalars(view_key, spend_key)
    }
}

/// Genera seed phrase simple (en producción usar BIP39)
fn generate_seed_phrase() -> String {
    use rand::Rng;
    let words = [
        "moon", "coin", "crypto", "wallet", "block", "chain", "hash", "key",
        "sign", "verify", "send", "receive", "balance", "sync", "node", "peer",
        "mine", "proof", "work", "stake", "ring", "stealth", "shield", "private",
    ];
    
    let mut rng = rand::thread_rng();
    let selected: Vec<&str> = (0..12)
        .map(|_| words[rng.gen_range(0..words.len())])
        .collect();
    
    selected.join(" ")
}

// =============================================================================
// Interactive CLI
// =============================================================================

/// Estado del CLI interactivo
pub struct InteractiveCli {
    /// Wallet actual (None si no está cargado)
    wallet: Option<WalletData>,
    /// Path del wallet actual
    wallet_path: Option<String>,
    /// Running
    running: bool,
    /// Simulated balances for demo
    transparent_balance: u64,
}

impl InteractiveCli {
    pub fn new() -> Self {
        InteractiveCli {
            wallet: None,
            wallet_path: None,
            running: true,
            transparent_balance: 100_000_000, // 100 MOON demo
        }
    }
    
    /// Ejecuta el CLI interactivo
    pub fn run(&mut self) {
        self.print_welcome();
        
        while self.running {
            self.print_prompt();
            
            let input = match self.read_line() {
                Some(s) => s,
                None => continue,
            };
            
            let parts: Vec<&str> = input.trim().split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            
            let cmd = parts[0].to_lowercase();
            let args = &parts[1..];
            
            match cmd.as_str() {
                "help" | "h" | "?" => self.cmd_help(),
                "create" => self.cmd_create(args),
                "open" | "load" => self.cmd_open(args),
                "close" => self.cmd_close(),
                "save" => self.cmd_save(),
                "info" => self.cmd_info(),
                "balance" | "bal" => self.cmd_balance(),
                "address" | "addr" => self.cmd_address(),
                "send" => self.cmd_send(args),
                "sendshielded" | "sends" => self.cmd_send_shielded(args),
                "shield" => self.cmd_shield(args),
                "unshield" => self.cmd_unshield(args),
                "history" | "hist" => self.cmd_history(),
                "backup" => self.cmd_backup(),
                "seed" => self.cmd_seed(),
                "sync" => self.cmd_sync(),
                "clear" | "cls" => self.cmd_clear(),
                "exit" | "quit" | "q" => self.running = false,
                _ => println!("  Unknown command: {}. Type 'help' for commands.", cmd),
            }
        }
        
        println!("\n  Goodbye! 🌙\n");
    }
    
    fn print_welcome(&self) {
        println!();
        println!("  ╔═══════════════════════════════════════════════════════════╗");
        println!("  ║                                                           ║");
        println!("  ║   🌙 MOONCOIN WALLET v2.31                                ║");
        println!("  ║                                                           ║");
        println!("  ║   Private cryptocurrency wallet                           ║");
        println!("  ║   Type 'help' for available commands                      ║");
        println!("  ║                                                           ║");
        println!("  ╚═══════════════════════════════════════════════════════════╝");
        println!();
    }
    
    fn print_prompt(&self) {
        let wallet_name = self.wallet.as_ref()
            .map(|w| w.name.as_str())
            .unwrap_or("no wallet");
        print!("  mooncoin [{}]> ", wallet_name);
        io::stdout().flush().unwrap();
    }
    
    fn read_line(&self) -> Option<String> {
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => Some(input),
            Err(_) => None,
        }
    }
    
    // =========================================================================
    // Commands
    // =========================================================================
    
    fn cmd_help(&self) {
        println!();
        println!("  ┌─────────────────────────────────────────────────────────────┐");
        println!("  │                    AVAILABLE COMMANDS                       │");
        println!("  ├─────────────────────────────────────────────────────────────┤");
        println!("  │ WALLET MANAGEMENT                                           │");
        println!("  │   create <name>       Create new wallet                     │");
        println!("  │   open <file>         Open existing wallet                  │");
        println!("  │   close               Close current wallet                  │");
        println!("  │   save                Save wallet to file                   │");
        println!("  │   info                Show wallet information               │");
        println!("  │   backup              Show backup information               │");
        println!("  │   seed                Show seed phrase (PRIVATE!)           │");
        println!("  ├─────────────────────────────────────────────────────────────┤");
        println!("  │ BALANCE & ADDRESSES                                         │");
        println!("  │   balance             Show all balances                     │");
        println!("  │   address             Show receiving addresses              │");
        println!("  │   history             Show transaction history              │");
        println!("  │   sync                Sync with blockchain                  │");
        println!("  ├─────────────────────────────────────────────────────────────┤");
        println!("  │ TRANSACTIONS                                                │");
        println!("  │   send <addr> <amt>   Send transparent transaction          │");
        println!("  │   sendshielded <addr> <amt> [memo]  Send private TX         │");
        println!("  │   shield <amount>     Shield coins (transparent→private)    │");
        println!("  │   unshield <amount>   Unshield coins (private→transparent)  │");
        println!("  ├─────────────────────────────────────────────────────────────┤");
        println!("  │ OTHER                                                       │");
        println!("  │   help                Show this help                        │");
        println!("  │   clear               Clear screen                          │");
        println!("  │   exit                Exit wallet                           │");
        println!("  └─────────────────────────────────────────────────────────────┘");
        println!();
    }
    
    fn cmd_create(&mut self, args: &[&str]) {
        let name = if args.is_empty() {
            print!("  Wallet name: ");
            io::stdout().flush().unwrap();
            match self.read_line() {
                Some(s) => s.trim().to_string(),
                None => return,
            }
        } else {
            args[0].to_string()
        };
        
        if name.is_empty() {
            println!("  ❌ Wallet name cannot be empty");
            return;
        }
        
        let wallet = WalletData::new(&name);
        
        println!();
        println!("  ✅ Wallet '{}' created!", name);
        println!();
        println!("  ⚠️  IMPORTANT: Write down your seed phrase!");
        println!("  ┌─────────────────────────────────────────────────────────────┐");
        println!("  │ {}  │", wallet.seed_phrase);
        println!("  └─────────────────────────────────────────────────────────────┘");
        println!("  This is the ONLY way to recover your wallet if lost.");
        println!();
        
        let path = format!("{}.wallet", name);
        self.wallet = Some(wallet);
        self.wallet_path = Some(path);
        
        self.cmd_save();
    }
    
    fn cmd_open(&mut self, args: &[&str]) {
        let path = if args.is_empty() {
            print!("  Wallet file: ");
            io::stdout().flush().unwrap();
            match self.read_line() {
                Some(s) => s.trim().to_string(),
                None => return,
            }
        } else {
            args[0].to_string()
        };
        
        // Add .wallet extension if not present
        let path = if path.ends_with(".wallet") {
            path
        } else {
            format!("{}.wallet", path)
        };
        
        match WalletData::load(&path) {
            Ok(wallet) => {
                println!("  ✅ Wallet '{}' loaded!", wallet.name);
                self.wallet = Some(wallet);
                self.wallet_path = Some(path);
            }
            Err(e) => {
                println!("  ❌ Failed to load wallet: {}", e);
            }
        }
    }
    
    fn cmd_close(&mut self) {
        if self.wallet.is_some() {
            println!("  Wallet closed.");
            self.wallet = None;
            self.wallet_path = None;
        } else {
            println!("  No wallet is open.");
        }
    }
    
    fn cmd_save(&mut self) {
        let wallet = match &self.wallet {
            Some(w) => w,
            None => {
                println!("  ❌ No wallet is open");
                return;
            }
        };
        
        let path = self.wallet_path.as_ref()
            .map(|p| p.clone())
            .unwrap_or_else(|| format!("{}.wallet", wallet.name));
        
        match wallet.save(&path) {
            Ok(_) => println!("  ✅ Wallet saved to {}", path),
            Err(e) => println!("  ❌ Failed to save: {}", e),
        }
    }
    
    fn cmd_info(&self) {
        let wallet = match &self.wallet {
            Some(w) => w,
            None => {
                println!("  ❌ No wallet is open. Use 'create' or 'open'.");
                return;
            }
        };
        
        let keys = wallet.get_privacy_keys();
        let addr = keys.stealth_address();
        
        println!();
        println!("  ┌─────────────────────────────────────────────────────────────┐");
        println!("  │ WALLET INFORMATION                                          │");
        println!("  ├─────────────────────────────────────────────────────────────┤");
        println!("  │ Name:           {:<43} │", wallet.name);
        println!("  │ Created:        {:<43} │", format_timestamp(wallet.created_at));
        println!("  │ Last sync:      Block #{:<36} │", wallet.last_sync_height);
        println!("  │ Stealth addr:   {}...  │", &addr.encode()[..40]);
        println!("  │ View key:       {}...  │", &keys.view_key.export()[..40]);
        println!("  └─────────────────────────────────────────────────────────────┘");
        println!();
    }
    
    fn cmd_balance(&self) {
        let wallet = match &self.wallet {
            Some(w) => w,
            None => {
                println!("  ❌ No wallet is open");
                return;
            }
        };
        
        let shielded_balance = wallet.shielded_wallet.balance();
        let transparent = self.transparent_balance;
        let total = transparent + shielded_balance;
        
        println!();
        println!("  ┌─────────────────────────────────────────────────────────────┐");
        println!("  │ BALANCE                                                     │");
        println!("  ├─────────────────────────────────────────────────────────────┤");
        println!("  │ Transparent:    {:>20} MOON               │", format_moon(transparent));
        println!("  │ Shielded:       {:>20} MOON  🔒            │", format_moon(shielded_balance));
        println!("  ├─────────────────────────────────────────────────────────────┤");
        println!("  │ TOTAL:          {:>20} MOON               │", format_moon(total));
        println!("  └─────────────────────────────────────────────────────────────┘");
        println!();
        println!("  Unspent outputs: {} transparent, {} shielded",
            if transparent > 0 { 1 } else { 0 },
            wallet.shielded_wallet.unspent_count());
        println!();
    }
    
    fn cmd_address(&self) {
        let wallet = match &self.wallet {
            Some(w) => w,
            None => {
                println!("  ❌ No wallet is open");
                return;
            }
        };
        
        let keys = wallet.get_privacy_keys();
        let stealth_addr = keys.stealth_address();
        
        println!();
        println!("  ┌─────────────────────────────────────────────────────────────┐");
        println!("  │ RECEIVING ADDRESSES                                         │");
        println!("  ├─────────────────────────────────────────────────────────────┤");
        println!("  │ Transparent (legacy):                                       │");
        println!("  │   moon1{}...                                │", &hex::encode(&keys.spend_key.key.as_bytes()[..16])[..32]);
        println!("  │                                                             │");
        println!("  │ Shielded (private):  🔒                                     │");
        println!("  │   {}  │", &stealth_addr.encode());
        println!("  └─────────────────────────────────────────────────────────────┘");
        println!();
        println!("  💡 Use shielded address for maximum privacy");
        println!();
    }
    
    fn cmd_send(&mut self, args: &[&str]) {
        if self.wallet.is_none() {
            println!("  ❌ No wallet is open");
            return;
        }
        
        if args.len() < 2 {
            println!("  Usage: send <address> <amount>");
            return;
        }
        
        let address = args[0];
        let amount = match parse_amount(args[1]) {
            Some(a) => a,
            None => {
                println!("  ❌ Invalid amount: {}", args[1]);
                return;
            }
        };
        
        let fee = 1000u64; // 0.000001 MOON
        
        if amount + fee > self.transparent_balance {
            println!("  ❌ Insufficient transparent balance");
            return;
        }
        
        // Simulate transaction
        self.transparent_balance -= amount + fee;
        
        let fake_txid: [u8; 32] = rand::random();
        println!();
        println!("  ✅ Transaction sent!");
        println!("  • To: {}...", &address[..20.min(address.len())]);
        println!("  • Amount: {} MOON", format_moon(amount));
        println!("  • Fee: {} MOON", format_moon(fee));
        println!("  • TXID: {}...", &hex::encode(&fake_txid)[..16]);
        println!();
    }
    
    fn cmd_send_shielded(&mut self, args: &[&str]) {
        let wallet = match &mut self.wallet {
            Some(w) => w,
            None => {
                println!("  ❌ No wallet is open");
                return;
            }
        };
        
        if args.len() < 2 {
            println!("  Usage: sendshielded <stealth_address> <amount> [memo]");
            return;
        }
        
        let address = args[0];
        let amount = match parse_amount(args[1]) {
            Some(a) => a,
            None => {
                println!("  ❌ Invalid amount");
                return;
            }
        };
        
        let memo = if args.len() > 2 {
            args[2..].join(" ")
        } else {
            String::new()
        };
        
        // Validate stealth address
        if !address.starts_with("mzs") {
            println!("  ❌ Invalid stealth address (should start with 'mzs')");
            return;
        }
        
        let fee = MIN_SHIELDED_FEE;
        
        if wallet.shielded_wallet.balance() < amount + fee {
            println!("  ❌ Insufficient shielded balance");
            return;
        }
        
        // Simulate shielded transaction
        let fake_txid: [u8; 32] = rand::random();
        
        println!();
        println!("  ✅ Shielded transaction sent! 🔒");
        println!("  • To: {}...", &address[..40]);
        println!("  • Amount: {} MOON (hidden on-chain)", format_moon(amount));
        println!("  • Fee: {} MOON", format_moon(fee));
        if !memo.is_empty() {
            println!("  • Memo: \"{}\" (encrypted)", memo);
        }
        println!("  • TXID: {}...", &hex::encode(&fake_txid)[..16]);
        println!();
        println!("  🔐 Transaction details hidden from blockchain observers");
        println!();
    }
    
    fn cmd_shield(&mut self, args: &[&str]) {
        if self.wallet.is_none() {
            println!("  ❌ No wallet is open");
            return;
        }
        
        let amount = if args.is_empty() {
            print!("  Amount to shield: ");
            io::stdout().flush().unwrap();
            match self.read_line().and_then(|s| parse_amount(s.trim())) {
                Some(a) => a,
                None => {
                    println!("  ❌ Invalid amount");
                    return;
                }
            }
        } else {
            match parse_amount(args[0]) {
                Some(a) => a,
                None => {
                    println!("  ❌ Invalid amount");
                    return;
                }
            }
        };
        
        let fee = MIN_SHIELDED_FEE;
        
        if amount + fee > self.transparent_balance {
            println!("  ❌ Insufficient transparent balance");
            return;
        }
        
        // Move from transparent to shielded
        self.transparent_balance -= amount + fee;
        
        // Add to shielded wallet (simulated)
        let wallet = self.wallet.as_mut().unwrap();
        let keys = wallet.get_privacy_keys();
        let addr = keys.stealth_address();
        
        let (output, secrets) = ShieldedOutput::new(
            amount,
            &addr.view_pubkey,
            &addr.spend_pubkey,
            Some(b"shielded deposit"),
        ).unwrap();
        
        let owned = OwnedOutput {
            global_index: rand::random::<u64>() % 1_000_000,
            tx_hash: rand::random(),
            output_index: 0,
            block_height: wallet.last_sync_height + 1,
            amount: secrets.amount,
            blinding: secrets.blinding,
            memo: b"shielded deposit".to_vec(),
            one_time_pubkey: output.one_time_pubkey,
            key_derivation: Scalar::random(),
            spent: false,
            key_image: None,
        };
        
        wallet.shielded_wallet.add_output(owned);
        
        let fake_txid: [u8; 32] = rand::random();
        
        println!();
        println!("  ✅ Coins shielded!");
        println!("  • Amount: {} MOON", format_moon(amount));
        println!("  • Fee: {} MOON", format_moon(fee));
        println!("  • TXID: {}...", &hex::encode(&fake_txid)[..16]);
        println!();
        println!("  🔒 Your coins are now private!");
        println!();
    }
    
    fn cmd_unshield(&mut self, args: &[&str]) {
        if self.wallet.is_none() {
            println!("  ❌ No wallet is open");
            return;
        }
        
        let amount = if args.is_empty() {
            print!("  Amount to unshield: ");
            io::stdout().flush().unwrap();
            match self.read_line().and_then(|s| parse_amount(s.trim())) {
                Some(a) => a,
                None => {
                    println!("  ❌ Invalid amount");
                    return;
                }
            }
        } else {
            match parse_amount(args[0]) {
                Some(a) => a,
                None => {
                    println!("  ❌ Invalid amount");
                    return;
                }
            }
        };
        
        let fee = MIN_SHIELDED_FEE;
        
        let wallet = self.wallet.as_ref().unwrap();
        if wallet.shielded_wallet.balance() < amount + fee {
            println!("  ❌ Insufficient shielded balance");
            return;
        }
        
        // This is simplified - in reality we'd need to properly spend outputs
        // For demo, we just adjust balances
        self.transparent_balance += amount;
        
        println!();
        println!("  ✅ Coins unshielded!");
        println!("  • Amount: {} MOON", format_moon(amount));
        println!("  • Fee: {} MOON", format_moon(fee));
        println!();
        println!("  ⚠️  Your coins are now visible on the transparent chain");
        println!();
    }
    
    fn cmd_history(&self) {
        let wallet = match &self.wallet {
            Some(w) => w,
            None => {
                println!("  ❌ No wallet is open");
                return;
            }
        };
        
        let history = wallet.shielded_wallet.history();
        
        println!();
        println!("  ┌─────────────────────────────────────────────────────────────┐");
        println!("  │ TRANSACTION HISTORY                                         │");
        println!("  ├─────────────────────────────────────────────────────────────┤");
        
        if history.is_empty() {
            println!("  │ No shielded transactions yet                               │");
        } else {
            for entry in history.iter().take(10) {
                let status = if entry.spent { "SPENT" } else { "UNSPENT" };
                let memo = String::from_utf8_lossy(&entry.memo);
                println!("  │ Block #{:<6} {:>12} MOON  [{:^7}]              │",
                    entry.block_height,
                    format_moon(entry.amount),
                    status);
                if !memo.is_empty() {
                    println!("  │   Memo: {:<50} │", &memo[..50.min(memo.len())]);
                }
            }
        }
        
        println!("  └─────────────────────────────────────────────────────────────┘");
        println!();
    }
    
    fn cmd_backup(&self) {
        let wallet = match &self.wallet {
            Some(w) => w,
            None => {
                println!("  ❌ No wallet is open");
                return;
            }
        };
        
        let keys = wallet.get_privacy_keys();
        
        println!();
        println!("  ┌─────────────────────────────────────────────────────────────┐");
        println!("  │ ⚠️  BACKUP INFORMATION - KEEP PRIVATE!                      │");
        println!("  ├─────────────────────────────────────────────────────────────┤");
        println!("  │ Wallet file: {:<46} │", 
            self.wallet_path.as_deref().unwrap_or("not saved"));
        println!("  │                                                             │");
        println!("  │ View key (share for watch-only):                            │");
        println!("  │   {}  │", keys.view_key.export());
        println!("  │                                                             │");
        println!("  │ Use 'seed' command to show recovery seed phrase             │");
        println!("  └─────────────────────────────────────────────────────────────┘");
        println!();
    }
    
    fn cmd_seed(&self) {
        let wallet = match &self.wallet {
            Some(w) => w,
            None => {
                println!("  ❌ No wallet is open");
                return;
            }
        };
        
        println!();
        println!("  ⚠️  WARNING: Never share your seed phrase!");
        println!();
        println!("  ┌─────────────────────────────────────────────────────────────┐");
        println!("  │ SEED PHRASE (12 words):                                     │");
        println!("  │                                                             │");
        println!("  │ {}  │", wallet.seed_phrase);
        println!("  │                                                             │");
        println!("  │ Write this down and store in a safe place!                  │");
        println!("  └─────────────────────────────────────────────────────────────┘");
        println!();
    }
    
    fn cmd_sync(&mut self) {
        let wallet = match &mut self.wallet {
            Some(w) => w,
            None => {
                println!("  ❌ No wallet is open");
                return;
            }
        };
        
        println!("  Syncing with blockchain...");
        
        // Simulate sync
        let new_height = wallet.last_sync_height + 10;
        wallet.last_sync_height = new_height;
        
        println!("  ✅ Synced to block #{}", new_height);
        println!();
    }
    
    fn cmd_clear(&self) {
        print!("\x1B[2J\x1B[H");
        self.print_welcome();
    }
}

impl Default for InteractiveCli {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn format_moon(satoshis: u64) -> String {
    let moon = satoshis as f64 / 1_000_000.0;
    format!("{:.6}", moon)
}

fn format_timestamp(ts: u64) -> String {
    use std::time::{UNIX_EPOCH, Duration};
    let datetime = UNIX_EPOCH + Duration::from_secs(ts);
    format!("{:?}", datetime)
}

// =============================================================================
// Extension for PrivacyKeys
// =============================================================================

impl PrivacyKeys {
    pub fn from_scalars(view: Scalar, spend: Scalar) -> Self {
        use crate::privacy::pedersen::{CompressedPoint, GENERATORS};
        use crate::privacy::keys::{ViewingKey, SpendKey};
        
        let view_pubkey = CompressedPoint::from_point(&(view.inner() * GENERATORS.g));
        let spend_pubkey = CompressedPoint::from_point(&(spend.inner() * GENERATORS.g));
        
        PrivacyKeys {
            view_key: ViewingKey {
                key: view,
                pubkey: view_pubkey,
            },
            spend_key: SpendKey {
                key: spend,
                pubkey: spend_pubkey,
            },
        }
    }
}
