// =============================================================================
// MOONCOIN v2.0 - Testnet
// =============================================================================
//
// Red de pruebas separada:
// - Parámetros diferentes (dificultad más baja)
// - Archivos separados (no mezclar con mainnet)
// - Prefijos de dirección diferentes
// - Puertos diferentes
// - Monedas sin valor real
//
// =============================================================================

use serde::{Serialize, Deserialize};

// =============================================================================
// Network Type
// =============================================================================

/// Tipo de red
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    /// Red principal (mainnet)
    Mainnet,
    /// Red de pruebas (testnet)
    Testnet,
    /// Red de regresión (regtest) - para tests automatizados
    Regtest,
}

impl Default for Network {
    fn default() -> Self {
        Network::Mainnet
    }
}

impl Network {
    /// Desde string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "mainnet" | "main" => Some(Network::Mainnet),
            "testnet" | "test" => Some(Network::Testnet),
            "regtest" | "reg" => Some(Network::Regtest),
            _ => None,
        }
    }
    
    /// A string
    pub fn to_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
        }
    }
    
    /// Nombre para mostrar
    pub fn display_name(&self) -> &'static str {
        match self {
            Network::Mainnet => "Mainnet",
            Network::Testnet => "Testnet",
            Network::Regtest => "Regtest",
        }
    }
    
    /// Color para terminal
    pub fn color_code(&self) -> &'static str {
        match self {
            Network::Mainnet => "\x1b[32m", // Verde
            Network::Testnet => "\x1b[33m", // Amarillo
            Network::Regtest => "\x1b[35m", // Magenta
        }
    }
}

// =============================================================================
// Network Parameters
// =============================================================================

/// Parámetros de red
#[derive(Clone, Debug)]
pub struct NetworkParams {
    /// Tipo de red
    pub network: Network,
    
    // === Direcciones ===
    /// Prefijo de dirección P2PKH
    pub p2pkh_prefix: u8,
    /// Prefijo de dirección P2SH
    pub p2sh_prefix: u8,
    /// HRP para Bech32 (SegWit)
    pub bech32_hrp: &'static str,
    
    // === Puertos ===
    /// Puerto P2P
    pub p2p_port: u16,
    /// Puerto RPC
    pub rpc_port: u16,
    /// Puerto Explorer
    pub explorer_port: u16,
    
    // === Archivos ===
    /// Directorio de datos
    pub data_dir: &'static str,
    /// Archivo de blockchain
    pub chain_file: &'static str,
    /// Archivo de wallet
    pub wallet_file: &'static str,
    
    // === Consenso ===
    /// Dificultad inicial
    pub initial_difficulty: u32,
    /// Tiempo objetivo entre bloques (segundos)
    pub block_time_target: u64,
    /// Intervalo de ajuste de dificultad
    pub difficulty_adjustment_interval: u64,
    /// Recompensa inicial (satoshis)
    pub initial_reward: u64,
    /// Intervalo de halving
    pub halving_interval: u64,
    /// Madurez de coinbase
    pub coinbase_maturity: u64,
    
    // === Genesis ===
    /// Hash del bloque genesis
    pub genesis_hash: &'static str,
    /// Timestamp del genesis
    pub genesis_timestamp: u64,
}

impl NetworkParams {
    /// Parámetros para Mainnet
    pub fn mainnet() -> Self {
        NetworkParams {
            network: Network::Mainnet,
            
            // Direcciones
            p2pkh_prefix: 0x32,      // 'M'
            p2sh_prefix: 0x35,       // '3' 
            bech32_hrp: "mc",
            
            // Puertos
            p2p_port: 38333,
            rpc_port: 38332,
            explorer_port: 3000,
            
            // Archivos
            data_dir: "mooncoin_data",
            chain_file: "mooncoin.chain",
            wallet_file: "wallet.dat",
            
            // Consenso
            initial_difficulty: 0x1d00ffff,
            block_time_target: 300,          // 5 minutos
            difficulty_adjustment_interval: 2016,
            initial_reward: 50_00000000,     // 50 MOON
            halving_interval: 210_000,
            coinbase_maturity: 100,
            
            // Genesis
            genesis_hash: "0000000000000000000000000000000000000000000000000000000000000000",
            genesis_timestamp: 1704067200,   // 2024-01-01
        }
    }
    
    /// Parámetros para Testnet
    pub fn testnet() -> Self {
        NetworkParams {
            network: Network::Testnet,
            
            // Direcciones (diferentes para evitar confusión)
            p2pkh_prefix: 0x6F,      // 'm' o 'n'
            p2sh_prefix: 0xC4,       // '2'
            bech32_hrp: "tmc",       // testnet mooncoin
            
            // Puertos (diferentes)
            p2p_port: 48333,
            rpc_port: 48332,
            explorer_port: 4000,
            
            // Archivos (separados)
            data_dir: "mooncoin_testnet",
            chain_file: "testnet.chain",
            wallet_file: "testnet_wallet.dat",
            
            // Consenso (más fácil para testing)
            initial_difficulty: 0x1f00ffff,  // Muy fácil
            block_time_target: 60,           // 1 minuto
            difficulty_adjustment_interval: 100,
            initial_reward: 50_00000000,
            halving_interval: 21_000,        // Más rápido
            coinbase_maturity: 10,           // Más rápido
            
            // Genesis
            genesis_hash: "0000000000000000000000000000000000000000000000000000000000000001",
            genesis_timestamp: 1704067200,
        }
    }
    
    /// Parámetros para Regtest
    pub fn regtest() -> Self {
        NetworkParams {
            network: Network::Regtest,
            
            // Direcciones
            p2pkh_prefix: 0x6F,
            p2sh_prefix: 0xC4,
            bech32_hrp: "rmcrt",
            
            // Puertos
            p2p_port: 58333,
            rpc_port: 58332,
            explorer_port: 5000,
            
            // Archivos
            data_dir: "mooncoin_regtest",
            chain_file: "regtest.chain",
            wallet_file: "regtest_wallet.dat",
            
            // Consenso (instantáneo para tests)
            initial_difficulty: 0x207fffff,  // Mínimo
            block_time_target: 1,            // 1 segundo
            difficulty_adjustment_interval: 1,
            initial_reward: 50_00000000,
            halving_interval: 150,
            coinbase_maturity: 1,
            
            // Genesis
            genesis_hash: "0000000000000000000000000000000000000000000000000000000000000002",
            genesis_timestamp: 1704067200,
        }
    }
    
    /// Obtiene parámetros para una red
    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::mainnet(),
            Network::Testnet => Self::testnet(),
            Network::Regtest => Self::regtest(),
        }
    }
    
    /// Convierte una dirección de una red a otra (solo display)
    pub fn address_prefix_char(&self) -> char {
        match self.network {
            Network::Mainnet => 'M',
            Network::Testnet => 't',
            Network::Regtest => 'r',
        }
    }
    
    /// Verifica si una dirección es válida para esta red
    pub fn is_valid_address(&self, address: &str) -> bool {
        match self.network {
            Network::Mainnet => {
                address.starts_with('M') || address.starts_with("mc1")
            }
            Network::Testnet => {
                address.starts_with('t') || address.starts_with('n') || 
                address.starts_with("tmc1")
            }
            Network::Regtest => {
                address.starts_with('r') || address.starts_with("rmcrt1")
            }
        }
    }
}

// =============================================================================
// Global Network State
// =============================================================================

use std::sync::RwLock;

lazy_static::lazy_static! {
    /// Red activa global
    static ref ACTIVE_NETWORK: RwLock<Network> = RwLock::new(Network::Mainnet);
    /// Parámetros activos
    static ref ACTIVE_PARAMS: RwLock<NetworkParams> = RwLock::new(NetworkParams::mainnet());
}

/// Establece la red activa
pub fn set_network(network: Network) {
    if let Ok(mut n) = ACTIVE_NETWORK.write() {
        *n = network;
    }
    if let Ok(mut p) = ACTIVE_PARAMS.write() {
        *p = NetworkParams::for_network(network);
    }
}

/// Obtiene la red activa
pub fn get_network() -> Network {
    ACTIVE_NETWORK.read().map(|n| *n).unwrap_or(Network::Mainnet)
}

/// Obtiene los parámetros activos
pub fn get_params() -> NetworkParams {
    ACTIVE_PARAMS.read().map(|p| p.clone()).unwrap_or_else(|_| NetworkParams::mainnet())
}

/// Verifica si estamos en testnet
pub fn is_testnet() -> bool {
    get_network() == Network::Testnet
}

/// Verifica si estamos en regtest
pub fn is_regtest() -> bool {
    get_network() == Network::Regtest
}

/// Verifica si estamos en mainnet
pub fn is_mainnet() -> bool {
    get_network() == Network::Mainnet
}

// =============================================================================
// Testnet Faucet
// =============================================================================

/// Faucet para testnet (dar monedas gratis para testing)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Faucet {
    /// Dirección del faucet
    pub address: String,
    /// Balance disponible
    pub balance: u64,
    /// Límite por solicitud
    pub limit_per_request: u64,
    /// Cooldown entre solicitudes (segundos)
    pub cooldown_secs: u64,
    /// Últimas solicitudes (dirección -> timestamp)
    pub last_requests: std::collections::HashMap<String, u64>,
}

impl Default for Faucet {
    fn default() -> Self {
        Self::new()
    }
}

impl Faucet {
    pub fn new() -> Self {
        Faucet {
            address: String::new(),
            balance: 1_000_000_00000000, // 1M tMOON
            limit_per_request: 100_00000000, // 100 tMOON
            cooldown_secs: 3600, // 1 hora
            last_requests: std::collections::HashMap::new(),
        }
    }
    
    /// Verifica si puede reclamar
    pub fn can_claim(&self, address: &str) -> Result<(), String> {
        if !is_testnet() && !is_regtest() {
            return Err("Faucet only available on testnet/regtest".to_string());
        }
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if let Some(&last) = self.last_requests.get(address) {
            let elapsed = now - last;
            if elapsed < self.cooldown_secs {
                let remaining = self.cooldown_secs - elapsed;
                return Err(format!("Please wait {} minutes", remaining / 60));
            }
        }
        
        if self.balance < self.limit_per_request {
            return Err("Faucet is empty".to_string());
        }
        
        Ok(())
    }
    
    /// Registra una solicitud
    pub fn record_claim(&mut self, address: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.last_requests.insert(address.to_string(), now);
        self.balance = self.balance.saturating_sub(self.limit_per_request);
    }
}

// =============================================================================
// Network Info Display
// =============================================================================

/// Muestra información de la red
pub fn print_network_info() {
    let params = get_params();
    let network = get_network();
    
    let color = params.network.color_code();
    let reset = "\x1b[0m";
    
    println!("{}══════════════════════════════════════{}", color, reset);
    println!("{}  Network: {}{}", color, params.network.display_name(), reset);
    println!("{}══════════════════════════════════════{}", color, reset);
    
    if network != Network::Mainnet {
        println!();
        println!("  ⚠️  WARNING: This is NOT mainnet!");
        println!("  ⚠️  Coins have NO real value.");
    }
}

/// Banner para testnet
pub fn testnet_banner() -> String {
    r#"
  ╔════════════════════════════════════════╗
  ║         🧪 TESTNET MODE 🧪             ║
  ║   Coins have NO real value!            ║
  ╚════════════════════════════════════════╝
"#.to_string()
}

/// Banner para regtest
pub fn regtest_banner() -> String {
    r#"
  ╔════════════════════════════════════════╗
  ║         🔬 REGTEST MODE 🔬             ║
  ║   For automated testing only           ║
  ╚════════════════════════════════════════╝
"#.to_string()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_network_params() {
        let mainnet = NetworkParams::mainnet();
        let testnet = NetworkParams::testnet();
        
        // Puertos diferentes
        assert_ne!(mainnet.p2p_port, testnet.p2p_port);
        assert_ne!(mainnet.rpc_port, testnet.rpc_port);
        
        // Archivos diferentes
        assert_ne!(mainnet.chain_file, testnet.chain_file);
        
        // Testnet más fácil
        assert!(testnet.initial_difficulty > mainnet.initial_difficulty);
        assert!(testnet.block_time_target < mainnet.block_time_target);
    }
    
    #[test]
    fn test_network_from_str() {
        assert_eq!(Network::from_str("mainnet"), Some(Network::Mainnet));
        assert_eq!(Network::from_str("testnet"), Some(Network::Testnet));
        assert_eq!(Network::from_str("regtest"), Some(Network::Regtest));
        assert_eq!(Network::from_str("invalid"), None);
    }
    
    #[test]
    fn test_address_validation() {
        let mainnet = NetworkParams::mainnet();
        let testnet = NetworkParams::testnet();
        
        assert!(mainnet.is_valid_address("MCtest123"));
        assert!(mainnet.is_valid_address("mc1qtest"));
        assert!(!mainnet.is_valid_address("ttest123"));
        
        assert!(testnet.is_valid_address("ttest123"));
        assert!(testnet.is_valid_address("tmc1qtest"));
        assert!(!testnet.is_valid_address("MCtest123"));
    }
}
