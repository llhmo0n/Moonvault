// =============================================================================
// MOONCOIN v2.0 - DNS Seeds & Peer Discovery
// =============================================================================
//
// Sistema de descubrimiento de nodos:
// - DNS Seeds para encontrar nodos iniciales
// - Seed nodes hardcodeados como fallback
// - Peer exchange entre nodos
// - Gestión de lista de peers conocidos
//
// =============================================================================

use std::net::{ToSocketAddrs, SocketAddr, IpAddr};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};

// =============================================================================
// Constants
// =============================================================================

/// Puerto por defecto para mainnet
pub const MAINNET_PORT: u16 = 38333;

/// Puerto por defecto para testnet
pub const TESTNET_PORT: u16 = 48333;

/// Archivo de peers conocidos
const KNOWN_PEERS_FILE: &str = "known_peers.json";

/// Máximo de peers a mantener
const MAX_KNOWN_PEERS: usize = 1000;

/// Tiempo de vida de un peer (segundos) antes de considerarlo stale
const PEER_TTL_SECS: u64 = 86400 * 7; // 7 días

// =============================================================================
// DNS Seeds
// =============================================================================

/// Obtiene los DNS seeds para mainnet
/// 
/// IMPORTANTE: Estos dominios deben apuntar a nodos confiables.
/// Cada dominio debe resolver a múltiples IPs de nodos activos.
/// 
/// Para configurar un DNS seed:
/// 1. Configura un servidor DNS autoritativo
/// 2. Agrega registros A apuntando a nodos Mooncoin
/// 3. Actualiza periódicamente con nodos activos
pub fn get_dns_seeds_mainnet() -> Vec<&'static str> {
    vec![
        // === CONFIGURAR TUS DNS SEEDS AQUÍ ===
        // Ejemplo:
        // "seed1.mooncoin.org",
        // "seed2.mooncoin.org",
        // "dnsseed.mooncoin.io",
        
        // Por ahora vacío hasta que tengas dominios configurados
    ]
}

/// Obtiene los DNS seeds para testnet
pub fn get_dns_seeds_testnet() -> Vec<&'static str> {
    vec![
        // "testnet-seed.mooncoin.org",
    ]
}

/// Resuelve un DNS seed a lista de IPs
pub fn resolve_dns_seed(seed: &str, port: u16) -> Vec<SocketAddr> {
    let mut addresses = Vec::new();
    
    let seed_with_port = format!("{}:{}", seed, port);
    
    match seed_with_port.to_socket_addrs() {
        Ok(addrs) => {
            for addr in addrs {
                addresses.push(addr);
            }
        }
        Err(e) => {
            log::warn!("Failed to resolve DNS seed {}: {}", seed, e);
        }
    }
    
    addresses
}

/// Resuelve todos los DNS seeds
pub fn resolve_all_dns_seeds(network: Network) -> Vec<SocketAddr> {
    let seeds = match network {
        Network::Mainnet => get_dns_seeds_mainnet(),
        Network::Testnet => get_dns_seeds_testnet(),
    };
    
    let port = match network {
        Network::Mainnet => MAINNET_PORT,
        Network::Testnet => TESTNET_PORT,
    };
    
    let mut all_addresses = Vec::new();
    
    for seed in seeds {
        let addrs = resolve_dns_seed(seed, port);
        all_addresses.extend(addrs);
    }
    
    // Eliminar duplicados
    let unique: HashSet<_> = all_addresses.into_iter().collect();
    unique.into_iter().collect()
}

// =============================================================================
// Hardcoded Seed Nodes
// =============================================================================

/// Nodos seed hardcodeados para mainnet (fallback si DNS falla)
/// 
/// IMPORTANTE: Mantener esta lista actualizada con nodos confiables.
/// Estos deben ser nodos que:
/// 1. Están siempre online
/// 2. Son de confianza (tuyos o de la comunidad)
/// 3. Tienen buena conectividad
pub fn get_seed_nodes_mainnet() -> Vec<&'static str> {
    vec![
        // === CONFIGURAR TUS SEED NODES AQUÍ ===
        // Ejemplo:
        // "192.168.1.100:38333",
        // "10.0.0.50:38333",
        // "seed1.mooncoin.org:38333",
        
        // Localhost para desarrollo (remover en producción)
        "127.0.0.1:38333",
    ]
}

/// Nodos seed hardcodeados para testnet
pub fn get_seed_nodes_testnet() -> Vec<&'static str> {
    vec![
        "127.0.0.1:48333",
    ]
}

/// Convierte string a SocketAddr
pub fn parse_seed_node(node: &str) -> Option<SocketAddr> {
    node.parse().ok()
}

/// Obtiene todos los seed nodes hardcodeados
pub fn get_all_seed_nodes(network: Network) -> Vec<SocketAddr> {
    let nodes = match network {
        Network::Mainnet => get_seed_nodes_mainnet(),
        Network::Testnet => get_seed_nodes_testnet(),
    };
    
    nodes.iter()
        .filter_map(|n| parse_seed_node(n))
        .collect()
}

// =============================================================================
// Network Type
// =============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Default for Network {
    fn default() -> Self {
        Network::Mainnet
    }
}

// =============================================================================
// Known Peer
// =============================================================================

/// Información de un peer conocido
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnownPeer {
    /// Dirección del peer
    pub address: String,
    /// Puerto
    pub port: u16,
    /// Última vez visto (timestamp)
    pub last_seen: u64,
    /// Última vez conectado exitosamente
    pub last_connected: Option<u64>,
    /// Número de conexiones exitosas
    pub success_count: u32,
    /// Número de fallos de conexión
    pub failure_count: u32,
    /// Versión del protocolo (si conocida)
    pub protocol_version: Option<u32>,
    /// User agent (si conocido)
    pub user_agent: Option<String>,
    /// Altura del blockchain (si conocida)
    pub best_height: Option<u64>,
    /// Servicios que ofrece
    pub services: u64,
    /// Es un seed node
    pub is_seed: bool,
    /// Fue baneado
    pub banned: bool,
    /// Razón del ban
    pub ban_reason: Option<String>,
}

impl KnownPeer {
    /// Crea un nuevo peer conocido
    pub fn new(address: &str, port: u16) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        KnownPeer {
            address: address.to_string(),
            port,
            last_seen: now,
            last_connected: None,
            success_count: 0,
            failure_count: 0,
            protocol_version: None,
            user_agent: None,
            best_height: None,
            services: 0,
            is_seed: false,
            banned: false,
            ban_reason: None,
        }
    }
    
    /// Crea desde SocketAddr
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self::new(&addr.ip().to_string(), addr.port())
    }
    
    /// Convierte a SocketAddr
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        let addr_str = format!("{}:{}", self.address, self.port);
        addr_str.parse().ok()
    }
    
    /// Marca como visto ahora
    pub fn mark_seen(&mut self) {
        self.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
    
    /// Marca conexión exitosa
    pub fn mark_success(&mut self) {
        self.mark_seen();
        self.last_connected = Some(self.last_seen);
        self.success_count += 1;
    }
    
    /// Marca fallo de conexión
    pub fn mark_failure(&mut self) {
        self.failure_count += 1;
    }
    
    /// Banea el peer
    pub fn ban(&mut self, reason: &str) {
        self.banned = true;
        self.ban_reason = Some(reason.to_string());
    }
    
    /// Desbanea el peer
    pub fn unban(&mut self) {
        self.banned = false;
        self.ban_reason = None;
    }
    
    /// Verifica si el peer está stale
    pub fn is_stale(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        now - self.last_seen > PEER_TTL_SECS
    }
    
    /// Calcula el score del peer (mayor = mejor)
    pub fn score(&self) -> i64 {
        let mut score: i64 = 0;
        
        // Bonus por conexiones exitosas
        score += self.success_count as i64 * 10;
        
        // Penalización por fallos
        score -= self.failure_count as i64 * 5;
        
        // Bonus si es seed
        if self.is_seed {
            score += 50;
        }
        
        // Penalización si está baneado
        if self.banned {
            score -= 1000;
        }
        
        // Bonus por reciente
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let age_hours = (now - self.last_seen) / 3600;
        score -= age_hours as i64;
        
        score
    }
}

// =============================================================================
// Peer Discovery Manager
// =============================================================================

/// Gestor de descubrimiento de peers
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerDiscovery {
    /// Peers conocidos
    pub peers: Vec<KnownPeer>,
    /// Red actual
    #[serde(default)]
    pub network: Network,
}

impl PeerDiscovery {
    /// Crea un nuevo gestor
    pub fn new(network: Network) -> Self {
        PeerDiscovery {
            peers: Vec::new(),
            network,
        }
    }
    
    /// Carga desde archivo
    pub fn load() -> Self {
        if !Path::new(KNOWN_PEERS_FILE).exists() {
            return PeerDiscovery::default();
        }
        
        match fs::read_to_string(KNOWN_PEERS_FILE) {
            Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
            Err(_) => PeerDiscovery::default(),
        }
    }
    
    /// Guarda a archivo
    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        fs::write(KNOWN_PEERS_FILE, json)
            .map_err(|e| format!("Write error: {}", e))
    }
    
    /// Agrega un peer
    pub fn add_peer(&mut self, addr: SocketAddr) {
        // Verificar si ya existe
        let addr_str = addr.ip().to_string();
        let port = addr.port();
        
        for peer in &mut self.peers {
            if peer.address == addr_str && peer.port == port {
                peer.mark_seen();
                return;
            }
        }
        
        // Agregar nuevo
        if self.peers.len() < MAX_KNOWN_PEERS {
            self.peers.push(KnownPeer::from_socket_addr(addr));
        } else {
            // Reemplazar el peer con peor score
            if let Some(worst_idx) = self.find_worst_peer_index() {
                self.peers[worst_idx] = KnownPeer::from_socket_addr(addr);
            }
        }
    }
    
    /// Encuentra el índice del peer con peor score
    fn find_worst_peer_index(&self) -> Option<usize> {
        self.peers.iter()
            .enumerate()
            .min_by_key(|(_, p)| p.score())
            .map(|(i, _)| i)
    }
    
    /// Marca un peer como exitoso
    pub fn mark_success(&mut self, addr: &SocketAddr) {
        let addr_str = addr.ip().to_string();
        let port = addr.port();
        
        for peer in &mut self.peers {
            if peer.address == addr_str && peer.port == port {
                peer.mark_success();
                return;
            }
        }
    }
    
    /// Marca un peer como fallido
    pub fn mark_failure(&mut self, addr: &SocketAddr) {
        let addr_str = addr.ip().to_string();
        let port = addr.port();
        
        for peer in &mut self.peers {
            if peer.address == addr_str && peer.port == port {
                peer.mark_failure();
                return;
            }
        }
    }
    
    /// Banea un peer
    pub fn ban_peer(&mut self, addr: &SocketAddr, reason: &str) {
        let addr_str = addr.ip().to_string();
        let port = addr.port();
        
        for peer in &mut self.peers {
            if peer.address == addr_str && peer.port == port {
                peer.ban(reason);
                return;
            }
        }
    }
    
    /// Obtiene peers para conectar (ordenados por score)
    pub fn get_peers_to_connect(&self, count: usize) -> Vec<SocketAddr> {
        let mut peers: Vec<_> = self.peers.iter()
            .filter(|p| !p.banned && !p.is_stale())
            .collect();
        
        peers.sort_by_key(|p| std::cmp::Reverse(p.score()));
        
        peers.into_iter()
            .take(count)
            .filter_map(|p| p.to_socket_addr())
            .collect()
    }
    
    /// Obtiene peers activos (vistos recientemente)
    pub fn get_active_peers(&self) -> Vec<&KnownPeer> {
        self.peers.iter()
            .filter(|p| !p.banned && !p.is_stale())
            .collect()
    }
    
    /// Limpia peers stale
    pub fn cleanup_stale(&mut self) {
        self.peers.retain(|p| !p.is_stale() || p.is_seed);
    }
    
    /// Número de peers conocidos
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
    
    /// Número de peers activos
    pub fn active_count(&self) -> usize {
        self.peers.iter()
            .filter(|p| !p.banned && !p.is_stale())
            .count()
    }
    
    /// Número de peers baneados
    pub fn banned_count(&self) -> usize {
        self.peers.iter()
            .filter(|p| p.banned)
            .count()
    }
    
    /// Descubre peers iniciales
    pub fn discover_initial_peers(&mut self) -> usize {
        let mut count = 0;
        
        // 1. Intentar DNS seeds
        let dns_peers = resolve_all_dns_seeds(self.network);
        for addr in dns_peers {
            self.add_peer(addr);
            count += 1;
        }
        
        // 2. Agregar seed nodes hardcodeados
        let seed_nodes = get_all_seed_nodes(self.network);
        for addr in seed_nodes {
            self.add_peer(addr);
            
            // Marcar como seed
            let addr_str = addr.ip().to_string();
            let port = addr.port();
            for peer in &mut self.peers {
                if peer.address == addr_str && peer.port == port {
                    peer.is_seed = true;
                }
            }
            
            count += 1;
        }
        
        count
    }
}

// =============================================================================
// Bootstrap
// =============================================================================

/// Inicializa el descubrimiento de peers
pub fn bootstrap_peer_discovery(network: Network) -> PeerDiscovery {
    let mut discovery = PeerDiscovery::load();
    discovery.network = network;
    
    // Si no hay peers, descubrir iniciales
    if discovery.peer_count() == 0 {
        let found = discovery.discover_initial_peers();
        log::info!("Discovered {} initial peers", found);
    }
    
    // Limpiar stale
    discovery.cleanup_stale();
    
    // Guardar
    let _ = discovery.save();
    
    discovery
}

// =============================================================================
// Addr Message (para intercambio de peers)
// =============================================================================

/// Mensaje de dirección para intercambio entre nodos
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddrMessage {
    /// Lista de direcciones
    pub addresses: Vec<AddrEntry>,
}

/// Entrada de dirección
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddrEntry {
    /// Timestamp
    pub timestamp: u64,
    /// Servicios
    pub services: u64,
    /// IP (v4 o v6)
    pub ip: String,
    /// Puerto
    pub port: u16,
}

impl AddrMessage {
    /// Crea un mensaje vacío
    pub fn new() -> Self {
        AddrMessage {
            addresses: Vec::new(),
        }
    }
    
    /// Agrega una dirección
    pub fn add(&mut self, addr: SocketAddr, services: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.addresses.push(AddrEntry {
            timestamp: now,
            services,
            ip: addr.ip().to_string(),
            port: addr.port(),
        });
    }
    
    /// Crea mensaje desde lista de peers
    pub fn from_peers(peers: &[KnownPeer], max: usize) -> Self {
        let mut msg = AddrMessage::new();
        
        for peer in peers.iter().take(max) {
            if !peer.banned && !peer.is_stale() {
                if let Ok(ip) = peer.address.parse::<IpAddr>() {
                    msg.addresses.push(AddrEntry {
                        timestamp: peer.last_seen,
                        services: peer.services,
                        ip: ip.to_string(),
                        port: peer.port,
                    });
                }
            }
        }
        
        msg
    }
    
    /// Convierte a lista de SocketAddr
    pub fn to_socket_addrs(&self) -> Vec<SocketAddr> {
        self.addresses.iter()
            .filter_map(|a| {
                let addr_str = format!("{}:{}", a.ip, a.port);
                addr_str.parse().ok()
            })
            .collect()
    }
}

impl Default for AddrMessage {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_known_peer() {
        let mut peer = KnownPeer::new("127.0.0.1", 38333);
        
        assert!(!peer.banned);
        assert!(!peer.is_stale());
        assert_eq!(peer.success_count, 0);
        
        peer.mark_success();
        assert_eq!(peer.success_count, 1);
        assert!(peer.last_connected.is_some());
        
        peer.ban("test");
        assert!(peer.banned);
        assert!(peer.score() < 0);
    }
    
    #[test]
    fn test_peer_discovery() {
        let mut discovery = PeerDiscovery::new(Network::Mainnet);
        
        let addr: SocketAddr = "127.0.0.1:38333".parse().unwrap();
        discovery.add_peer(addr);
        
        assert_eq!(discovery.peer_count(), 1);
        assert_eq!(discovery.active_count(), 1);
        
        discovery.ban_peer(&addr, "test");
        assert_eq!(discovery.banned_count(), 1);
    }
    
    #[test]
    fn test_addr_message() {
        let mut msg = AddrMessage::new();
        let addr: SocketAddr = "127.0.0.1:38333".parse().unwrap();
        
        msg.add(addr, 1);
        
        assert_eq!(msg.addresses.len(), 1);
        
        let addrs = msg.to_socket_addrs();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], addr);
    }
}
