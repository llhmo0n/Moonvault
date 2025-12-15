// =============================================================================
// MOONCOIN v2.0 - Peer Manager (Advanced Networking)
// =============================================================================
//
// Gestión avanzada de peers con:
// - DNS seed discovery
// - Peer scoring y banning
// - Persistencia de peers conocidos
// - Headers-first synchronization
// - Address relay
//
// =============================================================================

use std::collections::HashMap;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

use crate::lib::P2P_PORT;
use crate::network::BlockHeader;

// =============================================================================
// Constants
// =============================================================================

const PEERS_FILE: &str = "peers.json";
const MAX_PEERS: usize = 125;
const MAX_OUTBOUND: usize = 8;
const MAX_INBOUND: usize = 117;
const BAN_THRESHOLD: i32 = 100;
const BAN_DURATION: u64 = 24 * 60 * 60; // 24 hours in seconds
const PEER_TIMEOUT: u64 = 90; // 90 seconds without response = disconnect

// =============================================================================
// DNS Seeds
// =============================================================================

/// Lista de DNS seeds para descubrimiento de peers
pub fn get_dns_seeds() -> Vec<&'static str> {
    vec![
        // Cuando tengas servidores DNS seed, agrégalos aquí:
        // "seed.mooncoin.org",
        // "dnsseed.mooncoin.io",
        // "seed.mooncoin.net",
    ]
}

/// Lista de nodos semilla estáticos (IPs conocidas)
pub fn get_static_seeds() -> Vec<String> {
    vec![
        // Agrega IPs de nodos conocidos aquí:
        // "192.168.1.100:38333".to_string(),
        // "45.33.32.156:38333".to_string(),
    ]
}

/// Resuelve DNS seeds a direcciones IP
pub fn resolve_dns_seeds() -> Vec<SocketAddr> {
    let mut addresses = Vec::new();
    
    for seed in get_dns_seeds() {
        let host = format!("{}:{}", seed, P2P_PORT);
        if let Ok(addrs) = host.to_socket_addrs() {
            for addr in addrs {
                addresses.push(addr);
            }
        }
    }
    
    addresses
}

/// Obtiene todos los peers iniciales (DNS + estáticos)
pub fn get_bootstrap_peers() -> Vec<String> {
    let mut peers = Vec::new();
    
    // DNS seeds
    for addr in resolve_dns_seeds() {
        peers.push(addr.to_string());
    }
    
    // Static seeds
    peers.extend(get_static_seeds());
    
    peers
}

// =============================================================================
// Peer Info
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerData {
    pub addr: String,
    pub services: u64,
    pub last_seen: u64,
    pub last_try: u64,
    pub last_success: u64,
    pub attempts: u32,
    pub success_count: u32,
    pub ban_score: i32,
    pub banned_until: u64,
    pub user_agent: String,
    pub version: u32,
    pub height: u64,
    pub is_outbound: bool,
}

impl PeerData {
    pub fn new(addr: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        PeerData {
            addr,
            services: 0,
            last_seen: now,
            last_try: 0,
            last_success: 0,
            attempts: 0,
            success_count: 0,
            ban_score: 0,
            banned_until: 0,
            user_agent: String::new(),
            version: 0,
            height: 0,
            is_outbound: true,
        }
    }
    
    pub fn is_banned(&self) -> bool {
        if self.banned_until == 0 {
            return false;
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now < self.banned_until
    }
    
    pub fn update_seen(&mut self) {
        self.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    pub fn mark_success(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.last_success = now;
        self.last_seen = now;
        self.success_count += 1;
        
        // Reduce ban score on success
        self.ban_score = (self.ban_score - 1).max(0);
    }
    
    pub fn mark_attempt(&mut self) {
        self.last_try = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.attempts += 1;
    }
    
    pub fn add_ban_score(&mut self, score: i32, reason: &str) {
        self.ban_score += score;
        
        if self.ban_score >= BAN_THRESHOLD {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            self.banned_until = now + BAN_DURATION;
            log::warn!("Peer {} banned for {}: score={}", self.addr, reason, self.ban_score);
        }
    }
}

// =============================================================================
// Peer Manager
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerManager {
    /// Todos los peers conocidos
    pub peers: HashMap<String, PeerData>,
    
    /// Peers actualmente conectados
    #[serde(skip)]
    pub connected: HashMap<String, ConnectedPeer>,
    
    /// Nuestro nonce para detectar auto-conexión
    #[serde(skip)]
    pub local_nonce: u64,
}

#[derive(Clone, Debug)]
pub struct ConnectedPeer {
    pub addr: String,
    pub is_outbound: bool,
    pub connected_at: u64,
    pub last_recv: u64,
    pub last_send: u64,
    pub bytes_recv: u64,
    pub bytes_sent: u64,
    pub ping_nonce: Option<u64>,
    pub ping_time: Option<u64>,
    pub version: u32,
    pub height: u64,
    pub syncing: bool,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    pub fn new() -> Self {
        PeerManager {
            peers: HashMap::new(),
            connected: HashMap::new(),
            local_nonce: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        }
    }
    
    /// Carga peers desde disco
    pub fn load() -> Self {
        if let Ok(data) = fs::read_to_string(PEERS_FILE) {
            if let Ok(manager) = serde_json::from_str(&data) {
                return manager;
            }
        }
        Self::new()
    }
    
    /// Guarda peers a disco
    pub fn save(&self) {
        if let Ok(data) = serde_json::to_string_pretty(self) {
            let _ = fs::write(PEERS_FILE, data);
        }
    }
    
    /// Añade un nuevo peer
    pub fn add_peer(&mut self, addr: &str) -> bool {
        if self.peers.contains_key(addr) {
            return false;
        }
        
        if self.peers.len() >= MAX_PEERS * 10 {
            // Limpiar peers antiguos
            self.cleanup_old_peers();
        }
        
        self.peers.insert(addr.to_string(), PeerData::new(addr.to_string()));
        true
    }
    
    /// Añade múltiples peers
    pub fn add_peers(&mut self, addrs: &[String]) {
        for addr in addrs {
            self.add_peer(addr);
        }
    }
    
    /// Obtiene un peer para conectar
    pub fn get_peer_to_connect(&self) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Filtrar peers válidos
        let mut candidates: Vec<_> = self.peers.values()
            .filter(|p| {
                !p.is_banned() &&
                !self.connected.contains_key(&p.addr) &&
                (p.last_try == 0 || now - p.last_try > 60) // No reintentar muy rápido
            })
            .collect();
        
        // Ordenar por prioridad
        candidates.sort_by(|a, b| {
            // Priorizar peers exitosos recientes
            let a_score = a.success_count as i64 - a.attempts as i64;
            let b_score = b.success_count as i64 - b.attempts as i64;
            b_score.cmp(&a_score)
        });
        
        candidates.first().map(|p| p.addr.clone())
    }
    
    /// Obtiene peers para compartir con otros
    pub fn get_peers_to_relay(&self, count: usize) -> Vec<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut good_peers: Vec<_> = self.peers.values()
            .filter(|p| {
                !p.is_banned() &&
                p.success_count > 0 &&
                now - p.last_success < 3 * 60 * 60 // Visto en las últimas 3 horas
            })
            .collect();
        
        // Ordenar por last_success (más recientes primero)
        good_peers.sort_by(|a, b| b.last_success.cmp(&a.last_success));
        
        good_peers.iter()
            .take(count)
            .map(|p| p.addr.clone())
            .collect()
    }
    
    /// Marca peer como conectado
    pub fn peer_connected(&mut self, addr: &str, is_outbound: bool) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.connected.insert(addr.to_string(), ConnectedPeer {
            addr: addr.to_string(),
            is_outbound,
            connected_at: now,
            last_recv: now,
            last_send: now,
            bytes_recv: 0,
            bytes_sent: 0,
            ping_nonce: None,
            ping_time: None,
            version: 0,
            height: 0,
            syncing: false,
        });
        
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.mark_success();
            peer.is_outbound = is_outbound;
        } else {
            let mut peer = PeerData::new(addr.to_string());
            peer.mark_success();
            peer.is_outbound = is_outbound;
            self.peers.insert(addr.to_string(), peer);
        }
    }
    
    /// Marca peer como desconectado
    pub fn peer_disconnected(&mut self, addr: &str) {
        self.connected.remove(addr);
    }
    
    /// Actualiza info del peer después de version
    pub fn update_peer_info(&mut self, addr: &str, version: u32, height: u64, user_agent: &str) {
        if let Some(connected) = self.connected.get_mut(addr) {
            connected.version = version;
            connected.height = height;
        }
        
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.version = version;
            peer.height = height;
            peer.user_agent = user_agent.to_string();
            peer.update_seen();
        }
    }
    
    /// Añade ban score a un peer
    pub fn misbehaving(&mut self, addr: &str, score: i32, reason: &str) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.add_ban_score(score, reason);
            
            if peer.is_banned() {
                self.connected.remove(addr);
            }
        }
    }
    
    /// Banea un peer manualmente
    pub fn ban_peer(&mut self, addr: &str, duration_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.banned_until = now + duration_secs;
            peer.ban_score = BAN_THRESHOLD;
        }
        
        self.connected.remove(addr);
    }
    
    /// Desbanea un peer
    pub fn unban_peer(&mut self, addr: &str) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.banned_until = 0;
            peer.ban_score = 0;
        }
    }
    
    /// Limpia peers antiguos y baneados expirados
    pub fn cleanup_old_peers(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Eliminar peers muy antiguos sin éxito
        self.peers.retain(|_, p| {
            // Mantener si:
            // - Fue exitoso recientemente
            // - Es reciente
            // - No ha fallado muchas veces
            p.success_count > 0 ||
            now - p.last_seen < 7 * 24 * 60 * 60 || // 7 días
            p.attempts < 3
        });
        
        // Desbanear peers cuyo ban expiró
        for peer in self.peers.values_mut() {
            if peer.banned_until > 0 && now >= peer.banned_until {
                peer.banned_until = 0;
                peer.ban_score = 0;
            }
        }
    }
    
    /// Obtiene estadísticas
    pub fn stats(&self) -> PeerStats {
        let _now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let outbound = self.connected.values().filter(|p| p.is_outbound).count();
        let inbound = self.connected.values().filter(|p| !p.is_outbound).count();
        let banned = self.peers.values().filter(|p| p.is_banned()).count();
        let known = self.peers.len();
        
        let best_height = self.connected.values()
            .map(|p| p.height)
            .max()
            .unwrap_or(0);
        
        PeerStats {
            connected: self.connected.len(),
            outbound,
            inbound,
            banned,
            known,
            best_height,
        }
    }
    
    /// Verifica si podemos aceptar más conexiones outbound
    pub fn can_connect_outbound(&self) -> bool {
        self.connected.values().filter(|p| p.is_outbound).count() < MAX_OUTBOUND
    }
    
    /// Verifica si podemos aceptar más conexiones inbound
    pub fn can_accept_inbound(&self) -> bool {
        self.connected.values().filter(|p| !p.is_outbound).count() < MAX_INBOUND
    }
    
    /// Obtiene el peer con mayor altura
    pub fn get_best_peer(&self) -> Option<String> {
        self.connected.values()
            .max_by_key(|p| p.height)
            .map(|p| p.addr.clone())
    }
    
    /// Obtiene peers para sincronización
    pub fn get_sync_peers(&self) -> Vec<String> {
        let mut peers: Vec<_> = self.connected.values()
            .filter(|p| !p.syncing)
            .collect();
        
        peers.sort_by(|a, b| b.height.cmp(&a.height));
        
        peers.iter().take(3).map(|p| p.addr.clone()).collect()
    }
    
    /// Marca peer como sincronizando
    pub fn set_syncing(&mut self, addr: &str, syncing: bool) {
        if let Some(peer) = self.connected.get_mut(addr) {
            peer.syncing = syncing;
        }
    }
}

// =============================================================================
// Peer Stats
// =============================================================================

#[derive(Debug, Clone)]
pub struct PeerStats {
    pub connected: usize,
    pub outbound: usize,
    pub inbound: usize,
    pub banned: usize,
    pub known: usize,
    pub best_height: u64,
}

// =============================================================================
// Ban Reasons
// =============================================================================

pub mod ban_reason {
    pub const INVALID_BLOCK: i32 = 100;      // Ban inmediato
    pub const INVALID_TX: i32 = 10;          // Penalización menor
    pub const DOS_ATTACK: i32 = 100;         // Ban inmediato
    pub const PROTOCOL_VIOLATION: i32 = 20;  // Penalización media
    pub const TIMEOUT: i32 = 5;              // Penalización leve
    pub const INVALID_MESSAGE: i32 = 10;     // Penalización menor
    pub const SPAM: i32 = 50;                // Penalización alta
}

// =============================================================================
// Headers-First Sync
// =============================================================================

#[derive(Debug, Clone)]
pub struct HeadersSync {
    /// Headers descargados pero no validados
    pub pending_headers: Vec<BlockHeader>,
    
    /// Último header conocido
    pub tip_hash: String,
    
    /// Altura del tip
    pub tip_height: u64,
    
    /// Peer del que estamos sincronizando
    pub sync_peer: Option<String>,
    
    /// Bloques pendientes de descargar
    pub blocks_to_download: Vec<String>,
    
    /// Bloques en vuelo (solicitados pero no recibidos)
    pub blocks_in_flight: HashMap<String, u64>, // hash -> timestamp
}

impl Default for HeadersSync {
    fn default() -> Self {
        Self::new()
    }
}

impl HeadersSync {
    pub fn new() -> Self {
        HeadersSync {
            pending_headers: Vec::new(),
            tip_hash: String::new(),
            tip_height: 0,
            sync_peer: None,
            blocks_to_download: Vec::new(),
            blocks_in_flight: HashMap::new(),
        }
    }
    
    /// Inicializa sincronización desde nuestra cadena actual
    pub fn init(&mut self, tip_hash: String, tip_height: u64) {
        self.tip_hash = tip_hash;
        self.tip_height = tip_height;
    }
    
    /// Añade headers recibidos
    pub fn add_headers(&mut self, headers: Vec<BlockHeader>) -> Result<usize, String> {
        let mut added = 0;
        
        for header in headers {
            // Verificar que conecta con nuestro tip o pending
            if header.prev_hash == self.tip_hash || 
               self.pending_headers.last().map(|h| &h.hash) == Some(&header.prev_hash) {
                self.pending_headers.push(header);
                added += 1;
            } else {
                return Err("Header doesn't connect".to_string());
            }
        }
        
        // Actualizar tip
        if let Some(last) = self.pending_headers.last() {
            self.tip_hash = last.hash.clone();
            self.tip_height = last.height;
        }
        
        Ok(added)
    }
    
    /// Obtiene headers pendientes de validar
    pub fn get_pending_headers(&mut self, count: usize) -> Vec<BlockHeader> {
        let take = count.min(self.pending_headers.len());
        self.pending_headers.drain(..take).collect()
    }
    
    /// Añade bloque a la cola de descarga
    pub fn queue_block(&mut self, hash: String) {
        if !self.blocks_to_download.contains(&hash) && 
           !self.blocks_in_flight.contains_key(&hash) {
            self.blocks_to_download.push(hash);
        }
    }
    
    /// Obtiene siguiente bloque a descargar
    pub fn next_block_to_download(&mut self) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Limpiar bloques en vuelo que expiraron (30 segundos)
        self.blocks_in_flight.retain(|hash, timestamp| {
            if now - *timestamp > 30 {
                self.blocks_to_download.push(hash.clone());
                false
            } else {
                true
            }
        });
        
        // Obtener siguiente
        if let Some(hash) = self.blocks_to_download.pop() {
            self.blocks_in_flight.insert(hash.clone(), now);
            Some(hash)
        } else {
            None
        }
    }
    
    /// Marca bloque como recibido
    pub fn block_received(&mut self, hash: &str) {
        self.blocks_in_flight.remove(hash);
    }
    
    /// Verifica si la sincronización está completa
    pub fn is_synced(&self) -> bool {
        self.pending_headers.is_empty() && 
        self.blocks_to_download.is_empty() && 
        self.blocks_in_flight.is_empty()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_peer_manager() {
        let mut pm = PeerManager::new();
        
        pm.add_peer("192.168.1.1:38333");
        pm.add_peer("192.168.1.2:38333");
        
        assert_eq!(pm.peers.len(), 2);
        
        pm.peer_connected("192.168.1.1:38333", true);
        assert_eq!(pm.connected.len(), 1);
        
        pm.peer_disconnected("192.168.1.1:38333");
        assert_eq!(pm.connected.len(), 0);
    }
    
    #[test]
    fn test_ban_score() {
        let mut pm = PeerManager::new();
        pm.add_peer("192.168.1.1:38333");
        
        // Añadir ban score
        pm.misbehaving("192.168.1.1:38333", 50, "test");
        assert!(!pm.peers["192.168.1.1:38333"].is_banned());
        
        pm.misbehaving("192.168.1.1:38333", 50, "test");
        assert!(pm.peers["192.168.1.1:38333"].is_banned());
    }
}
