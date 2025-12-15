// =============================================================================
// MOONCOIN v2.22 - Dandelion++ Protocol
// =============================================================================
//
// Implementación del protocolo Dandelion++ para privacidad de red:
// - Oculta la IP del nodo que origina una transacción
// - Dos fases: Stem (propagación lineal) y Fluff (difusión normal)
// - Protección contra ataques de timing y graph analysis
//
// Paper: https://arxiv.org/abs/1805.11060
//
// =============================================================================

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use rand::Rng;

// =============================================================================
// Constants
// =============================================================================

/// Probabilidad de pasar de stem a fluff (por salto)
/// Geometric distribution con p = 0.1 → promedio 10 saltos
const STEM_TO_FLUFF_PROBABILITY: f64 = 0.1;

/// Tiempo máximo en stem phase antes de hacer fluff (failsafe)
const STEM_TIMEOUT_SECS: u64 = 60;

/// Intervalo para rotar el grafo de stem
const GRAPH_ROTATION_SECS: u64 = 600; // 10 minutos

/// Número de outbound stems por nodo
const NUM_STEM_PEERS: usize = 2;

/// Tiempo mínimo de embargo antes de difundir (anti-timing)
const MIN_EMBARGO_SECS: u64 = 5;

/// Tiempo máximo de embargo
const MAX_EMBARGO_SECS: u64 = 30;

/// Máximo de TXs en stem phase simultáneamente
const MAX_STEM_TXS: usize = 1000;

// =============================================================================
// Dandelion State
// =============================================================================

/// Fase actual de una transacción en Dandelion
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DandelionPhase {
    /// Fase stem: propagación lineal (privada)
    Stem,
    /// Fase fluff: difusión normal (pública)
    Fluff,
}

/// Estado de una transacción en el protocolo Dandelion
#[derive(Clone, Debug)]
pub struct DandelionTxState {
    /// ID de la transacción
    pub txid: String,
    /// Fase actual
    pub phase: DandelionPhase,
    /// Timestamp de entrada al sistema
    pub received_at: Instant,
    /// Timestamp de cuando debe hacer fluff (embargo)
    pub fluff_at: Instant,
    /// Número de saltos en stem (si conocido)
    pub stem_hops: u32,
    /// Peer que nos envió esta TX (None si es nuestra)
    pub received_from: Option<SocketAddr>,
    /// Si ya fue enviada en stem
    pub stem_sent: bool,
    /// Si ya fue difundida en fluff
    pub fluff_sent: bool,
}

impl DandelionTxState {
    /// Crea estado para TX propia (originada por nosotros)
    pub fn new_own(txid: String) -> Self {
        let now = Instant::now();
        let embargo = random_embargo();
        
        DandelionTxState {
            txid,
            phase: DandelionPhase::Stem,
            received_at: now,
            fluff_at: now + embargo,
            stem_hops: 0,
            received_from: None,
            stem_sent: false,
            fluff_sent: false,
        }
    }
    
    /// Crea estado para TX recibida en stem phase
    pub fn new_stem(txid: String, from: SocketAddr) -> Self {
        let now = Instant::now();
        let embargo = random_embargo();
        
        // Decidir si continuar stem o hacer fluff
        let phase = if should_fluff() {
            DandelionPhase::Fluff
        } else {
            DandelionPhase::Stem
        };
        
        DandelionTxState {
            txid,
            phase,
            received_at: now,
            fluff_at: now + embargo,
            stem_hops: 1, // Al menos 1 salto
            received_from: Some(from),
            stem_sent: false,
            fluff_sent: false,
        }
    }
    
    /// Crea estado para TX recibida en fluff phase
    pub fn new_fluff(txid: String, from: SocketAddr) -> Self {
        let now = Instant::now();
        
        DandelionTxState {
            txid,
            phase: DandelionPhase::Fluff,
            received_at: now,
            fluff_at: now, // Inmediato
            stem_hops: 0,
            received_from: Some(from),
            stem_sent: true, // No necesita stem
            fluff_sent: false,
        }
    }
    
    /// Verifica si el embargo expiró (debe hacer fluff)
    pub fn embargo_expired(&self) -> bool {
        Instant::now() >= self.fluff_at
    }
    
    /// Verifica si el stem timeout expiró (failsafe)
    pub fn stem_timeout(&self) -> bool {
        if self.phase == DandelionPhase::Stem && !self.stem_sent {
            self.received_at.elapsed() > Duration::from_secs(STEM_TIMEOUT_SECS)
        } else {
            false
        }
    }
    
    /// Marca como enviada en stem
    pub fn mark_stem_sent(&mut self) {
        self.stem_sent = true;
    }
    
    /// Marca como difundida en fluff
    pub fn mark_fluff_sent(&mut self) {
        self.fluff_sent = true;
    }
    
    /// Convierte a fluff phase
    pub fn convert_to_fluff(&mut self) {
        self.phase = DandelionPhase::Fluff;
    }
}

// =============================================================================
// Stem Graph
// =============================================================================

/// Grafo de stem: mapeo de peers entrantes a peers de salida
#[derive(Clone, Debug)]
pub struct StemGraph {
    /// Peers seleccionados para stem outbound
    pub stem_peers: Vec<SocketAddr>,
    /// Mapeo: peer entrante → peer de salida para stem
    pub routing_table: HashMap<SocketAddr, SocketAddr>,
    /// Timestamp de última rotación
    pub last_rotation: Instant,
    /// Epoch actual (incrementa con cada rotación)
    pub epoch: u64,
}

impl StemGraph {
    /// Crea un nuevo grafo vacío
    pub fn new() -> Self {
        StemGraph {
            stem_peers: Vec::new(),
            routing_table: HashMap::new(),
            last_rotation: Instant::now(),
            epoch: 0,
        }
    }
    
    /// Inicializa el grafo con peers disponibles
    pub fn initialize(&mut self, available_peers: &[SocketAddr]) {
        self.select_stem_peers(available_peers);
        self.last_rotation = Instant::now();
        self.epoch += 1;
    }
    
    /// Selecciona peers para stem
    fn select_stem_peers(&mut self, available_peers: &[SocketAddr]) {
        self.stem_peers.clear();
        self.routing_table.clear();
        
        if available_peers.is_empty() {
            return;
        }
        
        let mut rng = rand::thread_rng();
        let mut candidates: Vec<_> = available_peers.to_vec();
        
        // Shuffle y tomar los primeros NUM_STEM_PEERS
        use rand::seq::SliceRandom;
        candidates.shuffle(&mut rng);
        
        for peer in candidates.into_iter().take(NUM_STEM_PEERS) {
            self.stem_peers.push(peer);
        }
    }
    
    /// Obtiene el peer de salida para una TX recibida de un peer específico
    pub fn get_stem_relay(&mut self, from: Option<SocketAddr>) -> Option<SocketAddr> {
        if self.stem_peers.is_empty() {
            return None;
        }
        
        let mut rng = rand::thread_rng();
        
        match from {
            Some(peer) => {
                // TX recibida de otro peer: usar routing table
                if let Some(&dest) = self.routing_table.get(&peer) {
                    Some(dest)
                } else {
                    // Asignar nuevo destino para este peer
                    let dest = self.stem_peers[rng.gen_range(0..self.stem_peers.len())];
                    self.routing_table.insert(peer, dest);
                    Some(dest)
                }
            }
            None => {
                // TX propia: elegir peer aleatorio
                Some(self.stem_peers[rng.gen_range(0..self.stem_peers.len())])
            }
        }
    }
    
    /// Verifica si es momento de rotar el grafo
    pub fn should_rotate(&self) -> bool {
        self.last_rotation.elapsed() > Duration::from_secs(GRAPH_ROTATION_SECS)
    }
    
    /// Rota el grafo con nuevos peers
    pub fn rotate(&mut self, available_peers: &[SocketAddr]) {
        self.select_stem_peers(available_peers);
        self.last_rotation = Instant::now();
        self.epoch += 1;
        
        log::info!("Dandelion stem graph rotated (epoch {})", self.epoch);
    }
    
    /// Remueve un peer del grafo (si se desconecta)
    pub fn remove_peer(&mut self, peer: &SocketAddr) {
        self.stem_peers.retain(|p| p != peer);
        self.routing_table.retain(|k, v| k != peer && v != peer);
    }
}

impl Default for StemGraph {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Dandelion Manager
// =============================================================================

/// Gestor principal del protocolo Dandelion++
pub struct DandelionManager {
    /// Estado de TXs en proceso
    tx_states: HashMap<String, DandelionTxState>,
    /// Grafo de stem
    stem_graph: StemGraph,
    /// TXs que hemos visto (para evitar reprocessing)
    seen_txs: HashSet<String>,
    /// Si Dandelion está habilitado
    enabled: bool,
    /// Estadísticas
    stats: DandelionStats,
}

/// Estadísticas de Dandelion
#[derive(Clone, Debug, Default)]
pub struct DandelionStats {
    /// TXs propias enviadas
    pub own_txs_sent: u64,
    /// TXs recibidas en stem
    pub stem_txs_received: u64,
    /// TXs recibidas en fluff
    pub fluff_txs_received: u64,
    /// TXs que hicieron stem→fluff por timeout
    pub stem_timeouts: u64,
    /// Rotaciones de grafo
    pub graph_rotations: u64,
}

impl DandelionManager {
    /// Crea un nuevo manager
    pub fn new() -> Self {
        DandelionManager {
            tx_states: HashMap::new(),
            stem_graph: StemGraph::new(),
            seen_txs: HashSet::new(),
            enabled: true,
            stats: DandelionStats::default(),
        }
    }
    
    /// Habilita/deshabilita Dandelion
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        log::info!("Dandelion++ {}", if enabled { "enabled" } else { "disabled" });
    }
    
    /// Inicializa con peers disponibles
    pub fn initialize(&mut self, peers: &[SocketAddr]) {
        self.stem_graph.initialize(peers);
    }
    
    /// Procesa una TX propia (originada por nosotros)
    pub fn process_own_tx(&mut self, txid: String) -> DandelionAction {
        if !self.enabled {
            return DandelionAction::Fluff;
        }
        
        // Verificar si ya la vimos
        if self.seen_txs.contains(&txid) {
            return DandelionAction::Ignore;
        }
        
        // Verificar límite
        if self.tx_states.len() >= MAX_STEM_TXS {
            // Demasiadas TXs en stem, hacer fluff directo
            return DandelionAction::Fluff;
        }
        
        self.seen_txs.insert(txid.clone());
        
        // Crear estado
        let state = DandelionTxState::new_own(txid.clone());
        
        // Obtener peer de stem
        let stem_peer = self.stem_graph.get_stem_relay(None);
        
        self.tx_states.insert(txid.clone(), state);
        self.stats.own_txs_sent += 1;
        
        match stem_peer {
            Some(peer) => DandelionAction::Stem { to: peer },
            None => {
                // Sin peers de stem, hacer fluff directo
                self.tx_states.get_mut(&txid).map(|s| s.convert_to_fluff());
                DandelionAction::Fluff
            }
        }
    }
    
    /// Procesa una TX recibida de otro peer en stem phase
    pub fn process_stem_tx(&mut self, txid: String, from: SocketAddr) -> DandelionAction {
        if !self.enabled {
            return DandelionAction::Fluff;
        }
        
        // Verificar si ya la vimos
        if self.seen_txs.contains(&txid) {
            return DandelionAction::Ignore;
        }
        
        self.seen_txs.insert(txid.clone());
        self.stats.stem_txs_received += 1;
        
        // Crear estado (decide internamente si stem o fluff)
        let state = DandelionTxState::new_stem(txid.clone(), from);
        let phase = state.phase;
        
        self.tx_states.insert(txid.clone(), state);
        
        match phase {
            DandelionPhase::Stem => {
                // Continuar stem
                match self.stem_graph.get_stem_relay(Some(from)) {
                    Some(peer) if peer != from => {
                        DandelionAction::Stem { to: peer }
                    }
                    _ => {
                        // No hay peer válido, hacer fluff
                        self.tx_states.get_mut(&txid).map(|s| s.convert_to_fluff());
                        DandelionAction::Fluff
                    }
                }
            }
            DandelionPhase::Fluff => {
                // Transición a fluff
                DandelionAction::Fluff
            }
        }
    }
    
    /// Procesa una TX recibida en fluff phase (difusión normal)
    pub fn process_fluff_tx(&mut self, txid: String, from: SocketAddr) -> DandelionAction {
        // Verificar si ya la vimos
        if self.seen_txs.contains(&txid) {
            return DandelionAction::Ignore;
        }
        
        self.seen_txs.insert(txid.clone());
        self.stats.fluff_txs_received += 1;
        
        // En fluff, simplemente difundir
        let state = DandelionTxState::new_fluff(txid.clone(), from);
        self.tx_states.insert(txid, state);
        
        DandelionAction::Fluff
    }
    
    /// Tick periódico: verifica timeouts y embargos
    pub fn tick(&mut self) -> Vec<(String, DandelionAction)> {
        let mut actions = Vec::new();
        
        // Verificar TXs con embargo expirado
        let txids: Vec<_> = self.tx_states.keys().cloned().collect();
        
        for txid in txids {
            if let Some(state) = self.tx_states.get_mut(&txid) {
                // Timeout de stem (failsafe)
                if state.stem_timeout() {
                    state.convert_to_fluff();
                    self.stats.stem_timeouts += 1;
                    log::debug!("TX {} stem timeout, converting to fluff", &txid[..8]);
                }
                
                // Embargo expirado
                if state.embargo_expired() && !state.fluff_sent {
                    if state.phase == DandelionPhase::Fluff || state.stem_sent {
                        state.mark_fluff_sent();
                        actions.push((txid.clone(), DandelionAction::Fluff));
                    }
                }
            }
        }
        
        // Limpiar TXs completadas (fluff enviado)
        self.tx_states.retain(|_, s| !s.fluff_sent);
        
        // Rotar grafo si es necesario
        if self.stem_graph.should_rotate() {
            // Nota: la rotación real requiere lista de peers actualizada
            // Esto se hace desde el código que llama a tick()
            self.stats.graph_rotations += 1;
        }
        
        actions
    }
    
    /// Marca TX como enviada en stem
    pub fn mark_stem_sent(&mut self, txid: &str) {
        if let Some(state) = self.tx_states.get_mut(txid) {
            state.mark_stem_sent();
        }
    }
    
    /// Notifica desconexión de peer
    pub fn peer_disconnected(&mut self, peer: &SocketAddr) {
        self.stem_graph.remove_peer(peer);
    }
    
    /// Actualiza peers disponibles (para rotación)
    pub fn update_peers(&mut self, peers: &[SocketAddr]) {
        if self.stem_graph.should_rotate() {
            self.stem_graph.rotate(peers);
        }
    }
    
    /// Obtiene estadísticas
    pub fn stats(&self) -> &DandelionStats {
        &self.stats
    }
    
    /// Verifica si está habilitado
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    
    /// Número de TXs en stem
    pub fn stem_tx_count(&self) -> usize {
        self.tx_states.iter()
            .filter(|(_, s)| s.phase == DandelionPhase::Stem)
            .count()
    }
    
    /// Número de TXs en proceso
    pub fn pending_tx_count(&self) -> usize {
        self.tx_states.len()
    }
    
    /// Limpia TXs antiguas
    pub fn cleanup_old(&mut self, max_age_secs: u64) {
        let max_age = Duration::from_secs(max_age_secs);
        self.tx_states.retain(|_, s| s.received_at.elapsed() < max_age);
        
        // También limpiar seen_txs periódicamente
        if self.seen_txs.len() > 10000 {
            self.seen_txs.clear();
        }
    }
}

impl Default for DandelionManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Dandelion Action
// =============================================================================

/// Acción a tomar con una TX
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DandelionAction {
    /// Enviar en stem phase a un peer específico
    Stem { to: SocketAddr },
    /// Difundir normalmente (fluff)
    Fluff,
    /// Ignorar (ya procesada)
    Ignore,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Decide si transicionar a fluff (probabilidad geométrica)
fn should_fluff() -> bool {
    let mut rng = rand::thread_rng();
    rng.gen::<f64>() < STEM_TO_FLUFF_PROBABILITY
}

/// Genera tiempo de embargo aleatorio
fn random_embargo() -> Duration {
    let mut rng = rand::thread_rng();
    let secs = rng.gen_range(MIN_EMBARGO_SECS..=MAX_EMBARGO_SECS);
    Duration::from_secs(secs)
}

// =============================================================================
// Message Types
// =============================================================================

/// Tipo de mensaje para propagación de TX
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TxPropagation {
    /// TX en stem phase (solo para peer elegido)
    Stem {
        tx_data: Vec<u8>,
    },
    /// TX en fluff phase (difusión normal)
    Fluff {
        tx_data: Vec<u8>,
    },
}

impl TxPropagation {
    /// Crea mensaje stem
    pub fn stem(tx_data: Vec<u8>) -> Self {
        TxPropagation::Stem { tx_data }
    }
    
    /// Crea mensaje fluff
    pub fn fluff(tx_data: Vec<u8>) -> Self {
        TxPropagation::Fluff { tx_data }
    }
    
    /// Es stem?
    pub fn is_stem(&self) -> bool {
        matches!(self, TxPropagation::Stem { .. })
    }
    
    /// Obtiene datos de TX
    pub fn tx_data(&self) -> &[u8] {
        match self {
            TxPropagation::Stem { tx_data } => tx_data,
            TxPropagation::Fluff { tx_data } => tx_data,
        }
    }
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuración de Dandelion++
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DandelionConfig {
    /// Habilitado
    pub enabled: bool,
    /// Probabilidad stem→fluff
    pub fluff_probability: f64,
    /// Timeout de stem (segundos)
    pub stem_timeout_secs: u64,
    /// Intervalo de rotación de grafo (segundos)
    pub graph_rotation_secs: u64,
    /// Número de stem peers
    pub num_stem_peers: usize,
    /// Embargo mínimo (segundos)
    pub min_embargo_secs: u64,
    /// Embargo máximo (segundos)
    pub max_embargo_secs: u64,
}

impl Default for DandelionConfig {
    fn default() -> Self {
        DandelionConfig {
            enabled: true,
            fluff_probability: STEM_TO_FLUFF_PROBABILITY,
            stem_timeout_secs: STEM_TIMEOUT_SECS,
            graph_rotation_secs: GRAPH_ROTATION_SECS,
            num_stem_peers: NUM_STEM_PEERS,
            min_embargo_secs: MIN_EMBARGO_SECS,
            max_embargo_secs: MAX_EMBARGO_SECS,
        }
    }
}

// =============================================================================
// Display
// =============================================================================

/// Imprime información de Dandelion
pub fn print_dandelion_info(manager: &DandelionManager) {
    println!("Dandelion++ Status");
    println!("──────────────────────────────");
    println!("  Enabled:           {}", if manager.is_enabled() { "✅ Yes" } else { "❌ No" });
    println!("  Stem peers:        {}", manager.stem_graph.stem_peers.len());
    println!("  Graph epoch:       {}", manager.stem_graph.epoch);
    println!("  Pending TXs:       {}", manager.pending_tx_count());
    println!("  TXs in stem:       {}", manager.stem_tx_count());
    println!();
    println!("Statistics:");
    println!("  Own TXs sent:      {}", manager.stats.own_txs_sent);
    println!("  Stem TXs recv:     {}", manager.stats.stem_txs_received);
    println!("  Fluff TXs recv:    {}", manager.stats.fluff_txs_received);
    println!("  Stem timeouts:     {}", manager.stats.stem_timeouts);
    println!("  Graph rotations:   {}", manager.stats.graph_rotations);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dandelion_own_tx() {
        let mut manager = DandelionManager::new();
        let peers: Vec<SocketAddr> = vec![
            "192.168.1.1:38333".parse().unwrap(),
            "192.168.1.2:38333".parse().unwrap(),
        ];
        manager.initialize(&peers);
        
        let action = manager.process_own_tx("tx1".to_string());
        
        match action {
            DandelionAction::Stem { to } => {
                assert!(peers.contains(&to));
            }
            DandelionAction::Fluff => {
                // También válido si no hay peers de stem
            }
            DandelionAction::Ignore => panic!("Should not ignore own tx"),
        }
    }
    
    #[test]
    fn test_dandelion_duplicate() {
        let mut manager = DandelionManager::new();
        manager.initialize(&[]);
        
        let _ = manager.process_own_tx("tx1".to_string());
        let action = manager.process_own_tx("tx1".to_string());
        
        assert_eq!(action, DandelionAction::Ignore);
    }
    
    #[test]
    fn test_stem_graph_rotation() {
        let mut graph = StemGraph::new();
        let peers: Vec<SocketAddr> = vec![
            "192.168.1.1:38333".parse().unwrap(),
            "192.168.1.2:38333".parse().unwrap(),
            "192.168.1.3:38333".parse().unwrap(),
        ];
        
        graph.initialize(&peers);
        assert!(!graph.stem_peers.is_empty());
        
        let epoch1 = graph.epoch;
        graph.rotate(&peers);
        assert_eq!(graph.epoch, epoch1 + 1);
    }
    
    #[test]
    fn test_tx_state_embargo() {
        let state = DandelionTxState::new_own("tx1".to_string());
        
        // El embargo no debería haber expirado inmediatamente
        // (depende del random, pero MIN_EMBARGO_SECS > 0)
        assert!(!state.embargo_expired() || MIN_EMBARGO_SECS == 0);
    }
    
    #[test]
    fn test_disabled_dandelion() {
        let mut manager = DandelionManager::new();
        manager.set_enabled(false);
        
        let action = manager.process_own_tx("tx1".to_string());
        assert_eq!(action, DandelionAction::Fluff);
    }
}
