// =============================================================================
// MOONCOIN v2.0 - Red P2P Completa
// =============================================================================

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use serde::{Serialize, Deserialize};

use crate::lib::*;
use crate::block::Block;
use crate::transaction::Tx;

// =============================================================================
// Constantes de Red
// =============================================================================

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4MB
const MAX_BLOCKS_PER_REQUEST: usize = 500;

// =============================================================================
// Tipos de Mensajes P2P
// =============================================================================

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum NetMessage {
    // Handshake
    Version {
        version: u32,
        height: u64,
        addr_from: String,
        user_agent: String,
    },
    Verack,
    
    // Inventory (anunciar lo que tenemos)
    Inv(Vec<InvItem>),
    GetData(Vec<InvItem>),
    NotFound(Vec<InvItem>),
    
    // Bloques
    GetBlocks {
        start_hash: String,
        stop_hash: String,
    },
    GetHeaders {
        start_hash: String,
        stop_hash: String,
    },
    Headers(Vec<BlockHeader>),
    Block(Block),
    
    // Transacciones
    Tx(Tx),
    
    // Direcciones de peers
    GetAddr,
    Addr(Vec<PeerAddr>),
    
    // Ping/Pong
    Ping(u64),
    Pong(u64),
    
    // Rechazo
    Reject {
        message: String,
        reason: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum InvType {
    Tx,
    Block,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct InvItem {
    pub inv_type: InvType,
    pub hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlockHeader {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp: u64,
    pub difficulty_bits: u32,
}

impl From<&Block> for BlockHeader {
    fn from(block: &Block) -> Self {
        BlockHeader {
            height: block.height,
            hash: block.hash.clone(),
            prev_hash: block.prev_hash.clone(),
            timestamp: block.timestamp,
            difficulty_bits: block.difficulty_bits,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PeerAddr {
    pub addr: String,
    pub last_seen: u64,
    pub services: u64,
}

// =============================================================================
// Estado de un Peer
// =============================================================================

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: String,
    pub version: u32,
    pub height: u64,
    pub user_agent: String,
    pub connected_at: u64,
    pub last_seen: u64,
}

// =============================================================================
// Estado Compartido del Nodo
// =============================================================================

pub struct NodeState {
    // Blockchain
    pub chain: Vec<Block>,
    pub best_height: u64,
    pub best_hash: String,
    
    // Mempool
    pub mempool: HashMap<String, Tx>,
    
    // Peers
    pub peers: HashMap<String, PeerInfo>,
    pub known_addrs: HashSet<String>,
    pub banned: HashSet<String>,
    
    // Inventario conocido
    pub known_blocks: HashSet<String>,
    pub known_txs: HashSet<String>,
    
    // Bloques huérfanos
    pub orphan_blocks: HashMap<String, Block>,
    
    // Sincronización
    pub syncing: bool,
    pub sync_peer: Option<String>,
    
    // Mi dirección
    pub my_addr: String,
}

impl NodeState {
    pub fn new(chain: Vec<Block>, my_addr: String) -> Self {
        let best_height = if chain.is_empty() { 0 } else { chain.len() as u64 - 1 };
        let best_hash = chain.last().map(|b| b.hash.clone()).unwrap_or_default();
        
        let mut known_blocks = HashSet::new();
        for block in &chain {
            known_blocks.insert(block.hash.clone());
        }
        
        NodeState {
            chain,
            best_height,
            best_hash,
            mempool: HashMap::new(),
            peers: HashMap::new(),
            known_addrs: HashSet::new(),
            banned: HashSet::new(),
            known_blocks,
            known_txs: HashSet::new(),
            orphan_blocks: HashMap::new(),
            syncing: false,
            sync_peer: None,
            my_addr,
        }
    }
    
    pub fn update_chain(&mut self, chain: Vec<Block>) {
        self.best_height = if chain.is_empty() { 0 } else { chain.len() as u64 - 1 };
        self.best_hash = chain.last().map(|b| b.hash.clone()).unwrap_or_default();
        for block in &chain {
            self.known_blocks.insert(block.hash.clone());
        }
        self.chain = chain;
    }
}

// =============================================================================
// Eventos del Nodo
// =============================================================================

#[derive(Debug, Clone)]
pub enum NodeEvent {
    NewBlock(Block),
    NewTx(Tx),
    PeerConnected(String, u64),  // addr, their_height
    PeerDisconnected(String),
    SyncNeeded(String, u64),
}

// =============================================================================
// Serialización de Mensajes
// =============================================================================

fn serialize_message(msg: &NetMessage) -> Vec<u8> {
    let mut data = NETWORK_MAGIC.to_vec();
    let payload = bincode::serialize(msg).unwrap_or_default();
    data.extend(&(payload.len() as u32).to_le_bytes());
    data.extend(&payload);
    data
}

async fn read_message(stream: &mut TcpStream) -> Result<NetMessage, String> {
    let mut header = [0u8; 8];
    
    timeout(READ_TIMEOUT, stream.read_exact(&mut header)).await
        .map_err(|_| "Read timeout".to_string())?
        .map_err(|e| format!("Read error: {}", e))?;
    
    if &header[0..4] != NETWORK_MAGIC {
        return Err("Invalid magic".to_string());
    }
    
    let len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err("Message too large".to_string());
    }
    
    let mut payload = vec![0u8; len];
    timeout(READ_TIMEOUT, stream.read_exact(&mut payload)).await
        .map_err(|_| "Read timeout".to_string())?
        .map_err(|e| format!("Read error: {}", e))?;
    
    bincode::deserialize(&payload)
        .map_err(|e| format!("Deserialize error: {}", e))
}

async fn write_message(stream: &mut TcpStream, msg: &NetMessage) -> Result<(), String> {
    let data = serialize_message(msg);
    stream.write_all(&data).await
        .map_err(|e| format!("Write error: {}", e))?;
    stream.flush().await
        .map_err(|e| format!("Flush error: {}", e))?;
    Ok(())
}

// =============================================================================
// Handshake
// =============================================================================

async fn do_handshake(
    stream: &mut TcpStream,
    state: &Arc<RwLock<NodeState>>,
    outbound: bool,
) -> Result<PeerInfo, String> {
    let (my_height, my_addr) = {
        let s = state.read().await;
        (s.best_height, s.my_addr.clone())
    };
    
    if outbound {
        write_message(stream, &NetMessage::Version {
            version: PROTOCOL_VERSION,
            height: my_height,
            addr_from: my_addr.clone(),
            user_agent: format!("Mooncoin/2.0"),
        }).await?;
    }
    
    // Recibir version del peer
    let (peer_version, peer_height, peer_addr, peer_ua) = match read_message(stream).await? {
        NetMessage::Version { version, height, addr_from, user_agent } => {
            (version, height, addr_from, user_agent)
        }
        _ => return Err("Expected Version".to_string()),
    };
    
    if !outbound {
        write_message(stream, &NetMessage::Version {
            version: PROTOCOL_VERSION,
            height: my_height,
            addr_from: my_addr,
            user_agent: format!("Mooncoin/2.0"),
        }).await?;
    }
    
    // Enviar verack
    write_message(stream, &NetMessage::Verack).await?;
    
    // Recibir verack
    match read_message(stream).await? {
        NetMessage::Verack => {}
        _ => return Err("Expected Verack".to_string()),
    }
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    Ok(PeerInfo {
        addr: peer_addr,
        version: peer_version,
        height: peer_height,
        user_agent: peer_ua,
        connected_at: now,
        last_seen: now,
    })
}

// =============================================================================
// Handler de Mensajes
// =============================================================================

async fn handle_message(
    msg: NetMessage,
    stream: &mut TcpStream,
    state: &Arc<RwLock<NodeState>>,
    event_tx: &mpsc::Sender<NodeEvent>,
) -> Result<bool, String> {
    match msg {
        NetMessage::Ping(nonce) => {
            write_message(stream, &NetMessage::Pong(nonce)).await?;
        }
        
        NetMessage::Pong(_) => {}
        
        NetMessage::GetAddr => {
            let addrs: Vec<PeerAddr> = {
                let s = state.read().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                s.known_addrs.iter()
                    .take(100)
                    .map(|a| PeerAddr { addr: a.clone(), last_seen: now, services: 1 })
                    .collect()
            };
            write_message(stream, &NetMessage::Addr(addrs)).await?;
        }
        
        NetMessage::Addr(addrs) => {
            let mut s = state.write().await;
            for a in addrs {
                if !s.banned.contains(&a.addr) {
                    s.known_addrs.insert(a.addr);
                }
            }
        }
        
        NetMessage::Inv(items) => {
            let needed: Vec<InvItem> = {
                let s = state.read().await;
                items.into_iter()
                    .filter(|item| {
                        match item.inv_type {
                            InvType::Block => !s.known_blocks.contains(&item.hash),
                            InvType::Tx => !s.known_txs.contains(&item.hash),
                        }
                    })
                    .collect()
            };
            
            if !needed.is_empty() {
                write_message(stream, &NetMessage::GetData(needed)).await?;
            }
        }
        
        NetMessage::GetData(items) => {
            let s = state.read().await;
            for item in items {
                match item.inv_type {
                    InvType::Block => {
                        if let Some(block) = s.chain.iter().find(|b| b.hash == item.hash) {
                            write_message(stream, &NetMessage::Block(block.clone())).await?;
                        }
                    }
                    InvType::Tx => {
                        if let Some(tx) = s.mempool.get(&item.hash) {
                            write_message(stream, &NetMessage::Tx(tx.clone())).await?;
                        }
                    }
                }
            }
        }
        
        NetMessage::GetBlocks { start_hash, stop_hash } => {
            let s = state.read().await;
            let start_idx = if start_hash == "0".repeat(64) {
                0
            } else {
                s.chain.iter().position(|b| b.hash == start_hash).unwrap_or(0) + 1
            };
            
            let inv: Vec<InvItem> = s.chain.iter()
                .skip(start_idx)
                .take(MAX_BLOCKS_PER_REQUEST)
                .take_while(|b| stop_hash == "0".repeat(64) || b.hash != stop_hash)
                .map(|b| InvItem { inv_type: InvType::Block, hash: b.hash.clone() })
                .collect();
            
            if !inv.is_empty() {
                write_message(stream, &NetMessage::Inv(inv)).await?;
            }
        }
        
        NetMessage::GetHeaders { start_hash, stop_hash } => {
            let s = state.read().await;
            let start_idx = if start_hash == "0".repeat(64) {
                0
            } else {
                s.chain.iter().position(|b| b.hash == start_hash).unwrap_or(0) + 1
            };
            
            let headers: Vec<BlockHeader> = s.chain.iter()
                .skip(start_idx)
                .take(2000)
                .take_while(|b| stop_hash == "0".repeat(64) || b.hash != stop_hash)
                .map(BlockHeader::from)
                .collect();
            
            write_message(stream, &NetMessage::Headers(headers)).await?;
        }
        
        NetMessage::Block(block) => {
            let _ = event_tx.send(NodeEvent::NewBlock(block)).await;
        }
        
        NetMessage::Tx(tx) => {
            let _ = event_tx.send(NodeEvent::NewTx(tx)).await;
        }
        
        _ => {}
    }
    
    Ok(true)  // Continuar
}

// =============================================================================
// Servidor P2P
// =============================================================================

pub async fn start_p2p_server(
    state: Arc<RwLock<NodeState>>,
    event_tx: mpsc::Sender<NodeEvent>,
) {
    let addr = format!("0.0.0.0:{}", P2P_PORT);
    
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(_) => return,
    };
    
    loop {
        if let Ok((stream, peer_addr)) = listener.accept().await {
            let peer_str = peer_addr.to_string();
            let state_clone = Arc::clone(&state);
            let event_tx_clone = event_tx.clone();
            
            tokio::spawn(async move {
                handle_connection(peer_str, stream, state_clone, event_tx_clone, false).await;
            });
        }
    }
}

async fn handle_connection(
    addr: String,
    mut stream: TcpStream,
    state: Arc<RwLock<NodeState>>,
    event_tx: mpsc::Sender<NodeEvent>,
    outbound: bool,
) {
    // Handshake
    let peer_info = match do_handshake(&mut stream, &state, outbound).await {
        Ok(info) => info,
        Err(_) => return,
    };
    
    let peer_height = peer_info.height;
    
    // Registrar peer
    {
        let mut s = state.write().await;
        s.peers.insert(addr.clone(), peer_info);
        s.known_addrs.insert(addr.clone());
    }
    
    let _ = event_tx.send(NodeEvent::PeerConnected(addr.clone(), peer_height)).await;
    
    // Loop de mensajes
    loop {
        match read_message(&mut stream).await {
            Ok(msg) => {
                if handle_message(msg, &mut stream, &state, &event_tx).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    
    // Desregistrar
    {
        let mut s = state.write().await;
        s.peers.remove(&addr);
    }
    
    let _ = event_tx.send(NodeEvent::PeerDisconnected(addr)).await;
}

// =============================================================================
// Conexiones Salientes
// =============================================================================

pub async fn connect_to_peer(
    addr: &str,
    state: Arc<RwLock<NodeState>>,
    event_tx: mpsc::Sender<NodeEvent>,
) -> Result<(), String> {
    {
        let s = state.read().await;
        if s.peers.contains_key(addr) {
            return Err("Already connected".to_string());
        }
        if s.banned.contains(addr) {
            return Err("Banned".to_string());
        }
    }
    
    let stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
        .map_err(|_| "Timeout".to_string())?
        .map_err(|e| e.to_string())?;
    
    let addr_owned = addr.to_string();
    tokio::spawn(async move {
        handle_connection(addr_owned, stream, state, event_tx, true).await;
    });
    
    Ok(())
}

// =============================================================================
// Broadcast
// =============================================================================

pub async fn broadcast_inv(items: Vec<InvItem>, state: &Arc<RwLock<NodeState>>) {
    let peers: Vec<String> = {
        let s = state.read().await;
        s.peers.keys().cloned().collect()
    };
    
    let msg = serialize_message(&NetMessage::Inv(items));
    
    for peer in peers {
        if let Ok(mut stream) = timeout(Duration::from_secs(5), TcpStream::connect(&peer)).await {
            if let Ok(ref mut s) = stream {
                let _ = s.write_all(&msg).await;
            }
        }
    }
}

pub async fn broadcast_block(block: &Block, state: &Arc<RwLock<NodeState>>) {
    let inv = vec![InvItem {
        inv_type: InvType::Block,
        hash: block.hash.clone(),
    }];
    broadcast_inv(inv, state).await;
}

pub async fn broadcast_tx(tx: &Tx, state: &Arc<RwLock<NodeState>>) {
    let txid = crate::transaction::tx_hash(tx);
    let inv = vec![InvItem {
        inv_type: InvType::Tx,
        hash: txid,
    }];
    broadcast_inv(inv, state).await;
}

// =============================================================================
// Sincronización
// =============================================================================

pub async fn request_blocks_from_peer(
    peer_addr: &str,
    start_hash: &str,
    state: Arc<RwLock<NodeState>>,
) -> Result<Vec<Block>, String> {
    let mut stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(peer_addr)).await
        .map_err(|_| "Timeout".to_string())?
        .map_err(|e| e.to_string())?;
    
    // Handshake rápido
    do_handshake(&mut stream, &state, true).await?;
    
    // Pedir bloques
    write_message(&mut stream, &NetMessage::GetBlocks {
        start_hash: start_hash.to_string(),
        stop_hash: "0".repeat(64),
    }).await?;
    
    // Recibir inventario
    let inv = match read_message(&mut stream).await? {
        NetMessage::Inv(items) => items,
        _ => return Ok(vec![]),
    };
    
    if inv.is_empty() {
        return Ok(vec![]);
    }
    
    // Pedir datos
    write_message(&mut stream, &NetMessage::GetData(inv.clone())).await?;
    
    // Recibir bloques
    let mut blocks = Vec::new();
    for _ in 0..inv.len() {
        match timeout(Duration::from_secs(30), read_message(&mut stream)).await {
            Ok(Ok(NetMessage::Block(block))) => blocks.push(block),
            _ => break,
        }
    }
    
    Ok(blocks)
}

// =============================================================================
// Seed Nodes
// =============================================================================

pub fn get_seed_nodes() -> Vec<String> {
    // Agregar tus nodos semilla aquí
    vec![
        // "192.168.1.100:38333".to_string(),
        // "seed.mooncoin.org:38333".to_string(),
    ]
}

pub async fn bootstrap(state: Arc<RwLock<NodeState>>, event_tx: mpsc::Sender<NodeEvent>) {
    for seed in get_seed_nodes() {
        let s = Arc::clone(&state);
        let e = event_tx.clone();
        tokio::spawn(async move {
            let _ = connect_to_peer(&seed, s, e).await;
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
