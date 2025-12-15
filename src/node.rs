// =============================================================================
// MOONCOIN - NODO MÍNIMO VIABLE
// =============================================================================
//
// Este es el nodo más simple posible que puede:
//   1. Almacenar bloques
//   2. Minar nuevos bloques
//   3. Aceptar conexiones P2P básicas
//   4. Sincronizar con otros nodos
//
// Es deliberadamente simple. No es óptimo. Pero FUNCIONA.
//
// Úsalo para lanzar la red. Mejóralo después (o no).
//
// =============================================================================

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write, BufReader, BufWriter};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

// =============================================================================
// CONFIGURACIÓN
// =============================================================================

pub const NETWORK_PORT: u16 = 8333;
pub const DATA_DIR: &str = ".mooncoin";
pub const BLOCKS_FILE: &str = "blocks.dat";
pub const UTXO_FILE: &str = "utxos.dat";

// Parámetros del protocolo
pub const TARGET_BLOCK_TIME: u64 = 300; // 5 minutos
pub const INITIAL_REWARD: u64 = 50_0000_0000; // 50 MOON en satoshis
pub const HALVING_INTERVAL: u64 = 210_000;
pub const MAX_SUPPLY: u64 = 21_000_000_0000_0000; // 21M MOON en satoshis
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;

// =============================================================================
// ESTRUCTURAS DE DATOS
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(80);
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&self.prev_hash);
        data.extend_from_slice(&self.merkle_root);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.bits.to_le_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data
    }
    
    pub fn hash(&self) -> [u8; 32] {
        sha256d(&self.serialize())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl Transaction {
    pub fn txid(&self) -> [u8; 32] {
        let serialized = bincode::serialize(self).unwrap();
        sha256d(&serialized)
    }
    
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 
            && self.inputs[0].prev_txid == [0u8; 32]
            && self.inputs[0].prev_vout == 0xFFFFFFFF
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UTXO {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub height: u64,
}

// =============================================================================
// ALMACENAMIENTO
// =============================================================================

pub struct Storage {
    data_dir: PathBuf,
    blocks: Vec<Block>,
    utxos: HashMap<([u8; 32], u32), UTXO>,
    height: u64,
}

impl Storage {
    pub fn new() -> Self {
        let data_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DATA_DIR);
        
        fs::create_dir_all(&data_dir).ok();
        
        Storage {
            data_dir,
            blocks: Vec::new(),
            utxos: HashMap::new(),
            height: 0,
        }
    }
    
    pub fn load(&mut self) -> Result<(), String> {
        let blocks_path = self.data_dir.join(BLOCKS_FILE);
        
        if blocks_path.exists() {
            let file = File::open(&blocks_path)
                .map_err(|e| format!("Error abriendo blocks: {}", e))?;
            let reader = BufReader::new(file);
            self.blocks = bincode::deserialize_from(reader)
                .map_err(|e| format!("Error deserializando blocks: {}", e))?;
            self.height = self.blocks.len() as u64;
            
            // Reconstruir UTXOs
            self.rebuild_utxos();
            
            println!("Cargados {} bloques", self.blocks.len());
        }
        
        Ok(())
    }
    
    pub fn save(&self) -> Result<(), String> {
        let blocks_path = self.data_dir.join(BLOCKS_FILE);
        let file = File::create(&blocks_path)
            .map_err(|e| format!("Error creando blocks file: {}", e))?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, &self.blocks)
            .map_err(|e| format!("Error serializando blocks: {}", e))?;
        Ok(())
    }
    
    fn rebuild_utxos(&mut self) {
        self.utxos.clear();
        
        for (height, block) in self.blocks.iter().enumerate() {
            for tx in &block.transactions {
                let txid = tx.txid();
                
                // Remover UTXOs gastados
                for input in &tx.inputs {
                    if !tx.is_coinbase() {
                        self.utxos.remove(&(input.prev_txid, input.prev_vout));
                    }
                }
                
                // Agregar nuevos UTXOs
                for (vout, output) in tx.outputs.iter().enumerate() {
                    // No agregar OP_RETURN como UTXO
                    if output.script_pubkey.first() != Some(&0x6a) {
                        self.utxos.insert((txid, vout as u32), UTXO {
                            txid,
                            vout: vout as u32,
                            value: output.value,
                            script_pubkey: output.script_pubkey.clone(),
                            height: height as u64,
                        });
                    }
                }
            }
        }
    }
    
    pub fn add_block(&mut self, block: Block) -> Result<(), String> {
        // Validar que conecta con el último bloque
        if !self.blocks.is_empty() {
            let last_hash = self.blocks.last().unwrap().hash();
            if block.header.prev_hash != last_hash {
                return Err("Block does not connect".to_string());
            }
        }
        
        // Actualizar UTXOs
        for tx in &block.transactions {
            let txid = tx.txid();
            
            for input in &tx.inputs {
                if !tx.is_coinbase() {
                    self.utxos.remove(&(input.prev_txid, input.prev_vout));
                }
            }
            
            for (vout, output) in tx.outputs.iter().enumerate() {
                if output.script_pubkey.first() != Some(&0x6a) {
                    self.utxos.insert((txid, vout as u32), UTXO {
                        txid,
                        vout: vout as u32,
                        value: output.value,
                        script_pubkey: output.script_pubkey.clone(),
                        height: self.height,
                    });
                }
            }
        }
        
        self.blocks.push(block);
        self.height += 1;
        
        // Guardar periódicamente
        if self.height % 100 == 0 {
            self.save()?;
        }
        
        Ok(())
    }
    
    pub fn get_last_block(&self) -> Option<&Block> {
        self.blocks.last()
    }
    
    pub fn get_height(&self) -> u64 {
        self.height
    }
    
    pub fn get_block(&self, height: u64) -> Option<&Block> {
        self.blocks.get(height as usize)
    }
}

// =============================================================================
// MINERO
// =============================================================================

pub struct Miner {
    miner_address: Vec<u8>,
}

impl Miner {
    pub fn new(address: Vec<u8>) -> Self {
        Miner { miner_address: address }
    }
    
    /// Calcular recompensa del bloque
    pub fn get_block_reward(height: u64) -> u64 {
        let halvings = height / HALVING_INTERVAL;
        if halvings >= 64 {
            return 0;
        }
        INITIAL_REWARD >> halvings
    }
    
    /// Crear transacción coinbase
    pub fn create_coinbase(&self, height: u64, extra_nonce: u64) -> Transaction {
        let reward = Self::get_block_reward(height);
        
        // Script sig con altura y extra nonce
        let mut script_sig = Vec::new();
        script_sig.extend_from_slice(&height.to_le_bytes());
        script_sig.extend_from_slice(&extra_nonce.to_le_bytes());
        
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_vout: 0xFFFFFFFF,
                script_sig,
                sequence: 0xFFFFFFFF,
            }],
            outputs: vec![TxOutput {
                value: reward,
                script_pubkey: self.miner_address.clone(),
            }],
            locktime: 0,
        }
    }
    
    /// Crear bloque candidato
    pub fn create_candidate(
        &self,
        prev_hash: [u8; 32],
        height: u64,
        bits: u32,
        pending_txs: Vec<Transaction>,
    ) -> Block {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        
        let coinbase = self.create_coinbase(height, timestamp as u64);
        
        let mut transactions = vec![coinbase];
        transactions.extend(pending_txs);
        
        let merkle_root = compute_merkle_root(&transactions);
        
        let header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root,
            timestamp,
            bits,
            nonce: 0,
        };
        
        Block { header, transactions }
    }
    
    /// Minar un bloque
    pub fn mine(&self, mut block: Block, stop_signal: Arc<RwLock<bool>>) -> Option<Block> {
        let target = bits_to_target(block.header.bits);
        
        println!("Minando bloque...");
        
        loop {
            // Verificar señal de parada
            if *stop_signal.read().unwrap() {
                return None;
            }
            
            let hash = block.header.hash();
            
            if hash_meets_target(&hash, &target) {
                println!("¡Bloque encontrado! Nonce: {}", block.header.nonce);
                return Some(block);
            }
            
            block.header.nonce = block.header.nonce.wrapping_add(1);
            
            // Si overflow, actualizar timestamp
            if block.header.nonce == 0 {
                block.header.timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32;
            }
        }
    }
}

// =============================================================================
// NETWORKING P2P BÁSICO
// =============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    Version { height: u64 },
    GetBlocks { from_height: u64 },
    Blocks { blocks: Vec<Block> },
    NewBlock { block: Block },
    Ping,
    Pong,
}

pub struct Node {
    storage: Arc<RwLock<Storage>>,
    peers: Arc<RwLock<Vec<SocketAddr>>>,
    mining: Arc<RwLock<bool>>,
    miner_address: Vec<u8>,
}

impl Node {
    pub fn new(miner_address: Vec<u8>) -> Self {
        let mut storage = Storage::new();
        storage.load().ok();
        
        Node {
            storage: Arc::new(RwLock::new(storage)),
            peers: Arc::new(RwLock::new(Vec::new())),
            mining: Arc::new(RwLock::new(false)),
            miner_address,
        }
    }
    
    /// Iniciar servidor P2P
    pub fn start_server(&self) {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", NETWORK_PORT))
            .expect("No se pudo iniciar servidor");
        
        println!("Servidor P2P escuchando en puerto {}", NETWORK_PORT);
        
        let storage = Arc::clone(&self.storage);
        
        thread::spawn(move || {
            for stream in listener.incoming() {
                if let Ok(stream) = stream {
                    let storage = Arc::clone(&storage);
                    thread::spawn(move || {
                        Self::handle_connection(stream, storage);
                    });
                }
            }
        });
    }
    
    fn handle_connection(mut stream: TcpStream, storage: Arc<RwLock<Storage>>) {
        let peer_addr = stream.peer_addr().ok();
        println!("Nueva conexión de: {:?}", peer_addr);
        
        // Buffer para leer mensajes
        let mut buffer = vec![0u8; 1024 * 1024]; // 1MB max
        
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break, // Conexión cerrada
                Ok(n) => {
                    if let Ok(msg) = bincode::deserialize::<Message>(&buffer[..n]) {
                        let response = Self::process_message(msg, &storage);
                        if let Some(resp) = response {
                            let data = bincode::serialize(&resp).unwrap();
                            stream.write_all(&data).ok();
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }
    
    fn process_message(msg: Message, storage: &Arc<RwLock<Storage>>) -> Option<Message> {
        match msg {
            Message::Ping => Some(Message::Pong),
            
            Message::Version { height } => {
                let our_height = storage.read().unwrap().get_height();
                println!("Peer tiene altura {}, nosotros {}", height, our_height);
                Some(Message::Version { height: our_height })
            }
            
            Message::GetBlocks { from_height } => {
                let storage = storage.read().unwrap();
                let mut blocks = Vec::new();
                
                for h in from_height..storage.get_height().min(from_height + 500) {
                    if let Some(block) = storage.get_block(h) {
                        blocks.push(block.clone());
                    }
                }
                
                Some(Message::Blocks { blocks })
            }
            
            Message::Blocks { blocks } => {
                let mut storage = storage.write().unwrap();
                for block in blocks {
                    if let Err(e) = storage.add_block(block) {
                        println!("Error agregando bloque: {}", e);
                    }
                }
                None
            }
            
            Message::NewBlock { block } => {
                let mut storage = storage.write().unwrap();
                if let Err(e) = storage.add_block(block) {
                    println!("Error agregando nuevo bloque: {}", e);
                }
                None
            }
            
            _ => None,
        }
    }
    
    /// Conectar a un peer
    pub fn connect_peer(&self, addr: &str) {
        if let Ok(stream) = TcpStream::connect(addr) {
            let peer_addr = stream.peer_addr().ok();
            println!("Conectado a: {:?}", peer_addr);
            
            if let Some(addr) = peer_addr {
                self.peers.write().unwrap().push(addr);
            }
            
            // Enviar version
            let height = self.storage.read().unwrap().get_height();
            let msg = Message::Version { height };
            let data = bincode::serialize(&msg).unwrap();
            
            let mut stream = stream;
            stream.write_all(&data).ok();
        } else {
            println!("No se pudo conectar a {}", addr);
        }
    }
    
    /// Iniciar minería
    pub fn start_mining(&self) {
        *self.mining.write().unwrap() = true;
        
        let storage = Arc::clone(&self.storage);
        let mining = Arc::clone(&self.mining);
        let miner_address = self.miner_address.clone();
        
        thread::spawn(move || {
            let miner = Miner::new(miner_address);
            
            loop {
                if !*mining.read().unwrap() {
                    break;
                }
                
                let (prev_hash, height, bits) = {
                    let storage = storage.read().unwrap();
                    match storage.get_last_block() {
                        Some(block) => (block.hash(), storage.get_height(), block.header.bits),
                        None => {
                            println!("No hay bloque génesis. Crea uno primero.");
                            break;
                        }
                    }
                };
                
                let candidate = miner.create_candidate(prev_hash, height, bits, vec![]);
                
                let stop_signal = Arc::new(RwLock::new(false));
                
                if let Some(block) = miner.mine(candidate, stop_signal) {
                    let mut storage = storage.write().unwrap();
                    match storage.add_block(block.clone()) {
                        Ok(_) => {
                            println!(
                                "✓ Bloque {} minado! Hash: {}...",
                                height,
                                hex::encode(&block.hash()[..8])
                            );
                        }
                        Err(e) => println!("Error: {}", e),
                    }
                }
            }
        });
    }
    
    /// Detener minería
    pub fn stop_mining(&self) {
        *self.mining.write().unwrap() = false;
    }
    
    /// Obtener estado
    pub fn get_status(&self) -> String {
        let storage = self.storage.read().unwrap();
        let peers = self.peers.read().unwrap();
        let mining = *self.mining.read().unwrap();
        
        format!(
            "Altura: {}\nUTXOs: {}\nPeers: {}\nMinando: {}",
            storage.get_height(),
            storage.utxos.len(),
            peers.len(),
            mining
        )
    }
}

// =============================================================================
// UTILIDADES
// =============================================================================

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

fn bits_to_target(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x00FFFFFF;
    
    let mut target = [0u8; 32];
    
    if exponent >= 3 && exponent <= 32 {
        let start = 32 - exponent;
        target[start + 2] = (mantissa & 0xFF) as u8;
        target[start + 1] = ((mantissa >> 8) & 0xFF) as u8;
        target[start] = ((mantissa >> 16) & 0xFF) as u8;
    }
    
    target
}

fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in 0..32 {
        if hash[i] < target[i] { return true; }
        if hash[i] > target[i] { return false; }
    }
    true
}

fn compute_merkle_root(transactions: &[Transaction]) -> [u8; 32] {
    if transactions.is_empty() {
        return [0u8; 32];
    }
    
    let mut hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.txid()).collect();
    
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            let last = *hashes.last().unwrap();
            hashes.push(last);
        }
        
        let mut new_hashes = Vec::new();
        for pair in hashes.chunks(2) {
            let mut combined = Vec::new();
            combined.extend_from_slice(&pair[0]);
            combined.extend_from_slice(&pair[1]);
            new_hashes.push(sha256d(&combined));
        }
        hashes = new_hashes;
    }
    
    hashes[0]
}

// =============================================================================
// CLI
// =============================================================================

pub fn print_usage() {
    println!("
╔═══════════════════════════════════════════════════════════════════╗
║                      MOONCOIN NODE v1.0                           ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  Uso: mooncoin [comando]                                         ║
║                                                                   ║
║  Comandos:                                                        ║
║    start              Iniciar nodo                                ║
║    mine               Iniciar minería                             ║
║    stop               Detener minería                             ║
║    status             Ver estado del nodo                         ║
║    connect <ip:port>  Conectar a peer                            ║
║    genesis            Generar bloque génesis                      ║
║    help               Mostrar esta ayuda                          ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
");
}

// =============================================================================
// MAIN (Ejemplo de uso)
// =============================================================================

// Para usar como aplicación standalone, descomenta y compila:
//
// fn main() {
//     let args: Vec<String> = std::env::args().collect();
//     
//     // Dirección de minero (deberías generar una propia)
//     let miner_address = vec![0x76, 0xa9, /* ... pubkey hash ... */, 0x88, 0xac];
//     
//     let node = Node::new(miner_address);
//     
//     match args.get(1).map(|s| s.as_str()) {
//         Some("start") => {
//             node.start_server();
//             println!("Nodo iniciado. Presiona Ctrl+C para salir.");
//             loop { thread::sleep(Duration::from_secs(1)); }
//         }
//         Some("mine") => {
//             node.start_mining();
//             loop { thread::sleep(Duration::from_secs(1)); }
//         }
//         Some("status") => {
//             println!("{}", node.get_status());
//         }
//         Some("connect") => {
//             if let Some(addr) = args.get(2) {
//                 node.connect_peer(addr);
//             } else {
//                 println!("Uso: mooncoin connect <ip:port>");
//             }
//         }
//         Some("genesis") => {
//             println!("Generando bloque génesis...");
//             // Ver genesis_generator.rs
//         }
//         _ => print_usage(),
//     }
// }
