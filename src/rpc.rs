// =============================================================================
// MOONCOIN v2.0 - JSON-RPC Server (Simplified)
// =============================================================================

use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};

use crate::block::load_chain;
use crate::utxo::UtxoSet;
use crate::transaction::tx_hash;
use crate::mempool::Mempool;
use crate::lib::{format_coins, get_reward, HALVING_INTERVAL};
use crate::reorg::calculate_chain_work;

/// Puerto RPC (estilo Bitcoin)
pub const RPC_PORT: u16 = 8332;

/// Request JSON-RPC
#[derive(Deserialize)]
struct RpcRequest {
    method: String,
    params: Option<Value>,
    id: Option<Value>,
}

/// Response JSON-RPC
#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: String,
    result: Option<Value>,
    error: Option<RpcError>,
    id: Value,
}

#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl RpcResponse {
    fn success(id: Value, result: Value) -> Self {
        RpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }
    
    fn error(id: Value, code: i32, message: &str) -> Self {
        RpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(RpcError {
                code,
                message: message.to_string(),
            }),
            id,
        }
    }
}

/// Inicia el servidor RPC
pub async fn start_rpc_server() {
    let addr = format!("127.0.0.1:{}", RPC_PORT);
    
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(_) => return,
    };
    
    loop {
        if let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                
                if let Ok(n) = socket.read(&mut buf).await {
                    if n > 0 {
                        let response = handle_request(&buf[..n]);
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                }
            });
        }
    }
}

/// Procesa una request HTTP con JSON-RPC
fn handle_request(data: &[u8]) -> String {
    let request_str = String::from_utf8_lossy(data);
    
    // Buscar el body JSON (después de headers HTTP)
    let body = if let Some(pos) = request_str.find("\r\n\r\n") {
        &request_str[pos + 4..]
    } else {
        &request_str[..]
    };
    
    // Parsear JSON-RPC
    let rpc_request: RpcRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => {
            return http_response(&RpcResponse::error(json!(null), -32700, "Parse error"));
        }
    };
    
    let id = rpc_request.id.unwrap_or(json!(null));
    let params = rpc_request.params.unwrap_or(json!([]));
    
    // Ejecutar método
    let result = execute_method(&rpc_request.method, params);
    
    match result {
        Ok(value) => http_response(&RpcResponse::success(id, value)),
        Err((code, msg)) => http_response(&RpcResponse::error(id, code, &msg)),
    }
}

/// Ejecuta un método RPC
fn execute_method(method: &str, params: Value) -> Result<Value, (i32, String)> {
    // Cargar datos frescos del disco
    let chain = load_chain();
    let mempool = Mempool::load();
    
    match method {
        // === Blockchain ===
        "getblockcount" => {
            Ok(json!(chain.len().saturating_sub(1)))
        }
        
        "getbestblockhash" => {
            match chain.last() {
                Some(block) => Ok(json!(block.hash)),
                None => Err((-1, "No blocks".to_string())),
            }
        }
        
        "getblockhash" => {
            let height = params.get(0)
                .and_then(|v| v.as_u64())
                .ok_or((-1, "Missing height parameter".to_string()))?;
            
            match chain.get(height as usize) {
                Some(block) => Ok(json!(block.hash)),
                None => Err((-8, "Block height out of range".to_string())),
            }
        }
        
        "getblock" => {
            let hash = params.get(0)
                .and_then(|v| v.as_str())
                .ok_or((-1, "Missing hash parameter".to_string()))?;
            
            match chain.iter().find(|b| b.hash == hash) {
                Some(block) => {
                    Ok(json!({
                        "hash": block.hash,
                        "height": block.height,
                        "previousblockhash": block.prev_hash,
                        "merkleroot": block.merkle_root,
                        "time": block.timestamp,
                        "difficulty": block.difficulty_bits,
                        "nonce": block.nonce,
                        "nTx": block.txs.len(),
                        "tx": block.txs.iter().map(tx_hash).collect::<Vec<_>>(),
                    }))
                }
                None => Err((-5, "Block not found".to_string())),
            }
        }
        
        "getblockchaininfo" => {
            let height = chain.len().saturating_sub(1);
            let utxo = UtxoSet::rebuild_from_chain(&chain);
            let work = calculate_chain_work(&chain);
            
            Ok(json!({
                "chain": "mooncoin",
                "blocks": height,
                "bestblockhash": chain.last().map(|b| b.hash.clone()),
                "difficulty": chain.last().map(|b| b.difficulty_bits).unwrap_or(20),
                "chainwork": format!("{:x}", work),
                "supply": utxo.total_supply(),
                "supply_formatted": format_coins(utxo.total_supply()),
            }))
        }
        
        // === Mempool ===
        "getmempoolinfo" => {
            Ok(json!({
                "size": mempool.len(),
                "fees": mempool.total_fees(),
                "fees_formatted": format_coins(mempool.total_fees()),
            }))
        }
        
        "getrawmempool" => {
            let txids: Vec<&String> = mempool.txs.keys().collect();
            Ok(json!(txids))
        }
        
        // === Transacciones ===
        "getrawtransaction" => {
            let txid = params.get(0)
                .and_then(|v| v.as_str())
                .ok_or((-1, "Missing txid parameter".to_string()))?;
            
            // Buscar en mempool
            if let Some(entry) = mempool.get_tx_info(txid) {
                let tx = &entry.tx;
                return Ok(json!({
                    "txid": tx_hash(tx),
                    "fee": entry.fee,
                    "fee_formatted": format_coins(entry.fee),
                    "in_mempool": true,
                    "vin": tx.inputs.iter().map(|inp| json!({
                        "txid": inp.prev_tx_hash,
                        "vout": inp.prev_index,
                    })).collect::<Vec<_>>(),
                    "vout": tx.outputs.iter().enumerate().map(|(i, out)| json!({
                        "n": i,
                        "value": out.amount,
                        "value_formatted": format_coins(out.amount),
                        "address": out.to,
                    })).collect::<Vec<_>>(),
                }));
            }
            
            // Buscar en blockchain
            for (block_idx, block) in chain.iter().enumerate() {
                for tx in &block.txs {
                    if tx_hash(tx) == txid {
                        return Ok(json!({
                            "txid": tx_hash(tx),
                            "blockhash": block.hash,
                            "blockheight": block_idx,
                            "confirmations": chain.len() - block_idx,
                            "vin": tx.inputs.iter().map(|inp| json!({
                                "txid": inp.prev_tx_hash,
                                "vout": inp.prev_index,
                            })).collect::<Vec<_>>(),
                            "vout": tx.outputs.iter().enumerate().map(|(i, out)| json!({
                                "n": i,
                                "value": out.amount,
                                "value_formatted": format_coins(out.amount),
                                "address": out.to,
                            })).collect::<Vec<_>>(),
                        }));
                    }
                }
            }
            
            Err((-5, "Transaction not found".to_string()))
        }
        
        // === Utilidades ===
        "getinfo" => {
            let height = chain.len().saturating_sub(1);
            
            Ok(json!({
                "version": "2.0.0",
                "blocks": height,
                "difficulty": chain.last().map(|b| b.difficulty_bits).unwrap_or(20),
                "mempool_size": mempool.len(),
                "reward": get_reward(height as u64),
                "reward_formatted": format_coins(get_reward(height as u64)),
                "halving_in": HALVING_INTERVAL - (height as u64 % HALVING_INTERVAL),
            }))
        }
        
        "help" => {
            Ok(json!({
                "methods": [
                    "getblockcount - Returns block height",
                    "getbestblockhash - Returns tip block hash",
                    "getblockhash <height> - Returns block hash at height",
                    "getblock <hash> - Returns block data",
                    "getblockchaininfo - Returns chain info",
                    "getmempoolinfo - Returns mempool info",
                    "getrawmempool - Returns mempool txids",
                    "getrawtransaction <txid> - Returns transaction data",
                    "getinfo - Returns node info",
                    "help - Shows this help"
                ]
            }))
        }
        
        _ => Err((-32601, format!("Method not found: {}", method))),
    }
}

/// Genera respuesta HTTP
fn http_response(rpc: &RpcResponse) -> String {
    let body = serde_json::to_string(rpc).unwrap_or_default();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
}
