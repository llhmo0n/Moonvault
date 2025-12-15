// =============================================================================
// MOONCOIN v2.0 - Block Explorer Web
// =============================================================================

use std::convert::Infallible;
use std::net::SocketAddr;
use hyper::{Body, Request, Response, Server, Method, StatusCode};
use hyper::service::{make_service_fn, service_fn};

use crate::block::load_chain;
use crate::utxo::UtxoSet;
use crate::transaction::tx_hash;
use crate::lib::{HALVING_INTERVAL, get_reward};

// 1 MOON = 100_000_000 satoshis
const COIN: u64 = 100_000_000;

pub const EXPLORER_PORT: u16 = 3000;

/// Inicia el servidor del Block Explorer
pub async fn start_explorer() {
    let addr = SocketAddr::from(([0, 0, 0, 0], EXPLORER_PORT));
    
    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle_request))
    });
    
    let server = Server::bind(&addr).serve(make_svc);
    
    println!("Block Explorer running on http://127.0.0.1:{}", EXPLORER_PORT);
    
    if let Err(e) = server.await {
        eprintln!("Explorer server error: {}", e);
    }
}

/// Maneja las peticiones HTTP
async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path();
    let method = req.method();
    
    let response = match (method, path) {
        (&Method::GET, "/") => serve_home(),
        (&Method::GET, "/blocks") => serve_blocks(),
        (&Method::GET, "/api/stats") => serve_api_stats(),
        (&Method::GET, "/api/blocks") => serve_api_blocks(),
        (&Method::GET, path) if path.starts_with("/block/") => {
            let hash_or_height = &path[7..];
            serve_block_detail(hash_or_height)
        }
        (&Method::GET, path) if path.starts_with("/tx/") => {
            let txid = &path[4..];
            serve_tx_detail(txid)
        }
        (&Method::GET, path) if path.starts_with("/address/") => {
            let address = &path[9..];
            serve_address_detail(address)
        }
        (&Method::GET, path) if path.starts_with("/api/block/") => {
            let hash_or_height = &path[11..];
            serve_api_block(hash_or_height)
        }
        (&Method::GET, path) if path.starts_with("/api/tx/") => {
            let txid = &path[8..];
            serve_api_tx(txid)
        }
        (&Method::GET, path) if path.starts_with("/api/address/") => {
            let address = &path[13..];
            serve_api_address(address)
        }
        (&Method::GET, "/search") => {
            let query = req.uri().query().unwrap_or("");
            serve_search(query)
        }
        _ => serve_404(),
    };
    
    Ok(response)
}

// =============================================================================
// HTML Templates
// =============================================================================

fn html_header(title: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Mooncoin Explorer</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{
            background: rgba(0,0,0,0.3);
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 10px;
        }}
        header h1 {{
            color: #ffd700;
            font-size: 2em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        header h1::before {{ content: "🌙"; }}
        nav {{ margin-top: 15px; }}
        nav a {{
            color: #87ceeb;
            text-decoration: none;
            margin-right: 20px;
            padding: 8px 16px;
            border-radius: 5px;
            transition: background 0.3s;
        }}
        nav a:hover {{ background: rgba(255,255,255,0.1); }}
        .search-box {{
            margin-top: 15px;
            display: flex;
            gap: 10px;
        }}
        .search-box input {{
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 5px;
            background: rgba(255,255,255,0.1);
            color: #fff;
            font-size: 14px;
        }}
        .search-box input::placeholder {{ color: #888; }}
        .search-box button {{
            padding: 12px 24px;
            background: #ffd700;
            color: #1a1a2e;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
        }}
        .search-box button:hover {{ background: #ffed4a; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: rgba(255,255,255,0.05);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        .stat-card h3 {{ color: #888; font-size: 0.9em; margin-bottom: 10px; }}
        .stat-card .value {{ color: #ffd700; font-size: 1.8em; font-weight: bold; }}
        .card {{
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        .card h2 {{
            color: #ffd700;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }}
        th {{ color: #888; font-weight: normal; }}
        td {{ color: #e0e0e0; }}
        a {{ color: #87ceeb; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .hash {{ font-family: monospace; font-size: 0.9em; word-break: break-all; }}
        .amount {{ color: #4ade80; }}
        .amount.negative {{ color: #f87171; }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            background: rgba(255,215,0,0.2);
            color: #ffd700;
        }}
        .detail-grid {{
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 10px;
        }}
        .detail-grid dt {{ color: #888; }}
        .detail-grid dd {{ color: #e0e0e0; word-break: break-all; }}
        .tx-io {{
            display: grid;
            grid-template-columns: 1fr auto 1fr;
            gap: 20px;
            align-items: start;
        }}
        .tx-arrow {{
            color: #ffd700;
            font-size: 2em;
            padding-top: 20px;
        }}
        @media (max-width: 768px) {{
            .tx-io {{ grid-template-columns: 1fr; }}
            .tx-arrow {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Mooncoin Explorer</h1>
            <nav>
                <a href="/">Home</a>
                <a href="/blocks">Blocks</a>
            </nav>
            <form class="search-box" action="/search" method="get">
                <input type="text" name="q" placeholder="Search by block hash, tx hash, or address...">
                <button type="submit">Search</button>
            </form>
        </header>
"#, title)
}

fn html_footer() -> &'static str {
    r#"
    </div>
</body>
</html>"#
}

// =============================================================================
// Page Handlers
// =============================================================================

fn serve_home() -> Response<Body> {
    let chain = load_chain();
    let utxo = UtxoSet::rebuild_from_chain(&chain);
    
    let height = if chain.is_empty() { 0 } else { chain.len() - 1 };
    let supply = utxo.total_supply();
    let total_txs: usize = chain.iter().map(|b| b.txs.len()).sum();
    let difficulty = chain.last().map(|b| b.difficulty_bits).unwrap_or(0);
    let reward = get_reward(height as u64);
    let next_halving = HALVING_INTERVAL - (height as u64 % HALVING_INTERVAL);
    
    let mut html = html_header("Home");
    
    // Stats
    html.push_str(r#"<div class="stats-grid">"#);
    html.push_str(&format!(r#"
        <div class="stat-card">
            <h3>Block Height</h3>
            <div class="value">{}</div>
        </div>
    "#, height));
    html.push_str(&format!(r#"
        <div class="stat-card">
            <h3>Total Supply</h3>
            <div class="value">{:.2} MOON</div>
        </div>
    "#, supply as f64 / COIN as f64));
    html.push_str(&format!(r#"
        <div class="stat-card">
            <h3>Total Transactions</h3>
            <div class="value">{}</div>
        </div>
    "#, total_txs));
    html.push_str(&format!(r#"
        <div class="stat-card">
            <h3>Difficulty</h3>
            <div class="value">{}</div>
        </div>
    "#, difficulty));
    html.push_str(&format!(r#"
        <div class="stat-card">
            <h3>Block Reward</h3>
            <div class="value">{:.2} MOON</div>
        </div>
    "#, reward as f64 / COIN as f64));
    html.push_str(&format!(r#"
        <div class="stat-card">
            <h3>Next Halving</h3>
            <div class="value">{} blocks</div>
        </div>
    "#, next_halving));
    html.push_str(r#"</div>"#);
    
    // Recent blocks
    html.push_str(r#"<div class="card"><h2>Recent Blocks</h2><table>"#);
    html.push_str(r#"<tr><th>Height</th><th>Hash</th><th>Txs</th><th>Time</th></tr>"#);
    
    for block in chain.iter().rev().take(10) {
        let time = chrono::DateTime::from_timestamp(block.timestamp as i64, 0)
            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        
        html.push_str(&format!(r#"
            <tr>
                <td><a href="/block/{}">{}</a></td>
                <td class="hash"><a href="/block/{}">{}</a></td>
                <td>{}</td>
                <td>{}</td>
            </tr>
        "#, block.height, block.height, block.hash, &block.hash[..16], block.txs.len(), time));
    }
    
    html.push_str(r#"</table></div>"#);
    html.push_str(html_footer());
    
    Response::builder()
        .header("Content-Type", "text/html")
        .body(Body::from(html))
        .unwrap()
}

fn serve_blocks() -> Response<Body> {
    let chain = load_chain();
    
    let mut html = html_header("Blocks");
    html.push_str(r#"<div class="card"><h2>All Blocks</h2><table>"#);
    html.push_str(r#"<tr><th>Height</th><th>Hash</th><th>Merkle Root</th><th>Txs</th><th>Difficulty</th><th>Time</th></tr>"#);
    
    for block in chain.iter().rev() {
        let time = chrono::DateTime::from_timestamp(block.timestamp as i64, 0)
            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        
        html.push_str(&format!(r#"
            <tr>
                <td><a href="/block/{}">{}</a></td>
                <td class="hash"><a href="/block/{}">{}</a></td>
                <td class="hash">{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>
        "#, 
            block.height, block.height,
            block.hash, &block.hash[..16],
            &block.merkle_root[..16],
            block.txs.len(),
            block.difficulty_bits,
            time
        ));
    }
    
    html.push_str(r#"</table></div>"#);
    html.push_str(html_footer());
    
    Response::builder()
        .header("Content-Type", "text/html")
        .body(Body::from(html))
        .unwrap()
}

fn serve_block_detail(hash_or_height: &str) -> Response<Body> {
    let chain = load_chain();
    
    // Find block by hash or height
    let block = if let Ok(height) = hash_or_height.parse::<usize>() {
        chain.get(height).cloned()
    } else {
        chain.iter().find(|b| b.hash == hash_or_height).cloned()
    };
    
    let Some(block) = block else {
        return serve_404();
    };
    
    let time = chrono::DateTime::from_timestamp(block.timestamp as i64, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    
    let mut html = html_header(&format!("Block {}", block.height));
    
    html.push_str(r#"<div class="card"><h2>Block Details</h2>"#);
    html.push_str(r#"<dl class="detail-grid">"#);
    html.push_str(&format!(r#"<dt>Height</dt><dd>{}</dd>"#, block.height));
    html.push_str(&format!(r#"<dt>Hash</dt><dd class="hash">{}</dd>"#, block.hash));
    html.push_str(&format!(r#"<dt>Previous Hash</dt><dd class="hash"><a href="/block/{}">{}</a></dd>"#, block.prev_hash, block.prev_hash));
    html.push_str(&format!(r#"<dt>Merkle Root</dt><dd class="hash">{}</dd>"#, block.merkle_root));
    html.push_str(&format!(r#"<dt>Timestamp</dt><dd>{}</dd>"#, time));
    html.push_str(&format!(r#"<dt>Difficulty</dt><dd>{}</dd>"#, block.difficulty_bits));
    html.push_str(&format!(r#"<dt>Nonce</dt><dd>{}</dd>"#, block.nonce));
    html.push_str(&format!(r#"<dt>Transactions</dt><dd>{}</dd>"#, block.txs.len()));
    html.push_str(r#"</dl></div>"#);
    
    // Transactions
    html.push_str(r#"<div class="card"><h2>Transactions</h2><table>"#);
    html.push_str(r#"<tr><th>TxID</th><th>Inputs</th><th>Outputs</th><th>Amount</th></tr>"#);
    
    for tx in &block.txs {
        let txid = tx_hash(tx);
        let total_out: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        let is_coinbase = tx.is_coinbase();
        
        html.push_str(&format!(r#"
            <tr>
                <td class="hash"><a href="/tx/{}">{}</a> {}</td>
                <td>{}</td>
                <td>{}</td>
                <td class="amount">{:.8} MOON</td>
            </tr>
        "#,
            txid, &txid[..16],
            if is_coinbase { r#"<span class="badge">Coinbase</span>"# } else { "" },
            tx.inputs.len(),
            tx.outputs.len(),
            total_out as f64 / COIN as f64
        ));
    }
    
    html.push_str(r#"</table></div>"#);
    html.push_str(html_footer());
    
    Response::builder()
        .header("Content-Type", "text/html")
        .body(Body::from(html))
        .unwrap()
}

fn serve_tx_detail(txid: &str) -> Response<Body> {
    let chain = load_chain();
    
    // Find transaction
    let mut found_tx = None;
    let mut found_block = None;
    
    for block in &chain {
        for tx in &block.txs {
            if tx_hash(tx) == txid {
                found_tx = Some(tx.clone());
                found_block = Some(block.clone());
                break;
            }
        }
        if found_tx.is_some() { break; }
    }
    
    let Some(tx) = found_tx else {
        return serve_404();
    };
    let block = found_block.unwrap();
    
    let total_out: u64 = tx.outputs.iter().map(|o| o.amount).sum();
    
    let mut html = html_header("Transaction");
    
    html.push_str(r#"<div class="card"><h2>Transaction Details</h2>"#);
    html.push_str(r#"<dl class="detail-grid">"#);
    html.push_str(&format!(r#"<dt>TxID</dt><dd class="hash">{}</dd>"#, txid));
    html.push_str(&format!(r#"<dt>Block</dt><dd><a href="/block/{}">{}</a></dd>"#, block.height, block.height));
    html.push_str(&format!(r#"<dt>Block Hash</dt><dd class="hash"><a href="/block/{}">{}</a></dd>"#, block.hash, &block.hash[..32]));
    html.push_str(&format!(r#"<dt>Type</dt><dd>{}</dd>"#, if tx.is_coinbase() { "Coinbase (Mining Reward)" } else { "Regular Transaction" }));
    html.push_str(&format!(r#"<dt>Total Output</dt><dd class="amount">{:.8} MOON</dd>"#, total_out as f64 / COIN as f64));
    html.push_str(r#"</dl></div>"#);
    
    // Inputs and Outputs
    html.push_str(r#"<div class="card"><h2>Inputs & Outputs</h2>"#);
    html.push_str(r#"<div class="tx-io">"#);
    
    // Inputs
    html.push_str(r#"<div><h3 style="color:#888;margin-bottom:10px;">Inputs</h3>"#);
    if tx.is_coinbase() {
        html.push_str(r#"<div style="padding:10px;background:rgba(255,215,0,0.1);border-radius:5px;">Block Reward (Coinbase)</div>"#);
    } else {
        for input in &tx.inputs {
            html.push_str(&format!(r#"
                <div style="padding:10px;background:rgba(255,255,255,0.05);border-radius:5px;margin-bottom:5px;">
                    <a href="/tx/{}" class="hash">{}</a>
                    <span style="color:#888;">:{}</span>
                </div>
            "#, input.prev_tx_hash, &input.prev_tx_hash[..16], input.prev_index));
        }
    }
    html.push_str(r#"</div>"#);
    
    html.push_str(r#"<div class="tx-arrow">→</div>"#);
    
    // Outputs
    html.push_str(r#"<div><h3 style="color:#888;margin-bottom:10px;">Outputs</h3>"#);
    for (i, output) in tx.outputs.iter().enumerate() {
        html.push_str(&format!(r#"
            <div style="padding:10px;background:rgba(255,255,255,0.05);border-radius:5px;margin-bottom:5px;">
                <div><a href="/address/{}">{}</a></div>
                <div class="amount">{:.8} MOON</div>
                <div style="color:#666;font-size:0.8em;">Output #{}</div>
            </div>
        "#, output.to, &output.to, output.amount as f64 / COIN as f64, i));
    }
    html.push_str(r#"</div>"#);
    
    html.push_str(r#"</div></div>"#);
    html.push_str(html_footer());
    
    Response::builder()
        .header("Content-Type", "text/html")
        .body(Body::from(html))
        .unwrap()
}

fn serve_address_detail(address: &str) -> Response<Body> {
    let chain = load_chain();
    let utxo = UtxoSet::rebuild_from_chain(&chain);
    
    let balance = utxo.balance_of(address);
    let height = if chain.is_empty() { 0 } else { chain.len() as u64 - 1 };
    let spendable = utxo.spendable_balance(address, height);
    
    // Find all transactions involving this address
    let mut txs = Vec::new();
    for block in &chain {
        for tx in &block.txs {
            let txid = tx_hash(tx);
            
            // Check outputs (received)
            let mut received = 0u64;
            for output in &tx.outputs {
                if output.to == address {
                    received += output.amount;
                }
            }
            
            // Check inputs (sent) - simplified, would need to look up prev tx
            let sent = 0u64; // Would need to trace back inputs
            
            if received > 0 || sent > 0 {
                txs.push((block.height, txid, received, sent, block.timestamp));
            }
        }
    }
    
    let mut html = html_header(&format!("Address {}", &address[..12]));
    
    html.push_str(r#"<div class="card"><h2>Address Details</h2>"#);
    html.push_str(r#"<dl class="detail-grid">"#);
    html.push_str(&format!(r#"<dt>Address</dt><dd class="hash">{}</dd>"#, address));
    html.push_str(&format!(r#"<dt>Balance</dt><dd class="amount">{:.8} MOON</dd>"#, balance as f64 / COIN as f64));
    html.push_str(&format!(r#"<dt>Spendable</dt><dd class="amount">{:.8} MOON</dd>"#, spendable as f64 / COIN as f64));
    html.push_str(&format!(r#"<dt>Transactions</dt><dd>{}</dd>"#, txs.len()));
    html.push_str(r#"</dl></div>"#);
    
    // Transaction history
    html.push_str(r#"<div class="card"><h2>Transaction History</h2><table>"#);
    html.push_str(r#"<tr><th>Block</th><th>TxID</th><th>Received</th><th>Time</th></tr>"#);
    
    for (block_height, txid, received, _sent, timestamp) in txs.iter().rev() {
        let time = chrono::DateTime::from_timestamp(*timestamp as i64, 0)
            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        
        html.push_str(&format!(r#"
            <tr>
                <td><a href="/block/{}">{}</a></td>
                <td class="hash"><a href="/tx/{}">{}</a></td>
                <td class="amount">+{:.8} MOON</td>
                <td>{}</td>
            </tr>
        "#, block_height, block_height, txid, &txid[..16], *received as f64 / COIN as f64, time));
    }
    
    html.push_str(r#"</table></div>"#);
    html.push_str(html_footer());
    
    Response::builder()
        .header("Content-Type", "text/html")
        .body(Body::from(html))
        .unwrap()
}

fn serve_search(query: &str) -> Response<Body> {
    // Parse query parameter
    let q = query.split('&')
        .find(|s| s.starts_with("q="))
        .map(|s| &s[2..])
        .unwrap_or("")
        .trim();
    
    if q.is_empty() {
        return redirect("/");
    }
    
    let chain = load_chain();
    
    // Try to find as block height
    if let Ok(height) = q.parse::<usize>() {
        if height < chain.len() {
            return redirect(&format!("/block/{}", height));
        }
    }
    
    // Try to find as block hash
    if let Some(block) = chain.iter().find(|b| b.hash == q) {
        return redirect(&format!("/block/{}", block.hash));
    }
    
    // Try to find as transaction hash
    for block in &chain {
        for tx in &block.txs {
            if tx_hash(tx) == q {
                return redirect(&format!("/tx/{}", q));
            }
        }
    }
    
    // Assume it's an address
    if q.starts_with("M") && q.len() > 20 {
        return redirect(&format!("/address/{}", q));
    }
    
    // Not found
    let mut html = html_header("Not Found");
    html.push_str(&format!(r#"
        <div class="card">
            <h2>Not Found</h2>
            <p>No results found for: <code class="hash">{}</code></p>
            <p style="margin-top:10px;color:#888;">Try searching for:</p>
            <ul style="margin-top:10px;color:#888;">
                <li>Block height (e.g., 100)</li>
                <li>Block hash</li>
                <li>Transaction ID</li>
                <li>Address (starts with M)</li>
            </ul>
        </div>
    "#, q));
    html.push_str(html_footer());
    
    Response::builder()
        .header("Content-Type", "text/html")
        .body(Body::from(html))
        .unwrap()
}

fn serve_404() -> Response<Body> {
    let mut html = html_header("Not Found");
    html.push_str(r#"
        <div class="card">
            <h2>404 - Not Found</h2>
            <p>The page you're looking for doesn't exist.</p>
            <p style="margin-top:10px;"><a href="/">← Back to Home</a></p>
        </div>
    "#);
    html.push_str(html_footer());
    
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "text/html")
        .body(Body::from(html))
        .unwrap()
}

fn redirect(path: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", path)
        .body(Body::empty())
        .unwrap()
}

// =============================================================================
// API Endpoints (JSON)
// =============================================================================

fn serve_api_stats() -> Response<Body> {
    let chain = load_chain();
    let utxo = UtxoSet::rebuild_from_chain(&chain);
    
    let height = if chain.is_empty() { 0 } else { chain.len() - 1 };
    let supply = utxo.total_supply();
    let total_txs: usize = chain.iter().map(|b| b.txs.len()).sum();
    let difficulty = chain.last().map(|b| b.difficulty_bits).unwrap_or(0);
    
    let json = format!(r#"{{
        "height": {},
        "supply": {},
        "supply_formatted": "{:.8}",
        "total_transactions": {},
        "difficulty": {},
        "blocks": {}
    }}"#,
        height,
        supply,
        supply as f64 / COIN as f64,
        total_txs,
        difficulty,
        chain.len()
    );
    
    Response::builder()
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(json))
        .unwrap()
}

fn serve_api_blocks() -> Response<Body> {
    let chain = load_chain();
    
    let blocks: Vec<String> = chain.iter().rev().take(50).map(|block| {
        format!(r#"{{
            "height": {},
            "hash": "{}",
            "prev_hash": "{}",
            "merkle_root": "{}",
            "timestamp": {},
            "difficulty": {},
            "nonce": {},
            "tx_count": {}
        }}"#,
            block.height,
            block.hash,
            block.prev_hash,
            block.merkle_root,
            block.timestamp,
            block.difficulty_bits,
            block.nonce,
            block.txs.len()
        )
    }).collect();
    
    let json = format!("[{}]", blocks.join(","));
    
    Response::builder()
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(json))
        .unwrap()
}

fn serve_api_block(hash_or_height: &str) -> Response<Body> {
    let chain = load_chain();
    
    let block = if let Ok(height) = hash_or_height.parse::<usize>() {
        chain.get(height).cloned()
    } else {
        chain.iter().find(|b| b.hash == hash_or_height).cloned()
    };
    
    let Some(block) = block else {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error": "Block not found"}"#))
            .unwrap();
    };
    
    let txs: Vec<String> = block.txs.iter().map(|tx| {
        let txid = tx_hash(tx);
        let total: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        format!(r#"{{
            "txid": "{}",
            "inputs": {},
            "outputs": {},
            "total": {},
            "is_coinbase": {}
        }}"#, txid, tx.inputs.len(), tx.outputs.len(), total, tx.is_coinbase())
    }).collect();
    
    let json = format!(r#"{{
        "height": {},
        "hash": "{}",
        "prev_hash": "{}",
        "merkle_root": "{}",
        "timestamp": {},
        "difficulty": {},
        "nonce": {},
        "transactions": [{}]
    }}"#,
        block.height,
        block.hash,
        block.prev_hash,
        block.merkle_root,
        block.timestamp,
        block.difficulty_bits,
        block.nonce,
        txs.join(",")
    );
    
    Response::builder()
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(json))
        .unwrap()
}

fn serve_api_tx(txid: &str) -> Response<Body> {
    let chain = load_chain();
    
    for block in &chain {
        for tx in &block.txs {
            if tx_hash(tx) == txid {
                let inputs: Vec<String> = tx.inputs.iter().map(|i| {
                    format!(r#"{{"prev_tx": "{}", "prev_index": {}}}"#, i.prev_tx_hash, i.prev_index)
                }).collect();
                
                let outputs: Vec<String> = tx.outputs.iter().enumerate().map(|(i, o)| {
                    format!(r#"{{"index": {}, "address": "{}", "amount": {}}}"#, i, o.to, o.amount)
                }).collect();
                
                let json = format!(r#"{{
                    "txid": "{}",
                    "block_height": {},
                    "block_hash": "{}",
                    "is_coinbase": {},
                    "inputs": [{}],
                    "outputs": [{}]
                }}"#,
                    txid,
                    block.height,
                    block.hash,
                    tx.is_coinbase(),
                    inputs.join(","),
                    outputs.join(",")
                );
                
                return Response::builder()
                    .header("Content-Type", "application/json")
                    .header("Access-Control-Allow-Origin", "*")
                    .body(Body::from(json))
                    .unwrap();
            }
        }
    }
    
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"error": "Transaction not found"}"#))
        .unwrap()
}

fn serve_api_address(address: &str) -> Response<Body> {
    let chain = load_chain();
    let utxo = UtxoSet::rebuild_from_chain(&chain);
    
    let balance = utxo.balance_of(address);
    let height = if chain.is_empty() { 0 } else { chain.len() as u64 - 1 };
    let spendable = utxo.spendable_balance(address, height);
    
    let mut tx_count = 0;
    for block in &chain {
        for tx in &block.txs {
            for output in &tx.outputs {
                if output.to == address {
                    tx_count += 1;
                    break;
                }
            }
        }
    }
    
    let json = format!(r#"{{
        "address": "{}",
        "balance": {},
        "balance_formatted": "{:.8}",
        "spendable": {},
        "spendable_formatted": "{:.8}",
        "tx_count": {}
    }}"#,
        address,
        balance,
        balance as f64 / COIN as f64,
        spendable,
        spendable as f64 / COIN as f64,
        tx_count
    );
    
    Response::builder()
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(json))
        .unwrap()
}
