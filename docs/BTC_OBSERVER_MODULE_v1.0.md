# MOONCOIN BTC OBSERVER MODULE
## Technical Specification v1.0

```
Document Status:    NORMATIVE
Version:            1.0
Date:               2025-12-15
Scope:              Read-only Bitcoin observation for Mooncoin
Prerequisite:       MOONCOIN–BITCOIN OPERATIONAL MODEL v1.0
```

---

## 0. FUNDAMENTAL PRINCIPLE

```
┌─────────────────────────────────────────────────────────────────┐
│                    OBSERVER PRINCIPLE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│              Mooncoin OBSERVES Bitcoin.                         │
│              Mooncoin does NOT VALIDATE Bitcoin.                │
│              Mooncoin does NOT CONTROL Bitcoin.                 │
│                                                                 │
│ The Observer is a READ-ONLY window into Bitcoin state.          │
│ It has no ability to modify, sign, or broadcast anything.       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 1. MODULE PURPOSE

### 1.1 What the Observer Does

| Function | Description |
|----------|-------------|
| Verify UTXO existence | Check if a specific UTXO is unspent |
| Count confirmations | Report confirmation depth |
| Match script templates | Compare scripts against LOCK STANDARD |
| Track timelock status | Report if timelock has expired |
| Detect settlement | Observe when UTXO is spent |

### 1.2 What the Observer Does NOT Do

| Prohibited Function | Reason |
|---------------------|--------|
| Sign transactions | Not a wallet |
| Broadcast transactions | Not a node |
| Manage private keys | Not a key store |
| Validate signatures | Not a validator |
| Execute scripts | Not a script interpreter |
| Determine spendability | Cannot know if user has keys |

---

## 2. DATA SOURCES

### 2.1 Supported Backends

The Observer MAY connect to any of the following backends:

#### 2.1.1 Bitcoin Core RPC (Recommended)

```
Endpoint:       http://<host>:<port>
Authentication: RPC username/password
Methods Used:   
    - getrawtransaction
    - gettxout
    - getblockheader
    - getblockcount
    - gettxoutproof
```

**Configuration:**
```toml
[btc_observer]
backend = "bitcoin_core"
host = "127.0.0.1"
port = 8332
user = "rpcuser"
password = "rpcpassword"
```

#### 2.1.2 Electrum Server

```
Endpoint:       tcp://<host>:<port> or ssl://<host>:<port>
Protocol:       Electrum Protocol (JSON-RPC over TCP)
Methods Used:
    - blockchain.transaction.get
    - blockchain.scripthash.listunspent
    - blockchain.headers.subscribe
    - blockchain.transaction.get_merkle
```

**Configuration:**
```toml
[btc_observer]
backend = "electrum"
host = "electrum.example.com"
port = 50002
ssl = true
```

#### 2.1.3 Esplora API

```
Endpoint:       https://<host>/api
Protocol:       REST API
Methods Used:
    - GET /tx/<txid>
    - GET /tx/<txid>/outspend/<vout>
    - GET /block-height/<height>
    - GET /tx/<txid>/merkle-proof
```

**Configuration:**
```toml
[btc_observer]
backend = "esplora"
url = "https://blockstream.info/api"
```

### 2.2 Backend Requirements

All backends MUST provide:

| Capability | Required |
|------------|----------|
| Query transaction by txid | YES |
| Query UTXO status | YES |
| Query current block height | YES |
| Query block headers | YES |
| Merkle proof retrieval | OPTIONAL |

All backends MUST be:

| Property | Requirement |
|----------|-------------|
| Read-only | No write operations |
| Stateless | No wallet state |
| Keyless | No private key access |

---

## 3. OBSERVER INTERFACE

### 3.1 Core Interface Definition

```rust
/// BTC Observer - Read-only Bitcoin state observation
pub trait BtcObserver {
    /// Check if a UTXO exists (is unspent)
    fn utxo_exists(&self, txid: &str, vout: u32) -> Result<bool, ObserverError>;
    
    /// Get confirmation count for a transaction
    fn utxo_confirmations(&self, txid: &str, vout: u32) -> Result<i32, ObserverError>;
    
    /// Check if script matches a LOCK STANDARD template
    fn script_matches_standard(&self, script: &[u8]) -> Result<Option<TemplateMatch>, ObserverError>;
    
    /// Get timelock status from script
    fn timelock_status(&self, script: &[u8], current_height: u32) -> Result<TimelockStatus, ObserverError>;
    
    /// Get current Bitcoin block height
    fn current_block_height(&self) -> Result<u32, ObserverError>;
    
    /// Get Merkle proof for transaction (optional)
    fn get_merkle_proof(&self, txid: &str) -> Result<Option<MerkleProof>, ObserverError>;
    
    /// Get raw transaction data
    fn get_transaction(&self, txid: &str) -> Result<Transaction, ObserverError>;
}
```

### 3.2 Data Types

```rust
/// Result of template matching
pub struct TemplateMatch {
    pub template_name: String,      // "multisig_cltv" | "htlc_simple"
    pub timelock_value: Option<u32>, // Block height or relative blocks
    pub timelock_type: TimelockType, // Absolute | Relative
}

pub enum TimelockType {
    Absolute,   // OP_CHECKLOCKTIMEVERIFY
    Relative,   // OP_CHECKSEQUENCEVERIFY
}

/// Timelock status
pub struct TimelockStatus {
    pub expired: bool,
    pub timelock_block: u32,
    pub current_block: u32,
    pub blocks_remaining: i32,  // Negative if expired
}

/// Merkle proof for SPV verification
pub struct MerkleProof {
    pub block_height: u32,
    pub block_hash: String,
    pub merkle_path: Vec<String>,
    pub tx_index: u32,
}

/// Observer errors
pub enum ObserverError {
    ConnectionFailed(String),
    UtxoNotFound,
    TransactionNotFound,
    InvalidScript,
    BackendError(String),
    Timeout,
}
```

---

## 4. OPERATIONS SPECIFICATION

### 4.1 utxo_exists

**Purpose:** Determine if a specific UTXO is unspent.

**Input:**
| Parameter | Type | Description |
|-----------|------|-------------|
| txid | string | 64 hex characters |
| vout | u32 | Output index |

**Output:**
| Return | Meaning |
|--------|---------|
| true | UTXO exists and is unspent |
| false | UTXO does not exist or is spent |
| Error | Could not determine |

**Implementation Notes:**
- Query mempool AND blockchain
- Return false if transaction not found
- Return false if output index out of range
- Return false if output is spent

**Backend-Specific:**

Bitcoin Core:
```
gettxout "<txid>" <vout> true
```
Returns null if spent, object if unspent.

Electrum:
```
blockchain.scripthash.listunspent <scripthash>
```
Check if txid:vout is in the list.

Esplora:
```
GET /tx/<txid>/outspend/<vout>
```
Returns `{"spent": true/false}`.

### 4.2 utxo_confirmations

**Purpose:** Get the number of confirmations for a UTXO.

**Input:**
| Parameter | Type | Description |
|-----------|------|-------------|
| txid | string | 64 hex characters |
| vout | u32 | Output index |

**Output:**
| Return | Meaning |
|--------|---------|
| 0 | In mempool, not confirmed |
| 1+ | Number of confirmations |
| -1 | Transaction not found |
| Error | Could not determine |

**Calculation:**
```
confirmations = current_block_height - tx_block_height + 1
```

### 4.3 script_matches_standard

**Purpose:** Check if a script matches a LOCK STANDARD template.

**Input:**
| Parameter | Type | Description |
|-----------|------|-------------|
| script | bytes | Raw script bytes |

**Output:**
| Return | Meaning |
|--------|---------|
| Some(TemplateMatch) | Matches a template |
| None | Does not match any template |
| Error | Parse error |

**Matching Rules:**

For `multisig_cltv`:
```
Pattern:
  OP_IF
    OP_2 <33-bytes> <33-bytes> OP_2 OP_CHECKMULTISIG
  OP_ELSE
    <4-bytes> OP_CHECKLOCKTIMEVERIFY OP_DROP <33-bytes> OP_CHECKSIG
  OP_ENDIF

Extract:
  - pubkey_hot: bytes 3-35
  - pubkey_cold: bytes 36-68
  - locktime: bytes 72-75 (little-endian)
  - pubkey_recovery: bytes 78-110
```

For `htlc_simple`:
```
Pattern:
  OP_IF
    OP_SHA256 <32-bytes> OP_EQUALVERIFY <33-bytes> OP_CHECKSIG
  OP_ELSE
    <4-bytes> OP_CHECKSEQUENCEVERIFY OP_DROP <33-bytes> OP_CHECKSIG
  OP_ENDIF

Extract:
  - hash: bytes 3-34
  - pubkey: bytes 37-69
  - timeout: bytes 73-76 (little-endian)
  - refund_pubkey: bytes 79-111
```

**Critical Note:**
```
┌─────────────────────────────────────────────────────────────────┐
│ WARNING: STRUCTURAL MATCHING ONLY                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ This function matches STRUCTURE, not SEMANTICS.                  │
│                                                                 │
│ A script that matches the template MAY STILL BE INVALID:         │
│   - Public keys may be malformed                                 │
│   - Timelock may be unreasonable                                 │
│   - User may not control the private keys                        │
│                                                                 │
│ Matching a template provides NO GUARANTEE of correctness.        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4.4 timelock_status

**Purpose:** Determine if a timelock has expired.

**Input:**
| Parameter | Type | Description |
|-----------|------|-------------|
| script | bytes | Raw script bytes |
| current_height | u32 | Current block height |

**Output:**
```rust
TimelockStatus {
    expired: bool,
    timelock_block: u32,
    current_block: u32,
    blocks_remaining: i32,
}
```

**Logic:**

For absolute timelock (CLTV):
```
expired = current_height >= timelock_value
blocks_remaining = timelock_value - current_height
```

For relative timelock (CSV):
```
// Requires knowing the funding transaction's block height
funding_height = get_tx_block_height(funding_txid)
expiry_height = funding_height + timelock_value
expired = current_height >= expiry_height
blocks_remaining = expiry_height - current_height
```

### 4.5 current_block_height

**Purpose:** Get the current Bitcoin blockchain height.

**Output:**
| Return | Meaning |
|--------|---------|
| u32 | Current block height |
| Error | Could not determine |

**Backend-Specific:**

Bitcoin Core:
```
getblockcount
```

Electrum:
```
blockchain.headers.subscribe
```

Esplora:
```
GET /blocks/tip/height
```

### 4.6 get_merkle_proof

**Purpose:** Get SPV proof for a transaction.

**Input:**
| Parameter | Type | Description |
|-----------|------|-------------|
| txid | string | 64 hex characters |

**Output:**
| Return | Meaning |
|--------|---------|
| Some(MerkleProof) | Proof retrieved |
| None | Proof not available |
| Error | Could not retrieve |

**Use Case:** Light client verification without full blockchain.

---

## 5. STATE DERIVATION

### 5.1 Lock States

The Observer derives lock states from Bitcoin data:

| State | Condition |
|-------|-----------|
| UNKNOWN | UTXO not found OR not registered |
| LOCKED | utxo_exists=true AND timelock.expired=false |
| EXPIRED | utxo_exists=true AND timelock.expired=true |
| SETTLED | utxo_exists=false (UTXO was spent) |

### 5.2 State Derivation Logic

```rust
fn derive_lock_state(
    observer: &impl BtcObserver,
    txid: &str,
    vout: u32,
    script: &[u8]
) -> Result<LockState, ObserverError> {
    // Check if UTXO exists
    let exists = observer.utxo_exists(txid, vout)?;
    
    if !exists {
        return Ok(LockState::Settled);
    }
    
    // Get current block height
    let current_height = observer.current_block_height()?;
    
    // Check timelock status
    let timelock = observer.timelock_status(script, current_height)?;
    
    if timelock.expired {
        Ok(LockState::Expired)
    } else {
        Ok(LockState::Locked)
    }
}
```

### 5.3 State Diagram

```
                        ┌───────────────────┐
                        │      UNKNOWN      │
                        │  (not registered) │
                        └─────────┬─────────┘
                                  │
                          register with
                          valid UTXO
                                  │
                                  ▼
                        ┌───────────────────┐
                        │      LOCKED       │
                        │  (UTXO exists,    │
                        │   timelock active)│
                        └─────────┬─────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
        timelock expires    UTXO spent          UTXO spent
              │             (multisig path)     (external)
              ▼                   │                   │
    ┌───────────────────┐         │                   │
    │     EXPIRED       │         │                   │
    │  (UTXO exists,    │         │                   │
    │   can settle)     │         │                   │
    └─────────┬─────────┘         │                   │
              │                   │                   │
        UTXO spent                │                   │
        (recovery path)           │                   │
              │                   │                   │
              ▼                   ▼                   ▼
            ┌─────────────────────────────────────────┐
            │               SETTLED                    │
            │          (UTXO no longer exists)         │
            └─────────────────────────────────────────┘
```

---

## 6. UPDATE BEHAVIOR

### 6.1 Refresh Strategy

| Strategy | Description | Use Case |
|----------|-------------|----------|
| On-demand | Query only when user requests | Default |
| Polling | Query every N blocks | Background monitoring |
| Event-driven | Subscribe to updates | Real-time applications |

### 6.2 Default Behavior

```
Default: ON-DEMAND
- Query Bitcoin only when user calls status check
- No background polling
- No persistent connections
- Minimal resource usage
```

### 6.3 Polling (Optional)

If enabled:
```toml
[btc_observer]
polling_enabled = true
polling_interval_blocks = 6  # Check every ~1 hour
```

### 6.4 Caching

```
Cache Policy:
- UTXO status: Cache for 1 block (may change)
- Block height: Cache for 30 seconds
- Merkle proofs: Cache indefinitely (immutable)
- Transaction data: Cache indefinitely (immutable)
```

---

## 7. ERROR HANDLING

### 7.1 Error Categories

| Category | Examples | Behavior |
|----------|----------|----------|
| Connection | Timeout, refused | Retry with backoff |
| Not Found | UTXO missing, tx missing | Return appropriate status |
| Parse | Invalid script, bad data | Return error |
| Backend | RPC error, rate limit | Report to user |

### 7.2 Error Responses

```rust
impl BtcObserver {
    fn handle_error(&self, error: ObserverError) -> LockState {
        match error {
            ObserverError::UtxoNotFound => LockState::Unknown,
            ObserverError::TransactionNotFound => LockState::Unknown,
            ObserverError::ConnectionFailed(_) => {
                log::warn!("BTC node unreachable, state unknown");
                LockState::Unknown
            }
            _ => LockState::Unknown,
        }
    }
}
```

### 7.3 Retry Policy

```
Connection Errors:
  - Retry up to 3 times
  - Exponential backoff: 1s, 2s, 4s
  - After 3 failures, return Unknown state

Rate Limiting:
  - Respect backend rate limits
  - Queue requests if needed
  - Never spam the backend
```

---

## 8. REORGANIZATION HANDLING

### 8.1 Reorg Detection

```
A reorganization may:
- Unconfirm a previously confirmed transaction
- Change confirmation count
- Invalidate Merkle proofs
```

### 8.2 Reorg Response

```
When reorg detected:
1. Mark affected locks as "needs refresh"
2. Re-query UTXO status
3. Re-query confirmation count
4. Update state accordingly
5. Log the event
```

### 8.3 Deep Reorg Warning

```
If reorg depth > 6 blocks:
  - Alert user
  - Mark all recent registrations as uncertain
  - Recommend manual verification
```

---

## 9. SECURITY CONSIDERATIONS

### 9.1 Trust Model

```
┌─────────────────────────────────────────────────────────────────┐
│ TRUST ASSUMPTIONS                                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ The Observer trusts:                                             │
│   - The configured Bitcoin backend to return honest data         │
│   - The Bitcoin network's consensus rules                        │
│                                                                 │
│ The Observer does NOT trust:                                     │
│   - User-provided scripts (only matches structure)               │
│   - That the user can spend (cannot verify key ownership)        │
│   - Any data from Mooncoin (only observes Bitcoin)               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 9.2 Backend Verification

```
Recommended: Run your own Bitcoin node
- Full validation of all data
- No trust in third parties
- Maximum security

Alternative: Use multiple backends
- Query 2+ independent sources
- Compare results
- Alert on discrepancy
```

### 9.3 Attack Vectors

| Attack | Mitigation |
|--------|------------|
| Malicious backend lies about UTXO | Use own node or multiple sources |
| Backend omits transaction | Merkle proof verification |
| Eclipse attack on node | Multiple network connections |
| Stale data | Check block height freshness |

---

## 10. IMPLEMENTATION CHECKLIST

### 10.1 Required Functions

```
[ ] utxo_exists
[ ] utxo_confirmations
[ ] script_matches_standard (multisig_cltv)
[ ] script_matches_standard (htlc_simple)
[ ] timelock_status
[ ] current_block_height
```

### 10.2 Optional Functions

```
[ ] get_merkle_proof
[ ] get_transaction
[ ] polling support
[ ] multiple backend support
```

### 10.3 Testing Requirements

```
[ ] Test with confirmed UTXO
[ ] Test with unconfirmed UTXO
[ ] Test with spent UTXO
[ ] Test with non-existent UTXO
[ ] Test template matching (valid scripts)
[ ] Test template matching (invalid scripts)
[ ] Test timelock calculation (not expired)
[ ] Test timelock calculation (expired)
[ ] Test connection failure handling
[ ] Test reorg handling
```

---

## 11. REFERENCE IMPLEMENTATION NOTES

### 11.1 Minimal Implementation

A minimal conforming implementation needs only:
- Bitcoin Core RPC backend
- On-demand refresh
- Two template matchers

### 11.2 Recommended Libraries

| Language | Library |
|----------|---------|
| Rust | bitcoincore-rpc, bitcoin |
| Python | python-bitcoinrpc, python-bitcoinlib |
| JavaScript | bitcoinjs-lib |

### 11.3 Code Size Estimate

```
Minimal implementation: ~500-1000 lines
With all backends: ~2000-3000 lines
With caching and polling: ~3000-4000 lines
```

---

**END OF BTC OBSERVER MODULE SPECIFICATION**

```
The Observer sees.
The Observer reports.
The Observer does not act.
```
