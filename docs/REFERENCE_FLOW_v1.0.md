# MOONCOIN REFERENCE FLOW
## Implementation Guide v1.0

```
Document Status:    NORMATIVE
Version:            1.0
Date:               2025-12-15
Scope:              Step-by-step operational flow for LOCK–OPERATE–SETTLE
Prerequisite:       MOONCOIN–BITCOIN OPERATIONAL MODEL v1.0
```

---

## 0. PURPOSE

This document provides an unambiguous, step-by-step description of the LOCK–OPERATE–SETTLE cycle. It enables:

- Independent implementations
- User execution without central guidance
- Verification of conformance

This document is procedural, not pedagogical. It assumes the reader has read the Normative Specification and the Security and Failure Guide.

---

## 1. PRECONDITIONS

Before initiating the LOCK–OPERATE–SETTLE cycle, the following MUST be true:

### 1.1 User Requirements

| Requirement | Description |
|-------------|-------------|
| **PRE-1** | User controls BTC in at least one unspent UTXO |
| **PRE-2** | User has a functional Mooncoin wallet |
| **PRE-3** | User has read SECURITY_AND_FAILURE_GUIDE |
| **PRE-4** | User understands Mooncoin does NOT custody BTC |
| **PRE-5** | User accepts full responsibility for script correctness |

### 1.2 Technical Requirements

| Requirement | Description |
|-------------|-------------|
| **PRE-6** | Access to Bitcoin node (for observation and broadcast) |
| **PRE-7** | Access to Mooncoin node |
| **PRE-8** | Ability to sign Bitcoin transactions (external wallet) |
| **PRE-9** | Secure storage for BTC private keys |
| **PRE-10** | Secure storage for redeem script |

### 1.3 Mandatory Acknowledgment

User MUST acknowledge:

```
I understand that:
- Mooncoin does NOT validate the semantic correctness of my BTC script
- A malformed script may result in PERMANENT LOSS of my BTC
- Mooncoin cannot recover lost BTC under any circumstances
- I am solely responsible for verifying my script before funding
- I have backed up my recovery key and redeem script
```

---

## 2. PHASE: LOCK (Executed on Bitcoin)

### 2.1 Template Selection

User selects from LOCK STANDARD templates:

#### Option A: P2WSH Multisig + CLTV (DEFAULT)

```
OP_IF
    <2> <user_pubkey_hot> <user_pubkey_cold> <2> OP_CHECKMULTISIG
OP_ELSE
    <absolute_locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <user_pubkey_recovery> OP_CHECKSIG
OP_ENDIF
```

**Use case:** Standard lock with immediate exit via 2-of-2 multisig, or unilateral exit after timelock.

#### Option B: HTLC Simple (for atomicity)

```
OP_IF
    OP_SHA256 <hash> OP_EQUALVERIFY <user_pubkey> OP_CHECKSIG
OP_ELSE
    <relative_locktime> OP_CHECKSEQUENCEVERIFY OP_DROP
    <user_pubkey> OP_CHECKSIG
OP_ENDIF
```

**Use case:** Conditional release with automatic refund.

### 2.2 Parameter Generation

User generates the following parameters:

#### For Template A (Multisig + CLTV):

| Parameter | Format | Description |
|-----------|--------|-------------|
| `user_pubkey_hot` | 33 bytes compressed | Hot wallet public key |
| `user_pubkey_cold` | 33 bytes compressed | Cold storage public key |
| `user_pubkey_recovery` | 33 bytes compressed | Recovery key (for unilateral exit) |
| `absolute_locktime` | 4 bytes little-endian | Block height for timelock expiry |

#### For Template B (HTLC):

| Parameter | Format | Description |
|-----------|--------|-------------|
| `hash` | 32 bytes | SHA256 of preimage |
| `user_pubkey` | 33 bytes compressed | User's public key |
| `relative_locktime` | 4 bytes | Blocks after funding for refund |

### 2.3 Script Construction

#### 2.3.1 Assemble Redeem Script

Substitute parameters into selected template. Result is the `redeem_script`.

Example (Template A with placeholder values):
```
OP_IF
    OP_2
    <33-byte-hot-pubkey>
    <33-byte-cold-pubkey>
    OP_2
    OP_CHECKMULTISIG
OP_ELSE
    <4-byte-locktime>
    OP_CHECKLOCKTIMEVERIFY
    OP_DROP
    <33-byte-recovery-pubkey>
    OP_CHECKSIG
OP_ENDIF
```

#### 2.3.2 Compute Script Hash

```
script_hash = SHA256(redeem_script)
```

#### 2.3.3 Derive P2WSH Address

```
witness_program = 0x00 || 0x20 || script_hash
p2wsh_address = bech32_encode("bc", witness_program)
```

### 2.4 Transaction Construction

User constructs Bitcoin transaction:

| Field | Value |
|-------|-------|
| Version | 2 |
| Input | User's existing UTXO(s) |
| Output 0 | `<amount>` to `<p2wsh_address>` |
| Output 1 | Change to user's address (if applicable) |
| Locktime | 0 (or current block for RBF) |

**Fee calculation:** User's responsibility. Not within Mooncoin's scope.

### 2.5 Transaction Signing

User signs transaction using their existing wallet.

Mooncoin does NOT participate in signing.

### 2.6 Broadcast to Bitcoin

User broadcasts signed transaction to Bitcoin network.

Methods:
- Bitcoin Core: `sendrawtransaction <hex>`
- Electrum: Broadcast via GUI or CLI
- Block explorer: Manual submission

### 2.7 Confirmation Wait

User waits for transaction confirmation.

| Confirmation Level | Security |
|--------------------|----------|
| 1 confirmation | Minimum for registration |
| 6 confirmations | Recommended |
| 100+ confirmations | High-value locks |

### 2.8 Data Extraction

After confirmation, user extracts:

| Data | Source | Purpose |
|------|--------|---------|
| `txid` | Transaction hash | Unique identifier |
| `vout` | Output index (usually 0) | UTXO identification |
| `redeem_script` | From step 2.3.1 | Script verification |
| `block_height` | Block containing tx | Confirmation reference |
| `merkle_proof` | From Bitcoin node | SPV verification (optional) |

### 2.9 LOCK Completion Checklist

Before proceeding to registration:

```
[ ] Transaction confirmed (minimum 1, recommended 6)
[ ] txid recorded
[ ] vout recorded
[ ] redeem_script backed up securely
[ ] Recovery private key backed up securely
[ ] Timelock block height noted
```

---

## 3. PHASE: REGISTRATION (Mooncoin observes Bitcoin)

### 3.1 Registration Request

User submits registration to Mooncoin:

#### Request Format

```json
{
    "action": "register_lock",
    "btc_txid": "<64-char hex>",
    "btc_vout": <integer>,
    "redeem_script": "<hex-encoded script>",
    "expected_template": "multisig_cltv | htlc_simple"
}
```

### 3.2 Mooncoin Verification

Mooncoin performs the following checks:

| Check | Action | Failure Behavior |
|-------|--------|------------------|
| UTXO exists | Query BTC Observer | Reject registration |
| UTXO unspent | Query BTC Observer | Reject registration |
| Script format | Match against LOCK STANDARD | Reject if no match |
| Confirmations | Check >= 1 | Reject if unconfirmed |

### 3.3 What Mooncoin Does NOT Verify

```
┌─────────────────────────────────────────────────────────────────┐
│ WARNING: VERIFICATION SCOPE                                      │
├─────────────────────────────────────────────────────────────────┤
│ Mooncoin does NOT verify:                                        │
│   - That the user controls the required private keys             │
│   - That the script will execute correctly                       │
│   - That the timelock value is reasonable                        │
│   - That the public keys are valid                               │
│   - That the user can actually spend from this script            │
│                                                                 │
│ Mooncoin verifies ONLY format, not semantic correctness.         │
└─────────────────────────────────────────────────────────────────┘
```

### 3.4 Registration Response

#### Success Response

```json
{
    "status": "OBSERVED",
    "lock_id": "<internal reference>",
    "btc_txid": "<txid>",
    "btc_vout": <vout>,
    "template_matched": "multisig_cltv",
    "timelock_block": <block_height>,
    "current_block": <current_height>,
    "blocks_until_expiry": <remaining>,
    "warning": "Mooncoin has observed this UTXO but does NOT guarantee script correctness. You are solely responsible for the validity of your lock script."
}
```

#### Failure Response

```json
{
    "status": "REJECTED",
    "reason": "<specific reason>",
    "details": "<additional information>"
}
```

### 3.5 Registration State

After successful registration, the lock enters state: **LOCKED**

State is stored in Mooncoin but has NO effect on Bitcoin.

---

## 4. PHASE: OPERATE (Executed on Mooncoin)

### 4.1 Available Operations

During OPERATE phase, user can perform standard Mooncoin operations:

| Operation | Description | Relation to LOCK |
|-----------|-------------|------------------|
| Send MOON | Transfer MOON to another address | Independent |
| Receive MOON | Receive MOON from others | Independent |
| Vault operations | Create/manage vaults | Independent |
| Social Recovery | Configure recovery contacts | Independent |
| Inheritance | Configure inheritance rules | Independent |

### 4.2 Critical Understanding

```
┌─────────────────────────────────────────────────────────────────┐
│ NORMATIVE STATEMENT: OPERATE INDEPENDENCE                        │
├─────────────────────────────────────────────────────────────────┤
│ Operations in Mooncoin are COMPLETELY INDEPENDENT of the LOCK.   │
│                                                                 │
│ - MOON is not a representation of locked BTC                     │
│ - MOON balance is unrelated to BTC locked amount                 │
│ - Spending MOON does not affect the BTC LOCK                     │
│ - The LOCK exists only for the user's accounting purposes        │
│                                                                 │
│ There is NO peg. There is NO backing. There is NO redemption.    │
└─────────────────────────────────────────────────────────────────┘
```

### 4.3 Lock Status Query

User can query lock status at any time:

#### Request

```json
{
    "action": "query_lock_status",
    "btc_txid": "<txid>",
    "btc_vout": <vout>
}
```

#### Response

```json
{
    "status": "LOCKED | EXPIRED | SETTLED | UNKNOWN",
    "btc_txid": "<txid>",
    "btc_vout": <vout>,
    "timelock_block": <target_block>,
    "current_block": <current_block>,
    "blocks_remaining": <remaining | 0 | -N>,
    "utxo_exists": true | false,
    "last_checked": "<timestamp>"
}
```

### 4.4 State Transitions

```
                    ┌──────────────────────────────┐
                    │           LOCKED             │
                    │  (UTXO exists, timelock      │
                    │   not expired)               │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────┴───────────────┐
                    │                              │
          timelock expires                  UTXO spent
                    │                         (any path)
                    ▼                              │
        ┌───────────────────────┐                  │
        │       EXPIRED         │                  │
        │  (UTXO exists,        │                  │
        │   timelock passed)    │                  │
        └───────────┬───────────┘                  │
                    │                              │
               UTXO spent                          │
              (recovery path)                      │
                    │                              │
                    ▼                              ▼
              ┌─────────────────────────────────────┐
              │             SETTLED                 │
              │        (UTXO no longer exists)      │
              └─────────────────────────────────────┘
```

---

## 5. PHASE: SETTLE (Executed on Bitcoin)

### 5.1 Precondition Check

Before attempting SETTLE, verify:

| Condition | Check Method | Required State |
|-----------|--------------|----------------|
| Timelock expired | `query_lock_status` | `EXPIRED` |
| UTXO still exists | `query_lock_status` | `utxo_exists: true` |
| Recovery key available | User verification | User confirms |

### 5.2 Optional: MOON Burn

User MAY burn MOON for accounting purposes.

#### Burn Transaction

```json
{
    "action": "burn",
    "amount": "<moon_amount>",
    "burn_address": "moon1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq<checksum>",
    "memo": "SETTLE: <btc_txid>:<vout>"
}
```

#### Burn Properties

| Property | Value |
|----------|-------|
| Required for BTC recovery | **NO** |
| Reversible | **NO** |
| Purpose | Accounting, social signal |
| Effect on BTC | **NONE** |

```
┌─────────────────────────────────────────────────────────────────┐
│ WARNING: BURN IS OPTIONAL                                        │
├─────────────────────────────────────────────────────────────────┤
│ Burning MOON is NOT required to recover BTC.                     │
│ The burn exists only for accounting consistency.                 │
│ User may recover BTC without burning any MOON.                   │
│ User may burn MOON without recovering BTC.                       │
│ These are independent actions.                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 5.3 Construct Bitcoin Exit Transaction

User constructs the settlement transaction:

#### Transaction Structure (Template A - Recovery Path)

| Field | Value |
|-------|-------|
| Version | 2 |
| Inputs | 1 |
| Input 0 prevout | `<lock_txid>:<vout>` |
| Input 0 sequence | `0xFFFFFFFE` (for CLTV) |
| Outputs | 1 (or 2 with change) |
| Output 0 | `<full_amount - fee>` to `<user_btc_address>` |
| Locktime | `<timelock_block>` (must be >= script timelock) |

#### Witness Structure (Recovery Path)

```
witness = [
    <signature_recovery_key>,
    <00>,                        # OP_FALSE to take ELSE branch
    <redeem_script>
]
```

### 5.4 Transaction Signing

User signs with recovery private key.

Signing occurs in user's Bitcoin wallet.

**Mooncoin does NOT sign.**
**Mooncoin does NOT hold keys.**
**Mooncoin does NOT participate.**

### 5.5 Transaction Verification (Optional)

Before broadcast, user MAY verify:

```
bitcoin-cli testmempoolaccept '["<signed_tx_hex>"]'
```

Expected result:
```json
[{"txid": "<txid>", "allowed": true}]
```

### 5.6 Broadcast to Bitcoin

User broadcasts signed transaction:

```
bitcoin-cli sendrawtransaction <signed_tx_hex>
```

### 5.7 Confirmation Wait

User waits for confirmation.

1 confirmation = SETTLE complete.

### 5.8 Settlement Verification

After confirmation, verify in Mooncoin:

```json
{
    "action": "query_lock_status",
    "btc_txid": "<original_lock_txid>",
    "btc_vout": <original_vout>
}
```

Expected response:
```json
{
    "status": "SETTLED",
    "utxo_exists": false,
    "settlement_txid": "<exit_txid>",
    "settled_at_block": <block_height>
}
```

### 5.9 SETTLE Completion

The LOCK–OPERATE–SETTLE cycle is complete.

User has:
- Recovered BTC to their address
- Optionally burned MOON
- Closed their operational position

---

## 6. STATE DIAGRAM

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      LOCK–OPERATE–SETTLE STATES                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│    [NONE]                                                               │
│       │                                                                 │
│       │ User creates LOCK script                                        │
│       │ User funds P2WSH address                                        │
│       │ User registers with Mooncoin                                    │
│       ▼                                                                 │
│    [LOCKED] ◄─────────────────────────────────────────────────┐        │
│       │                                                       │        │
│       │ Mooncoin observes UTXO                                │        │
│       │ User operates in Mooncoin                             │        │
│       │                                                       │        │
│       ├─── timelock expires ───►[EXPIRED]                     │        │
│       │                             │                         │        │
│       │                             │ User constructs exit tx │        │
│       │                             │ User signs with         │        │
│       │                             │   recovery key          │        │
│       │                             │ User broadcasts         │        │
│       │                             ▼                         │        │
│       │                         [SETTLED]                     │        │
│       │                             ▲                         │        │
│       │                             │                         │        │
│       └─── UTXO spent (any path) ───┘                         │        │
│              (multisig, or                                    │        │
│               external spend)                                 │        │
│                                                               │        │
│    [UNKNOWN] ─── UTXO not found / not registered ─────────────┘        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 7. ERROR HANDLING

### 7.1 Registration Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| `UTXO_NOT_FOUND` | Transaction not confirmed | Wait for confirmation |
| `UTXO_ALREADY_SPENT` | UTXO was spent | Cannot register |
| `SCRIPT_MISMATCH` | Script doesn't match templates | Use LOCK STANDARD template |
| `INVALID_TXID` | Malformed transaction ID | Verify txid format |

### 7.2 Query Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| `LOCK_NOT_FOUND` | Not registered | Register first |
| `BTC_NODE_UNAVAILABLE` | Cannot reach Bitcoin | Retry later |
| `STATE_UNKNOWN` | Cannot determine state | Check BTC node |

### 7.3 Settlement Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| `TIMELOCK_NOT_EXPIRED` | Too early | Wait for expiry |
| `UTXO_ALREADY_SPENT` | Already settled | No action needed |
| `INVALID_SIGNATURE` | Wrong key used | Sign with correct key |
| `SCRIPT_EXECUTION_FAILED` | Script error | Cannot recover (user error) |

---

## 8. TIMING REFERENCE

### 8.1 Bitcoin Block Times

| Metric | Value |
|--------|-------|
| Target block time | 10 minutes |
| Blocks per hour | ~6 |
| Blocks per day | ~144 |
| Blocks per week | ~1008 |
| Blocks per month | ~4320 |

### 8.2 Recommended Timelocks

| Duration | Blocks | Use Case |
|----------|--------|----------|
| 1 week | 1008 | Short-term operational |
| 2 weeks | 2016 | Standard operational |
| 1 month | 4320 | Extended operational |
| 3 months | 12960 | Long-term hold |

### 8.3 Warning Thresholds

| Timelock | Warning |
|----------|---------|
| < 144 blocks (1 day) | "Very short timelock" |
| > 52560 blocks (1 year) | "Very long timelock" |
| > 210000 blocks (~4 years) | "Extreme timelock" |

---

## 9. CHECKLIST SUMMARY

### 9.1 Pre-LOCK Checklist

```
[ ] Read SECURITY_AND_FAILURE_GUIDE
[ ] Understand Mooncoin does not custody BTC
[ ] Generated all required keys
[ ] Backed up recovery private key
[ ] Selected appropriate timelock
[ ] Verified script matches template exactly
[ ] Tested with small amount first (recommended)
```

### 9.2 Post-LOCK Checklist

```
[ ] Transaction confirmed (6+ blocks recommended)
[ ] Recorded txid
[ ] Recorded vout
[ ] Backed up redeem script
[ ] Registered with Mooncoin
[ ] Verified status shows LOCKED
```

### 9.3 Pre-SETTLE Checklist

```
[ ] Verified timelock has expired
[ ] Verified UTXO still exists
[ ] Recovery private key accessible
[ ] Redeem script available
[ ] Destination BTC address verified
[ ] Transaction fee calculated
```

### 9.4 Post-SETTLE Checklist

```
[ ] Exit transaction confirmed
[ ] BTC received at destination
[ ] Mooncoin status shows SETTLED
[ ] Optional: MOON burned for accounting
```

---

## 10. REFERENCE DATA FORMATS

### 10.1 Transaction ID

```
Format: 64 hexadecimal characters (32 bytes)
Example: a1b2c3d4e5f6...0123456789abcdef
Endianness: Display is reversed from internal
```

### 10.2 Redeem Script

```
Format: Hexadecimal string
Length: Variable (typically 100-200 bytes for LOCK STANDARD)
Encoding: Raw bytes, hex-encoded
```

### 10.3 Public Keys

```
Format: Compressed SEC format
Length: 33 bytes (66 hex characters)
Prefix: 02 or 03
```

### 10.4 Timelock Value

```
Format: Block height (absolute) or block count (relative)
Encoding: 4 bytes, little-endian
Range: 1 to 500000000 (block heights)
```

---

**END OF REFERENCE FLOW**

```
This document describes WHAT to do.
CLI_SPECIFICATION describes HOW to do it.
SECURITY_AND_FAILURE_GUIDE describes WHAT CAN GO WRONG.
```
