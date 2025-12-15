# MOONCOIN CLI SPECIFICATION
## Reference Implementation v1.0

```
Document Status:    NORMATIVE
Version:            1.0
Date:               2025-12-15
Scope:              Minimum viable CLI for LOCK–OPERATE–SETTLE
Prerequisite:       REFERENCE_FLOW_v1.0
```

---

## 0. DESIGN PRINCIPLES

### 0.1 Core Principles

| Principle | Description |
|-----------|-------------|
| **Correct over convenient** | Safety before usability |
| **Explicit over implicit** | No hidden behaviors |
| **Ugly but auditable** | Clarity over aesthetics |
| **Warnings before destruction** | Mandatory confirmations |
| **Read-only for Bitcoin** | Never sign or broadcast BTC |

### 0.2 What This CLI Does

- Generates LOCK scripts from LOCK STANDARD templates
- Displays mandatory warnings
- Observes Bitcoin UTXOs (read-only)
- Interacts with Mooncoin for OPERATE
- Prepares (but does not execute) SETTLE transactions

### 0.3 What This CLI Does NOT Do

- Sign Bitcoin transactions
- Broadcast to Bitcoin
- Manage Bitcoin private keys
- Estimate Bitcoin fees
- Automate any Bitcoin operation

---

## 1. COMMAND STRUCTURE

### 1.1 Top-Level Commands

```
moon <command> <subcommand> [options]

Commands:
    lock        LOCK script generation and management
    observe     Bitcoin UTXO observation
    operate     Mooncoin operations
    settle      SETTLE preparation
    config      Configuration management
    help        Display help information
    version     Display version information
```

### 1.2 Global Options

```
--config <path>     Path to config file (default: ~/.moon/config.toml)
--btc-node <url>    Bitcoin node URL (overrides config)
--moon-node <url>   Mooncoin node URL (overrides config)
--verbose           Enable verbose output
--json              Output in JSON format
--no-warnings       Suppress warnings (DANGEROUS)
--yes               Auto-confirm prompts (DANGEROUS)
```

---

## 2. LOCK COMMANDS

### 2.1 moon lock templates

Lists available LOCK STANDARD templates.

```
Usage: moon lock templates [--json]

Output:
┌─────────────────────────────────────────────────────────────────┐
│ LOCK STANDARD Templates                                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ 1. multisig_cltv (DEFAULT)                                      │
│    2-of-2 multisig OR unilateral exit after timelock            │
│    Parameters: pubkey_hot, pubkey_cold, pubkey_recovery,        │
│                locktime_blocks                                  │
│                                                                 │
│ 2. htlc_simple                                                  │
│    Hash-locked with timeout refund                              │
│    Parameters: hash_hex, pubkey, timeout_blocks                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 moon lock generate

Generates a LOCK script from template and parameters.

```
Usage: moon lock generate --template <name> --params <file> [--output <file>]

Options:
    --template <name>   Template name (multisig_cltv | htlc_simple)
    --params <file>     JSON file with parameters
    --output <file>     Output file (default: stdout)
```

#### Parameter File Format (multisig_cltv)

```json
{
    "template": "multisig_cltv",
    "pubkey_hot": "02<64-hex-chars>",
    "pubkey_cold": "03<64-hex-chars>",
    "pubkey_recovery": "02<64-hex-chars>",
    "locktime_blocks": 1008
}
```

#### Parameter File Format (htlc_simple)

```json
{
    "template": "htlc_simple",
    "hash_hex": "<64-hex-chars-sha256>",
    "pubkey": "02<64-hex-chars>",
    "timeout_blocks": 144
}
```

#### Output

```
┌─────────────────────────────────────────────────────────────────┐
│ ⚠️  WARNING: READ CAREFULLY                                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Mooncoin does NOT validate the semantic correctness of this     │
│ script. Mooncoin verifies ONLY that the format matches the      │
│ template structure.                                             │
│                                                                 │
│ YOU ARE SOLELY RESPONSIBLE FOR:                                 │
│   - Verifying the public keys are correct                       │
│   - Verifying you control the corresponding private keys        │
│   - Verifying the timelock value is appropriate                 │
│   - Testing with a small amount before committing large funds   │
│                                                                 │
│ A MALFORMED SCRIPT MAY RESULT IN PERMANENT LOSS OF BTC.         │
│                                                                 │
│ Mooncoin CANNOT recover lost funds under ANY circumstances.     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Do you understand and accept these risks? [yes/NO]: yes

LOCK Script Generated
─────────────────────
Template:        multisig_cltv
Timelock:        Block 880000 (~7 days from now)

Redeem Script (hex):
6352210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae6703f00d00b17521021e0a7a68a8c4bd6d1c3e7f4e9d5d7e5cac9d7e8f1a2b3c4d5e6f0112233445566ac68

P2WSH Address:
bc1q8z5t3w9...xyzabc123

Witness Script (for spending):
<place in witness when spending>

BACKUP REQUIREMENTS:
1. Save the redeem script above
2. Save your recovery private key
3. Note the timelock block: 880000

Without these, you CANNOT recover your BTC.
```

### 2.3 moon lock export

Exports instructions for creating the LOCK transaction in an external wallet.

```
Usage: moon lock export --script <file> --format <format>

Options:
    --script <file>     File containing generated script
    --format <format>   Output format: btc-cli | electrum | manual

Formats:
    btc-cli     Bitcoin Core CLI commands
    electrum    Electrum wallet instructions
    manual      Step-by-step manual instructions
```

#### Example Output (btc-cli format)

```
# Bitcoin Core Instructions for LOCK Transaction
# Generated by moon CLI v1.0

# Step 1: Create raw transaction
bitcoin-cli createrawtransaction \
    '[{"txid":"<your-input-txid>","vout":<your-input-vout>}]' \
    '[{"bc1q8z5t3w9...xyzabc123":<amount>}]'

# Step 2: Fund transaction (adds change output and fee)
bitcoin-cli fundrawtransaction <raw-tx-hex>

# Step 3: Sign transaction
bitcoin-cli signrawtransactionwithwallet <funded-tx-hex>

# Step 4: Broadcast transaction
bitcoin-cli sendrawtransaction <signed-tx-hex>

# Step 5: Wait for confirmation
bitcoin-cli gettransaction <txid>

# After confirmation, register with Mooncoin:
moon observe register --txid <txid> --vout 0 --script <redeem-script-hex>
```

### 2.4 moon lock verify

Verifies a redeem script matches a LOCK STANDARD template.

```
Usage: moon lock verify --script <hex>

Output (success):
✓ Script matches template: multisig_cltv
  Timelock: Block 880000
  Recovery pubkey: 02...

Output (failure):
✗ Script does not match any LOCK STANDARD template
  Reason: Unknown opcode at position 45
```

---

## 3. OBSERVE COMMANDS

### 3.1 moon observe register

Registers a LOCK with Mooncoin.

```
Usage: moon observe register --txid <txid> --vout <n> --script <hex>

Options:
    --txid <txid>       Bitcoin transaction ID (64 hex chars)
    --vout <n>          Output index (usually 0)
    --script <hex>      Redeem script (hex encoded)
```

#### Output (success)

```
┌─────────────────────────────────────────────────────────────────┐
│ ⚠️  OBSERVATION WARNING                                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ Mooncoin has OBSERVED this UTXO but provides NO GUARANTEE       │
│ that the script is correct or that you can spend from it.       │
│                                                                 │
│ This registration is for YOUR ACCOUNTING PURPOSES ONLY.         │
│                                                                 │
│ Mooncoin does NOT custody, control, or validate your BTC.       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Registration Successful
───────────────────────
Status:          OBSERVED
Lock ID:         moon_lock_a1b2c3d4
BTC TXID:        a1b2c3d4e5f6...
BTC Vout:        0
Template:        multisig_cltv
Timelock Block:  880000
Current Block:   879500
Blocks Remaining: 500 (~3.5 days)
Confirmations:   12
```

#### Output (failure)

```
Registration Failed
───────────────────
Reason: UTXO_NOT_FOUND
Details: Transaction a1b2c3d4... not found or not yet confirmed.

Possible causes:
- Transaction not yet broadcast
- Transaction not yet confirmed (wait for 1+ confirmations)
- Incorrect txid

Action: Verify transaction on a block explorer and retry.
```

### 3.2 moon observe status

Queries the status of a registered LOCK.

```
Usage: moon observe status --txid <txid> --vout <n>
       moon observe status --lock-id <id>

Output:
Lock Status
───────────
Lock ID:          moon_lock_a1b2c3d4
BTC TXID:         a1b2c3d4e5f6...
BTC Vout:         0
Status:           LOCKED | EXPIRED | SETTLED | UNKNOWN
UTXO Exists:      Yes | No
Timelock Block:   880000
Current Block:    879800
Blocks Remaining: 200 (~1.4 days) | EXPIRED | N/A
Last Checked:     2025-12-15 14:30:00 UTC
```

### 3.3 moon observe list

Lists all registered LOCKs for this user.

```
Usage: moon observe list [--status <status>] [--json]

Options:
    --status <status>   Filter by status (locked|expired|settled|all)
    --json              Output in JSON format

Output:
Registered LOCKs
────────────────
ID                  TXID (short)    Status    Blocks Left
moon_lock_a1b2c3d4  a1b2c3d4...     LOCKED    200
moon_lock_e5f6a7b8  e5f6a7b8...     EXPIRED   -
moon_lock_c9d0e1f2  c9d0e1f2...     SETTLED   -

Total: 3 locks (1 locked, 1 expired, 1 settled)
```

### 3.4 moon observe refresh

Forces a refresh of LOCK status from Bitcoin.

```
Usage: moon observe refresh --txid <txid> --vout <n>
       moon observe refresh --all

Output:
Refreshing lock status...
✓ moon_lock_a1b2c3d4: LOCKED → LOCKED (no change)
✓ moon_lock_e5f6a7b8: LOCKED → EXPIRED (timelock passed)
```

---

## 4. OPERATE COMMANDS

### 4.1 moon operate balance

Shows Mooncoin balance.

```
Usage: moon operate balance [--address <address>]

Output:
Mooncoin Balance
────────────────
Address:    mc1q...xyz
Available:  1234.56789012 MOON
Pending:    0.00000000 MOON
In Vaults:  500.00000000 MOON
Total:      1734.56789012 MOON
```

### 4.2 moon operate send

Sends MOON to another address.

```
Usage: moon operate send --to <address> --amount <moon> [--memo <text>]

Options:
    --to <address>      Destination Mooncoin address
    --amount <moon>     Amount to send
    --memo <text>       Optional memo

Output:
┌─────────────────────────────────────────────────────────────────┐
│ Transaction Preview                                              │
├─────────────────────────────────────────────────────────────────┤
│ From:     mc1q...abc                                             │
│ To:       mc1q...xyz                                             │
│ Amount:   100.00000000 MOON                                      │
│ Fee:      0.00001000 MOON                                        │
│ Memo:     Payment for services                                   │
└─────────────────────────────────────────────────────────────────┘

Confirm transaction? [yes/NO]: yes

Transaction Sent
────────────────
TXID: moon_tx_f1e2d3c4...
Status: Pending (awaiting confirmation)
```

### 4.3 moon operate receive

Displays receive address.

```
Usage: moon operate receive [--new]

Options:
    --new    Generate new address

Output:
Receive Address
───────────────
Address: mc1q8z5t3w9xyzabc123def456ghi789jkl012mno345

QR: [ASCII QR code or instruction to use --qr flag]
```

### 4.4 moon operate history

Shows transaction history.

```
Usage: moon operate history [--limit <n>] [--json]

Output:
Transaction History
───────────────────
Date                 Type      Amount          Balance
2025-12-15 14:30    RECEIVE   +100.00000000   1234.56789012
2025-12-15 10:15    SEND      -50.00000000    1134.56789012
2025-12-14 09:00    RECEIVE   +200.00000000   1184.56789012
```

### 4.5 moon operate vault

Vault management subcommands.

```
Usage: moon operate vault <subcommand>

Subcommands:
    create      Create a new vault
    list        List vaults
    status      Check vault status
    cancel      Cancel pending vault withdrawal
```

---

## 5. SETTLE COMMANDS

### 5.1 moon settle check

Checks if a LOCK is ready for settlement.

```
Usage: moon settle check --txid <txid> --vout <n>
       moon settle check --lock-id <id>

Output (not ready):
Settlement Check
────────────────
Lock ID:          moon_lock_a1b2c3d4
Status:           NOT READY
Reason:           Timelock not expired
Timelock Block:   880000
Current Block:    879800
Blocks Remaining: 200
Estimated Time:   ~1.4 days

Output (ready):
Settlement Check
────────────────
Lock ID:          moon_lock_a1b2c3d4
Status:           READY
Timelock Block:   880000
Current Block:    880500
Blocks Past:      500

You may now proceed with settlement.
Run: moon settle export --lock-id moon_lock_a1b2c3d4 --destination <btc_address>
```

### 5.2 moon settle burn

Burns MOON for accounting purposes.

```
Usage: moon settle burn --amount <moon> [--memo <text>]

Options:
    --amount <moon>     Amount to burn
    --memo <text>       Optional memo (e.g., "SETTLE: <txid>")
```

#### Output

```
┌─────────────────────────────────────────────────────────────────┐
│ ⚠️  WARNING: IRREVERSIBLE OPERATION                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ You are about to PERMANENTLY DESTROY 100.00000000 MOON.         │
│                                                                 │
│ This action CANNOT be reversed.                                 │
│ These MOON will be PERMANENTLY removed from circulation.        │
│                                                                 │
│ NOTE: Burning MOON is NOT required to recover your BTC.         │
│ This burn is for accounting purposes only.                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Type 'BURN' to confirm: BURN

Burn Successful
───────────────
Amount Burned:  100.00000000 MOON
Burn TXID:      moon_tx_burn_a1b2c3d4...
Memo:           SETTLE: a1b2c3d4e5f6...
```

### 5.3 moon settle export

Generates unsigned Bitcoin exit transaction.

```
Usage: moon settle export --lock-id <id> --destination <btc_address> [--fee-rate <sat/vb>]

Options:
    --lock-id <id>              Lock ID or --txid/--vout
    --destination <address>     BTC address to receive funds
    --fee-rate <sat/vb>         Fee rate (default: user must specify)
```

#### Output

```
┌─────────────────────────────────────────────────────────────────┐
│ ⚠️  WARNING: VERIFY CAREFULLY                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ You are about to generate a transaction that will send your     │
│ BTC to the following address:                                   │
│                                                                 │
│   bc1q9876543210...abcdefghijklmnop                             │
│                                                                 │
│ VERIFY THIS ADDRESS IS CORRECT.                                 │
│ Mooncoin CANNOT reverse Bitcoin transactions.                   │
│ Sending to a wrong address means PERMANENT LOSS.                │
│                                                                 │
│ You are SOLELY RESPONSIBLE for this transaction.                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Confirm destination address is correct? [yes/NO]: yes

Unsigned Transaction Generated
──────────────────────────────
Lock ID:        moon_lock_a1b2c3d4
Input TXID:     a1b2c3d4e5f6...
Input Vout:     0
Input Amount:   0.10000000 BTC
Destination:    bc1q9876543210...
Output Amount:  0.09999000 BTC
Fee:            0.00001000 BTC (10 sat/vB)

Unsigned TX (hex):
02000000000101a1b2c3d4e5f6...

───────────────────────────────────────────────────────────────────
SIGNING INSTRUCTIONS
───────────────────────────────────────────────────────────────────

This transaction must be signed with your RECOVERY PRIVATE KEY.

The witness must contain:
1. Signature from recovery key
2. Empty push (0x00) to select ELSE branch
3. The redeem script

Using Bitcoin Core:
  bitcoin-cli signrawtransactionwithkey <unsigned_tx_hex> '["<recovery_privkey_wif>"]'

Using other wallets:
  Import your recovery key and sign the transaction manually.

After signing, broadcast with:
  bitcoin-cli sendrawtransaction <signed_tx_hex>

───────────────────────────────────────────────────────────────────

Saved to: settle_tx_a1b2c3d4.txt
```

### 5.4 moon settle verify

Verifies a signed settlement transaction.

```
Usage: moon settle verify --signed-tx <hex>

Output (valid):
Transaction Verification
────────────────────────
Status:         VALID
Inputs:         1
Outputs:        1
Total In:       0.10000000 BTC
Total Out:      0.09999000 BTC
Fee:            0.00001000 BTC

Input 0:
  TXID:         a1b2c3d4e5f6...
  Vout:         0
  Script Type:  P2WSH (matches LOCK STANDARD)
  Signature:    VALID

Output 0:
  Address:      bc1q9876543210...
  Amount:       0.09999000 BTC

Ready for broadcast.

Output (invalid):
Transaction Verification
────────────────────────
Status:         INVALID
Reason:         Signature verification failed
Details:        Signature does not match recovery pubkey

Check:
- Are you signing with the correct private key?
- Is the redeem script correct?
```

---

## 6. CONFIG COMMANDS

### 6.1 moon config show

Displays current configuration.

```
Usage: moon config show

Output:
Configuration
─────────────
Config File:    ~/.moon/config.toml
BTC Node:       http://localhost:8332
Mooncoin Node:  http://localhost:38332
Wallet File:    ~/.moon/wallet.dat
Network:        mainnet
```

### 6.2 moon config set

Sets configuration values.

```
Usage: moon config set <key> <value>

Keys:
    btc-node        Bitcoin node URL
    moon-node       Mooncoin node URL
    network         mainnet | testnet
    wallet-file     Path to wallet file

Example:
moon config set btc-node http://192.168.1.100:8332
```

### 6.3 moon config init

Initializes configuration with interactive prompts.

```
Usage: moon config init

Output:
Mooncoin CLI Configuration
──────────────────────────

Bitcoin Node URL [http://localhost:8332]: 
Mooncoin Node URL [http://localhost:38332]: 
Network [mainnet]: 

Configuration saved to ~/.moon/config.toml
```

---

## 7. HELP AND VERSION

### 7.1 moon help

```
Usage: moon help [command]

Example:
moon help lock generate
```

### 7.2 moon version

```
Usage: moon version

Output:
moon CLI v1.0.0
Mooncoin Reference Implementation
Protocol Version: 1.0
```

---

## 8. ERROR CODES

| Code | Name | Description |
|------|------|-------------|
| 0 | SUCCESS | Operation completed |
| 1 | GENERAL_ERROR | Unspecified error |
| 2 | CONFIG_ERROR | Configuration problem |
| 3 | CONNECTION_ERROR | Cannot connect to node |
| 4 | INVALID_INPUT | Invalid user input |
| 5 | UTXO_NOT_FOUND | Bitcoin UTXO not found |
| 6 | SCRIPT_MISMATCH | Script doesn't match template |
| 7 | TIMELOCK_NOT_EXPIRED | Cannot settle yet |
| 8 | INSUFFICIENT_FUNDS | Not enough MOON |
| 9 | USER_CANCELLED | User cancelled operation |
| 10 | VERIFICATION_FAILED | Signature or script verification failed |

---

## 9. SECURITY CONSIDERATIONS

### 9.1 Never Implemented

The following features are NEVER implemented by design:

| Feature | Reason |
|---------|--------|
| BTC private key storage | Mooncoin must not hold BTC keys |
| BTC transaction signing | User must sign externally |
| BTC transaction broadcast | User must broadcast manually |
| Automatic fee estimation | User must decide fees |
| Address book / contacts | Reduces verification friction |
| Transaction batching | Adds complexity |

### 9.2 Mandatory Warnings

The following warnings MUST be displayed and CANNOT be suppressed except with `--no-warnings` flag:

| Command | Warning |
|---------|---------|
| `lock generate` | Script responsibility warning |
| `observe register` | Observation-only warning |
| `settle burn` | Irreversibility warning |
| `settle export` | Address verification warning |

### 9.3 Confirmation Requirements

The following operations REQUIRE explicit confirmation:

| Operation | Confirmation |
|-----------|--------------|
| `lock generate` | Type 'yes' |
| `operate send` | Type 'yes' |
| `settle burn` | Type 'BURN' |
| `settle export` | Type 'yes' |

---

## 10. IMPLEMENTATION NOTES

### 10.1 Minimum Dependencies

Reference implementation should minimize dependencies:

- Bitcoin RPC client (for observation)
- Mooncoin RPC client
- Script parsing library
- Address encoding (bech32)
- JSON parsing
- Terminal I/O

### 10.2 No GUI

This specification defines CLI only. GUI implementations are outside scope.

### 10.3 Portability

CLI should compile on:
- Linux (primary)
- macOS
- Windows (best effort)

### 10.4 Audit Priority

The following components should be audited first:
1. Script generation (`lock generate`)
2. Script verification (`lock verify`)
3. Transaction construction (`settle export`)

---

**END OF CLI SPECIFICATION**

```
This CLI is intentionally minimal.
Convenience is not a goal.
Correctness is the only goal.
```
