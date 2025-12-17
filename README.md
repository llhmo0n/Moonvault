# 🔐 MoonVault v4.0

## Bitcoin Security Infrastructure

> **"Protecting your Bitcoin, not replacing it."**

---

## ⚠️ CRITICAL NOTICE

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   MoonVault is NOT money. It is infrastructure software.                  ║
║                                                                           ║
║   • 'Gas units' have NO monetary value                                    ║
║   • Gas is NOT transferable - burn only                                   ║
║   • BTC is the ONLY economic asset                                        ║
║   • Service fees are paid in BTC on Bitcoin L1                            ║
║                                                                           ║
║   If anyone tries to sell you gas units, they are scamming you.           ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## 🎯 What is MoonVault?

MoonVault provides **security services for Bitcoin self-custody**:

| Problem | MoonVault Solution |
|---------|-------------------|
| **Theft** | Vaults with hot/cold keys and panic button |
| **Human Error** | Delays and cancellation windows |
| **Key Loss** | Recovery paths with timelocks |

**MoonVault is NOT:**
- A cryptocurrency or digital money
- A competitor to Bitcoin
- An investment or store of value

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BITCOIN L1                                     │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  • Your BTC (always here, never custodied by MoonVault)             │   │
│   │  • Fee Pool (service fees in BTC)                                   │   │
│   │  • Vault Scripts (P2WSH addresses)                                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                              ▲                                              │
│                              │ observes (never custodies)                   │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         MOONVAULT                                   │   │
│   │  • Coordination layer (ordering events)                             │   │
│   │  • Service activation (after BTC payment)                           │   │
│   │  • Gas burning (anti-spam only)                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘

INVARIANT: If MoonVault disappears, you can ALWAYS recover your BTC 
           directly on Bitcoin L1 using your keys + timelock.
```

---

## 📦 Installation

```bash
git clone https://github.com/llhmo0n/MoonVault.git
cd MoonVault
cargo build --release
./target/release/moonvault --help
```

---

## 🔧 Commands

### Fee System (BTC payments)

```bash
# Generate invoice for a service
moonvault fee-invoice vault-create --pubkey <YOUR_PUBKEY> --testnet

# Verify payment
moonvault fee-verify <BITCOIN_TXID> --invoice <INVOICE_ID> --testnet

# Check Fee Pool status
moonvault fee-pool-status --testnet
```

### Vault Services

```bash
# Create vault (after paying invoice)
moonvault vault-create \
  --invoice <INVOICE_ID> \
  --hot-key <HOT_PUBKEY> \
  --cold-key <COLD_PUBKEY> \
  --recovery-key <RECOVERY_PUBKEY> \
  --timelock <BLOCK_HEIGHT> \
  --testnet

# Check vault status
moonvault vault-status <VAULT_ID> --testnet

# Activate panic button
moonvault vault-panic <VAULT_ID> --recovery-key <PRIVKEY>

# List vaults
moonvault vault-list
```

### Gas (Anti-spam)

```bash
moonvault gas-balance    # Check balance
moonvault run            # Mine gas
```

---

## 💰 Fee Schedule

| Service | BTC Fee | Gas Burn |
|---------|---------|----------|
| Create Vault | 10,000 sats | 1 gas |
| Modify Vault | 5,000 sats | 1 gas |
| Monitoring | 1,000 sats/month | 0 gas |

**Distribution (immutable):** 70% Nodes, 20% Maintenance, 10% Reserve

---

## 🔐 Vault Features

| Key | Purpose |
|-----|---------|
| **Hot** | Daily operations (limited) |
| **Cold** | Large withdrawals (delayed) |
| **Recovery** | Emergencies (after timelock) |

**Panic Button:** Freeze all operations instantly if compromise detected.

---

## ⛽ Gas System

Gas is **NOT money**. It only prevents spam.

- Not transferable
- Burnable only
- No market value
- Mine it by running a node

---

## 🚫 MoonVault NEVER

- ❌ Custodies your BTC
- ❌ Moves your BTC
- ❌ Creates money/tokens
- ❌ Competes with Bitcoin
- ❌ Has governance over funds

---

## 📜 License

MIT License

---

**MoonVault - Protecting your Bitcoin, not replacing it.** 🔐
