# BTC Lock - Documentación Técnica

## Visión General

BTC Lock es el módulo que implementa el puente entre Mooncoin y Bitcoin. Permite a los usuarios bloquear BTC en scripts Bitcoin con timelock mientras operan con MOON.

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                        BTC LOCK MODULE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Script     │  │   Template   │  │   Address    │          │
│  │  Generator   │  │   Matcher    │  │  Generator   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Esplora    │  │    Lock      │  │  Settlement  │          │
│  │   Observer   │  │   Registry   │  │   Builder    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                 ┌────────────────────────┐
                 │   Bitcoin Network      │
                 │   (via Esplora API)    │
                 └────────────────────────┘
```

---

## Componentes

### 1. Script Generator

Genera scripts Bitcoin válidos para LOCKs.

#### multisig_cltv

```
OP_IF
    OP_2
    <pubkey_hot>
    <pubkey_cold>
    OP_2
    OP_CHECKMULTISIG
OP_ELSE
    <timelock>
    OP_CHECKLOCKTIMEVERIFY
    OP_DROP
    <pubkey_recovery>
    OP_CHECKSIG
OP_ENDIF
```

**Hex breakdown:**
```
63          OP_IF
52          OP_2
21          PUSH 33 bytes (pubkey_hot)
[33 bytes]  pubkey_hot
21          PUSH 33 bytes (pubkey_cold)  
[33 bytes]  pubkey_cold
52          OP_2
ae          OP_CHECKMULTISIG
67          OP_ELSE
03          PUSH 3 bytes (timelock)
[3 bytes]   timelock (little-endian)
b1          OP_CHECKLOCKTIMEVERIFY
75          OP_DROP
21          PUSH 33 bytes (pubkey_recovery)
[33 bytes]  pubkey_recovery
ac          OP_CHECKSIG
68          OP_ENDIF
```

#### htlc_simple

```
OP_IF
    OP_SHA256
    <hash>
    OP_EQUALVERIFY
    <pubkey>
    OP_CHECKSIG
OP_ELSE
    <timeout>
    OP_CHECKSEQUENCEVERIFY
    OP_DROP
    <pubkey>
    OP_CHECKSIG
OP_ENDIF
```

### 2. Template Matcher

Verifica que un script coincida con un template conocido y extrae parámetros.

```rust
pub struct TemplateMatch {
    pub template: LockTemplate,
    pub timelock_value: u32,
    pub pubkeys: Vec<String>,
}
```

### 3. P2WSH Address Generator

Genera direcciones Pay-to-Witness-Script-Hash:

```rust
// 1. SHA256 del redeem script
let script_hash = sha256(redeem_script);

// 2. Witness program: 0x00 0x20 [32-byte hash]
let witness_program = [0x00, 0x20] + script_hash;

// 3. Bech32 encode
let address = bech32_encode(hrp, witness_program);
// hrp = "bc" (mainnet) o "tb" (testnet)
```

### 4. Esplora Observer

Cliente HTTP para la API de Blockstream:

```rust
pub struct EsploraObserver {
    base_url: String,
    network: BitcoinNetwork,
    timeout_secs: u64,
}

impl BtcObserver for EsploraObserver {
    fn utxo_exists(&self, txid: &str, vout: u32) -> Result<bool, ObserverError>;
    fn utxo_confirmations(&self, txid: &str, vout: u32) -> Result<i32, ObserverError>;
    fn current_block_height(&self) -> Result<u32, ObserverError>;
    fn get_utxo(&self, txid: &str, vout: u32) -> Result<Option<UtxoInfo>, ObserverError>;
}
```

**Endpoints usados:**
- `GET /blocks/tip/height` - Altura actual
- `GET /tx/{txid}` - Información de transacción
- `GET /tx/{txid}/outspend/{vout}` - Estado de gasto del output

### 5. Lock Registry

Almacena LOCKs registrados localmente en `btc_locks.json`:

```json
[
  {
    "lock_id": "moon_lock_00000001",
    "btc_txid": "abc123...",
    "btc_vout": 0,
    "redeem_script_hex": "6352...",
    "template": "multisig_cltv",
    "timelock_block": 4806800,
    "registered_at": 1702656000,
    "state": "Locked",
    "last_checked": 1702656100,
    "amount_sats": 189592,
    "p2wsh_address": "tb1q..."
  }
]
```

### 6. Settlement TX Builder

Construye transacciones Bitcoin firmadas para recuperar BTC.

#### Proceso:

1. **Parsear inputs**
   - Clave privada → SecretKey
   - Redeem script → bytes

2. **Construir transacción**
   ```
   Version: 2
   Marker: 0x00
   Flag: 0x01
   Input count: 1
   Input: [prevout_txid, vout, empty_scriptsig, sequence]
   Output count: 1
   Output: [amount, scriptpubkey]
   Witness: [signature, 0x00, redeem_script]
   nLockTime: timelock_block
   ```

3. **Calcular sighash (BIP143)**
   - Hash de prevouts
   - Hash de sequences
   - scriptCode (redeem script)
   - Valor del input
   - nLockTime

4. **Firmar**
   - ECDSA con secp256k1
   - Agregar SIGHASH_ALL (0x01)

5. **Construir witness**
   ```
   03          # 3 items
   [len][sig]  # signature + sighash
   01 00       # OP_FALSE (selecciona branch ELSE)
   [len][script] # redeem script
   ```

---

## Estados de un LOCK

```
        ┌─────────────┐
        │   UNKNOWN   │
        └──────┬──────┘
               │ register
               ▼
        ┌─────────────┐
        │   LOCKED    │ ◄─── UTXO existe, timelock activo
        └──────┬──────┘
               │ timelock expires
               ▼
        ┌─────────────┐
        │   EXPIRED   │ ◄─── Puede hacer settlement
        └──────┬──────┘
               │ broadcast settlement tx
               ▼
        ┌─────────────┐
        │   SETTLED   │ ◄─── UTXO gastado
        └─────────────┘
```

---

## Seguridad

### Qué hace Mooncoin:
- ✅ Genera scripts Bitcoin válidos
- ✅ Observa el estado de UTXOs
- ✅ Construye transacciones de settlement
- ✅ Firma con la clave privada proporcionada

### Qué NO hace Mooncoin:
- ❌ Custodiar claves privadas
- ❌ Almacenar BTC
- ❌ Validar la corrección semántica del script
- ❌ Garantizar que el usuario controla las claves
- ❌ Recuperar fondos perdidos

### Responsabilidad del usuario:
1. Verificar que controla las claves privadas
2. Guardar el redeem script de forma segura
3. Probar con cantidades pequeñas primero
4. Verificar el timelock antes de fondear

---

## API Reference

### generate_multisig_cltv

```rust
pub fn generate_multisig_cltv(params: &MultisigCltvParams) -> Result<Vec<u8>, ScriptError>

struct MultisigCltvParams {
    pubkey_hot: String,      // 33 bytes hex
    pubkey_cold: String,     // 33 bytes hex
    pubkey_recovery: String, // 33 bytes hex
    locktime_blocks: u32,    // Block height
}
```

### match_lock_template

```rust
pub fn match_lock_template(script: &[u8]) -> Result<Option<TemplateMatch>, ScriptError>
```

### script_to_p2wsh_address

```rust
pub fn script_to_p2wsh_address(redeem_script: &[u8], mainnet: bool) -> String
```

### build_settlement_tx

```rust
pub fn build_settlement_tx(params: &SettlementParams) -> Result<SettlementTx, SettlementError>

struct SettlementParams {
    input_txid: String,
    input_vout: u32,
    input_amount: u64,
    redeem_script_hex: String,
    recovery_privkey_hex: String,
    destination_address: String,
    fee_rate: u64,
    locktime: u32,
    testnet: bool,
}

struct SettlementTx {
    tx_hex: String,    // Ready for broadcast
    txid: String,
    fee_sats: u64,
    output_sats: u64,
}
```

---

## Ejemplos

### Generar LOCK

```bash
mooncoin btc-lock-generate --testnet \
  --pubkey-hot 030df53d72ff6b6e8d96f446bdb084640bb813712b88b924af58e87b0e51d9e5a4 \
  --pubkey-cold 022985dd1f1962526681d62e06812db208de363b7cbc9b6d5040512f8848b19fcc \
  --pubkey-recovery 0267a1aec505bcce46096c4f9de6c9658a9da361313787b5f08cdd0d60572162dd \
  --timelock 4806800
```

### Verificar script

```bash
mooncoin btc-lock-verify 635221030df53d72ff6b6e8d96f446bdb084640bb813712b88b924af58e87b0e51d9e5a421022985dd1f1962526681d62e06812db208de363b7cbc9b6d5040512f8848b19fcc52ae6703905849b175210267a1aec505bcce46096c4f9de6c9658a9da361313787b5f08cdd0d60572162ddac68
```

### Settlement

```bash
mooncoin btc-lock-settle --testnet \
  --txid b43fe2718e95e541ba29eb179d707291ac9e7c418871ce7a9703948690599f1e \
  --vout 0 \
  --destination tb1q... \
  --privkey 540bc61760b4e48c90376efaaa52538bb63aba6fc7aada3c395fc63da473945c \
  --fee-rate 2
```

---

## Limitaciones Actuales

1. **Sin broadcast automático** - El usuario debe hacer broadcast manualmente
2. **Sin RBF** - No soporta Replace-By-Fee
3. **Fee estático** - No consulta mempool para estimar fees
4. **Solo 2 templates** - multisig_cltv y htlc_simple
5. **Registro local** - No sincroniza entre dispositivos
