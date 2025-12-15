# 🌙 Mooncoin v2.1

**La Plata Digital - Complemento operativo para Bitcoin**

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Bitcoin](https://img.shields.io/badge/Bitcoin-Testnet%20%7C%20Mainnet-yellow.svg)](https://bitcoin.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📖 Filosofía

> **Bitcoin = Oro Digital** (reserva de valor, no se gasta diariamente)  
> **Mooncoin = Plata Digital** (transacciones diarias, uso práctico)

Mooncoin **NO compite** con Bitcoin. Mooncoin **complementa** a Bitcoin proporcionando una capa operativa mientras tu BTC permanece seguro y bloqueado en la blockchain de Bitcoin.

---

## 🔐 Modelo LOCK-OPERATE-SETTLE

El corazón de Mooncoin es el puente con Bitcoin:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CICLO MOONCOIN-BITCOIN                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. LOCK     Usuario bloquea BTC en script con timelock        │
│               ↓                                                 │
│   2. OPERATE  Usuario opera con MOON (BTC intocado)             │
│               ↓                                                 │
│   3. SETTLE   Timelock expira → Usuario recupera su BTC         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Principios fundamentales:**
- Mooncoin **NUNCA** custodia BTC
- Mooncoin **SOLO** observa la blockchain de Bitcoin
- El usuario **SIEMPRE** controla sus claves privadas
- El BTC **SIEMPRE** puede ser recuperado después del timelock

---

## 🚀 Instalación

### Requisitos
- Rust 1.70 o superior
- Conexión a internet (para observar Bitcoin)

### Compilar desde fuente

```bash
git clone https://github.com/tu-usuario/mooncoin.git
cd mooncoin
cargo build --release
```

### Verificar instalación

```bash
./target/release/mooncoin btc-lock-health
```

---

## 📋 Comandos BTC Lock

### Verificación del Sistema
```bash
mooncoin btc-lock-health          # Verificar todos los componentes
mooncoin btc-lock-connect         # Probar conexión a Bitcoin mainnet
mooncoin btc-lock-connect --testnet  # Probar conexión a testnet
```

### Generación de LOCKs
```bash
mooncoin btc-lock-templates       # Ver templates disponibles
mooncoin btc-lock-keygen          # Generar claves de prueba (testnet)
mooncoin btc-lock-generate        # Generar script LOCK
mooncoin btc-lock-verify <script> # Verificar script
```

### Gestión de LOCKs
```bash
mooncoin btc-lock-register        # Registrar LOCK para observación
mooncoin btc-lock-status          # Ver estado de un LOCK
mooncoin btc-lock-list            # Listar todos los LOCKs
mooncoin btc-lock-refresh         # Actualizar estados desde Bitcoin
```

### Settlement
```bash
mooncoin btc-lock-settle-check    # Verificar si listo para settlement
mooncoin btc-lock-settle          # Construir TX de settlement
```

### Consultas Bitcoin
```bash
mooncoin btc-lock-query-tx <txid> # Consultar transacción
mooncoin btc-lock-check-utxo      # Verificar UTXO en blockchain
```

---

## 🔄 Flujo Completo (Ejemplo Testnet)

### 1. Verificar sistema
```bash
./target/release/mooncoin btc-lock-health
```

### 2. Generar claves de prueba
```bash
./target/release/mooncoin btc-lock-keygen
```
**⚠️ Guarda las claves privadas, especialmente RECOVERY**

### 3. Generar script LOCK
```bash
./target/release/mooncoin btc-lock-generate --testnet \
  --pubkey-hot <HOT_PUBKEY> \
  --pubkey-cold <COLD_PUBKEY> \
  --pubkey-recovery <RECOVERY_PUBKEY> \
  --timelock <BLOQUE_ACTUAL+100>
```

### 4. Enviar tBTC
Envía testnet BTC a la dirección P2WSH generada usando cualquier wallet.

Faucets recomendados:
- https://coinfaucet.eu/en/btc-testnet/
- https://testnet-faucet.mempool.co/

### 5. Registrar LOCK
```bash
./target/release/mooncoin btc-lock-register --testnet \
  --txid <TXID> \
  --vout 0 \
  --script <REDEEM_SCRIPT_HEX>
```

### 6. Monitorear estado
```bash
./target/release/mooncoin btc-lock-status --testnet --txid <TXID>
```

### 7. Settlement (cuando expire el timelock)
```bash
./target/release/mooncoin btc-lock-settle --testnet \
  --txid <TXID> \
  --vout 0 \
  --destination <TU_DIRECCION_DESTINO> \
  --privkey <RECOVERY_PRIVKEY_HEX> \
  --fee-rate 2
```

### 8. Broadcast
Usa la transacción hex generada:
- Web: https://blockstream.info/testnet/tx/push
- API: `curl -X POST -d '<TX_HEX>' https://blockstream.info/testnet/api/tx`

---

## 🏗️ Arquitectura

```
src/
├── main.rs           # CLI principal (~7,100 líneas)
│   ├── Wallet commands
│   ├── Mining commands
│   ├── Network commands
│   ├── Explorer commands
│   └── BTC Lock commands (15 comandos)
│
├── btc_lock.rs       # Módulo BTC Lock (~1,700 líneas)
│   ├── Script generation (multisig_cltv, htlc_simple)
│   ├── Template matching
│   ├── P2WSH address generation
│   ├── Esplora API client (mainnet/testnet/signet)
│   ├── Lock registry
│   └── Settlement TX builder
│
└── lib.rs            # Constantes del protocolo
```

---

## 🔧 Templates LOCK Soportados

### multisig_cltv (Recomendado)
2-of-2 multisig con recuperación unilateral después del timelock.

```
IF
  2 <pubkey_hot> <pubkey_cold> 2 CHECKMULTISIG
ELSE
  <timelock> CHECKLOCKTIMEVERIFY DROP
  <pubkey_recovery> CHECKSIG
ENDIF
```

**Uso:**
- Gasto inmediato: requiere firma hot + cold
- Después de timelock: solo firma recovery

### htlc_simple
Hash Time-Locked Contract con timeout de refund.

```
IF
  SHA256 <hash> EQUALVERIFY <pubkey> CHECKSIG
ELSE
  <timeout> CHECKSEQUENCEVERIFY DROP <pubkey> CHECKSIG
ENDIF
```

---

## 🌐 Conexión a Bitcoin

Mooncoin se conecta a Bitcoin via API Esplora (Blockstream):

| Red | API |
|-----|-----|
| Mainnet | https://blockstream.info/api |
| Testnet | https://blockstream.info/testnet/api |
| Signet | https://mempool.space/signet/api |

No requiere nodo Bitcoin local.

---

## ⚠️ Advertencias de Seguridad

1. **GUARDA TUS CLAVES PRIVADAS** - Sin ellas perderás tu BTC permanentemente
2. **GUARDA EL REDEEM SCRIPT** - Necesario para el settlement
3. **VERIFICA EL TIMELOCK** - Asegúrate que sea una fecha futura razonable
4. **PRUEBA CON TESTNET** - Siempre prueba antes de usar mainnet
5. **VERIFICA DIRECCIONES** - Un error de dirección es irreversible

---

## 📊 Estados de un LOCK

| Estado | Descripción | Acción |
|--------|-------------|--------|
| `LOCKED` | UTXO existe, timelock activo | Esperar |
| `EXPIRED` | Timelock expirado | Puede hacer settlement |
| `SETTLED` | UTXO gastado | Ciclo completado |
| `UNKNOWN` | Error consultando | Verificar conexión |

---

## 🛠️ Dependencias Principales

| Crate | Uso |
|-------|-----|
| `ureq` | Cliente HTTP para Esplora API |
| `secp256k1` | Criptografía de curva elíptica |
| `sha2` | Hashing SHA256 |
| `serde` | Serialización JSON |
| `clap` | Framework CLI |
| `tokio` | Runtime async |

---

## 📜 Changelog

### v2.1 (2024-12-15)
- ✅ Módulo BTC Lock completo
- ✅ Conexión a Bitcoin real (Esplora API)
- ✅ Settlement TX Builder
- ✅ 15 comandos CLI para BTC Lock
- ✅ Soporte mainnet/testnet/signet

### v2.0
- Blockchain Mooncoin funcional
- Wallet HD (BIP39/BIP32)
- Mining y consenso
- Block explorer integrado

### v1.0
- Implementación inicial

---

## 🤝 Contribuir

1. Fork el repositorio
2. Crea una rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

---

## 📄 Licencia

MIT License - ver [LICENSE](LICENSE)

---

## 👤 Autor

**KNKI**

Mooncoin - La Plata Digital  
*Bitcoin 2009 style in Rust 2025*

---

## 🔗 Links

- [Bitcoin](https://bitcoin.org/)
- [Blockstream Explorer](https://blockstream.info/)
- [Esplora API Docs](https://github.com/Blockstream/esplora/blob/master/API.md)
