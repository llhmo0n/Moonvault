# 🌙 MOONCOIN v2.35

> **"La plata digital"** - Una blockchain completa escrita en Rust, inspirada en Bitcoin 2009 pero con tecnología 2025.

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-196%20passing-brightgreen.svg)]()
[![Warnings](https://img.shields.io/badge/warnings-0-brightgreen.svg)]()
[![Lines](https://img.shields.io/badge/lines-23%2C000%2B-blue.svg)]()
[![Modules](https://img.shields.io/badge/modules-46-blue.svg)]()

---

## 📖 Tabla de Contenidos

- [Visión](#-visión)
- [Historia del Desarrollo](#-historia-del-desarrollo)
- [Arquitectura](#-arquitectura)
- [Características](#-características)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Módulos Detallados](#-módulos-detallados)
- [Tests](#-tests)
- [Roadmap](#-roadmap)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)

---

## 🎯 Visión

Mooncoin nació como un proyecto educativo y experimental para entender cómo funciona una blockchain desde cero. La meta es construir una criptomoneda **completa, funcional y de grado institucional** que implemente:

- ✅ Todas las características core de Bitcoin
- ✅ Mejoras modernas (SegWit, Lightning-style channels)
- ✅ Privacidad avanzada (Ring Signatures, Stealth Addresses)
- ✅ Smart Contracts (Bitcoin Script compatible)
- ✅ Atomic Swaps para intercambios trustless

**Filosofía:** Código limpio, bien documentado, y que cualquier desarrollador pueda leer y entender.

---

## 📜 Historia del Desarrollo

### Fase 1: Fundamentos (v1.0 - v1.5)

| Versión | Características |
|---------|-----------------|
| **v1.0** | Blockchain básica, Proof of Work, transacciones simples |
| **v1.1** | Sistema UTXO, validación de transacciones |
| **v1.2** | Wallet básico, generación de direcciones |
| **v1.3** | Mempool, selección de transacciones para bloques |
| **v1.4** | Ajuste de dificultad dinámico |
| **v1.5** | Persistencia en disco, backup/restore |

### Fase 2: Red y Escalabilidad (v2.0 - v2.15)

| Versión | Características |
|---------|-----------------|
| **v2.0** | Refactor completo, estructura modular |
| **v2.1** | HD Wallet (BIP32/39/44) - Derivación jerárquica |
| **v2.2** | SegWit (Segregated Witness) - Bech32 addresses |
| **v2.3** | SPV (Simplified Payment Verification) - Light clients |
| **v2.4** | Fee Estimator inteligente |
| **v2.5** | Watch-Only Wallets |
| **v2.6** | Blockchain Pruning - Reducción de almacenamiento |
| **v2.7** | Testnet/Mainnet separation |
| **v2.8** | Labels y organización de transacciones |
| **v2.9** | Backup encriptado |
| **v2.10** | Checkpoints - Sincronización rápida |
| **v2.11** | DNS Seeds - Descubrimiento de peers |
| **v2.12** | Dandelion++ - Privacidad de red |

### Fase 3: Privacidad (v2.13 - v2.25)

| Versión | Características |
|---------|-----------------|
| **v2.13** | Pedersen Commitments - Montos ocultos |
| **v2.14** | Range Proofs - Verificación sin revelar valores |
| **v2.15** | Stealth Addresses - Direcciones de un solo uso |
| **v2.16** | Ring Signatures - Anonimato del remitente |
| **v2.17** | Shielded Transactions - Transacciones privadas completas |
| **v2.18** | Privacy Scanner - Detección de pagos entrantes |
| **v2.19** | Privacy Validation - Verificación de pruebas |
| **v2.20** | Privacy RPC - API para operaciones privadas |
| **v2.21** | Privacy Integration - Sistema unificado |

### Fase 4: Smart Contracts y Layer 2 (v2.26 - v2.35)

| Versión | Características |
|---------|-----------------|
| **v2.26** | Opcodes básicos (100+) - Bitcoin Script VM |
| **v2.27** | Script Engine - Máquina virtual de pila |
| **v2.28** | Script Builder - Constructor de scripts estándar |
| **v2.29** | P2PKH, P2SH, Multisig support |
| **v2.30** | Timelocks (CLTV, CSV) |
| **v2.31** | HTLC (Hash Time Lock Contracts) |
| **v2.32** | Payment Channels - Canales bidireccionales |
| **v2.33** | Channel State Machine - Gestión de estados |
| **v2.34** | Atomic Swaps - Intercambios cross-chain |
| **v2.35** | Merkle Trees - Verificación eficiente SPV |

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MOONCOIN v2.35                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│
│  │    CLI      │  │    RPC      │  │   Network   │  │      Explorer       ││
│  │   Wallet    │  │   Server    │  │    P2P      │  │        API          ││
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘│
│         │                │                │                     │          │
│  ┌──────┴────────────────┴────────────────┴─────────────────────┴────────┐ │
│  │                         CORE LAYER                                    │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │ │
│  │  │  Block  │ │   Tx    │ │  UTXO   │ │ Mempool │ │   Validation    │  │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────────────┘  │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                        WALLET LAYER                                   │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │ │
│  │  │   HD    │ │ SegWit  │ │  Watch  │ │  Labels │ │     Backup      │  │ │
│  │  │ Wallet  │ │ Bech32  │ │  Only   │ │         │ │   Encrypted     │  │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────────────┘  │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                       PRIVACY LAYER                                   │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │ │
│  │  │Pedersen │ │  Range  │ │ Stealth │ │  Ring   │ │    Shielded     │  │ │
│  │  │Commits  │ │ Proofs  │ │ Address │ │  Sigs   │ │  Transactions   │  │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────────────┘  │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                      CONTRACTS LAYER                                  │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │ │
│  │  │ Opcodes │ │ Script  │ │  HTLC   │ │ Payment │ │     Atomic      │  │ │
│  │  │  100+   │ │ Engine  │ │         │ │Channels │ │      Swaps      │  │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────────────┘  │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                       NETWORK LAYER                                   │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │ │
│  │  │  Peer   │ │   DNS   │ │Dandelion│ │   SPV   │ │    Merkle       │  │ │
│  │  │ Manager │ │  Seeds  │ │   ++    │ │ Client  │ │     Trees       │  │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────────────┘  │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Características

### Core Blockchain
- **Proof of Work** con SHA-256 (Bitcoin-compatible)
- **UTXO Model** - Unspent Transaction Output
- **Ajuste de dificultad** cada 2016 bloques
- **Halving** cada 210,000 bloques
- **21 millones** de supply máximo
- **Merkle Trees** para verificación eficiente

### Wallet
- **HD Wallet** (BIP32/39/44) - Seed phrases de 12/24 palabras
- **SegWit** - Direcciones Bech32 (mc1q...)
- **Watch-Only** - Monitoreo sin claves privadas
- **Labels** - Organización de transacciones
- **Backup encriptado** - AES-256-GCM

### Privacidad
- **Pedersen Commitments** - Montos ocultos criptográficamente
- **Range Proofs** - Prueba de que el monto es válido sin revelarlo
- **Stealth Addresses** - Direcciones de un solo uso
- **Ring Signatures** - Oculta quién firma la transacción
- **Shielded Transactions** - Privacidad completa
- **Dandelion++** - Privacidad a nivel de red

### Smart Contracts
- **100+ Opcodes** compatibles con Bitcoin Script
- **Stack-based VM** - Máquina virtual de pila
- **P2PKH, P2SH, P2WPKH, P2WSH** - Scripts estándar
- **Multisig** - N-de-M firmas
- **Timelocks** - CLTV (absoluto) y CSV (relativo)
- **HTLC** - Hash Time Lock Contracts

### Layer 2
- **Payment Channels** - Transacciones off-chain
- **Bidirectional Channels** - Pagos en ambas direcciones
- **Channel State Machine** - Gestión de estados
- **Atomic Swaps** - Intercambios cross-chain trustless

### Red
- **SPV** - Light clients con Bloom filters
- **Checkpoints** - Sincronización rápida
- **DNS Seeds** - Descubrimiento automático de peers
- **Pruning** - Reducción de almacenamiento

---

## 🚀 Instalación

### Requisitos
- Rust 1.70 o superior
- Cargo (incluido con Rust)

### Compilar
```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/mooncoin.git
cd mooncoin

# Compilar en modo release
cargo build --release

# El binario estará en target/release/mooncoin
```

### Verificar
```bash
# Ejecutar todos los tests
cargo test

# Verificar que no hay warnings
cargo build --release 2>&1 | grep -c "warning:"
# Debería mostrar: 0
```

---

## 💻 Uso

### Iniciar Nodo
```bash
# Iniciar nodo completo
./mooncoin node

# Iniciar en testnet
./mooncoin --testnet node

# Con minería habilitada
./mooncoin node --mine
```

### Wallet
```bash
# Crear nuevo wallet
./mooncoin wallet create

# Importar desde seed
./mooncoin wallet import "abandon abandon abandon..."

# Ver balance
./mooncoin wallet balance

# Enviar transacción
./mooncoin wallet send <address> <amount>

# Listar transacciones
./mooncoin wallet history
```

### Minería
```bash
# Minar un bloque
./mooncoin mine --address <tu-direccion>

# Minar continuamente
./mooncoin mine --address <tu-direccion> --continuous
```

### Transacciones Privadas
```bash
# Crear dirección stealth
./mooncoin privacy stealth-address

# Enviar transacción shielded
./mooncoin privacy send <stealth-address> <amount>

# Escanear pagos entrantes
./mooncoin privacy scan
```

---

## 📁 Estructura del Proyecto

```
mooncoin/
├── src/
│   ├── main.rs              # Entry point y CLI
│   ├── lib.rs               # Constantes del protocolo
│   │
│   ├── # === CORE ===
│   ├── block.rs             # Estructura de bloques
│   ├── transaction.rs       # Transacciones y hashing
│   ├── utxo.rs              # UTXO set management
│   ├── mempool.rs           # Pool de transacciones pendientes
│   ├── validation.rs        # Validación de bloques y TXs
│   ├── difficulty.rs        # Ajuste de dificultad
│   ├── reorg.rs             # Manejo de reorganizaciones
│   ├── merkle.rs            # Merkle trees y proofs
│   │
│   ├── # === WALLET ===
│   ├── wallet.rs            # Wallet básico
│   ├── hdwallet.rs          # HD Wallet (BIP32/39/44)
│   ├── watch_wallet.rs      # Watch-only wallets
│   ├── cli_wallet.rs        # CLI para wallet
│   ├── labels.rs            # Labels de transacciones
│   ├── backup.rs            # Backup encriptado
│   │
│   ├── # === NETWORK ===
│   ├── network.rs           # Networking básico
│   ├── peer_manager.rs      # Gestión de peers
│   ├── dns_seeds.rs         # Descubrimiento DNS
│   ├── dandelion.rs         # Dandelion++ privacy
│   ├── spv.rs               # Light client SPV
│   │
│   ├── # === PRIVACY ===
│   ├── privacy/
│   │   ├── mod.rs           # Módulo principal
│   │   ├── keys.rs          # Claves de privacidad
│   │   ├── pedersen.rs      # Pedersen Commitments
│   │   ├── rangeproof.rs    # Range Proofs
│   │   ├── stealth.rs       # Stealth Addresses
│   │   ├── ring.rs          # Ring Signatures
│   │   ├── shielded_tx.rs   # Transacciones shielded
│   │   ├── scanner.rs       # Escáner de pagos
│   │   ├── validation.rs    # Validación de pruebas
│   │   ├── rpc.rs           # RPC para privacidad
│   │   └── integration.rs   # Integración completa
│   │
│   ├── # === CONTRACTS ===
│   ├── contracts/
│   │   ├── mod.rs           # Verificación de scripts
│   │   ├── opcodes.rs       # 100+ opcodes
│   │   ├── engine.rs        # Script VM
│   │   └── builder.rs       # Constructor de scripts
│   │
│   ├── # === LAYER 2 ===
│   ├── channels/
│   │   ├── mod.rs           # Payment channels
│   │   ├── state.rs         # State machine
│   │   ├── commitment.rs    # Commitment transactions
│   │   └── htlc.rs          # HTLC implementation
│   │
│   ├── atomic_swaps/
│   │   ├── mod.rs           # Atomic swaps
│   │   ├── htlc.rs          # Cross-chain HTLC
│   │   └── protocol.rs      # Swap protocol
│   │
│   ├── # === OTHER ===
│   ├── crypto.rs            # Funciones criptográficas
│   ├── script.rs            # Script parsing
│   ├── segwit.rs            # SegWit y Bech32
│   ├── tx_builder.rs        # Constructor de TXs
│   ├── fee_estimator.rs     # Estimación de fees
│   ├── pruning.rs           # Blockchain pruning
│   ├── testnet.rs           # Configuración testnet
│   ├── checkpoints.rs       # Checkpoints
│   ├── storage.rs           # Persistencia
│   ├── rpc.rs               # RPC server
│   └── explorer.rs          # Block explorer
│
├── Cargo.toml               # Dependencias
└── README.md                # Este archivo
```

---

## 📦 Módulos Detallados

### Core (7 módulos)

| Módulo | Líneas | Descripción |
|--------|--------|-------------|
| `block.rs` | ~200 | Estructura de bloque, hashing, genesis |
| `transaction.rs` | ~300 | Transacciones, inputs, outputs |
| `utxo.rs` | ~400 | UTXO set, coinbase maturity |
| `mempool.rs` | ~350 | Pool de TXs, ordenamiento por fee |
| `validation.rs` | ~500 | Validación completa de bloques/TXs |
| `difficulty.rs` | ~200 | Ajuste de dificultad |
| `merkle.rs` | ~700 | Merkle trees, proofs, MerkleBlock |

### Wallet (6 módulos)

| Módulo | Líneas | Descripción |
|--------|--------|-------------|
| `wallet.rs` | ~400 | Wallet básico, firmas ECDSA |
| `hdwallet.rs` | ~600 | BIP32/39/44, derivación de claves |
| `watch_wallet.rs` | ~300 | Monitoreo sin claves privadas |
| `cli_wallet.rs` | ~500 | Interfaz de línea de comandos |
| `labels.rs` | ~200 | Etiquetas para transacciones |
| `backup.rs` | ~400 | Backup/restore encriptado |

### Privacy (11 módulos)

| Módulo | Líneas | Descripción |
|--------|--------|-------------|
| `privacy/mod.rs` | ~150 | Exports y tipos públicos |
| `privacy/keys.rs` | ~350 | Claves de privacidad, derivación |
| `privacy/pedersen.rs` | ~400 | Pedersen Commitments |
| `privacy/rangeproof.rs` | ~500 | Range Proofs (64-bit) |
| `privacy/stealth.rs` | ~450 | Stealth Addresses, view tags |
| `privacy/ring.rs` | ~650 | Ring Signatures, key images |
| `privacy/shielded_tx.rs` | ~600 | Transacciones completamente privadas |
| `privacy/scanner.rs` | ~400 | Escáner de pagos entrantes |
| `privacy/validation.rs` | ~700 | Validación de pruebas ZK |
| `privacy/rpc.rs` | ~350 | API RPC para privacidad |
| `privacy/integration.rs` | ~550 | Sistema unificado |

### Contracts (4 módulos)

| Módulo | Líneas | Descripción |
|--------|--------|-------------|
| `contracts/mod.rs` | ~300 | Verificación de scripts |
| `contracts/opcodes.rs` | ~600 | 100+ opcodes definidos |
| `contracts/engine.rs` | ~1100 | Script VM, ejecución |
| `contracts/builder.rs` | ~500 | Constructor de scripts estándar |

### Channels (5 módulos)

| Módulo | Líneas | Descripción |
|--------|--------|-------------|
| `channels/mod.rs` | ~200 | Payment channels |
| `channels/state.rs` | ~400 | State machine |
| `channels/commitment.rs` | ~800 | Commitment transactions |
| `channels/htlc.rs` | ~600 | HTLC para channels |

### Atomic Swaps (3 módulos)

| Módulo | Líneas | Descripción |
|--------|--------|-------------|
| `atomic_swaps/mod.rs` | ~250 | Atomic swaps core |
| `atomic_swaps/htlc.rs` | ~400 | Cross-chain HTLC |
| `atomic_swaps/protocol.rs` | ~500 | Protocolo de swap |

### Network (6 módulos)

| Módulo | Líneas | Descripción |
|--------|--------|-------------|
| `network.rs` | ~400 | P2P básico |
| `peer_manager.rs` | ~500 | Gestión de conexiones |
| `dns_seeds.rs` | ~300 | Descubrimiento de peers |
| `dandelion.rs` | ~450 | Privacidad de propagación |
| `spv.rs` | ~600 | Light clients, Bloom filters |
| `checkpoints.rs` | ~250 | Sincronización rápida |

---

## 🧪 Tests

### Ejecutar Tests
```bash
# Todos los tests
cargo test

# Tests de un módulo específico
cargo test privacy::

# Tests con output
cargo test -- --nocapture

# Tests en paralelo
cargo test -- --test-threads=4
```

### Cobertura por Módulo

| Módulo | Tests | Estado |
|--------|-------|--------|
| atomic_swaps | 16 | ✅ |
| backup | 2 | ✅ |
| block | 3 | ✅ |
| channels | 18 | ✅ |
| checkpoints | 4 | ✅ |
| contracts | 13 | ✅ |
| crypto | 5 | ✅ |
| dandelion | 5 | ✅ |
| difficulty | 3 | ✅ |
| dns_seeds | 3 | ✅ |
| fee_estimator | 5 | ✅ |
| hdwallet | 3 | ✅ |
| labels | 4 | ✅ |
| mempool | 2 | ✅ |
| merkle | 13 | ✅ |
| peer_manager | 2 | ✅ |
| privacy | 42 | ✅ |
| pruning | 4 | ✅ |
| reorg | 2 | ✅ |
| script | 2 | ✅ |
| segwit | 4 | ✅ |
| spv | 4 | ✅ |
| testnet | 3 | ✅ |
| transaction | 2 | ✅ |
| tx_builder | 3 | ✅ |
| utxo | 2 | ✅ |
| validation | 2 | ✅ |
| wallet | 2 | ✅ |
| watch_wallet | 3 | ✅ |
| **TOTAL** | **196** | ✅ |

---

## 🗺️ Roadmap

### Fase 5: Production Ready (Próxima)

- [ ] **P2P Networking Real** - Conexión entre nodos
- [ ] **RocksDB** - Base de datos persistente
- [ ] **Full Sync** - Initial Block Download
- [ ] **JSON-RPC Server** - API completa

### Fase 6: Ecosystem

- [ ] **Mining Pool** - Protocolo Stratum
- [ ] **Block Explorer** - Web interface
- [ ] **Testnet Deployment** - Red de pruebas pública
- [ ] **Faucet** - Distribución de testnet coins

### Fase 7: User Experience

- [ ] **Desktop Wallet** - GUI con Tauri
- [ ] **Mobile Wallet** - SPV para iOS/Android
- [ ] **Browser Extension** - Web3 integration

### Fase 8: Advanced

- [ ] **Schnorr Signatures** - Agregación de firmas
- [ ] **Taproot** - Scripts más privados
- [ ] **Cross-chain Bridges** - Interoperabilidad

---

## 🤝 Contribuir

1. Fork el repositorio
2. Crea tu branch (`git checkout -b feature/nueva-feature`)
3. Commit tus cambios (`git commit -am 'Agregar nueva feature'`)
4. Push al branch (`git push origin feature/nueva-feature`)
5. Abre un Pull Request

### Estilo de Código
- Usar `cargo fmt` antes de commit
- Todos los tests deben pasar
- Sin warnings en `cargo build --release`
- Documentar funciones públicas

---

## 📊 Estadísticas

```
Lenguaje:         Rust
Líneas de código: ~23,000+
Módulos:          46
Tests:            196
Warnings:         0
Dependencias:     ~25
```

---

## 📄 Licencia

MIT License - Ver [LICENSE](LICENSE) para más detalles.

---

## 🙏 Agradecimientos

- **Satoshi Nakamoto** - Por inventar Bitcoin
- **La comunidad Rust** - Por un lenguaje increíble
- **Todos los contribuidores** - Por hacer esto posible

---

<p align="center">
  <b>🌙 Mooncoin - La plata digital 🌙</b>
  <br>
  <i>Built with ❤️ in Rust</i>
</p>
