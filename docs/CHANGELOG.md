# Changelog

Todos los cambios notables de este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - 2024-12-15

### Agregado
- **Módulo BTC Lock completo** - Puente Mooncoin-Bitcoin
  - Generación de scripts LOCK (multisig_cltv, htlc_simple)
  - Template matching y verificación
  - Generación de direcciones P2WSH
  - Registro y monitoreo de LOCKs
  - Settlement TX Builder con firma ECDSA
  
- **Conexión a Bitcoin real** via Esplora API
  - Soporte para Mainnet, Testnet y Signet
  - Consulta de transacciones
  - Verificación de UTXOs
  - Monitoreo de altura de bloques

- **15 comandos CLI para BTC Lock**
  - `btc-lock-health` - Verificación del sistema
  - `btc-lock-connect` - Probar conexión
  - `btc-lock-templates` - Ver templates
  - `btc-lock-keygen` - Generar claves de prueba
  - `btc-lock-generate` - Generar script LOCK
  - `btc-lock-verify` - Verificar script
  - `btc-lock-register` - Registrar LOCK
  - `btc-lock-status` - Ver estado
  - `btc-lock-list` - Listar LOCKs
  - `btc-lock-refresh` - Actualizar estados
  - `btc-lock-settle-check` - Verificar settlement
  - `btc-lock-settle` - Construir TX settlement
  - `btc-lock-query-tx` - Consultar TX
  - `btc-lock-check-utxo` - Verificar UTXO
  - `btc-lock-demo` - Demo completo

### Cambiado
- Actualizado `Cargo.toml` con dependencia `ureq` para HTTP

### Archivos
- `src/main.rs` - 7,149 líneas
- `src/btc_lock.rs` - 1,661 líneas (nuevo)

---

## [2.0.0] - 2024-12-14

### Agregado
- Blockchain Mooncoin funcional
- Sistema de consenso Proof-of-Work
- Wallet HD con soporte BIP39/BIP32
- Generación de direcciones
- Transacciones y mempool
- Mining con ajuste de dificultad
- Block explorer integrado (web)
- Comandos de red P2P
- Sistema de contratos básicos
- Merkle trees para verificación

### Archivos
- `src/main.rs` - ~5,700 líneas
- `src/lib.rs` - Constantes del protocolo

---

## [1.0.0] - 2024-12-13

### Agregado
- Implementación inicial
- Estructura básica del proyecto
- CLI con clap

---

## Roadmap Futuro

### v2.2 (Planificado)
- [ ] Broadcast automático de transacciones
- [ ] Notificaciones de cambio de estado
- [ ] Múltiples templates LOCK adicionales
- [ ] Estimación dinámica de fees

### v3.0 (Planificado)
- [ ] Red P2P entre nodos Mooncoin
- [ ] Sincronización de estados LOCK
- [ ] Interfaz web para gestión
- [ ] Mobile wallet
