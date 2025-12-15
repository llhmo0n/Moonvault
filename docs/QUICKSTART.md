# 🚀 Guía de Inicio Rápido

Empieza a usar Mooncoin BTC Lock en 5 minutos.

## 1. Compilar

```bash
git clone https://github.com/tu-usuario/mooncoin.git
cd mooncoin
cargo build --release
```

## 2. Verificar Instalación

```bash
./target/release/mooncoin btc-lock-health
```

Deberías ver todos los checks en ✅

## 3. Primera Prueba (Testnet)

### Generar claves de prueba

```bash
./target/release/mooncoin btc-lock-keygen
```

**⚠️ Guarda las claves privadas que aparecen!**

### Generar LOCK

Copia el comando que aparece y modifica el timelock.

Primero, obtén el bloque actual:
```bash
./target/release/mooncoin btc-lock-connect --testnet
```

Usa ese número + 10 como timelock:
```bash
./target/release/mooncoin btc-lock-generate --testnet \
  --pubkey-hot <TU_HOT_PUBKEY> \
  --pubkey-cold <TU_COLD_PUBKEY> \
  --pubkey-recovery <TU_RECOVERY_PUBKEY> \
  --timelock <BLOQUE_ACTUAL+10>
```

### Obtener tBTC

Ve a https://coinfaucet.eu/en/btc-testnet/ y envía a la dirección P2WSH generada.

### Registrar

```bash
./target/release/mooncoin btc-lock-register --testnet \
  --txid <TXID_DEL_FAUCET> \
  --vout 0 \
  --script <TU_REDEEM_SCRIPT>
```

### Monitorear

```bash
./target/release/mooncoin btc-lock-status --testnet --txid <TXID>
```

### Settlement (cuando expire)

```bash
./target/release/mooncoin btc-lock-settle --testnet \
  --txid <TXID> \
  --vout 0 \
  --destination <TU_DIRECCION_TESTNET> \
  --privkey <TU_RECOVERY_PRIVKEY> \
  --fee-rate 2
```

Broadcast la TX hex en: https://blockstream.info/testnet/tx/push

---

## Comandos Útiles

| Comando | Descripción |
|---------|-------------|
| `btc-lock-health` | Verificar sistema |
| `btc-lock-connect --testnet` | Ver bloque actual |
| `btc-lock-list` | Ver todos tus LOCKs |
| `btc-lock-query-tx <txid> --testnet` | Consultar TX |

---

## Siguiente Paso

Lee la [documentación completa](docs/BTC_LOCK.md) para entender todos los detalles.
