# Guía de Seguridad

## ⚠️ Advertencias Críticas

### 1. Pérdida de Claves = Pérdida de BTC

**Si pierdes tu clave privada de RECOVERY, perderás tu BTC permanentemente.**

Mooncoin NO puede:
- Recuperar claves perdidas
- Revertir transacciones
- Acceder a tus fondos

### 2. Mooncoin NO Custodia

Mooncoin es una herramienta de observación. Tu BTC siempre permanece en la blockchain de Bitcoin, controlado únicamente por las claves privadas.

---

## 🔐 Mejores Prácticas

### Generación de Claves

1. **Usa `btc-lock-keygen` solo para pruebas (testnet)**
2. **Para mainnet, genera claves con herramientas auditadas:**
   - Hardware wallets (Ledger, Trezor)
   - Bitcoin Core
   - Electrum

### Almacenamiento de Claves

| Qué guardar | Cómo guardarlo |
|-------------|----------------|
| Recovery privkey | Hardware wallet, papel offline, steel backup |
| Hot privkey | Solo si necesitas gasto cooperativo |
| Cold privkey | Almacenamiento frío separado |
| Redeem script | Puede estar en texto plano (no es secreto) |

### Antes de Fondear

1. **Verifica que controlas las claves privadas**
   - Firma un mensaje de prueba con cada clave
   
2. **Verifica el timelock**
   - Asegúrate que el bloque objetivo está en el futuro
   - Calcula cuánto tiempo tendrás el BTC bloqueado
   
3. **Prueba con cantidades pequeñas**
   - Primero testnet
   - Luego mainnet con cantidad mínima
   - Después cantidades mayores

### Durante el LOCK

1. **Monitorea el estado regularmente**
   ```bash
   mooncoin btc-lock-status --txid <TXID>
   ```

2. **No pierdas el redeem script**
   - Aunque no es secreto, lo necesitas para settlement

3. **Mantén acceso a tu recovery key**
   - La necesitarás cuando expire el timelock

### Settlement

1. **Verifica el timelock ha expirado**
   ```bash
   mooncoin btc-lock-settle-check --txid <TXID>
   ```

2. **Verifica la dirección destino**
   - Triple-check la dirección antes de generar la TX
   
3. **Revisa el fee**
   - Asegúrate que el fee rate es razonable
   
4. **Verifica la TX antes de broadcast**
   - Puedes decodificar el hex en blockstream.info

---

## 🚨 Escenarios de Riesgo

### Script Malformado

**Problema:** El script generado no es gastable.

**Causa:** Claves públicas inválidas o corrutas.

**Prevención:**
- Verifica el script con `btc-lock-verify`
- Prueba con testnet primero
- Usa claves de fuentes confiables

### Pérdida de Recovery Key

**Problema:** No puedes hacer settlement después del timelock.

**Consecuencia:** BTC permanece bloqueado para siempre.

**Prevención:**
- Múltiples backups de la recovery key
- Almacenamiento en ubicaciones físicas separadas
- Considera usar un esquema multisig para la recovery key

### Timelock Demasiado Largo

**Problema:** BTC bloqueado por años.

**Prevención:**
- Calcula cuidadosamente el timelock
- 1 mes ≈ 4,320 bloques
- 1 año ≈ 52,560 bloques

### Pérdida del Redeem Script

**Problema:** No puedes construir la transacción de settlement.

**Consecuencia:** Necesitas reconstruir el script (posible si tienes las pubkeys y timelock).

**Prevención:**
- Guarda el redeem script junto con el registro del LOCK
- Es información pública, no requiere protección especial

---

## 📋 Checklist Pre-LOCK

```
[ ] Tengo la clave privada de recovery guardada de forma segura
[ ] Tengo la clave privada de hot guardada
[ ] Tengo la clave privada de cold guardada
[ ] Verifiqué que las pubkeys son correctas
[ ] El timelock es razonable para mis necesidades
[ ] Probé el flujo completo en testnet
[ ] Tengo múltiples backups de las claves
[ ] Entiendo que Mooncoin NO puede recuperar mis fondos
```

---

## 📋 Checklist Pre-Settlement

```
[ ] El timelock ha expirado (bloque actual >= timelock)
[ ] El UTXO no ha sido gastado
[ ] Tengo la clave privada de recovery
[ ] Tengo el redeem script
[ ] La dirección destino es correcta
[ ] El fee rate es razonable
[ ] Revisé la transacción antes de broadcast
```

---

## 🛟 Recuperación de Emergencia

### Si perdiste el redeem script

Si tienes las pubkeys y el timelock, puedes reconstruirlo:

```bash
mooncoin btc-lock-generate \
  --pubkey-hot <PUBKEY> \
  --pubkey-cold <PUBKEY> \
  --pubkey-recovery <PUBKEY> \
  --timelock <BLOCK>
```

El script generado será idéntico.

### Si tienes problemas de conexión

Los comandos BTC Lock usan la API de Blockstream. Si hay problemas:

1. Verifica tu conexión a internet
2. Prueba acceder a https://blockstream.info manualmente
3. Espera unos minutos y reintenta

### Si el settlement falla

1. Verifica que el timelock haya expirado
2. Verifica que el UTXO no haya sido gastado
3. Verifica que la clave privada es correcta
4. Verifica que el redeem script coincide

---

## 📞 Soporte

Mooncoin es software de código abierto. Para soporte:

1. Revisa la documentación
2. Abre un issue en GitHub
3. Únete a la comunidad

**NUNCA compartas tus claves privadas con nadie, incluyendo "soporte".**
