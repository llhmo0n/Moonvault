# Contribuir a Mooncoin

¡Gracias por tu interés en contribuir a Mooncoin! 🌙

## Código de Conducta

- Sé respetuoso y constructivo
- Enfócate en el código, no en las personas
- Ayuda a mantener un ambiente inclusivo

## Cómo Contribuir

### Reportar Bugs

1. Verifica que el bug no haya sido reportado ya
2. Abre un issue con:
   - Descripción clara del problema
   - Pasos para reproducir
   - Comportamiento esperado vs actual
   - Versión de Mooncoin y sistema operativo

### Sugerir Mejoras

1. Abre un issue describiendo la mejora
2. Explica el caso de uso
3. Si es posible, propón una implementación

### Pull Requests

1. Fork el repositorio
2. Crea una rama descriptiva:
   ```bash
   git checkout -b feature/nueva-funcionalidad
   git checkout -b fix/descripcion-del-bug
   ```
3. Escribe código limpio y documentado
4. Asegúrate que compila sin warnings:
   ```bash
   cargo build --release
   cargo clippy
   ```
5. Agrega tests si es apropiado
6. Commit con mensajes descriptivos:
   ```
   feat: agregar comando btc-lock-xxx
   fix: corregir error en template matching
   docs: actualizar README con ejemplos
   ```
7. Push y abre un PR

## Estilo de Código

- Usa `rustfmt` para formatear
- Sigue las convenciones de Rust
- Documenta funciones públicas
- Usa nombres descriptivos

## Estructura del Proyecto

```
src/
├── main.rs        # CLI y comandos
├── btc_lock.rs    # Módulo BTC Lock
└── lib.rs         # Constantes

docs/
├── BTC_LOCK.md    # Documentación técnica
└── SECURITY.md    # Guía de seguridad
```

## Tests

```bash
# Ejecutar tests
cargo test

# Tests específicos
cargo test btc_lock
```

## Áreas que Necesitan Ayuda

- [ ] Más templates LOCK
- [ ] Broadcast automático de transacciones
- [ ] Interfaz web
- [ ] Documentación en más idiomas
- [ ] Tests de integración

## Preguntas

Si tienes preguntas, abre un issue con el tag `question`.

---

¡Gracias por contribuir! 🚀
