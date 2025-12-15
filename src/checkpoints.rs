// =============================================================================
// MOONCOIN v2.0 - Checkpoints
// =============================================================================
//
// Sistema de checkpoints para seguridad de la red:
// - Bloques verificados hardcodeados
// - Previene ataques 51% en cadenas alternativas
// - Previene ataques de reorganización profunda
// - Acelera sincronización inicial
//
// =============================================================================

use std::collections::HashMap;

// =============================================================================
// Checkpoint Entry
// =============================================================================

/// Un checkpoint es un bloque verificado y confiable
#[derive(Clone, Debug)]
pub struct Checkpoint {
    /// Altura del bloque
    pub height: u64,
    /// Hash del bloque (debe coincidir exactamente)
    pub hash: &'static str,
    /// Timestamp mínimo esperado
    pub min_timestamp: u64,
    /// Descripción opcional
    pub description: &'static str,
}

// =============================================================================
// Checkpoints Hardcodeados
// =============================================================================

/// Obtiene los checkpoints para mainnet
/// 
/// IMPORTANTE: Estos deben actualizarse periódicamente con bloques
/// que han sido verificados y tienen suficientes confirmaciones.
/// 
/// Para agregar un nuevo checkpoint:
/// 1. Esperar al menos 10,000 confirmaciones
/// 2. Verificar el hash del bloque manualmente
/// 3. Agregar aquí con la altura, hash y timestamp
pub fn get_mainnet_checkpoints() -> Vec<Checkpoint> {
    vec![
        // Genesis block - siempre debe estar
        Checkpoint {
            height: 0,
            hash: "0000000000000000000000000000000000000000000000000000000000000000",
            min_timestamp: 0,
            description: "Genesis block",
        },
        
        // === AGREGAR CHECKPOINTS AQUÍ ===
        // Ejemplo (descomentar y modificar cuando tengas bloques reales):
        //
        // Checkpoint {
        //     height: 10000,
        //     hash: "00000000000000001234567890abcdef...",
        //     min_timestamp: 1704067200,
        //     description: "First major checkpoint",
        // },
        //
        // Checkpoint {
        //     height: 50000,
        //     hash: "00000000000000009876543210fedcba...",
        //     min_timestamp: 1710000000,
        //     description: "50K blocks milestone",
        // },
    ]
}

/// Obtiene los checkpoints para testnet
pub fn get_testnet_checkpoints() -> Vec<Checkpoint> {
    vec![
        Checkpoint {
            height: 0,
            hash: "0000000000000000000000000000000000000000000000000000000000000001",
            min_timestamp: 0,
            description: "Testnet genesis",
        },
    ]
}

// =============================================================================
// Checkpoint Manager
// =============================================================================

/// Gestor de checkpoints
pub struct CheckpointManager {
    /// Checkpoints indexados por altura
    checkpoints: HashMap<u64, Checkpoint>,
    /// Altura del último checkpoint
    last_checkpoint_height: u64,
    /// Red activa
    network: Network,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl CheckpointManager {
    /// Crea un nuevo gestor para mainnet
    pub fn new_mainnet() -> Self {
        Self::new(Network::Mainnet)
    }
    
    /// Crea un nuevo gestor para testnet
    pub fn new_testnet() -> Self {
        Self::new(Network::Testnet)
    }
    
    /// Crea un nuevo gestor
    pub fn new(network: Network) -> Self {
        let checkpoint_list = match network {
            Network::Mainnet => get_mainnet_checkpoints(),
            Network::Testnet => get_testnet_checkpoints(),
        };
        
        let mut checkpoints = HashMap::new();
        let mut last_height = 0u64;
        
        for cp in checkpoint_list {
            if cp.height > last_height {
                last_height = cp.height;
            }
            checkpoints.insert(cp.height, cp);
        }
        
        CheckpointManager {
            checkpoints,
            last_checkpoint_height: last_height,
            network,
        }
    }
    
    /// Verifica si un bloque cumple con el checkpoint (si existe)
    pub fn verify_checkpoint(&self, height: u64, hash: &str) -> CheckpointResult {
        match self.checkpoints.get(&height) {
            Some(checkpoint) => {
                if checkpoint.hash == hash {
                    CheckpointResult::Valid
                } else {
                    CheckpointResult::Invalid {
                        expected: checkpoint.hash.to_string(),
                        got: hash.to_string(),
                        height,
                    }
                }
            }
            None => CheckpointResult::NoCheckpoint,
        }
    }
    
    /// Verifica si un bloque tiene checkpoint
    pub fn has_checkpoint(&self, height: u64) -> bool {
        self.checkpoints.contains_key(&height)
    }
    
    /// Obtiene el checkpoint para una altura específica
    pub fn get_checkpoint(&self, height: u64) -> Option<&Checkpoint> {
        self.checkpoints.get(&height)
    }
    
    /// Obtiene la altura del último checkpoint
    pub fn last_checkpoint_height(&self) -> u64 {
        self.last_checkpoint_height
    }
    
    /// Verifica si una altura está antes del último checkpoint
    /// (útil para determinar si podemos hacer skip de verificación)
    pub fn is_before_last_checkpoint(&self, height: u64) -> bool {
        height < self.last_checkpoint_height
    }
    
    /// Verifica si una reorganización es válida
    /// No permitimos reorgs que vayan antes del último checkpoint
    pub fn is_reorg_allowed(&self, reorg_depth: u64, current_height: u64) -> bool {
        if current_height < reorg_depth {
            return false;
        }
        
        let reorg_to_height = current_height - reorg_depth;
        
        // No permitir reorg antes del último checkpoint
        reorg_to_height >= self.last_checkpoint_height
    }
    
    /// Profundidad máxima de reorg permitida
    pub fn max_reorg_depth(&self, current_height: u64) -> u64 {
        if current_height > self.last_checkpoint_height {
            current_height - self.last_checkpoint_height
        } else {
            0
        }
    }
    
    /// Verifica timestamp mínimo
    pub fn verify_timestamp(&self, height: u64, timestamp: u64) -> bool {
        match self.checkpoints.get(&height) {
            Some(checkpoint) => timestamp >= checkpoint.min_timestamp,
            None => true, // Sin checkpoint, cualquier timestamp válido
        }
    }
    
    /// Lista todos los checkpoints
    pub fn list_checkpoints(&self) -> Vec<&Checkpoint> {
        let mut cps: Vec<_> = self.checkpoints.values().collect();
        cps.sort_by_key(|c| c.height);
        cps
    }
    
    /// Número de checkpoints
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }
}

/// Resultado de verificación de checkpoint
#[derive(Clone, Debug, PartialEq)]
pub enum CheckpointResult {
    /// El bloque coincide con el checkpoint
    Valid,
    /// El bloque NO coincide con el checkpoint (PELIGRO)
    Invalid {
        expected: String,
        got: String,
        height: u64,
    },
    /// No hay checkpoint para esta altura
    NoCheckpoint,
}

impl CheckpointResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, CheckpointResult::Valid | CheckpointResult::NoCheckpoint)
    }
    
    pub fn is_invalid(&self) -> bool {
        matches!(self, CheckpointResult::Invalid { .. })
    }
}

// =============================================================================
// Reorg Protection
// =============================================================================

/// Configuración de protección contra reorganizaciones
#[derive(Clone, Debug)]
pub struct ReorgProtection {
    /// Máxima profundidad de reorg permitida (en bloques)
    pub max_reorg_depth: u64,
    /// Altura mínima para considerar un bloque "seguro"
    pub safe_confirmations: u64,
    /// Penalización por cadenas que intentan reorg profundo
    pub deep_reorg_penalty: bool,
}

impl Default for ReorgProtection {
    fn default() -> Self {
        ReorgProtection {
            max_reorg_depth: 100,        // Máximo 100 bloques de reorg
            safe_confirmations: 6,        // 6 confirmaciones = seguro
            deep_reorg_penalty: true,     // Penalizar intentos de reorg profundo
        }
    }
}

impl ReorgProtection {
    /// Verifica si una reorganización es aceptable
    pub fn is_reorg_acceptable(&self, depth: u64) -> bool {
        depth <= self.max_reorg_depth
    }
    
    /// Verifica si un bloque tiene suficientes confirmaciones
    pub fn is_confirmed(&self, confirmations: u64) -> bool {
        confirmations >= self.safe_confirmations
    }
    
    /// Nivel de seguridad basado en confirmaciones
    pub fn security_level(&self, confirmations: u64) -> SecurityLevel {
        if confirmations == 0 {
            SecurityLevel::Unconfirmed
        } else if confirmations < 3 {
            SecurityLevel::Low
        } else if confirmations < self.safe_confirmations {
            SecurityLevel::Medium
        } else if confirmations < 100 {
            SecurityLevel::High
        } else {
            SecurityLevel::Maximum
        }
    }
}

/// Nivel de seguridad de una transacción
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Sin confirmar - puede ser revertida fácilmente
    Unconfirmed,
    /// Baja - 1-2 confirmaciones
    Low,
    /// Media - 3-5 confirmaciones
    Medium,
    /// Alta - 6-99 confirmaciones
    High,
    /// Máxima - 100+ confirmaciones
    Maximum,
}

impl SecurityLevel {
    pub fn description(&self) -> &'static str {
        match self {
            SecurityLevel::Unconfirmed => "Unconfirmed - High risk of reversal",
            SecurityLevel::Low => "Low - Wait for more confirmations",
            SecurityLevel::Medium => "Medium - Relatively safe for small amounts",
            SecurityLevel::High => "High - Safe for most transactions",
            SecurityLevel::Maximum => "Maximum - Extremely unlikely to be reversed",
        }
    }
    
    pub fn emoji(&self) -> &'static str {
        match self {
            SecurityLevel::Unconfirmed => "⚠️",
            SecurityLevel::Low => "🟡",
            SecurityLevel::Medium => "🟠",
            SecurityLevel::High => "🟢",
            SecurityLevel::Maximum => "✅",
        }
    }
    
    pub fn min_amount_safe(&self) -> &'static str {
        match self {
            SecurityLevel::Unconfirmed => "Do not trust",
            SecurityLevel::Low => "< 0.1 MOON",
            SecurityLevel::Medium => "< 10 MOON",
            SecurityLevel::High => "< 1000 MOON",
            SecurityLevel::Maximum => "Any amount",
        }
    }
}

// =============================================================================
// Chain Validation with Checkpoints
// =============================================================================

/// Valida una cadena completa contra los checkpoints
pub fn validate_chain_checkpoints(
    chain: &[(u64, &str)], // Vec de (height, hash)
    manager: &CheckpointManager,
) -> Result<(), String> {
    for (height, hash) in chain {
        match manager.verify_checkpoint(*height, hash) {
            CheckpointResult::Valid => {
                // Checkpoint válido, continuar
            }
            CheckpointResult::Invalid { expected, got, height } => {
                return Err(format!(
                    "CHECKPOINT MISMATCH at height {}!\nExpected: {}\nGot: {}\n\
                    This could indicate a chain attack or corrupted data.",
                    height, expected, got
                ));
            }
            CheckpointResult::NoCheckpoint => {
                // No hay checkpoint, continuar
            }
        }
    }
    
    Ok(())
}

/// Verifica si podemos hacer fast-sync (saltar verificación de firmas)
/// para bloques antes del último checkpoint
pub fn can_fast_sync(height: u64, manager: &CheckpointManager) -> bool {
    // Solo podemos hacer fast-sync si:
    // 1. El bloque está antes del último checkpoint
    // 2. Tenemos al menos un checkpoint después de este bloque
    manager.is_before_last_checkpoint(height)
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Imprime información de checkpoints
pub fn print_checkpoint_info(manager: &CheckpointManager) {
    println!("Checkpoint Information:");
    println!("─────────────────────────");
    println!("Network: {:?}", manager.network);
    println!("Total checkpoints: {}", manager.checkpoint_count());
    println!("Last checkpoint height: {}", manager.last_checkpoint_height());
    println!();
    
    if manager.checkpoint_count() > 0 {
        println!("Checkpoints:");
        for cp in manager.list_checkpoints() {
            println!("  Height {}: {}...", cp.height, &cp.hash[..16.min(cp.hash.len())]);
            if !cp.description.is_empty() {
                println!("    └─ {}", cp.description);
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_checkpoint_verification() {
        let manager = CheckpointManager::new_mainnet();
        
        // Genesis debe ser válido
        let result = manager.verify_checkpoint(
            0, 
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(result, CheckpointResult::Valid);
        
        // Hash incorrecto debe fallar
        let result = manager.verify_checkpoint(0, "wronghash");
        assert!(result.is_invalid());
        
        // Altura sin checkpoint
        let result = manager.verify_checkpoint(12345, "anyhash");
        assert_eq!(result, CheckpointResult::NoCheckpoint);
    }
    
    #[test]
    fn test_reorg_protection() {
        let protection = ReorgProtection::default();
        
        assert!(protection.is_reorg_acceptable(10));
        assert!(protection.is_reorg_acceptable(100));
        assert!(!protection.is_reorg_acceptable(101));
        
        assert!(!protection.is_confirmed(0));
        assert!(!protection.is_confirmed(5));
        assert!(protection.is_confirmed(6));
        assert!(protection.is_confirmed(100));
    }
    
    #[test]
    fn test_security_levels() {
        let protection = ReorgProtection::default();
        
        assert_eq!(protection.security_level(0), SecurityLevel::Unconfirmed);
        assert_eq!(protection.security_level(1), SecurityLevel::Low);
        assert_eq!(protection.security_level(3), SecurityLevel::Medium);
        assert_eq!(protection.security_level(6), SecurityLevel::High);
        assert_eq!(protection.security_level(100), SecurityLevel::Maximum);
    }
    
    #[test]
    fn test_max_reorg_depth() {
        let manager = CheckpointManager::new_mainnet();
        
        // Con solo genesis (height 0), desde height 100:
        // max_reorg = 100 - 0 = 100
        assert_eq!(manager.max_reorg_depth(100), 100);
        
        // Desde height 0, no se puede hacer reorg
        assert_eq!(manager.max_reorg_depth(0), 0);
    }
}
