// =============================================================================
// MOONCOIN - Recovery Social: Process Manager
// =============================================================================
//
// Gestión del proceso de recovery y su ciclo de vida.
//
// =============================================================================

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    RecoveryId, RecoveryConfig, RecoveryError,
    guardian::{Guardian, GuardianSet, GuardianSignature},
    script::RecoveryScript,
};

// =============================================================================
// Recovery State
// =============================================================================

/// Estado del proceso de recovery
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryState {
    /// Configurado pero no activo
    Configured,
    
    /// Recovery iniciado, recolectando firmas
    Initiated {
        initiated_at_block: u64,
        initiated_at_time: u64,
        initiator_pubkey: Vec<u8>,
    },
    
    /// Firmas suficientes, esperando delay
    PendingDelay {
        initiated_at_block: u64,
        executable_at_block: u64,
        signatures_count: usize,
    },
    
    /// Delay completado, ejecutable
    Executable {
        initiated_at_block: u64,
        signatures_count: usize,
    },
    
    /// Recovery completado
    Completed {
        completed_at_block: u64,
        recovery_txid: String,
    },
    
    /// Cancelado por el usuario
    Cancelled {
        cancelled_at_block: u64,
        reason: Option<String>,
    },
    
    /// Expirado (no se completó a tiempo)
    Expired {
        expired_at_block: u64,
    },
}

impl RecoveryState {
    pub fn is_active(&self) -> bool {
        matches!(self, 
            RecoveryState::Initiated { .. } | 
            RecoveryState::PendingDelay { .. } |
            RecoveryState::Executable { .. }
        )
    }
    
    pub fn is_executable(&self) -> bool {
        matches!(self, RecoveryState::Executable { .. })
    }
    
    pub fn description(&self) -> String {
        match self {
            RecoveryState::Configured => "Configured - Not active".to_string(),
            RecoveryState::Initiated { .. } => "Initiated - Collecting signatures".to_string(),
            RecoveryState::PendingDelay { executable_at_block, .. } => 
                format!("Pending delay - Executable at block {}", executable_at_block),
            RecoveryState::Executable { .. } => "Ready to execute".to_string(),
            RecoveryState::Completed { recovery_txid, .. } => 
                format!("Completed - TX: {}", &recovery_txid[..16.min(recovery_txid.len())]),
            RecoveryState::Cancelled { reason, .. } => 
                format!("Cancelled - {}", reason.as_deref().unwrap_or("No reason")),
            RecoveryState::Expired { .. } => "Expired".to_string(),
        }
    }
}

// =============================================================================
// Recovery Process
// =============================================================================

/// Proceso de recovery activo
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryProcess {
    /// ID del recovery
    pub id: RecoveryId,
    
    /// Estado actual
    pub state: RecoveryState,
    
    /// Configuración
    pub config: RecoveryConfig,
    
    /// Script de recovery
    pub script: RecoveryScript,
    
    /// Set de guardianes
    pub guardians: GuardianSet,
    
    /// Firmas recolectadas
    pub signatures: Vec<GuardianSignature>,
    
    /// Razón proporcionada por los guardianes
    pub recovery_reason: Option<String>,
    
    /// Block height de creación
    pub created_at_block: u64,
    
    /// Timestamp de creación
    pub created_at_time: u64,
    
    /// Última actividad
    pub last_activity_block: u64,
    
    /// Balance a recuperar (satoshis)
    pub balance: u64,
}

impl RecoveryProcess {
    /// Crear nuevo proceso de recovery
    pub fn new(
        user_pubkey: [u8; 33],
        guardians: GuardianSet,
        config: RecoveryConfig,
        current_block: u64,
    ) -> Result<Self, RecoveryError> {
        config.validate()?;
        
        let script = RecoveryScript::new(
            user_pubkey,
            &guardians,
            config.tier.delay_blocks(),
        );
        
        let id = RecoveryId::generate(&user_pubkey, &guardians.guardians);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Ok(RecoveryProcess {
            id,
            state: RecoveryState::Configured,
            config,
            script,
            guardians,
            signatures: Vec::new(),
            recovery_reason: None,
            created_at_block: current_block,
            created_at_time: now,
            last_activity_block: current_block,
            balance: 0,
        })
    }
    
    /// Iniciar proceso de recovery (primer guardián firma)
    pub fn initiate(
        &mut self,
        initiator_signature: GuardianSignature,
        reason: Option<String>,
        current_block: u64,
    ) -> Result<(), RecoveryError> {
        if self.state.is_active() {
            return Err(RecoveryError::RecoveryAlreadyActive);
        }
        
        // Verificar que el firmante es un guardián válido
        let initiator_pk: [u8; 33] = initiator_signature.guardian_pubkey;
        if self.guardians.get_by_pubkey(&initiator_pk).is_none() {
            return Err(RecoveryError::InvalidSignature("Not a guardian".to_string()));
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.state = RecoveryState::Initiated {
            initiated_at_block: current_block,
            initiated_at_time: now,
            initiator_pubkey: initiator_pk.to_vec(),
        };
        
        self.signatures.push(initiator_signature);
        self.recovery_reason = reason;
        self.last_activity_block = current_block;
        
        self.check_threshold(current_block);
        
        Ok(())
    }
    
    /// Agregar firma de guardián
    pub fn add_signature(
        &mut self,
        signature: GuardianSignature,
        current_block: u64,
    ) -> Result<(), RecoveryError> {
        if !self.state.is_active() {
            return Err(RecoveryError::NoActiveRecovery);
        }
        
        // Verificar que el firmante es un guardián válido
        let signer_pk: [u8; 33] = signature.guardian_pubkey;
        if self.guardians.get_by_pubkey(&signer_pk).is_none() {
            return Err(RecoveryError::InvalidSignature("Not a guardian".to_string()));
        }
        
        // Verificar que no ha firmado ya
        if self.signatures.iter().any(|s| s.guardian_pubkey == signer_pk) {
            return Err(RecoveryError::InvalidSignature("Already signed".to_string()));
        }
        
        self.signatures.push(signature);
        self.last_activity_block = current_block;
        
        self.check_threshold(current_block);
        
        Ok(())
    }
    
    /// Verificar si se alcanzó el threshold
    fn check_threshold(&mut self, current_block: u64) {
        if self.signatures.len() >= self.guardians.threshold {
            if let RecoveryState::Initiated { initiated_at_block, .. } = self.state {
                let executable_at = initiated_at_block + self.config.tier.delay_blocks() as u64;
                
                self.state = RecoveryState::PendingDelay {
                    initiated_at_block,
                    executable_at_block: executable_at,
                    signatures_count: self.signatures.len(),
                };
            }
        }
    }
    
    /// Actualizar estado basado en block height
    pub fn update_state(&mut self, current_block: u64) {
        if let RecoveryState::PendingDelay { initiated_at_block, executable_at_block, signatures_count } = self.state {
            if current_block >= executable_at_block {
                self.state = RecoveryState::Executable {
                    initiated_at_block,
                    signatures_count,
                };
            }
        }
    }
    
    /// Verificar si se puede ejecutar
    pub fn can_execute(&self, current_block: u64) -> bool {
        match &self.state {
            RecoveryState::Executable { .. } => true,
            RecoveryState::PendingDelay { executable_at_block, .. } => {
                current_block >= *executable_at_block
            }
            _ => false,
        }
    }
    
    /// Ejecutar recovery
    pub fn execute(
        &mut self,
        current_block: u64,
        recovery_txid: String,
    ) -> Result<(), RecoveryError> {
        if !self.can_execute(current_block) {
            if let RecoveryState::PendingDelay { executable_at_block, .. } = self.state {
                return Err(RecoveryError::DelayNotMet {
                    blocks_remaining: executable_at_block.saturating_sub(current_block),
                });
            }
            return Err(RecoveryError::NoActiveRecovery);
        }
        
        self.state = RecoveryState::Completed {
            completed_at_block: current_block,
            recovery_txid,
        };
        
        self.last_activity_block = current_block;
        
        Ok(())
    }
    
    /// Cancelar recovery (solo el usuario puede)
    pub fn cancel(
        &mut self,
        current_block: u64,
        reason: Option<String>,
    ) -> Result<(), RecoveryError> {
        if !self.state.is_active() {
            return Err(RecoveryError::NoActiveRecovery);
        }
        
        self.state = RecoveryState::Cancelled {
            cancelled_at_block: current_block,
            reason,
        };
        
        self.last_activity_block = current_block;
        
        Ok(())
    }
    
    /// Obtener bloques restantes para ejecución
    pub fn blocks_until_executable(&self, current_block: u64) -> Option<u64> {
        if let RecoveryState::PendingDelay { executable_at_block, .. } = self.state {
            if current_block < executable_at_block {
                return Some(executable_at_block - current_block);
            }
        }
        None
    }
    
    /// Número de firmas recolectadas
    pub fn signatures_count(&self) -> usize {
        self.signatures.len()
    }
    
    /// Firmas faltantes
    pub fn signatures_needed(&self) -> usize {
        self.guardians.threshold.saturating_sub(self.signatures.len())
    }
    
    /// Dirección del script de recovery
    pub fn address(&self) -> String {
        self.script.p2sh_address()
    }
}

// =============================================================================
// Recovery Manager
// =============================================================================

/// Gestor de múltiples procesos de recovery
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryManager {
    /// Procesos por ID
    processes: HashMap<String, RecoveryProcess>,
    
    /// Block height actual
    current_block: u64,
    
    /// Índice de direcciones a IDs
    address_index: HashMap<String, String>,
}

impl RecoveryManager {
    /// Crear nuevo manager
    pub fn new() -> Self {
        RecoveryManager {
            processes: HashMap::new(),
            current_block: 0,
            address_index: HashMap::new(),
        }
    }
    
    /// Actualizar block height
    pub fn update_block_height(&mut self, height: u64) {
        self.current_block = height;
        
        // Actualizar estados
        for process in self.processes.values_mut() {
            process.update_state(height);
        }
    }
    
    /// Crear nuevo proceso de recovery
    pub fn create_recovery(
        &mut self,
        user_pubkey: [u8; 33],
        guardians: GuardianSet,
        config: RecoveryConfig,
    ) -> Result<RecoveryId, RecoveryError> {
        let process = RecoveryProcess::new(
            user_pubkey,
            guardians,
            config,
            self.current_block,
        )?;
        
        let id = process.id.clone();
        let address = process.address();
        
        self.address_index.insert(address, id.to_hex());
        self.processes.insert(id.to_hex(), process);
        
        Ok(id)
    }
    
    /// Obtener proceso por ID
    pub fn get_process(&self, id: &RecoveryId) -> Option<&RecoveryProcess> {
        self.processes.get(&id.to_hex())
    }
    
    /// Obtener proceso mutable
    pub fn get_process_mut(&mut self, id: &RecoveryId) -> Option<&mut RecoveryProcess> {
        self.processes.get_mut(&id.to_hex())
    }
    
    /// Iniciar recovery
    pub fn initiate_recovery(
        &mut self,
        id: &RecoveryId,
        signature: GuardianSignature,
        reason: Option<String>,
    ) -> Result<(), RecoveryError> {
        let current_block = self.current_block;
        let process = self.get_process_mut(id)
            .ok_or(RecoveryError::Other("Recovery not found".to_string()))?;
        
        process.initiate(signature, reason, current_block)
    }
    
    /// Agregar firma
    pub fn add_signature(
        &mut self,
        id: &RecoveryId,
        signature: GuardianSignature,
    ) -> Result<(), RecoveryError> {
        let current_block = self.current_block;
        let process = self.get_process_mut(id)
            .ok_or(RecoveryError::Other("Recovery not found".to_string()))?;
        
        process.add_signature(signature, current_block)
    }
    
    /// Ejecutar recovery
    pub fn execute_recovery(
        &mut self,
        id: &RecoveryId,
        recovery_txid: String,
    ) -> Result<(), RecoveryError> {
        let current_block = self.current_block;
        let process = self.get_process_mut(id)
            .ok_or(RecoveryError::Other("Recovery not found".to_string()))?;
        
        process.execute(current_block, recovery_txid)
    }
    
    /// Cancelar recovery
    pub fn cancel_recovery(
        &mut self,
        id: &RecoveryId,
        reason: Option<String>,
    ) -> Result<(), RecoveryError> {
        let current_block = self.current_block;
        let process = self.get_process_mut(id)
            .ok_or(RecoveryError::Other("Recovery not found".to_string()))?;
        
        process.cancel(current_block, reason)
    }
    
    /// Listar todos los procesos
    pub fn list_processes(&self) -> Vec<&RecoveryProcess> {
        self.processes.values().collect()
    }
    
    /// Listar procesos activos
    pub fn active_processes(&self) -> Vec<&RecoveryProcess> {
        self.processes.values()
            .filter(|p| p.state.is_active())
            .collect()
    }
    
    /// Número de procesos
    pub fn count(&self) -> usize {
        self.processes.len()
    }
}

impl Default for RecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    fn sample_pubkey(seed: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        pk[1] = seed;
        pk
    }
    
    fn sample_guardian_set() -> GuardianSet {
        let guardians = vec![
            Guardian::new("Alice".to_string(), sample_pubkey(1)),
            Guardian::new("Bob".to_string(), sample_pubkey(2)),
            Guardian::new("Carol".to_string(), sample_pubkey(3)),
        ];
        GuardianSet::new(guardians, 2).unwrap()
    }
    
    fn sample_signature(guardian_seed: u8) -> GuardianSignature {
        GuardianSignature::new(
            sample_pubkey(guardian_seed),
            vec![0x30, 0x44, 0x02, 0x20],
            vec![0xAB; 32],
        )
    }
    
    #[test]
    fn test_recovery_process_creation() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        let config = RecoveryConfig::new("MC1destination".to_string());
        
        let process = RecoveryProcess::new(user_pk, guardians, config, 1000).unwrap();
        
        assert_eq!(process.state, RecoveryState::Configured);
        assert!(process.address().starts_with("MR"));
    }
    
    #[test]
    fn test_initiate_recovery() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        let config = RecoveryConfig::new("MC1destination".to_string());
        
        let mut process = RecoveryProcess::new(user_pk, guardians, config, 1000).unwrap();
        
        // Iniciar con firma de Alice (guardián 1)
        let sig = sample_signature(1);
        process.initiate(sig, Some("Lost keys".to_string()), 1001).unwrap();
        
        assert!(process.state.is_active());
        assert_eq!(process.signatures_count(), 1);
        assert_eq!(process.signatures_needed(), 1); // 2-of-3, tiene 1, necesita 1 más
    }
    
    #[test]
    fn test_add_signatures_until_threshold() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        let config = RecoveryConfig::new("MC1destination".to_string());
        
        let mut process = RecoveryProcess::new(user_pk, guardians, config, 1000).unwrap();
        
        // Primera firma (Alice)
        process.initiate(sample_signature(1), None, 1001).unwrap();
        
        // Segunda firma (Bob) - alcanza threshold
        process.add_signature(sample_signature(2), 1002).unwrap();
        
        assert_eq!(process.signatures_count(), 2);
        assert_eq!(process.signatures_needed(), 0);
        
        // Estado debe ser PendingDelay
        assert!(matches!(process.state, RecoveryState::PendingDelay { .. }));
    }
    
    #[test]
    fn test_duplicate_signature_rejected() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        let config = RecoveryConfig::new("MC1destination".to_string());
        
        let mut process = RecoveryProcess::new(user_pk, guardians, config, 1000).unwrap();
        
        process.initiate(sample_signature(1), None, 1001).unwrap();
        
        // Intentar firmar de nuevo con Alice
        let result = process.add_signature(sample_signature(1), 1002);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_execute_after_delay() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        let config = RecoveryConfig::new("MC1destination".to_string())
            .with_tier(super::super::RecoveryTier::Custom(4320)); // 100 bloques de delay
        
        let mut process = RecoveryProcess::new(user_pk, guardians, config, 1000).unwrap();
        
        process.initiate(sample_signature(1), None, 1000).unwrap();
        process.add_signature(sample_signature(2), 1001).unwrap();
        
        // No se puede ejecutar antes del delay
        assert!(!process.can_execute(5000));
        
        // Se puede ejecutar después del delay
        process.update_state(5320);
        assert!(process.can_execute(5320));
        
        // Ejecutar
        process.execute(5320, "txid123".to_string()).unwrap();
        
        assert!(matches!(process.state, RecoveryState::Completed { .. }));
    }
    
    #[test]
    fn test_cancel_recovery() {
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        let config = RecoveryConfig::new("MC1destination".to_string());
        
        let mut process = RecoveryProcess::new(user_pk, guardians, config, 1000).unwrap();
        
        process.initiate(sample_signature(1), None, 1001).unwrap();
        
        // Usuario cancela
        process.cancel(1002, Some("Found my keys!".to_string())).unwrap();
        
        assert!(matches!(process.state, RecoveryState::Cancelled { .. }));
    }
    
    #[test]
    fn test_recovery_manager() {
        let mut manager = RecoveryManager::new();
        manager.update_block_height(1000);
        
        let user_pk = sample_pubkey(10);
        let guardians = sample_guardian_set();
        let config = RecoveryConfig::new("MC1destination".to_string());
        
        // Crear recovery
        let id = manager.create_recovery(user_pk, guardians, config).unwrap();
        
        assert_eq!(manager.count(), 1);
        
        // Iniciar
        manager.initiate_recovery(&id, sample_signature(1), None).unwrap();
        
        // Verificar estado
        let process = manager.get_process(&id).unwrap();
        assert!(process.state.is_active());
    }
}
