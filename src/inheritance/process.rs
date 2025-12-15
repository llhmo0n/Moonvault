// =============================================================================
// MOONCOIN - Herencia Digital: Process Manager
// =============================================================================

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    InheritanceId, InheritanceConfig, InheritanceError,
    heir::HeirSet,
    script::InheritanceScript,
};

// =============================================================================
// Inheritance State
// =============================================================================

/// Estado del proceso de herencia
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InheritanceState {
    /// Activo, dueño en control
    Active {
        /// Último check-in (block height)
        last_checkin_block: u64,
        /// Próximo check-in recomendado
        next_checkin_block: u64,
    },
    
    /// Advertencia: check-in atrasado
    Warning {
        last_checkin_block: u64,
        blocks_overdue: u64,
    },
    
    /// Crítico: herencia ejecutable pronto
    Critical {
        last_checkin_block: u64,
        executable_at_block: u64,
        blocks_remaining: u64,
    },
    
    /// Herencia ejecutable
    Claimable {
        last_checkin_block: u64,
        claimable_since_block: u64,
    },
    
    /// Herencia ejecutada
    Executed {
        executed_at_block: u64,
        distribution_txid: String,
    },
    
    /// Cancelado por el dueño
    Cancelled {
        cancelled_at_block: u64,
    },
}

impl InheritanceState {
    pub fn is_active(&self) -> bool {
        matches!(self, InheritanceState::Active { .. } | 
                       InheritanceState::Warning { .. } | 
                       InheritanceState::Critical { .. })
    }
    
    pub fn is_claimable(&self) -> bool {
        matches!(self, InheritanceState::Claimable { .. })
    }
    
    pub fn description(&self) -> String {
        match self {
            InheritanceState::Active { next_checkin_block, .. } => 
                format!("Active - Next check-in at block {}", next_checkin_block),
            InheritanceState::Warning { blocks_overdue, .. } => 
                format!("Warning - Check-in overdue by {} blocks", blocks_overdue),
            InheritanceState::Critical { blocks_remaining, .. } => 
                format!("Critical - {} blocks until claimable", blocks_remaining),
            InheritanceState::Claimable { .. } => 
                "Claimable - Heirs can claim funds".to_string(),
            InheritanceState::Executed { distribution_txid, .. } => 
                format!("Executed - TX: {}", &distribution_txid[..16.min(distribution_txid.len())]),
            InheritanceState::Cancelled { .. } => 
                "Cancelled".to_string(),
        }
    }
}

// =============================================================================
// Inheritance Process
// =============================================================================

/// Proceso de herencia activo
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InheritanceProcess {
    /// ID
    pub id: InheritanceId,
    
    /// Estado actual
    pub state: InheritanceState,
    
    /// Configuración
    pub config: InheritanceConfig,
    
    /// Script
    pub script: InheritanceScript,
    
    /// Herederos
    pub heirs: HeirSet,
    
    /// Balance (satoshis)
    pub balance: u64,
    
    /// Block height de creación
    pub created_at_block: u64,
    
    /// Timestamp de creación
    pub created_at_time: u64,
    
    /// Último check-in
    pub last_checkin_block: u64,
    
    /// Historial de check-ins
    pub checkin_history: Vec<CheckinRecord>,
    
    /// Total de check-ins realizados
    pub total_checkins: u32,
}

/// Registro de check-in
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckinRecord {
    pub block_height: u64,
    pub timestamp: u64,
    pub txid: Option<String>,
}

impl InheritanceProcess {
    /// Crear nuevo proceso de herencia
    pub fn new(
        owner_pubkey: [u8; 33],
        heirs: HeirSet,
        config: InheritanceConfig,
        current_block: u64,
    ) -> Result<Self, InheritanceError> {
        config.validate()?;
        
        let script = InheritanceScript::new(
            owner_pubkey,
            &heirs,
            config.inactivity_period.blocks(),
        );
        
        let id = InheritanceId::generate(&owner_pubkey, &heirs.heirs);
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let next_checkin = current_block + config.checkin_interval as u64;
        
        Ok(InheritanceProcess {
            id,
            state: InheritanceState::Active {
                last_checkin_block: current_block,
                next_checkin_block: next_checkin,
            },
            config,
            script,
            heirs,
            balance: 0,
            created_at_block: current_block,
            created_at_time: now,
            last_checkin_block: current_block,
            checkin_history: vec![CheckinRecord {
                block_height: current_block,
                timestamp: now,
                txid: None,
            }],
            total_checkins: 1,
        })
    }
    
    /// Realizar check-in
    pub fn checkin(
        &mut self,
        current_block: u64,
        txid: Option<String>,
    ) -> Result<(), InheritanceError> {
        if !self.state.is_active() && !self.state.is_claimable() {
            return Err(InheritanceError::AlreadyExecuted);
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Registrar check-in
        self.checkin_history.push(CheckinRecord {
            block_height: current_block,
            timestamp: now,
            txid,
        });
        
        self.last_checkin_block = current_block;
        self.total_checkins += 1;
        
        // Actualizar estado
        let next_checkin = current_block + self.config.checkin_interval as u64;
        self.state = InheritanceState::Active {
            last_checkin_block: current_block,
            next_checkin_block: next_checkin,
        };
        
        Ok(())
    }
    
    /// Actualizar estado basado en block height
    pub fn update_state(&mut self, current_block: u64) {
        if matches!(self.state, InheritanceState::Executed { .. } | InheritanceState::Cancelled { .. }) {
            return;
        }
        
        let blocks_since_checkin = current_block.saturating_sub(self.last_checkin_block);
        let inactivity = self.config.inactivity_period.blocks() as u64;
        let checkin_interval = self.config.checkin_interval as u64;
        
        if blocks_since_checkin >= inactivity {
            // Herencia ejecutable
            self.state = InheritanceState::Claimable {
                last_checkin_block: self.last_checkin_block,
                claimable_since_block: self.last_checkin_block + inactivity,
            };
        } else if blocks_since_checkin >= inactivity - self.config.notification_threshold as u64 {
            // Crítico
            self.state = InheritanceState::Critical {
                last_checkin_block: self.last_checkin_block,
                executable_at_block: self.last_checkin_block + inactivity,
                blocks_remaining: inactivity - blocks_since_checkin,
            };
        } else if blocks_since_checkin > checkin_interval {
            // Advertencia
            self.state = InheritanceState::Warning {
                last_checkin_block: self.last_checkin_block,
                blocks_overdue: blocks_since_checkin - checkin_interval,
            };
        } else {
            // Activo normal
            self.state = InheritanceState::Active {
                last_checkin_block: self.last_checkin_block,
                next_checkin_block: self.last_checkin_block + checkin_interval,
            };
        }
    }
    
    /// Verificar si la herencia es ejecutable
    pub fn is_claimable(&self, current_block: u64) -> bool {
        let blocks_since = current_block.saturating_sub(self.last_checkin_block);
        blocks_since >= self.config.inactivity_period.blocks() as u64
    }
    
    /// Ejecutar herencia (distribuir a herederos)
    pub fn execute(
        &mut self,
        current_block: u64,
        distribution_txid: String,
    ) -> Result<Vec<(String, u64)>, InheritanceError> {
        if !self.is_claimable(current_block) {
            let blocks_since = current_block.saturating_sub(self.last_checkin_block);
            let inactivity = self.config.inactivity_period.blocks() as u64;
            return Err(InheritanceError::InactivityNotMet {
                blocks_remaining: inactivity - blocks_since,
            });
        }
        
        // Calcular distribución
        let distribution = self.heirs.calculate_distribution(self.balance);
        
        // Actualizar estado
        self.state = InheritanceState::Executed {
            executed_at_block: current_block,
            distribution_txid,
        };
        
        self.balance = 0;
        
        Ok(distribution)
    }
    
    /// Cancelar herencia (solo el dueño)
    pub fn cancel(&mut self, current_block: u64) -> Result<(), InheritanceError> {
        if matches!(self.state, InheritanceState::Executed { .. }) {
            return Err(InheritanceError::AlreadyExecuted);
        }
        
        self.state = InheritanceState::Cancelled {
            cancelled_at_block: current_block,
        };
        
        Ok(())
    }
    
    /// Depositar fondos
    pub fn deposit(&mut self, amount: u64) {
        self.balance += amount;
    }
    
    /// Retirar fondos (dueño)
    pub fn withdraw(&mut self, amount: u64) -> Result<(), InheritanceError> {
        if amount > self.balance {
            return Err(InheritanceError::Other("Insufficient balance".to_string()));
        }
        self.balance -= amount;
        Ok(())
    }
    
    /// Bloques hasta que sea claimable
    pub fn blocks_until_claimable(&self, current_block: u64) -> Option<u64> {
        if self.is_claimable(current_block) {
            return None;
        }
        
        let blocks_since = current_block.saturating_sub(self.last_checkin_block);
        let inactivity = self.config.inactivity_period.blocks() as u64;
        
        Some(inactivity - blocks_since)
    }
    
    /// Bloques hasta próximo check-in recomendado
    pub fn blocks_until_checkin(&self, current_block: u64) -> Option<u64> {
        let next = self.last_checkin_block + self.config.checkin_interval as u64;
        if current_block >= next {
            None // Ya debería hacer check-in
        } else {
            Some(next - current_block)
        }
    }
    
    /// Dirección del script
    pub fn address(&self) -> String {
        self.script.p2sh_address()
    }
}

// =============================================================================
// Inheritance Manager
// =============================================================================

/// Gestor de múltiples herencias
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InheritanceManager {
    /// Procesos por ID
    processes: HashMap<String, InheritanceProcess>,
    
    /// Block height actual
    current_block: u64,
    
    /// Índice de direcciones
    address_index: HashMap<String, String>,
}

impl InheritanceManager {
    /// Crear nuevo manager
    pub fn new() -> Self {
        InheritanceManager {
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
    
    /// Crear nueva herencia
    pub fn create_inheritance(
        &mut self,
        owner_pubkey: [u8; 33],
        heirs: HeirSet,
        config: InheritanceConfig,
    ) -> Result<InheritanceId, InheritanceError> {
        let process = InheritanceProcess::new(
            owner_pubkey,
            heirs,
            config,
            self.current_block,
        )?;
        
        let id = process.id.clone();
        let address = process.address();
        
        self.address_index.insert(address, id.to_hex());
        self.processes.insert(id.to_hex(), process);
        
        Ok(id)
    }
    
    /// Obtener proceso
    pub fn get_process(&self, id: &InheritanceId) -> Option<&InheritanceProcess> {
        self.processes.get(&id.to_hex())
    }
    
    /// Obtener proceso mutable
    pub fn get_process_mut(&mut self, id: &InheritanceId) -> Option<&mut InheritanceProcess> {
        self.processes.get_mut(&id.to_hex())
    }
    
    /// Realizar check-in
    pub fn checkin(
        &mut self,
        id: &InheritanceId,
        txid: Option<String>,
    ) -> Result<(), InheritanceError> {
        let current = self.current_block;
        let process = self.get_process_mut(id)
            .ok_or(InheritanceError::Other("Inheritance not found".to_string()))?;
        
        process.checkin(current, txid)
    }
    
    /// Ejecutar herencia
    pub fn execute_inheritance(
        &mut self,
        id: &InheritanceId,
        distribution_txid: String,
    ) -> Result<Vec<(String, u64)>, InheritanceError> {
        let current = self.current_block;
        let process = self.get_process_mut(id)
            .ok_or(InheritanceError::Other("Inheritance not found".to_string()))?;
        
        process.execute(current, distribution_txid)
    }
    
    /// Listar todos los procesos
    pub fn list_processes(&self) -> Vec<&InheritanceProcess> {
        self.processes.values().collect()
    }
    
    /// Procesos que necesitan check-in
    pub fn processes_needing_checkin(&self) -> Vec<&InheritanceProcess> {
        self.processes.values()
            .filter(|p| matches!(p.state, 
                InheritanceState::Warning { .. } | 
                InheritanceState::Critical { .. }
            ))
            .collect()
    }
    
    /// Procesos claimables
    pub fn claimable_processes(&self) -> Vec<&InheritanceProcess> {
        self.processes.values()
            .filter(|p| p.state.is_claimable())
            .collect()
    }
    
    /// Número de procesos
    pub fn count(&self) -> usize {
        self.processes.len()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::heir::{Heir, HeirShare};
    use super::super::config::InactivityPeriod;
    
    fn sample_pubkey(seed: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        pk[1] = seed;
        pk
    }
    
    fn sample_heirs() -> HeirSet {
        HeirSet::new(vec![
            Heir::new("MC1heir1".to_string(), HeirShare::new(50).unwrap()),
            Heir::new("MC1heir2".to_string(), HeirShare::new(50).unwrap()),
        ]).unwrap()
    }
    
    #[test]
    fn test_inheritance_process_creation() {
        let owner = sample_pubkey(1);
        let heirs = sample_heirs();
        let config = InheritanceConfig::new(InactivityPeriod::OneYear);
        
        let process = InheritanceProcess::new(owner, heirs, config, 1000).unwrap();
        
        assert!(process.state.is_active());
        assert!(process.address().starts_with("MI"));
    }
    
    #[test]
    fn test_checkin() {
        let owner = sample_pubkey(1);
        let heirs = sample_heirs();
        let config = InheritanceConfig::new(InactivityPeriod::OneYear);
        
        let mut process = InheritanceProcess::new(owner, heirs, config, 1000).unwrap();
        
        // Hacer check-in
        process.checkin(50000, Some("tx123".to_string())).unwrap();
        
        assert_eq!(process.last_checkin_block, 50000);
        assert_eq!(process.total_checkins, 2);
    }
    
    #[test]
    fn test_state_transitions() {
        let owner = sample_pubkey(1);
        let heirs = sample_heirs();
        // Usar período corto para testing
        let config = InheritanceConfig::new(InactivityPeriod::Custom(super::super::MIN_INACTIVITY_BLOCKS));
        
        let mut process = InheritanceProcess::new(owner, heirs, config, 1000).unwrap();
        
        // Estado inicial: Active
        assert!(process.state.is_active());
        
        // Avanzar tiempo: Warning
        process.update_state(1000 + 15000);
        assert!(matches!(process.state, InheritanceState::Warning { .. }));
        
        // Avanzar más: Critical
        process.update_state(1000 + 24000);
        assert!(matches!(process.state, InheritanceState::Critical { .. }));
        
        // Avanzar pasado inactividad: Claimable
        process.update_state(1000 + 30000);
        assert!(process.state.is_claimable());
    }
    
    #[test]
    fn test_execute_inheritance() {
        let owner = sample_pubkey(1);
        let heirs = sample_heirs();
        let config = InheritanceConfig::new(InactivityPeriod::Custom(super::super::MIN_INACTIVITY_BLOCKS));
        
        let mut process = InheritanceProcess::new(owner, heirs, config, 1000).unwrap();
        process.deposit(1_000_000);
        
        // No se puede ejecutar antes del período
        let result = process.execute(2000, "tx".to_string());
        assert!(result.is_err());
        
        // Avanzar tiempo
        let claimable_block = 1000 + super::super::MIN_INACTIVITY_BLOCKS as u64;
        
        // Ahora sí se puede ejecutar
        let distribution = process.execute(claimable_block, "dist_tx".to_string()).unwrap();
        
        assert_eq!(distribution.len(), 2);
        assert_eq!(distribution[0].1, 500_000);
        assert_eq!(distribution[1].1, 500_000);
        assert!(matches!(process.state, InheritanceState::Executed { .. }));
    }
    
    #[test]
    fn test_checkin_resets_timer() {
        let owner = sample_pubkey(1);
        let heirs = sample_heirs();
        let config = InheritanceConfig::new(InactivityPeriod::Custom(super::super::MIN_INACTIVITY_BLOCKS));
        
        let mut process = InheritanceProcess::new(owner, heirs, config, 1000).unwrap();
        
        // Avanzar a Warning
        process.update_state(1000 + 15000);
        assert!(matches!(process.state, InheritanceState::Warning { .. }));
        
        // Check-in resetea el timer
        process.checkin(1000 + 15000, None).unwrap();
        
        // Estado debe volver a Active
        assert!(matches!(process.state, InheritanceState::Active { .. }));
    }
    
    #[test]
    fn test_inheritance_manager() {
        let mut manager = InheritanceManager::new();
        manager.update_block_height(1000);
        
        let owner = sample_pubkey(1);
        let heirs = sample_heirs();
        let config = InheritanceConfig::new(InactivityPeriod::OneYear);
        
        // Crear herencia
        let id = manager.create_inheritance(owner, heirs, config).unwrap();
        
        assert_eq!(manager.count(), 1);
        
        // Obtener proceso
        let process = manager.get_process(&id).unwrap();
        assert!(process.state.is_active());
    }
}
