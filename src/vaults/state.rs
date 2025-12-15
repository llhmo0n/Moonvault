// =============================================================================
// MOONCOIN - Vault State Machine
// =============================================================================
//
// Gestión del estado de un vault y sus transiciones.
//
// ESTADOS DEL VAULT:
// ==================
//
//   ┌──────────┐
//   │  ACTIVE  │ ←── Estado inicial, fondos disponibles
//   └────┬─────┘
//        │
//        │ initiate_withdrawal()
//        ▼
//   ┌─────────────────┐
//   │    PENDING      │ ←── Retiro iniciado, esperando delay
//   │  (countdown)    │
//   └────┬───────┬────┘
//        │       │
//        │       │ cancel() [con cold key]
//        │       ▼
//        │  ┌───────────┐
//        │  │ CANCELLED │ ←── Fondos enviados a recovery
//        │  └───────────┘
//        │
//        │ [delay completo]
//        ▼
//   ┌───────────┐
//   │ WITHDRAWN │ ←── Fondos retirados exitosamente
//   └───────────┘
//
// =============================================================================

use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

// =============================================================================
// Vault Status
// =============================================================================

/// Estado actual del vault
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultStatus {
    /// Vault activo, listo para recibir o iniciar retiro
    Active,
    
    /// Retiro pendiente, en período de espera
    PendingWithdrawal {
        /// Block height cuando se inició el retiro
        initiated_at_block: u64,
        /// Block height cuando el retiro será ejecutable
        executable_at_block: u64,
        /// Dirección destino del retiro
        destination: String,
        /// Monto del retiro (satoshis)
        amount: u64,
        /// Timestamp de inicio
        initiated_at_time: u64,
    },
    
    /// Retiro cancelado, fondos enviados a recovery
    Cancelled {
        /// Block height de la cancelación
        cancelled_at_block: u64,
        /// TXID de la transacción de recuperación
        recovery_txid: String,
        /// Dirección de recuperación
        recovery_address: String,
        /// Monto recuperado
        amount: u64,
        /// Razón de la cancelación (opcional)
        reason: Option<String>,
    },
    
    /// Retiro completado exitosamente
    Withdrawn {
        /// Block height del retiro
        withdrawn_at_block: u64,
        /// TXID del retiro
        txid: String,
        /// Dirección destino
        destination: String,
        /// Monto retirado
        amount: u64,
    },
    
    /// Vault cerrado (sin fondos)
    Closed {
        /// Razón del cierre
        reason: String,
        /// Block height del cierre
        closed_at_block: u64,
    },
}

impl VaultStatus {
    /// Verificar si el vault está activo
    pub fn is_active(&self) -> bool {
        matches!(self, VaultStatus::Active)
    }
    
    /// Verificar si hay un retiro pendiente
    pub fn is_pending(&self) -> bool {
        matches!(self, VaultStatus::PendingWithdrawal { .. })
    }
    
    /// Verificar si el vault fue cancelado
    pub fn is_cancelled(&self) -> bool {
        matches!(self, VaultStatus::Cancelled { .. })
    }
    
    /// Verificar si se completó un retiro
    pub fn is_withdrawn(&self) -> bool {
        matches!(self, VaultStatus::Withdrawn { .. })
    }
    
    /// Verificar si el vault está cerrado
    pub fn is_closed(&self) -> bool {
        matches!(self, VaultStatus::Closed { .. })
    }
    
    /// Descripción legible del estado
    pub fn description(&self) -> String {
        match self {
            VaultStatus::Active => "Active - Ready for deposits or withdrawals".to_string(),
            VaultStatus::PendingWithdrawal { executable_at_block, amount, .. } => {
                format!("Pending withdrawal of {} sats, executable at block {}", 
                    amount, executable_at_block)
            }
            VaultStatus::Cancelled { amount, recovery_address, .. } => {
                format!("Cancelled - {} sats sent to recovery: {}", 
                    amount, &recovery_address[..20.min(recovery_address.len())])
            }
            VaultStatus::Withdrawn { amount, destination, .. } => {
                format!("Withdrawn - {} sats to {}", 
                    amount, &destination[..20.min(destination.len())])
            }
            VaultStatus::Closed { reason, .. } => {
                format!("Closed - {}", reason)
            }
        }
    }
}

impl Default for VaultStatus {
    fn default() -> Self {
        VaultStatus::Active
    }
}

// =============================================================================
// Withdrawal Request
// =============================================================================

/// Solicitud de retiro
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    /// ID único de la solicitud
    #[serde(with = "serde_hash32")]
    pub request_id: [u8; 32],
    
    /// Monto a retirar (satoshis)
    pub amount: u64,
    
    /// Dirección destino
    pub destination: String,
    
    /// Block height cuando se creó
    pub created_at_block: u64,
    
    /// Timestamp de creación
    pub created_at_time: u64,
    
    /// Bloques de delay requeridos
    pub delay_blocks: u32,
    
    /// Block height cuando será ejecutable
    pub executable_at_block: u64,
    
    /// Fee estimado para la transacción
    pub estimated_fee: u64,
    
    /// Firma de la hot key (prueba de autorización)
    pub hot_key_signature: Option<Vec<u8>>,
    
    /// Hash de la transacción pendiente
    pub pending_txid: Option<String>,
    
    /// Estado de la solicitud
    pub status: WithdrawalRequestStatus,
    
    /// Notas del usuario (opcional)
    pub notes: Option<String>,
}

mod serde_hash32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    
    pub fn serialize<S>(data: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(data).serialize(serializer)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Estado de una solicitud de retiro
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalRequestStatus {
    /// Creada, pendiente de firma
    Created,
    
    /// Firmada, pendiente de broadcast
    Signed,
    
    /// Broadcast, esperando delay
    Pending,
    
    /// Ejecutable (delay completado)
    Executable,
    
    /// Completada exitosamente
    Completed,
    
    /// Cancelada
    Cancelled,
    
    /// Expirada (no se ejecutó a tiempo)
    Expired,
}

impl WithdrawalRequest {
    /// Crear nueva solicitud de retiro
    pub fn new(
        amount: u64,
        destination: String,
        current_block: u64,
        delay_blocks: u32,
        estimated_fee: u64,
    ) -> Self {
        use sha2::{Sha256, Digest};
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Generar ID único
        let mut hasher = Sha256::new();
        hasher.update(b"withdrawal:");
        hasher.update(amount.to_le_bytes());
        hasher.update(destination.as_bytes());
        hasher.update(now.to_le_bytes());
        let hash = hasher.finalize();
        let mut request_id = [0u8; 32];
        request_id.copy_from_slice(&hash);
        
        WithdrawalRequest {
            request_id,
            amount,
            destination,
            created_at_block: current_block,
            created_at_time: now,
            delay_blocks,
            executable_at_block: current_block + delay_blocks as u64,
            estimated_fee,
            hot_key_signature: None,
            pending_txid: None,
            status: WithdrawalRequestStatus::Created,
            notes: None,
        }
    }
    
    /// Verificar si el retiro es ejecutable dado el block height actual
    pub fn is_executable(&self, current_block: u64) -> bool {
        current_block >= self.executable_at_block
    }
    
    /// Obtener bloques restantes hasta que sea ejecutable
    pub fn blocks_remaining(&self, current_block: u64) -> u64 {
        if current_block >= self.executable_at_block {
            0
        } else {
            self.executable_at_block - current_block
        }
    }
    
    /// Tiempo estimado restante (en segundos, asumiendo 5 min/bloque)
    pub fn time_remaining_secs(&self, current_block: u64) -> u64 {
        self.blocks_remaining(current_block) * 300
    }
    
    /// Tiempo estimado restante (legible)
    pub fn time_remaining_human(&self, current_block: u64) -> String {
        let secs = self.time_remaining_secs(current_block);
        
        if secs == 0 {
            "Ready".to_string()
        } else if secs < 3600 {
            format!("{} minutes", secs / 60)
        } else if secs < 86400 {
            format!("{} hours", secs / 3600)
        } else {
            format!("{} days", secs / 86400)
        }
    }
    
    /// ID corto para mostrar
    pub fn short_id(&self) -> String {
        hex::encode(&self.request_id[..4])
    }
}

// =============================================================================
// Vault State
// =============================================================================

/// Estado completo de un vault
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultState {
    /// ID del vault
    pub vault_id: super::VaultId,
    
    /// Estado actual
    pub status: VaultStatus,
    
    /// Balance actual (satoshis)
    pub balance: u64,
    
    /// Block height de creación
    pub created_at_block: u64,
    
    /// Timestamp de creación
    pub created_at_time: u64,
    
    /// Última actividad (block height)
    pub last_activity_block: u64,
    
    /// Solicitudes de retiro (historial)
    pub withdrawal_requests: Vec<WithdrawalRequest>,
    
    /// Solicitud de retiro activa (si existe)
    pub active_withdrawal: Option<WithdrawalRequest>,
    
    /// Depósitos recibidos (historial simplificado)
    pub deposits: Vec<DepositRecord>,
    
    /// Total depositado históricamente
    pub total_deposited: u64,
    
    /// Total retirado históricamente
    pub total_withdrawn: u64,
    
    /// Número de cancelaciones
    pub cancellation_count: u32,
}

/// Registro de depósito
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositRecord {
    pub txid: String,
    pub amount: u64,
    pub block_height: u64,
    pub timestamp: u64,
}

impl VaultState {
    /// Crear nuevo estado de vault
    pub fn new(vault_id: super::VaultId, current_block: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        VaultState {
            vault_id,
            status: VaultStatus::Active,
            balance: 0,
            created_at_block: current_block,
            created_at_time: now,
            last_activity_block: current_block,
            withdrawal_requests: Vec::new(),
            active_withdrawal: None,
            deposits: Vec::new(),
            total_deposited: 0,
            total_withdrawn: 0,
            cancellation_count: 0,
        }
    }
    
    /// Registrar depósito
    pub fn record_deposit(&mut self, txid: String, amount: u64, block_height: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.deposits.push(DepositRecord {
            txid,
            amount,
            block_height,
            timestamp: now,
        });
        
        self.balance += amount;
        self.total_deposited += amount;
        self.last_activity_block = block_height;
    }
    
    /// Iniciar retiro
    pub fn initiate_withdrawal(
        &mut self,
        amount: u64,
        destination: String,
        current_block: u64,
        delay_blocks: u32,
        estimated_fee: u64,
    ) -> Result<WithdrawalRequest, &'static str> {
        // Validaciones
        if !self.status.is_active() {
            return Err("Vault is not active");
        }
        
        if self.active_withdrawal.is_some() {
            return Err("There is already an active withdrawal");
        }
        
        if amount > self.balance {
            return Err("Insufficient balance");
        }
        
        if amount == 0 {
            return Err("Amount must be greater than 0");
        }
        
        // Crear solicitud
        let request = WithdrawalRequest::new(
            amount,
            destination.clone(),
            current_block,
            delay_blocks,
            estimated_fee,
        );
        
        // Actualizar estado
        self.status = VaultStatus::PendingWithdrawal {
            initiated_at_block: current_block,
            executable_at_block: request.executable_at_block,
            destination,
            amount,
            initiated_at_time: request.created_at_time,
        };
        
        self.active_withdrawal = Some(request.clone());
        self.last_activity_block = current_block;
        
        Ok(request)
    }
    
    /// Cancelar retiro activo
    pub fn cancel_withdrawal(
        &mut self,
        current_block: u64,
        recovery_txid: String,
        recovery_address: String,
        reason: Option<String>,
    ) -> Result<(), &'static str> {
        let withdrawal = self.active_withdrawal.take()
            .ok_or("No active withdrawal to cancel")?;
        
        // Actualizar estado
        self.status = VaultStatus::Cancelled {
            cancelled_at_block: current_block,
            recovery_txid,
            recovery_address: recovery_address.clone(),
            amount: withdrawal.amount,
            reason,
        };
        
        // Mover a historial
        let mut cancelled_request = withdrawal;
        cancelled_request.status = WithdrawalRequestStatus::Cancelled;
        self.withdrawal_requests.push(cancelled_request);
        
        // Actualizar contadores
        self.balance = 0; // Fondos enviados a recovery
        self.cancellation_count += 1;
        self.last_activity_block = current_block;
        
        Ok(())
    }
    
    /// Completar retiro
    pub fn complete_withdrawal(
        &mut self,
        current_block: u64,
        txid: String,
    ) -> Result<(), &'static str> {
        // IMPORTANTE: Verificar primero SIN remover el withdrawal
        let executable_at = self.active_withdrawal
            .as_ref()
            .ok_or("No active withdrawal to complete")?
            .executable_at_block;
        
        if current_block < executable_at {
            return Err("Withdrawal is not yet executable");
        }
        
        // Ahora sí podemos remover (sabemos que existe y es ejecutable)
        let withdrawal = self.active_withdrawal.take().unwrap();
        
        // Actualizar estado
        self.status = VaultStatus::Withdrawn {
            withdrawn_at_block: current_block,
            txid,
            destination: withdrawal.destination.clone(),
            amount: withdrawal.amount,
        };
        
        // Mover a historial
        let mut completed_request = withdrawal.clone();
        completed_request.status = WithdrawalRequestStatus::Completed;
        self.withdrawal_requests.push(completed_request);
        
        // Actualizar balance
        self.balance = self.balance.saturating_sub(withdrawal.amount);
        self.total_withdrawn += withdrawal.amount;
        self.last_activity_block = current_block;
        
        Ok(())
    }
    
    /// Verificar si se puede cancelar (hay retiro pendiente)
    pub fn can_cancel(&self) -> bool {
        self.active_withdrawal.is_some()
    }
    
    /// Verificar si se puede completar retiro
    pub fn can_complete_withdrawal(&self, current_block: u64) -> bool {
        if let Some(ref withdrawal) = self.active_withdrawal {
            current_block >= withdrawal.executable_at_block
        } else {
            false
        }
    }
    
    /// Obtener bloques restantes para retiro
    pub fn blocks_until_withdrawal(&self, current_block: u64) -> Option<u64> {
        self.active_withdrawal.as_ref().map(|w| w.blocks_remaining(current_block))
    }
    
    /// Reactivar vault después de cancelación
    pub fn reactivate(&mut self, current_block: u64) -> Result<(), &'static str> {
        if !self.status.is_cancelled() {
            return Err("Can only reactivate a cancelled vault");
        }
        
        self.status = VaultStatus::Active;
        self.last_activity_block = current_block;
        
        Ok(())
    }
}

// =============================================================================
// State Transitions (Validación formal)
// =============================================================================

/// Transiciones válidas del vault
#[derive(Clone, Debug)]
pub enum StateTransition {
    Deposit { amount: u64 },
    InitiateWithdrawal { amount: u64, destination: String },
    CancelWithdrawal { reason: Option<String> },
    CompleteWithdrawal,
    Reactivate,
    Close { reason: String },
}

impl VaultState {
    /// Verificar si una transición es válida
    pub fn is_valid_transition(&self, transition: &StateTransition) -> bool {
        match (&self.status, transition) {
            // Depósito: solo cuando está activo
            (VaultStatus::Active, StateTransition::Deposit { .. }) => true,
            
            // Iniciar retiro: solo cuando está activo y sin retiro pendiente
            (VaultStatus::Active, StateTransition::InitiateWithdrawal { .. }) => {
                self.active_withdrawal.is_none()
            }
            
            // Cancelar: solo cuando hay retiro pendiente
            (VaultStatus::PendingWithdrawal { .. }, StateTransition::CancelWithdrawal { .. }) => true,
            
            // Completar: solo cuando hay retiro pendiente (y el tiempo pasó - se verifica aparte)
            (VaultStatus::PendingWithdrawal { .. }, StateTransition::CompleteWithdrawal) => true,
            
            // Reactivar: solo después de cancelación
            (VaultStatus::Cancelled { .. }, StateTransition::Reactivate) => true,
            
            // Cerrar: desde activo o cancelado
            (VaultStatus::Active, StateTransition::Close { .. }) => true,
            (VaultStatus::Cancelled { .. }, StateTransition::Close { .. }) => true,
            
            _ => false,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    fn sample_vault_id() -> super::super::VaultId {
        super::super::VaultId([0xAB; 32])
    }
    
    #[test]
    fn test_vault_state_creation() {
        let state = VaultState::new(sample_vault_id(), 1000);
        
        assert!(state.status.is_active());
        assert_eq!(state.balance, 0);
        assert_eq!(state.created_at_block, 1000);
    }
    
    #[test]
    fn test_deposit() {
        let mut state = VaultState::new(sample_vault_id(), 1000);
        
        state.record_deposit("tx123".to_string(), 1_000_000, 1001);
        
        assert_eq!(state.balance, 1_000_000);
        assert_eq!(state.total_deposited, 1_000_000);
        assert_eq!(state.deposits.len(), 1);
    }
    
    #[test]
    fn test_initiate_withdrawal() {
        let mut state = VaultState::new(sample_vault_id(), 1000);
        state.record_deposit("tx123".to_string(), 1_000_000, 1001);
        
        let result = state.initiate_withdrawal(
            500_000,
            "MC1destination".to_string(),
            1002,
            144,
            1000,
        );
        
        assert!(result.is_ok());
        assert!(state.status.is_pending());
        assert!(state.active_withdrawal.is_some());
    }
    
    #[test]
    fn test_withdrawal_insufficient_balance() {
        let mut state = VaultState::new(sample_vault_id(), 1000);
        state.record_deposit("tx123".to_string(), 1_000_000, 1001);
        
        let result = state.initiate_withdrawal(
            2_000_000, // Más que el balance
            "MC1destination".to_string(),
            1002,
            144,
            1000,
        );
        
        assert!(result.is_err());
        assert!(state.status.is_active()); // No cambió
    }
    
    #[test]
    fn test_cancel_withdrawal() {
        let mut state = VaultState::new(sample_vault_id(), 1000);
        state.record_deposit("tx123".to_string(), 1_000_000, 1001);
        state.initiate_withdrawal(
            500_000,
            "MC1destination".to_string(),
            1002,
            144,
            1000,
        ).unwrap();
        
        let result = state.cancel_withdrawal(
            1003,
            "recovery_tx".to_string(),
            "MC1recovery".to_string(),
            Some("Detected suspicious activity".to_string()),
        );
        
        assert!(result.is_ok());
        assert!(state.status.is_cancelled());
        assert_eq!(state.cancellation_count, 1);
    }
    
    #[test]
    fn test_complete_withdrawal() {
        let mut state = VaultState::new(sample_vault_id(), 1000);
        state.record_deposit("tx123".to_string(), 1_000_000, 1001);
        state.initiate_withdrawal(
            500_000,
            "MC1destination".to_string(),
            1002,
            144, // 144 bloques de delay
            1000,
        ).unwrap();
        
        // Intentar completar antes de tiempo
        let early_result = state.complete_withdrawal(1050, "early_tx".to_string());
        assert!(early_result.is_err());
        
        // El withdrawal debe seguir existiendo después del error
        assert!(state.active_withdrawal.is_some());
        
        // Completar después del delay
        let result = state.complete_withdrawal(1002 + 144, "final_tx".to_string());
        assert!(result.is_ok());
        assert!(state.status.is_withdrawn());
        assert_eq!(state.balance, 500_000); // Se retiró la mitad
    }
    
    #[test]
    fn test_withdrawal_request_timing() {
        let request = WithdrawalRequest::new(
            1_000_000,
            "MC1dest".to_string(),
            1000,
            144,
            1000,
        );
        
        // Verificar ejecutabilidad
        assert!(!request.is_executable(1000));
        assert!(!request.is_executable(1100));
        assert!(request.is_executable(1144));
        assert!(request.is_executable(1200));
        
        // Bloques restantes
        assert_eq!(request.blocks_remaining(1000), 144);
        assert_eq!(request.blocks_remaining(1100), 44);
        assert_eq!(request.blocks_remaining(1200), 0);
    }
    
    #[test]
    fn test_state_transitions() {
        let mut state = VaultState::new(sample_vault_id(), 1000);
        
        // Depósito válido en estado activo
        assert!(state.is_valid_transition(&StateTransition::Deposit { amount: 100 }));
        
        // Retiro válido en estado activo
        assert!(state.is_valid_transition(&StateTransition::InitiateWithdrawal {
            amount: 100,
            destination: "test".to_string(),
        }));
        
        // Cancelar no válido sin retiro pendiente
        assert!(!state.is_valid_transition(&StateTransition::CancelWithdrawal { reason: None }));
        
        // Después de iniciar retiro
        state.record_deposit("tx".to_string(), 1000, 1001);
        state.initiate_withdrawal(100, "dest".to_string(), 1002, 10, 10).unwrap();
        
        // Ahora cancelar sí es válido
        assert!(state.is_valid_transition(&StateTransition::CancelWithdrawal { reason: None }));
    }
    
    #[test]
    fn test_reactivate_after_cancel() {
        let mut state = VaultState::new(sample_vault_id(), 1000);
        state.record_deposit("tx".to_string(), 1000, 1001);
        state.initiate_withdrawal(500, "dest".to_string(), 1002, 10, 10).unwrap();
        state.cancel_withdrawal(1003, "rec_tx".to_string(), "rec_addr".to_string(), None).unwrap();
        
        // Reactivar
        let result = state.reactivate(1004);
        assert!(result.is_ok());
        assert!(state.status.is_active());
    }
}
